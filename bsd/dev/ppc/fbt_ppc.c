/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)fbt.c	1.15	05/09/19 SMI" */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#define MACH__POSIX_C_SOURCE_PRIVATE 1 /* pulls in suitable savearea from mach/ppc/thread_status.h */
#include <kern/cpu_data.h>
#include <kern/thread.h>
#include <mach/thread_status.h>

#include <mach-o/loader.h> 
#include <mach-o/nlist.h>

extern struct mach_header _mh_execute_header; /* the kernel's mach header */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <miscfs/devfs/devfs.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/fbt.h>

#include <sys/dtrace_glue.h>
#include <machine/cpu_capabilities.h>

#define DTRACE_INVOP_NOP_SKIP 4

#define DTRACE_INVOP_MFLR_R0 11
#define DTRACE_INVOP_MFLR_R0_SKIP 4

#define FBT_MFLR_R0		0x7c0802a6

#define FBT_MTLR_R0		0x7c0803a6
#define FBT_BLR			0x4e800020
#define FBT_BCTR		0x4e800420

#define FBT_LI_MASK 0x03fffffc
#define FBT_JUMP	0x48000000
#define IS_JUMP(instr) (((instr) & ~FBT_LI_MASK) == FBT_JUMP) /* Relative, No LR update -- AA == 0b, LK == 0b */
#define FBT_LI_EXTD64(instr) \
	(((instr) & 0x02000000) ? \
	 	(((uint64_t)((instr) & FBT_LI_MASK)) | 0xfffffffffc000000ULL) : \
	 	 ((uint64_t)((instr) & FBT_LI_MASK)))

#define FBT_PATCHVAL	0x7c810808
#define FBT_AFRAMES_ENTRY		6
#define FBT_AFRAMES_RETURN		6

#define	FBT_ENTRY	"entry"
#define	FBT_RETURN	"return"
#define	FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & fbt_probetab_mask)

extern dtrace_provider_id_t	fbt_id;
extern fbt_probe_t		**fbt_probetab;
extern int			fbt_probetab_mask;

/*
 * Critical routines that must not be probed. PR_5221096, PR_5379018.
 */

static const char * critical_blacklist[] =
{
	"bcopy_phys",
	"bcopy_physvir_32",
	"cpu_control",
	"cpu_exit_wait",
	"cpu_info",
	"cpu_info_count",
	"cpu_init",
	"cpu_machine_init",
	"cpu_per_proc_alloc",
	"cpu_per_proc_free",
	"cpu_signal_handler",
	"cpu_sleep",
	"cpu_start",
	"cpu_subtype",
	"cpu_threadtype",
	"cpu_to_processor",
	"cpu_type",
	"mapSkipListVerifyC",
	"ml_nofault_copy",
	"register_cpu_setup_func",
	"unregister_cpu_setup_func"
};
#define CRITICAL_BLACKLIST_COUNT (sizeof(critical_blacklist)/sizeof(critical_blacklist[0]))

/*
 * The transitive closure of entry points that can be reached from probe context.
 * (Apart from routines whose names begin with dtrace_ or dtxnu_.)
 */
static const char * probe_ctx_closure[] =
{
	"Debugger",
	"MapUserMemoryWindow",
	"OSCompareAndSwap",
	"absolutetime_to_microtime",
	"bcopy",
	"clock_get_calendar_nanotime_nowait",
	"copyin",
	"copyinstr",
	"copyout",
	"copyoutstr",
	"cpu_number",
	"current_proc",
	"current_processor",
	"current_task",
	"current_thread",
	"debug_enter",
	"find_user_regs",
	"getPerProc",
	"get_bsdtask_info",
	"get_bsdthread_info",
	"get_threadtask",
	"hw_atomic_and",
	"hw_compare_and_store",
	"hw_find_map",
	"kauth_cred_get",
	"kauth_getgid",
	"kauth_getuid",
	"mach_absolute_time",
	"mapping_drop_busy",
	"mapping_find",
	"mapping_phys_lookup",
	"max_valid_stack_address",
	"ml_at_interrupt_context",
	"ml_phys_write_byte_64",
	"ml_phys_write_half_64",
	"ml_phys_write_word_64",
	"ml_set_interrupts_enabled",
	"panic",
	"pmap_find_phys",
	"prf",
	"proc_is64bit",
	"proc_selfname",
	"proc_selfpid",
	"psignal_lock",
	"splhigh",
	"splx",
	"strlcpy",
	"timer_grab"
};
#define PROBE_CTX_CLOSURE_COUNT (sizeof(probe_ctx_closure)/sizeof(probe_ctx_closure[0]))

static int _cmp(const void *a, const void *b)
{
	return strcmp((const char *)a, *(const char **)b);
}

static const void * bsearch(
	register const void *key,
	const void *base0,
	size_t nmemb,
	register size_t size,
	register int (*compar)(const void *, const void *)) {

	register const char *base = base0;
	register size_t lim;
	register int cmp;
	register const void *p;

	for (lim = nmemb; lim != 0; lim >>= 1) {
		p = base + (lim >> 1) * size;
		cmp = (*compar)(key, p);
		if (cmp == 0)
			return p;
		if (cmp > 0) {	/* key > p: move right */
			base = (const char *)p + size;
			lim--;
		}		/* else move left */
	}
	return (NULL);
}

int
fbt_invop(uintptr_t addr, uintptr_t *stack, uintptr_t rval)
{
	fbt_probe_t *fbt = fbt_probetab[FBT_ADDR2NDX(addr)];
	uint64_t mask = (_cpu_capabilities & k64Bit) ? 0xffffffffffffffffULL : 0x00000000ffffffffULL;

	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint == addr) {
			
			if (fbt->fbtp_roffset == 0) {
				ppc_saved_state_t *regs = (ppc_saved_state_t *)stack;

				CPU->cpu_dtrace_caller = addr;
				
				dtrace_probe(fbt->fbtp_id, regs->save_r3 & mask, regs->save_r4 & mask,
					regs->save_r5 & mask, regs->save_r6 & mask, regs->save_r7 & mask);
					
				CPU->cpu_dtrace_caller = NULL;
			} else {
			
				dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset, rval, 0, 0, 0);

				if (fbt->fbtp_rval == DTRACE_INVOP_TAILJUMP) {
					ppc_saved_state_t *regs = (ppc_saved_state_t *)stack;

					regs->save_srr0 = (uint64_t)fbt->fbtp_patchpoint + FBT_LI_EXTD64(fbt->fbtp_savedval);
					regs->save_srr0 &= mask;
				}
				
				CPU->cpu_dtrace_caller = NULL;
			}

			return (fbt->fbtp_rval);
		}
	}

	return (0);
}

#include <ppc/proc_reg.h> /* For USER_MODE */
#define IS_USER_TRAP(regs) USER_MODE((regs)->save_srr1)
#define T_VECTOR_SIZE   4               /* function pointer size */
#define T_PROGRAM       (0x07 * T_VECTOR_SIZE)
#define FBT_EXCEPTION_CODE T_PROGRAM

kern_return_t
fbt_perfCallback(
                int         trapno,
                ppc_saved_state_t *regs,
                int         unused1,
                int         unused2)
{
#pragma unused (unused1)
#pragma unused (unused2)
	kern_return_t retval = KERN_FAILURE;
	
	if (!IS_USER_TRAP(regs) && FBT_EXCEPTION_CODE == trapno) {
		boolean_t oldlevel;
		
		oldlevel = ml_set_interrupts_enabled(FALSE);
						
		switch (dtrace_invop( regs->save_srr0, (uintptr_t *)regs, regs->save_r3 )) {
		case DTRACE_INVOP_NOP:
			regs->save_srr0 += DTRACE_INVOP_NOP_SKIP;	/* Skip over the bytes of the patched NOP */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_MFLR_R0:
			regs->save_r0 = regs->save_lr;					/* Emulate patched mflr r0 */
			regs->save_srr0 += DTRACE_INVOP_MFLR_R0_SKIP;	/* Skip over the bytes of the patched mflr r0 */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_RET:
			regs->save_srr0 = regs->save_lr;				/* Emulate patched blr by resuming execution at the LR */
			retval = KERN_SUCCESS;
			break;
			
		case DTRACE_INVOP_BCTR:
			regs->save_srr0 = regs->save_ctr;				/* Emulate patched bctr by resuming execution at the CTR */
			retval = KERN_SUCCESS;
			break;
			
		case DTRACE_INVOP_TAILJUMP:
			retval = KERN_SUCCESS;
			break;
			
		default:
			retval = KERN_FAILURE;
			break;
		}
		ml_set_interrupts_enabled(oldlevel);
	}
	
	return retval;
}

kern_return_t
fbt_perfIntCallback(
                int         trapno,
                ppc_saved_state_t *regs,
                int         unused1,
                int         unused2)
{
	kern_return_t retval = KERN_FAILURE;
	
	if (KERN_SUCCESS == (retval = fbt_perfCallback(trapno, regs, unused1, unused2)))
		enable_preemption();
	
	return retval;
}

/*ARGSUSED*/
static void
__fbt_provide_module(void *arg, struct modctl *ctl)
{
#pragma unused(arg)
	struct mach_header			*mh;
	struct load_command         *cmd;
    struct segment_command      *orig_ts = NULL, *orig_le = NULL;
    struct symtab_command       *orig_st = NULL;
	struct nlist                *sym = NULL;
	char						*strings;
	uintptr_t					instrLow, instrHigh;
	char						*modname;
	unsigned int i;

	int gIgnoreFBTBlacklist = 0;
	PE_parse_boot_argn("IgnoreFBTBlacklist", &gIgnoreFBTBlacklist, sizeof (gIgnoreFBTBlacklist));

	mh = (struct mach_header *)(ctl->address);
	modname = ctl->mod_modname;
	
	if (0 == ctl->address || 0 == ctl->size) /* Has the linker been jettisoned? */
		return;
		
	/*
	 * Employees of dtrace and their families are ineligible.  Void
	 * where prohibited.
	 */

	if (strcmp(modname, "com.apple.driver.dtrace") == 0)
		return;

	if (strstr(modname, "CHUD") != NULL)
		return;
		
	if (mh->magic != MH_MAGIC)
		return;
		
	cmd = (struct load_command *) &mh[1];
	for (i = 0; i < mh->ncmds; i++) {
        if (cmd->cmd == LC_SEGMENT) {
            struct segment_command *orig_sg = (struct segment_command *) cmd;
 
            if (strcmp(SEG_TEXT, orig_sg->segname) == 0)
                orig_ts = orig_sg;
            else if (strcmp(SEG_LINKEDIT, orig_sg->segname) == 0)
                orig_le = orig_sg;
            else if (strcmp("", orig_sg->segname) == 0)
                orig_ts = orig_sg; /* kexts have a single unnamed segment */
        }
        else if (cmd->cmd == LC_SYMTAB)
            orig_st = (struct symtab_command *) cmd;

        cmd = (struct load_command *) ((caddr_t) cmd + cmd->cmdsize);
    }

	if ((orig_ts == NULL) || (orig_st == NULL) || (orig_le == NULL))
		return;

    sym = (struct nlist *)orig_le->vmaddr;
    strings = ((char *)sym) + orig_st->nsyms * sizeof(struct nlist);
	
	/* Find extent of the TEXT section */
	instrLow = (uintptr_t)orig_ts->vmaddr;
	instrHigh = (uintptr_t)(orig_ts->vmaddr + orig_ts->vmsize);

	for (i = 0; i < orig_st->nsyms; i++) {
		fbt_probe_t *fbt, *retfbt;
		machine_inst_t *instr, *limit, theInstr;
        uint8_t n_type = sym[i].n_type & (N_TYPE | N_EXT);
		char *name = strings + sym[i].n_un.n_strx;
		int j;

		/* Check that the symbol is a global and that it has a name. */
        if (((N_SECT | N_EXT) != n_type && (N_ABS | N_EXT) != n_type))
            continue;
			
		if (0 == sym[i].n_un.n_strx) /* iff a null, "", name. */
			continue;
 
		/* Lop off omnipresent leading underscore. */			
		if (*name == '_')
			name += 1;
		
		if (strstr(name, "dtrace_") == name &&
		    strstr(name, "dtrace_safe_") != name) {
			/*
			 * Anything beginning with "dtrace_" may be called
			 * from probe context unless it explitly indicates
			 * that it won't be called from probe context by
			 * using the prefix "dtrace_safe_".
			 */
			continue;
		}
		
        if (strstr(name, "dsmos_") == name) 
            continue; /* Don't Steal Mac OS X! */

        if (strstr(name, "dtxnu_") == name ||
			strstr(name, "_dtrace") == name) 
			continue; /* Shims in dtrace.c */
		
		if (strstr(name, "chud") == name)
			continue; /* Professional courtesy. */

        if (strstr(name, "hibernate_") == name)
            continue; /* Let sleeping dogs lie. */
        
        if (0 == strcmp(name, "ZN9IOService14newTemperatureElPS_") || /* IOService::newTemperature */
            0 == strcmp(name, "ZN9IOService26temperatureCriticalForZoneEPS_")) /* IOService::temperatureCriticalForZone */
            continue; /* Per the fire code */

		/*
		 * Place no probes (illegal instructions) in the exception handling path!
		 */
		if (0 == strcmp(name, "L_handler700") ||
			0 == strcmp(name, "save_get_phys_64") ||
			0 == strcmp(name, "save_get_phys_32") ||
			0 == strcmp(name, "EmulExit") ||
			0 == strcmp(name, "Emulate") ||
			0 == strcmp(name, "Emulate64") ||
			0 == strcmp(name, "switchSegs") ||
			0 == strcmp(name, "save_ret_phys"))
			continue;

		if (0 == strcmp(name, "thandler") ||
			0 == strcmp(name, "versave") ||
			0 == strcmp(name, "timer_event") ||
			0 == strcmp(name, "hw_atomic_or") ||
			0 == strcmp(name, "trap"))
			continue;

		if (0 == strcmp(name, "fbt_perfCallback") ||
			0 == strcmp(name, "fbt_perfIntCallback") ||
			0 == strcmp(name, "ml_set_interrupts_enabled") ||
			0 == strcmp(name, "dtrace_invop") ||
			0 == strcmp(name, "fbt_invop") ||
			0 == strcmp(name, "sdt_invop") ||
			0 == strcmp(name, "max_valid_stack_address"))
			continue;

		/*
		 * Probes encountered while we're on the interrupt stack are routed along
		 * the interrupt handling path. No probes allowed there either!
		 */
		if (0 == strcmp(name, "ihandler") ||
			0 == strcmp(name, "interrupt") ||
			0 == strcmp(name, "disable_preemption"))
			continue;

		/*
		 * Avoid weird stack voodoo in and under machine_stack_handoff et al
		 */
        if (strstr(name, "machine_stack") == name ||
            0 == strcmp(name, "getPerProc") ||     /* Called in machine_stack_handoff with weird stack state */
            0 == strcmp(name, "fpu_save") ||     /* Called in machine_stack_handoff with weird stack state */
            0 == strcmp(name, "vec_save") ||     /* Called in machine_stack_handoff with weird stack state */
            0 == strcmp(name, "pmap_switch"))     /* Called in machine_stack_handoff with weird stack state */
				continue;

		/*
		 * Avoid machine_ routines. PR_5346750.
		 */
		if (strstr(name, "machine_") == name)
			continue;

		/*
		 * Avoid low level pmap and virtual machine monitor PowerPC routines. See PR_5379018.
		 */

		if (strstr(name, "hw_") == name ||
			strstr(name, "mapping_") == name ||
			strstr(name, "commpage_") == name ||
			strstr(name, "pmap_") == name ||
			strstr(name, "vmm_") == name)
				continue;
		/*
		 * Place no probes on critical routines. PR_5221096
		 */
		if (!gIgnoreFBTBlacklist && 
			bsearch( name, critical_blacklist, CRITICAL_BLACKLIST_COUNT, sizeof(name), _cmp ) != NULL)
				continue;

		/*
		 * Place no probes that could be hit in probe context.
		 */
		if (!gIgnoreFBTBlacklist && 
			bsearch( name, probe_ctx_closure, PROBE_CTX_CLOSURE_COUNT, sizeof(name), _cmp ) != NULL)
				continue;

		/*
		 * Place no probes that could be hit on the way to the debugger.
		 */
		if (strstr(name, "kdp_") == name ||
			strstr(name, "kdb_") == name ||
			strstr(name, "kdbg_") == name ||
			strstr(name, "kdebug_") == name ||
			0 == strcmp(name, "kernel_debug") ||
			0 == strcmp(name, "Debugger") ||
			0 == strcmp(name, "Call_DebuggerC") ||
			0 == strcmp(name, "lock_debugger") ||
			0 == strcmp(name, "unlock_debugger") ||
			0 == strcmp(name, "SysChoked")) 
			continue;
		
		/*
		 * Place no probes that could be hit on the way to a panic.
		 */
		if (NULL != strstr(name, "panic_") ||
			0 == strcmp(name, "panic") ||
			0 == strcmp(name, "handleMck") ||
			0 == strcmp(name, "unresolved_kernel_trap"))
			continue;
		
		if (dtrace_probe_lookup(fbt_id, modname, name, NULL) != 0)
			continue;
			
		/*
		 * Scan forward for mflr r0.
		 */
		for (j = 0, instr = (machine_inst_t *)sym[i].n_value, theInstr = 0;
			 (j < 4) && ((uintptr_t)instr >= instrLow) && (instrHigh > (uintptr_t)instr);
			 j++, instr++) 
		{
			theInstr = *instr;
			if (theInstr == FBT_MFLR_R0) /* Place the entry probe here. */
				break;
			if (theInstr == FBT_MTLR_R0) /* We've gone too far, bail. */
				break;
			if (theInstr == FBT_BLR) /* We've gone too far, bail. */
				break;
		}
			
		if (theInstr != FBT_MFLR_R0)
			continue;
			
		limit = (machine_inst_t *)instrHigh;

		fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
		strlcpy( (char *)&(fbt->fbtp_name), name, MAX_FBTP_NAME_CHARS );
		fbt->fbtp_id = dtrace_probe_create(fbt_id, modname, name, FBT_ENTRY, FBT_AFRAMES_ENTRY, fbt);
		fbt->fbtp_patchpoint = instr;
		fbt->fbtp_ctl = ctl;
		fbt->fbtp_loadcnt = ctl->mod_loadcnt;
		fbt->fbtp_rval = DTRACE_INVOP_MFLR_R0;
		fbt->fbtp_savedval = theInstr;
		fbt->fbtp_patchval = FBT_PATCHVAL;

		fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
		fbt->fbtp_symndx = i;
		fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

		instr++; /* Move on down the line */
		retfbt = NULL;
again:
		if (instr >= limit)
			continue;

		/*
		 * We (desperately) want to avoid erroneously instrumenting a
		 * jump table. To determine if we're looking at a true instruction
		 * or an inline jump table that happens to contain the same
		 * byte sequences, we resort to some heuristic sleeze:  we
		 * treat this instruction as being contained within a pointer,
		 * and see if that pointer points to within the body of the
		 * function.  If it does, we refuse to instrument it.
		 */
		{
			machine_inst_t *ptr = *(machine_inst_t **)instr;

			if (ptr >= (machine_inst_t *)sym[i].n_value && ptr < limit) {
				instr++;
				goto again;
			}
		}

		/*
		 * OK, it's an instruction.
		 */
		theInstr = *instr;

		/* Walked onto the start of the next routine? If so, bail out from this function. */
		if (theInstr == FBT_MFLR_R0)
			continue;

		if (theInstr != FBT_MTLR_R0) {
			instr++;
			goto again;
		}

		/*
		 * Found mtlr r0;
		 * Scan forward for a blr, bctr, or a jump (relative, no LR change).
		 */
		instr++;
		for (j = 0; (j < 12) && (instr < limit); j++, instr++) {
			theInstr = *instr;
			if (theInstr == FBT_BLR || theInstr == FBT_BCTR || IS_JUMP(theInstr) || 
				theInstr == FBT_MFLR_R0 || theInstr == FBT_MTLR_R0)
				break;
		}

		if (!(theInstr == FBT_BLR || theInstr == FBT_BCTR || IS_JUMP(theInstr)))
			goto again;

		/*
		 * We have a winner: "mtlr r0; ... ; {blr, bctr, j}" !
		 */
		fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
		strlcpy( (char *)&(fbt->fbtp_name), name, MAX_FBTP_NAME_CHARS );

		if (retfbt == NULL) {
			fbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
			    name, FBT_RETURN, FBT_AFRAMES_RETURN, fbt);
		} else {
			retfbt->fbtp_next = fbt;
			fbt->fbtp_id = retfbt->fbtp_id;
		}

		retfbt = fbt;
		fbt->fbtp_patchpoint = instr;
		fbt->fbtp_ctl = ctl;
		fbt->fbtp_loadcnt = ctl->mod_loadcnt;

		if (theInstr == FBT_BLR)
			fbt->fbtp_rval = DTRACE_INVOP_RET;
		else if (theInstr == FBT_BCTR)
			fbt->fbtp_rval = DTRACE_INVOP_BCTR;
		else
			fbt->fbtp_rval = DTRACE_INVOP_TAILJUMP;

		fbt->fbtp_roffset =
		    (uintptr_t)((uint8_t *)instr - (uint8_t *)sym[i].n_value);

		fbt->fbtp_savedval = *instr;
		fbt->fbtp_patchval = FBT_PATCHVAL;
		fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
		fbt->fbtp_symndx = i;
		fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;
		instr++;
		goto again;
	}
}

extern struct modctl g_fbt_kernctl;
#undef kmem_alloc /* from its binding to dt_kmem_alloc glue */
#undef kmem_free /* from its binding to dt_kmem_free glue */
#include <vm/vm_kern.h>

/*ARGSUSED*/
void
fbt_provide_module(void *arg, struct modctl *ctl)
{
#pragma unused(ctl)
	__fbt_provide_module(arg, &g_fbt_kernctl);

    kmem_free(kernel_map, (vm_offset_t)g_fbt_kernctl.address, round_page_32(g_fbt_kernctl.size));
	g_fbt_kernctl.address = 0;
	g_fbt_kernctl.size = 0;
}
