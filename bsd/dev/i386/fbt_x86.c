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
#include <kern/thread.h>
#include <mach/thread_status.h>
#include <mach/vm_param.h>
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

#define DTRACE_INVOP_NOP_SKIP 1
#define DTRACE_INVOP_MOVL_ESP_EBP 10
#define DTRACE_INVOP_MOVL_ESP_EBP_SKIP 2
#define DTRACE_INVOP_LEAVE_SKIP 1

#define	FBT_PUSHL_EBP			0x55
#define	FBT_MOVL_ESP_EBP0_V0	0x8b
#define	FBT_MOVL_ESP_EBP1_V0	0xec
#define	FBT_MOVL_ESP_EBP0_V1	0x89
#define	FBT_MOVL_ESP_EBP1_V1	0xe5
#define	FBT_REX_RSP_RBP			0x48

#define	FBT_POPL_EBP			0x5d
#define	FBT_RET					0xc3
#define	FBT_RET_IMM16			0xc2
#define	FBT_LEAVE				0xc9
#define	FBT_JMP_SHORT_REL		0xeb /* Jump short, relative, displacement relative to next instr. */
#define	FBT_JMP_NEAR_REL		0xe9 /* Jump near, relative, displacement relative to next instr. */
#define	FBT_JMP_FAR_ABS			0xea /* Jump far, absolute, address given in operand */
#define FBT_RET_LEN				1
#define FBT_RET_IMM16_LEN		3
#define	FBT_JMP_SHORT_REL_LEN	2
#define	FBT_JMP_NEAR_REL_LEN	5
#define	FBT_JMP_FAR_ABS_LEN		5

#define	FBT_PATCHVAL			0xf0
#define FBT_AFRAMES_ENTRY		7
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
	"console_cpu_alloc", 
	"console_cpu_free", 
	"cpu_IA32e_disable", 
	"cpu_IA32e_enable", 
	"cpu_control", 
	"cpu_data_alloc", 
	"cpu_desc_init", 
	"cpu_desc_init64", 
	"cpu_desc_load64", 
	"cpu_exit_wait", 
	"cpu_info", 
	"cpu_info_count", 
	"cpu_init", 
	"cpu_interrupt", 
	"cpu_machine_init", 
	"cpu_mode_init", 
	"cpu_processor_alloc", 
	"cpu_processor_free", 
	"cpu_signal_handler", 
	"cpu_sleep", 
	"cpu_start", 
	"cpu_subtype", 
	"cpu_thread_alloc", 
	"cpu_thread_halt", 
	"cpu_thread_init", 
	"cpu_threadtype", 
	"cpu_to_processor", 
	"cpu_topology_start", 
	"cpu_type", 
	"cpu_window_init", 
	"cpuid_cpu_display",
	"handle_pending_TLB_flushes",
	"hw_compare_and_store",
	"machine_idle_cstate",
	"mca_cpu_alloc",
	"mca_cpu_init",
	"ml_nofault_copy",
	"pmap_cpu_alloc", 
	"pmap_cpu_free", 
	"pmap_cpu_high_map_vaddr", 
	"pmap_cpu_high_shared_remap", 
	"pmap_cpu_init",
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
	"OSCompareAndSwap",
	"absolutetime_to_microtime",
	"ast_pending",
	"clock_get_calendar_nanotime_nowait",
	"copyin",
	"copyin_user",
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
	"flush_tlb64",
	"get_bsdtask_info",
	"get_bsdthread_info",
	"hw_atomic_and",
	"kauth_cred_get",
	"kauth_getgid",
	"kauth_getuid",
	"kernel_preempt_check",
	"mach_absolute_time",
	"max_valid_stack_address",
	"ml_at_interrupt_context",
	"ml_phys_write_byte_64",
	"ml_phys_write_half_64",
	"ml_phys_write_word_64",
	"ml_set_interrupts_enabled",
	"panic",
	"pmap64_pde",
	"pmap64_pdpt",
	"pmap_find_phys",
	"pmap_get_mapwindow",
	"pmap_pde",
	"pmap_pte",
	"pmap_put_mapwindow",
	"pmap_valid_page",
	"prf",
	"proc_is64bit",
	"proc_selfname",
	"proc_selfpid",
	"psignal_lock",
	"rtc_nanotime_load",
	"rtc_nanotime_read",
	"strlcpy",
	"sync_iss_to_iks_unconditionally",
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
	uintptr_t stack0 = 0, stack1 = 0, stack2 = 0, stack3 = 0, stack4 = 0;
	fbt_probe_t *fbt = fbt_probetab[FBT_ADDR2NDX(addr)];

	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint == addr) {

			if (fbt->fbtp_roffset == 0) {
				uintptr_t *stacktop;
        			if (CPU_ON_INTR(CPU))
                			stacktop = (uintptr_t *)dtrace_get_cpu_int_stack_top();
        			else
                			stacktop = (uintptr_t *)(dtrace_get_kernel_stack(current_thread()) + KERNEL_STACK_SIZE);

				stack += 1; /* skip over the target's pushl'd %ebp */

				if (stack <= stacktop)
					CPU->cpu_dtrace_caller = *stack++;
				if (stack <= stacktop)
					stack0 = *stack++;
				if (stack <= stacktop)
					stack1 = *stack++;
				if (stack <= stacktop)
					stack2 = *stack++;
				if (stack <= stacktop)
					stack3 = *stack++;
				if (stack <= stacktop)
					stack4 = *stack++;

				dtrace_probe(fbt->fbtp_id, stack0, stack1, stack2, stack3, stack4);
				CPU->cpu_dtrace_caller = 0;
			} else {
				dtrace_probe(fbt->fbtp_id, fbt->fbtp_roffset, rval, 0, 0, 0);
				CPU->cpu_dtrace_caller = 0;
			}

			return (fbt->fbtp_rval);
		}
	}

	return (0);
}

#define IS_USER_TRAP(regs) (regs && (((regs)->cs & 3) != 0))
#define T_INVALID_OPCODE 6
#define FBT_EXCEPTION_CODE T_INVALID_OPCODE

kern_return_t
fbt_perfCallback(
                int         		trapno,
                x86_saved_state_t 	*tagged_regs,
                __unused int        unused1,
                __unused int        unused2)
{
	kern_return_t retval = KERN_FAILURE;
	x86_saved_state32_t *saved_state = saved_state32(tagged_regs);
	struct x86_saved_state32_from_kernel *regs = (struct x86_saved_state32_from_kernel *)saved_state;

	if (FBT_EXCEPTION_CODE == trapno && !IS_USER_TRAP(saved_state)) {
		boolean_t oldlevel, cpu_64bit;
		uint32_t esp_probe, *ebp, edi, fp, *pDst, delta = 0;
		int emul;

		cpu_64bit = ml_is64bit();
		oldlevel = ml_set_interrupts_enabled(FALSE);

		/* Calculate where the stack pointer was when the probe instruction "fired." */
		if (cpu_64bit) {
			esp_probe = saved_state->uesp; /* Easy, x86_64 establishes this value in idt64.s */
		} else {
			esp_probe = (uint32_t)&(regs[1]); /* Nasty, infer the location above the save area */
		}

		emul = dtrace_invop( saved_state->eip, (uintptr_t *)esp_probe, saved_state->eax );
		__asm__ volatile(".globl _dtrace_invop_callsite");
		__asm__ volatile("_dtrace_invop_callsite:");

		switch (emul) {
		case DTRACE_INVOP_NOP:
			saved_state->eip += DTRACE_INVOP_NOP_SKIP;	/* Skip over the patched NOP */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_MOVL_ESP_EBP:
			saved_state->ebp = esp_probe;						/* Emulate patched movl %esp,%ebp */
			saved_state->eip += DTRACE_INVOP_MOVL_ESP_EBP_SKIP;	/* Skip over the bytes of the patched movl %esp,%ebp */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_POPL_EBP:
		case DTRACE_INVOP_LEAVE:
/*
 * Emulate first micro-op of patched leave: movl %ebp,%esp
 * fp points just below the return address slot for target's ret 
 * and at the slot holding the frame pointer saved by the target's prologue.
 */
			fp = saved_state->ebp;
/* Emulate second micro-op of patched leave: patched popl %ebp
 * savearea ebp is set for the frame of the caller to target
 * The *live* %esp will be adjusted below for pop increment(s)
 */
			saved_state->ebp = *(uint32_t *)fp;
/* Skip over the patched leave */
			saved_state->eip += DTRACE_INVOP_LEAVE_SKIP;
/*
 * Lift the stack to account for the emulated leave
 * Account for words local in this frame
 * (in "case DTRACE_INVOP_POPL_EBP:" this is zero.)
 */
			delta = ((uint32_t *)fp) - ((uint32_t *)esp_probe);
/* Account for popping off the ebp (just accomplished by the emulation
 * above...)
 */
			delta += 1;
			
			if (cpu_64bit)
				saved_state->uesp += (delta << 2);

/* XXX Fragile in the extreme. Obtain the value of %edi that our caller pushed
 * (on behalf of its caller -- trap_from_kernel()). Ultimately,
 * trap_from_kernel's stack pointer is restored from this slot.
 * This is sensitive to the manner in which the compiler preserves %edi,
 * and trap_from_kernel()'s internals.
 */
			ebp = (uint32_t *)__builtin_frame_address(0);
			ebp = (uint32_t *)*ebp;
			edi = *(ebp - 1);
/* Shift contents of stack */
			for (pDst = (uint32_t *)fp;
			     pDst > (((uint32_t *)edi));
				 pDst--)
				*pDst = pDst[-delta];
/* Now adjust the value of %edi in our caller (kernel_trap)'s frame */
			*(ebp - 1) = edi + (delta << 2);

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
	unsigned int i, j;

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
		machine_inst_t *instr, *limit, theInstr, i1, i2;
		uint8_t n_type = sym[i].n_type & (N_TYPE | N_EXT);
		char *name = strings + sym[i].n_un.n_strx;
		int size;

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
		if (0 == strcmp(name, "t_invop") ||
			0 == strcmp(name, "enter_lohandler") ||
			0 == strcmp(name, "lo_alltraps") ||
			0 == strcmp(name, "kernel_trap") ||
			0 == strcmp(name, "i386_astintr"))
			continue;

		if (0 == strcmp(name, "current_thread") ||
			0 == strcmp(name, "ast_pending") ||
			0 == strcmp(name, "fbt_perfCallback") ||
			0 == strcmp(name, "machine_thread_get_kern_state") ||
			0 == strcmp(name, "ml_set_interrupts_enabled") ||
			0 == strcmp(name, "dtrace_invop") ||
			0 == strcmp(name, "fbt_invop") ||
			0 == strcmp(name, "sdt_invop") ||
			0 == strcmp(name, "max_valid_stack_address"))
			continue;

		/*
		 * Voodoo.
		 */
		if (strstr(name, "machine_stack_") == name ||
			strstr(name, "mapping_") == name ||
			0 == strcmp(name, "tmrCvt") ||

			strstr(name, "tsc_") == name ||

			strstr(name, "pmCPU") == name ||
			0 == strcmp(name, "Cstate_table_set") ||
			0 == strcmp(name, "pmKextRegister") ||
			0 == strcmp(name, "pmSafeMode") ||
			0 == strcmp(name, "pmUnregister") ||
			strstr(name, "pms") == name ||
			0 == strcmp(name, "power_management_init") ||
			strstr(name, "usimple_") == name ||

			strstr(name, "rtc_") == name ||
			strstr(name, "_rtc_") == name ||
			strstr(name, "rtclock_") == name ||
			strstr(name, "clock_") == name ||
			strstr(name, "absolutetime_to_") == name ||
			0 == strcmp(name, "setPop") ||
			0 == strcmp(name, "nanoseconds_to_absolutetime") ||
			0 == strcmp(name, "nanotime_to_absolutetime") ||

			strstr(name, "etimer_") == name ||

			strstr(name, "commpage_") == name ||
			strstr(name, "pmap_") == name ||
			strstr(name, "ml_") == name ||
			strstr(name, "PE_") == name ||
			strstr(name, "lapic_") == name ||
			strstr(name, "acpi_") == name)
			continue;

        /*
         * Avoid machine_ routines. PR_5346750.
         */
        if (strstr(name, "machine_") == name)
            continue;

		if (0 == strcmp(name, "handle_pending_TLB_flushes"))
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

		for (j = 0, instr = (machine_inst_t *)sym[i].n_value, theInstr = 0;
			 (j < 4) && ((uintptr_t)instr >= instrLow) && (instrHigh > (uintptr_t)(instr + 2)); 
			 j++) {
			theInstr = instr[0];
			if (theInstr == FBT_PUSHL_EBP || theInstr == FBT_RET || theInstr == FBT_RET_IMM16)
				break;

			if ((size = dtrace_instr_size(instr)) <= 0)
				break;
 
			instr += size;
		}

		if (theInstr != FBT_PUSHL_EBP)
			continue;

		i1 = instr[1];
		i2 = instr[2];

		limit = (machine_inst_t *)instrHigh;

		if ((i1 == FBT_MOVL_ESP_EBP0_V0 && i2 == FBT_MOVL_ESP_EBP1_V0) ||
			(i1 == FBT_MOVL_ESP_EBP0_V1 && i2 == FBT_MOVL_ESP_EBP1_V1)) {
				instr += 1; /* Advance to the movl %esp,%ebp */
				theInstr = i1;
		} else {
			/*
			 * Sometimes, the compiler will schedule an intervening instruction
			 * in the function prologue. Example:
			 *
			 * _mach_vm_read:
			 * 000006d8        pushl   %ebp
			 * 000006d9        movl    $0x00000004,%edx
			 * 000006de        movl    %esp,%ebp
			 * 
			 * Try the next instruction, to see if it is a movl %esp,%ebp
			 */

			instr += 1; /* Advance past the pushl %ebp */
			if ((size = dtrace_instr_size(instr)) <= 0)
				continue;
 
			instr += size;

			if ((instr + 1) >= limit)
				continue;

			i1 = instr[0];
			i2 = instr[1];

			if (!(i1 == FBT_MOVL_ESP_EBP0_V0 && i2 == FBT_MOVL_ESP_EBP1_V0) &&
				!(i1 == FBT_MOVL_ESP_EBP0_V1 && i2 == FBT_MOVL_ESP_EBP1_V1))
				continue;

			/* instr already points at the movl %esp,%ebp */
			theInstr = i1;
		}

		fbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
		strlcpy( (char *)&(fbt->fbtp_name), name, MAX_FBTP_NAME_CHARS );
		fbt->fbtp_id = dtrace_probe_create(fbt_id, modname, name, FBT_ENTRY, FBT_AFRAMES_ENTRY, fbt);
		fbt->fbtp_patchpoint = instr;
		fbt->fbtp_ctl = ctl;
		fbt->fbtp_loadcnt = ctl->mod_loadcnt;
		fbt->fbtp_rval = DTRACE_INVOP_MOVL_ESP_EBP;
		fbt->fbtp_savedval = theInstr;
		fbt->fbtp_patchval = FBT_PATCHVAL;

		fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
		fbt->fbtp_symndx = i;
		fbt_probetab[FBT_ADDR2NDX(instr)] = fbt;

		retfbt = NULL;
again:
		if (instr >= limit)
			continue;

		/*
		 * If this disassembly fails, then we've likely walked off into
		 * a jump table or some other unsuitable area.  Bail out of the
		 * disassembly now.
		 */
		if ((size = dtrace_instr_size(instr)) <= 0)
			continue;

		/*
		 * We (desperately) want to avoid erroneously instrumenting a
		 * jump table, especially given that our markers are pretty
		 * short:  two bytes on x86, and just one byte on amd64.  To
		 * determine if we're looking at a true instruction sequence
		 * or an inline jump table that happens to contain the same
		 * byte sequences, we resort to some heuristic sleeze:  we
		 * treat this instruction as being contained within a pointer,
		 * and see if that pointer points to within the body of the
		 * function.  If it does, we refuse to instrument it.
		 */
		for (j = 0; j < sizeof (uintptr_t); j++) {
			uintptr_t check = (uintptr_t)instr - j;
			uint8_t *ptr;

			if (check < sym[i].n_value)
				break;

			if (check + sizeof (uintptr_t) > (uintptr_t)limit)
				continue;

			ptr = *(uint8_t **)check;

			if (ptr >= (uint8_t *)sym[i].n_value && ptr < limit) {
				instr += size;
				goto again;
			}
		}

		/*
		 * OK, it's an instruction.
		 */
		theInstr = instr[0];

		/* Walked onto the start of the next routine? If so, bail out of this function. */
		if (theInstr == FBT_PUSHL_EBP)
			continue;

		if (!(size == 1 && (theInstr == FBT_POPL_EBP || theInstr == FBT_LEAVE))) {
			instr += size;
			goto again;
		}

		/*
		 * Found the popl %ebp; or leave.
		 */
		machine_inst_t *patch_instr = instr;

		/*
		 * Scan forward for a "ret", or "jmp".
		 */
		instr += size;
		if (instr >= limit)
			continue;

		size = dtrace_instr_size(instr);
		if (size <= 0) /* Failed instruction decode? */
			continue;

		theInstr = instr[0];

		if (!(size == FBT_RET_LEN && (theInstr == FBT_RET)) &&
			!(size == FBT_RET_IMM16_LEN && (theInstr == FBT_RET_IMM16)) &&
			!(size == FBT_JMP_SHORT_REL_LEN && (theInstr == FBT_JMP_SHORT_REL)) &&
			!(size == FBT_JMP_NEAR_REL_LEN && (theInstr == FBT_JMP_NEAR_REL)) &&
			!(size == FBT_JMP_FAR_ABS_LEN && (theInstr == FBT_JMP_FAR_ABS)))
			continue;

		/*
		 * popl %ebp; ret; or leave; ret; or leave; jmp tailCalledFun; -- We have a winner!
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
		fbt->fbtp_patchpoint = patch_instr;
		fbt->fbtp_ctl = ctl;
		fbt->fbtp_loadcnt = ctl->mod_loadcnt;

		if (*patch_instr == FBT_POPL_EBP) {
			fbt->fbtp_rval = DTRACE_INVOP_POPL_EBP;
		} else {
			ASSERT(*patch_instr == FBT_LEAVE);
			fbt->fbtp_rval = DTRACE_INVOP_LEAVE;
		}
		fbt->fbtp_roffset =
		    (uintptr_t)(patch_instr - (uint8_t *)sym[i].n_value);

		fbt->fbtp_savedval = *patch_instr;
		fbt->fbtp_patchval = FBT_PATCHVAL;
		fbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(patch_instr)];
		fbt->fbtp_symndx = i;
		fbt_probetab[FBT_ADDR2NDX(patch_instr)] = fbt;

		instr += size;
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
