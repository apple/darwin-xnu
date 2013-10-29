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
#include <libkern/kernel_mach_header.h>
#include <libkern/OSAtomic.h>

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
#define DTRACE_INVOP_MOV_RSP_RBP 11
#define DTRACE_INVOP_MOV_RSP_RBP_SKIP 3
#define DTRACE_INVOP_POP_RBP 12
#define DTRACE_INVOP_POP_RBP_SKIP 1
#define DTRACE_INVOP_LEAVE_SKIP 1

#define	FBT_PUSHL_EBP			0x55
#define	FBT_MOVL_ESP_EBP0_V0	0x8b
#define	FBT_MOVL_ESP_EBP1_V0	0xec
#define	FBT_MOVL_ESP_EBP0_V1	0x89
#define	FBT_MOVL_ESP_EBP1_V1	0xe5

#define	FBT_PUSH_RBP			0x55
#define	FBT_REX_RSP_RBP			0x48
#define	FBT_MOV_RSP_RBP0		0x89
#define	FBT_MOV_RSP_RBP1		0xe5
#define	FBT_POP_RBP				0x5d

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

extern int			gIgnoreFBTBlacklist; /* From fbt_init */

kern_return_t fbt_perfCallback(int, x86_saved_state_t *, uintptr_t *, __unused int);

/*
 * Critical routines that must not be probed. PR_5221096, PR_5379018.
 * The blacklist must be kept in alphabetic order for purposes of bsearch().
 */

static const char * critical_blacklist[] =
{
	"bcopy_phys",
	"console_cpu_alloc", 
	"console_cpu_free", 
	"cpu_IA32e_disable", 
	"cpu_IA32e_enable", 
	"cpu_NMI_interrupt", 
	"cpu_control", 
	"cpu_data_alloc", 
	"cpu_desc_init",
	"cpu_desc_init64", 	
	"cpu_desc_load",
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
	"cpu_topology_sort",
	"cpu_topology_start_cpu", 	
	"cpu_type", 
	"cpuid_cpu_display",
	"cpuid_extfeatures",
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
	"unregister_cpu_setup_func",
	"vstart"
};
#define CRITICAL_BLACKLIST_COUNT (sizeof(critical_blacklist)/sizeof(critical_blacklist[0]))

/*
 * The transitive closure of entry points that can be reached from probe context.
 * (Apart from routines whose names begin with dtrace_).
 */
static const char * probe_ctx_closure[] =
{
	"Debugger",
	"IS_64BIT_PROCESS",
	"OSCompareAndSwap",
	"absolutetime_to_microtime",
	"act_set_astbsd",
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
	"psignal_lock",
	"rtc_nanotime_load",
	"rtc_nanotime_read",
	"sdt_getargdesc",
	"strlcpy",
	"sync_iss_to_iks_unconditionally",
	"systrace_stub",
	"timer_grab"
};
#define PROBE_CTX_CLOSURE_COUNT (sizeof(probe_ctx_closure)/sizeof(probe_ctx_closure[0]))


static int _cmp(const void *a, const void *b)
{
	return strncmp((const char *)a, *(const char **)b, strlen((const char *)a) + 1);
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

/*
 * Module validation
 */ 
static int
is_module_valid(struct modctl* ctl)
{
	ASSERT(!MOD_FBT_PROBES_PROVIDED(ctl));
	ASSERT(!MOD_FBT_INVALID(ctl));
	
	if (0 == ctl->mod_address || 0 == ctl->mod_size) {
		return FALSE;
	}
	
	if (0 == ctl->mod_loaded) {
	        return FALSE;
	}
	
	if (strstr(ctl->mod_modname, "CHUD") != NULL)
		return FALSE;
	
        /*
	 * If the user sets this, trust they know what they are doing.
	 */
	if (gIgnoreFBTBlacklist)   /* per boot-arg set in fbt_init() */
		return TRUE;

	/*
	 * These drivers control low level functions that when traced
	 * cause problems often in the sleep/wake paths as well as 
	 * critical debug and panic paths.
	 * If somebody really wants to drill in on one of these kexts, then
	 * they can override blacklisting using the boot-arg above.
	 */

	if (strstr(ctl->mod_modname, "AppleACPIEC") != NULL)
		return FALSE;

	if (strstr(ctl->mod_modname, "AppleACPIPlatform") != NULL)
		return FALSE;	

	if (strstr(ctl->mod_modname, "AppleRTC") != NULL)
		return FALSE;

	if (strstr(ctl->mod_modname, "IOACPIFamily") != NULL)
		return FALSE;

	if (strstr(ctl->mod_modname, "AppleIntelCPUPowerManagement") != NULL)
		return FALSE;
	
	if (strstr(ctl->mod_modname, "AppleProfile") != NULL)
		return FALSE;

	if (strstr(ctl->mod_modname, "AppleIntelProfile") != NULL)
		return FALSE;

	if (strstr(ctl->mod_modname, "AppleEFI") != NULL)
		return FALSE;

	return TRUE;
}

/*
 * FBT probe name validation
 */
static int
is_symbol_valid(const char* name)
{
	/*
	 * If the user set this, trust they know what they are doing.
	 */
	if (gIgnoreFBTBlacklist)
		return TRUE;
		
	if (LIT_STRNSTART(name, "dtrace_") && !LIT_STRNSTART(name, "dtrace_safe_")) {
		/*
		 * Anything beginning with "dtrace_" may be called
		 * from probe context unless it explitly indicates
		 * that it won't be called from probe context by
		 * using the prefix "dtrace_safe_".
		 */
		return FALSE;
	}
	
	if (LIT_STRNSTART(name, "fasttrap_") ||
	    LIT_STRNSTART(name, "fuword") ||
	    LIT_STRNSTART(name, "suword") ||
	    LIT_STRNEQL(name, "sprlock") ||
	    LIT_STRNEQL(name, "sprunlock") ||
	    LIT_STRNEQL(name, "uread") ||
	    LIT_STRNEQL(name, "uwrite")) {
		return FALSE; /* Fasttrap inner-workings. */
	}
	
	if (LIT_STRNSTART(name, "dsmos_")) 
		return FALSE; /* Don't Steal Mac OS X! */
	
        if (LIT_STRNSTART(name, "_dtrace"))
		return FALSE; /* Shims in dtrace.c */
	
	if (LIT_STRNSTART(name, "chud"))
		return FALSE; /* Professional courtesy. */
	
	if (LIT_STRNSTART(name, "hibernate_"))
		return FALSE; /* Let sleeping dogs lie. */

	if (LIT_STRNEQL(name, "_ZNK6OSData14getBytesNoCopyEv"))
		return FALSE;  /* Data::getBytesNoCopy, IOHibernateSystemWake path */
	
	if (LIT_STRNEQL(name, "_ZN9IOService14newTemperatureElPS_") || /* IOService::newTemperature */
	    LIT_STRNEQL(name, "_ZN9IOService26temperatureCriticalForZoneEPS_")) { /* IOService::temperatureCriticalForZone */
		return FALSE; /* Per the fire code */
	}
	
	/*
	 * Place no probes (illegal instructions) in the exception handling path!
	 */
	if (LIT_STRNEQL(name, "t_invop") ||
	    LIT_STRNEQL(name, "enter_lohandler") ||
	    LIT_STRNEQL(name, "lo_alltraps") ||
	    LIT_STRNEQL(name, "kernel_trap") ||
	    LIT_STRNEQL(name, "interrupt") ||		  
	    LIT_STRNEQL(name, "i386_astintr")) {
		return FALSE;
	}
	
	if (LIT_STRNEQL(name, "current_thread") ||
	    LIT_STRNEQL(name, "ast_pending") ||
	    LIT_STRNEQL(name, "fbt_perfCallback") ||
	    LIT_STRNEQL(name, "machine_thread_get_kern_state") ||
	    LIT_STRNEQL(name, "get_threadtask") ||
	    LIT_STRNEQL(name, "ml_set_interrupts_enabled") ||
	    LIT_STRNEQL(name, "dtrace_invop") ||
	    LIT_STRNEQL(name, "fbt_invop") ||
	    LIT_STRNEQL(name, "sdt_invop") ||
	    LIT_STRNEQL(name, "max_valid_stack_address")) {
		return FALSE;
	}
	
	/*
	 * Voodoo.
	 */
	if (LIT_STRNSTART(name, "machine_stack_") ||
	    LIT_STRNSTART(name, "mapping_") ||
	    LIT_STRNEQL(name, "tmrCvt") ||
	    
	    LIT_STRNSTART(name, "tsc_") ||
	    
	    LIT_STRNSTART(name, "pmCPU") ||
	    LIT_STRNEQL(name, "pmKextRegister") ||
	    LIT_STRNEQL(name, "pmMarkAllCPUsOff") ||
	    LIT_STRNEQL(name, "pmSafeMode") ||
	    LIT_STRNEQL(name, "pmTimerSave") ||
	    LIT_STRNEQL(name, "pmTimerRestore") ||
	    LIT_STRNEQL(name, "pmUnRegister") ||
	    LIT_STRNSTART(name, "pms") ||
	    LIT_STRNEQL(name, "power_management_init") ||
	    LIT_STRNSTART(name, "usimple_") ||
	    LIT_STRNSTART(name, "lck_spin_lock") ||
	    LIT_STRNSTART(name, "lck_spin_unlock") ||		  
	    
	    LIT_STRNSTART(name, "rtc_") ||
	    LIT_STRNSTART(name, "_rtc_") ||
	    LIT_STRNSTART(name, "rtclock_") ||
	    LIT_STRNSTART(name, "clock_") ||
	    LIT_STRNSTART(name, "absolutetime_to_") ||
	    LIT_STRNEQL(name, "setPop") ||
	    LIT_STRNEQL(name, "nanoseconds_to_absolutetime") ||
	    LIT_STRNEQL(name, "nanotime_to_absolutetime") ||
	    
	    LIT_STRNSTART(name, "etimer_") ||
	    
	    LIT_STRNSTART(name, "commpage_") ||
	    LIT_STRNSTART(name, "pmap_") ||
	    LIT_STRNSTART(name, "ml_") ||
	    LIT_STRNSTART(name, "PE_") ||
	    LIT_STRNEQL(name, "kprintf") ||
	    LIT_STRNSTART(name, "lapic_") ||
	    LIT_STRNSTART(name, "act_machine") ||
	    LIT_STRNSTART(name, "acpi_")  ||
	    LIT_STRNSTART(name, "pal_")){
		return FALSE;
	}

	/*
         * Avoid machine_ routines. PR_5346750.
         */
        if (LIT_STRNSTART(name, "machine_"))
		return FALSE;
	
	if (LIT_STRNEQL(name, "handle_pending_TLB_flushes"))
		return FALSE;
	
        /*
         * Place no probes on critical routines. PR_5221096
         */
        if (bsearch( name, critical_blacklist, CRITICAL_BLACKLIST_COUNT, sizeof(name), _cmp ) != NULL)
                return FALSE;
	
        /*
	 * Place no probes that could be hit in probe context.
	 */
	if (bsearch( name, probe_ctx_closure, PROBE_CTX_CLOSURE_COUNT, sizeof(name), _cmp ) != NULL) {
		return FALSE;
	}
	
	/*
	 * Place no probes that could be hit on the way to the debugger.
	 */
	if (LIT_STRNSTART(name, "kdp_") ||
	    LIT_STRNSTART(name, "kdb_") ||
	    LIT_STRNSTART(name, "kdbg_") ||
	    LIT_STRNSTART(name, "kdebug_") ||
	    LIT_STRNSTART(name, "kernel_debug") ||
	    LIT_STRNSTART(name, "debug_") ||
	    LIT_STRNEQL(name, "Debugger") ||
	    LIT_STRNEQL(name, "Call_DebuggerC") ||
	    LIT_STRNEQL(name, "lock_debugger") ||
	    LIT_STRNEQL(name, "unlock_debugger") ||
	    LIT_STRNEQL(name, "packA")  ||
	    LIT_STRNEQL(name, "unpackA")  ||
	    LIT_STRNEQL(name, "SysChoked"))  {
		return FALSE;
	}
	
	
	/*
	 * Place no probes that could be hit on the way to a panic.
	 */
	if (NULL != strstr(name, "panic_") ||
	    LIT_STRNEQL(name, "panic") ||
	    LIT_STRNEQL(name, "preemption_underflow_panic")) {
		return FALSE;
	}
	
	return TRUE;
}

int
fbt_invop(uintptr_t addr, uintptr_t *state, uintptr_t rval)
{
	fbt_probe_t *fbt = fbt_probetab[FBT_ADDR2NDX(addr)];
	
	for (; fbt != NULL; fbt = fbt->fbtp_hashnext) {
		if ((uintptr_t)fbt->fbtp_patchpoint == addr) {

			if (fbt->fbtp_roffset == 0) {
				x86_saved_state64_t *regs = (x86_saved_state64_t *)state;

				CPU->cpu_dtrace_caller = *(uintptr_t *)(((uintptr_t)(regs->isf.rsp))+sizeof(uint64_t)); // 8(%rsp)
				/* 64-bit ABI, arguments passed in registers. */
				dtrace_probe(fbt->fbtp_id, regs->rdi, regs->rsi, regs->rdx, regs->rcx, regs->r8);
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

#define IS_USER_TRAP(regs) (regs && (((regs)->isf.cs & 3) != 0))
#define T_INVALID_OPCODE 6
#define FBT_EXCEPTION_CODE T_INVALID_OPCODE
#define T_PREEMPT       255

kern_return_t
fbt_perfCallback(
                int         		trapno,
                x86_saved_state_t 	*tagged_regs,
		uintptr_t		*lo_spp,
                __unused int        unused2)
{
	kern_return_t retval = KERN_FAILURE;
	x86_saved_state64_t *saved_state = saved_state64(tagged_regs);

	if (FBT_EXCEPTION_CODE == trapno && !IS_USER_TRAP(saved_state)) {
		boolean_t oldlevel;
		uint64_t rsp_probe, fp, delta = 0;
		uintptr_t old_sp;
		uint32_t *pDst;
		int emul;


		oldlevel = ml_set_interrupts_enabled(FALSE);

		/* Calculate where the stack pointer was when the probe instruction "fired." */
		rsp_probe = saved_state->isf.rsp; /* Easy, x86_64 establishes this value in idt64.s */

		__asm__ volatile(
			"Ldtrace_invop_callsite_pre_label:\n"
			".data\n"
			".private_extern _dtrace_invop_callsite_pre\n"
			"_dtrace_invop_callsite_pre:\n"
			"  .quad Ldtrace_invop_callsite_pre_label\n"
			".text\n"
				 );

		emul = dtrace_invop( saved_state->isf.rip, (uintptr_t *)saved_state, saved_state->rax );

		__asm__ volatile(
			"Ldtrace_invop_callsite_post_label:\n"
			".data\n"
			".private_extern _dtrace_invop_callsite_post\n"
			"_dtrace_invop_callsite_post:\n"
			"  .quad Ldtrace_invop_callsite_post_label\n"
			".text\n"
				 );		

		switch (emul) {
		case DTRACE_INVOP_NOP:
			saved_state->isf.rip += DTRACE_INVOP_NOP_SKIP;	/* Skip over the patched NOP (planted by sdt). */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_MOV_RSP_RBP:
			saved_state->rbp = rsp_probe;							/* Emulate patched mov %rsp,%rbp */
			saved_state->isf.rip += DTRACE_INVOP_MOV_RSP_RBP_SKIP;	/* Skip over the bytes of the patched mov %rsp,%rbp */
			retval = KERN_SUCCESS;
			break;

		case DTRACE_INVOP_POP_RBP:
		case DTRACE_INVOP_LEAVE:
/*
 * Emulate first micro-op of patched leave: mov %rbp,%rsp
 * fp points just below the return address slot for target's ret 
 * and at the slot holding the frame pointer saved by the target's prologue.
 */
			fp = saved_state->rbp;
/* Emulate second micro-op of patched leave: patched pop %rbp
 * savearea rbp is set for the frame of the caller to target
 * The *live* %rsp will be adjusted below for pop increment(s)
 */
			saved_state->rbp = *(uint64_t *)fp;
/* Skip over the patched leave */
			saved_state->isf.rip += DTRACE_INVOP_LEAVE_SKIP;
/*
 * Lift the stack to account for the emulated leave
 * Account for words local in this frame
 * (in "case DTRACE_INVOP_POPL_EBP:" this is zero.)
 */
			delta = ((uint32_t *)fp) - ((uint32_t *)rsp_probe); /* delta is a *word* increment */
/* Account for popping off the rbp (just accomplished by the emulation
 * above...)
 */
			delta += 2;
			saved_state->isf.rsp += (delta << 2);
/* Obtain the stack pointer recorded by the trampolines */
			old_sp = *lo_spp;
/* Shift contents of stack */
			for (pDst = (uint32_t *)fp;
			     pDst > (((uint32_t *)old_sp));
				 pDst--)
				*pDst = pDst[-delta];

/* Track the stack lift in "saved_state". */
			saved_state = (x86_saved_state64_t *) (((uintptr_t)saved_state) + (delta << 2));
/* Adjust the stack pointer utilized by the trampolines */
			*lo_spp = old_sp + (delta << 2);

			retval = KERN_SUCCESS;
			break;
			
		default:
			retval = KERN_FAILURE;
			break;
		}
		saved_state->isf.trapno = T_PREEMPT; /* Avoid call to i386_astintr()! */

		ml_set_interrupts_enabled(oldlevel);
	}

	return retval;
}

/*ARGSUSED*/
static void
__provide_probe_64(struct modctl *ctl, uintptr_t instrLow, uintptr_t instrHigh, char *modname, char* symbolName, machine_inst_t* symbolStart)
{
	unsigned int			j;
	unsigned int			doenable = 0;
	dtrace_id_t			thisid;

	fbt_probe_t *newfbt, *retfbt, *entryfbt;
	machine_inst_t *instr, *limit, theInstr, i1, i2, i3;
	int size;
		
	for (j = 0, instr = symbolStart, theInstr = 0;
	     (j < 4) && ((uintptr_t)instr >= instrLow) && (instrHigh > (uintptr_t)(instr + 2)); 
	     j++) {
		theInstr = instr[0];
		if (theInstr == FBT_PUSH_RBP || theInstr == FBT_RET || theInstr == FBT_RET_IMM16)
			break;
		
		if ((size = dtrace_instr_size(instr)) <= 0)
			break;
		
		instr += size;
	}
	
	if (theInstr != FBT_PUSH_RBP)
		return;
	
	i1 = instr[1];
	i2 = instr[2];
	i3 = instr[3];
	
	limit = (machine_inst_t *)instrHigh;
	
	if (i1 == FBT_REX_RSP_RBP && i2 == FBT_MOV_RSP_RBP0 && i3 == FBT_MOV_RSP_RBP1) {
		instr += 1; /* Advance to the mov %rsp,%rbp */
		theInstr = i1;
	} else {
		return;
	}
#if 0
	else {
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
			return;
		
		instr += size;
		
		if ((instr + 1) >= limit)
			return;
		
		i1 = instr[0];
		i2 = instr[1];
		
		if (!(i1 == FBT_MOVL_ESP_EBP0_V0 && i2 == FBT_MOVL_ESP_EBP1_V0) &&
		    !(i1 == FBT_MOVL_ESP_EBP0_V1 && i2 == FBT_MOVL_ESP_EBP1_V1))
			return;
		
		/* instr already points at the movl %esp,%ebp */
		theInstr = i1;
	}
#endif
	thisid = dtrace_probe_lookup(fbt_id, modname, symbolName, FBT_ENTRY);
	newfbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
	strlcpy( (char *)&(newfbt->fbtp_name), symbolName, MAX_FBTP_NAME_CHARS );
	
	if (thisid != 0) {
		/*
		 * The dtrace_probe previously existed, so we have to hook
		 * the newfbt entry onto the end of the existing fbt's chain.
		 * If we find an fbt entry that was previously patched to
		 * fire, (as indicated by the current patched value), then
		 * we want to enable this newfbt on the spot.
		 */
		entryfbt = dtrace_probe_arg (fbt_id, thisid);
		ASSERT (entryfbt != NULL);
		for(; entryfbt != NULL; entryfbt = entryfbt->fbtp_next) {
			if (entryfbt->fbtp_currentval == entryfbt->fbtp_patchval)
				doenable++;
			
			if (entryfbt->fbtp_next == NULL) {
				entryfbt->fbtp_next = newfbt;
				newfbt->fbtp_id = entryfbt->fbtp_id;
				break;
			}
		}		    
	}
	else {
		/*
		 * The dtrace_probe did not previously exist, so we
		 * create it and hook in the newfbt.  Since the probe is
		 * new, we obviously do not need to enable it on the spot.
		 */
		newfbt->fbtp_id = dtrace_probe_create(fbt_id, modname, symbolName, FBT_ENTRY, FBT_AFRAMES_ENTRY, newfbt);
		doenable = 0;
	}
	
	newfbt->fbtp_patchpoint = instr;
	newfbt->fbtp_ctl = ctl;
	newfbt->fbtp_loadcnt = ctl->mod_loadcnt;
	newfbt->fbtp_rval = DTRACE_INVOP_MOV_RSP_RBP;
	newfbt->fbtp_savedval = theInstr;
	newfbt->fbtp_patchval = FBT_PATCHVAL;
	newfbt->fbtp_currentval = 0;
	newfbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(instr)];
	fbt_probetab[FBT_ADDR2NDX(instr)] = newfbt;
	
	if (doenable)
		fbt_enable(NULL, newfbt->fbtp_id, newfbt);
	
	/*
	 * The fbt entry chain is in place, one entry point per symbol.
	 * The fbt return chain can have multiple return points per symbol.
	 * Here we find the end of the fbt return chain.
	 */
	
	doenable=0;
	
	thisid = dtrace_probe_lookup(fbt_id, modname, symbolName, FBT_RETURN);
	if (thisid != 0) {
		/* The dtrace_probe previously existed, so we have to
		 * find the end of the existing fbt chain.  If we find
		 * an fbt return that was previously patched to fire,
		 * (as indicated by the currrent patched value), then
		 * we want to enable any new fbts on the spot.
		 */
		retfbt = dtrace_probe_arg (fbt_id, thisid);
		ASSERT(retfbt != NULL);
		for (;  retfbt != NULL; retfbt =  retfbt->fbtp_next) {
			if (retfbt->fbtp_currentval == retfbt->fbtp_patchval)
				doenable++;
			if(retfbt->fbtp_next == NULL)
				break;
		}
	}
	else {
		doenable = 0;
		retfbt = NULL;
	}
	
again:
	if (instr >= limit)
		return;
	
	/*
	 * If this disassembly fails, then we've likely walked off into
	 * a jump table or some other unsuitable area.  Bail out of the
	 * disassembly now.
	 */
	if ((size = dtrace_instr_size(instr)) <= 0)
		return;
	
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
		
		if (check < (uintptr_t)symbolStart)
			break;
		
		if (check + sizeof (uintptr_t) > (uintptr_t)limit)
			continue;
		
		ptr = *(uint8_t **)check;
		
		if (ptr >= (uint8_t *)symbolStart && ptr < limit) {
			instr += size;
			goto again;
		}
	}
	
	/*
	 * OK, it's an instruction.
	 */
	theInstr = instr[0];
	
	/* Walked onto the start of the next routine? If so, bail out of this function. */
	if (theInstr == FBT_PUSH_RBP)
		return;
	
	if (!(size == 1 && (theInstr == FBT_POP_RBP || theInstr == FBT_LEAVE))) {
		instr += size;
		goto again;
	}
	
	/*
	 * Found the pop %rbp; or leave.
	 */
	machine_inst_t *patch_instr = instr;
	
	/*
	 * Scan forward for a "ret", or "jmp".
	 */
	instr += size;
	if (instr >= limit)
		return;
	
	size = dtrace_instr_size(instr);
	if (size <= 0) /* Failed instruction decode? */
		return;
	
	theInstr = instr[0];
	
	if (!(size == FBT_RET_LEN && (theInstr == FBT_RET)) &&
	    !(size == FBT_RET_IMM16_LEN && (theInstr == FBT_RET_IMM16)) &&
	    !(size == FBT_JMP_SHORT_REL_LEN && (theInstr == FBT_JMP_SHORT_REL)) &&
	    !(size == FBT_JMP_NEAR_REL_LEN && (theInstr == FBT_JMP_NEAR_REL)) &&
	    !(size == FBT_JMP_FAR_ABS_LEN && (theInstr == FBT_JMP_FAR_ABS)))
		return;
	
	/*
	 * pop %rbp; ret; or leave; ret; or leave; jmp tailCalledFun; -- We have a winner!
	 */
	newfbt = kmem_zalloc(sizeof (fbt_probe_t), KM_SLEEP);
	strlcpy( (char *)&(newfbt->fbtp_name), symbolName, MAX_FBTP_NAME_CHARS );
	
	if (retfbt == NULL) {
		newfbt->fbtp_id = dtrace_probe_create(fbt_id, modname,
						      symbolName, FBT_RETURN, FBT_AFRAMES_RETURN, newfbt);
	} else {
		retfbt->fbtp_next = newfbt;
		newfbt->fbtp_id = retfbt->fbtp_id;
	}
	
	retfbt = newfbt;
	newfbt->fbtp_patchpoint = patch_instr;
	newfbt->fbtp_ctl = ctl;
	newfbt->fbtp_loadcnt = ctl->mod_loadcnt;
	
	if (*patch_instr == FBT_POP_RBP) {
		newfbt->fbtp_rval = DTRACE_INVOP_POP_RBP;
	} else {
		ASSERT(*patch_instr == FBT_LEAVE);
		newfbt->fbtp_rval = DTRACE_INVOP_LEAVE;
	}
	newfbt->fbtp_roffset =
	(uintptr_t)(patch_instr - (uint8_t *)symbolStart);
	
	newfbt->fbtp_savedval = *patch_instr;
	newfbt->fbtp_patchval = FBT_PATCHVAL;
	newfbt->fbtp_hashnext = fbt_probetab[FBT_ADDR2NDX(patch_instr)];
	fbt_probetab[FBT_ADDR2NDX(patch_instr)] = newfbt;
	
	if (doenable)
		fbt_enable(NULL, newfbt->fbtp_id, newfbt);
	
	instr += size;
	goto again;
}

static void
__kernel_syms_provide_module(void *arg, struct modctl *ctl)
{
#pragma unused(arg)
	kernel_mach_header_t		*mh;
	struct load_command		*cmd;
	kernel_segment_command_t	*orig_ts = NULL, *orig_le = NULL;
	struct symtab_command		*orig_st = NULL;
	kernel_nlist_t			*sym = NULL;
	char				*strings;
	uintptr_t			instrLow, instrHigh;
	char				*modname;
	unsigned int			i;
	
	mh = (kernel_mach_header_t *)(ctl->mod_address);
	modname = ctl->mod_modname;
	
	if (mh->magic != MH_MAGIC_KERNEL)
		return;
	
	cmd = (struct load_command *) &mh[1];
	for (i = 0; i < mh->ncmds; i++) {
		if (cmd->cmd == LC_SEGMENT_KERNEL) {
			kernel_segment_command_t *orig_sg = (kernel_segment_command_t *) cmd;
			
			if (LIT_STRNEQL(orig_sg->segname, SEG_TEXT))
				orig_ts = orig_sg;
			else if (LIT_STRNEQL(orig_sg->segname, SEG_LINKEDIT))
				orig_le = orig_sg;
			else if (LIT_STRNEQL(orig_sg->segname, ""))
				orig_ts = orig_sg; /* kexts have a single unnamed segment */
		}
		else if (cmd->cmd == LC_SYMTAB)
			orig_st = (struct symtab_command *) cmd;
		
		cmd = (struct load_command *) ((caddr_t) cmd + cmd->cmdsize);
	}
	
	if ((orig_ts == NULL) || (orig_st == NULL) || (orig_le == NULL))
		return;
	
	sym = (kernel_nlist_t *)(orig_le->vmaddr + orig_st->symoff - orig_le->fileoff);
	strings = (char *)(orig_le->vmaddr + orig_st->stroff - orig_le->fileoff);
	
	/* Find extent of the TEXT section */
	instrLow = (uintptr_t)orig_ts->vmaddr;
	instrHigh = (uintptr_t)(orig_ts->vmaddr + orig_ts->vmsize);
	
	for (i = 0; i < orig_st->nsyms; i++) {
		uint8_t n_type = sym[i].n_type & (N_TYPE | N_EXT);
		char *name = strings + sym[i].n_un.n_strx;
		
		/* Check that the symbol is a global and that it has a name. */
		if (((N_SECT | N_EXT) != n_type && (N_ABS | N_EXT) != n_type))
			continue;
		
		if (0 == sym[i].n_un.n_strx) /* iff a null, "", name. */
			continue;
		
		/* Lop off omnipresent leading underscore. */			
		if (*name == '_')
			name += 1;
		
		/*
		 * We're only blacklisting functions in the kernel for now.
		 */
		if (MOD_IS_MACH_KERNEL(ctl) && !is_symbol_valid(name))
			continue;
		
		__provide_probe_64(ctl, instrLow, instrHigh, modname, name, (machine_inst_t*)sym[i].n_value);
	}
}

static void
__user_syms_provide_module(void *arg, struct modctl *ctl)
{
#pragma unused(arg)
	char				*modname;
	unsigned int			i;
	
	modname = ctl->mod_modname;
	
	dtrace_module_symbols_t* module_symbols = ctl->mod_user_symbols;
	if (module_symbols) {
		for (i=0; i<module_symbols->dtmodsyms_count; i++) {

		        /* 
			 * symbol->dtsym_addr (the symbol address) passed in from
			 * user space, is already slid for both kexts and kernel.
			 */
			dtrace_symbol_t* symbol = &module_symbols->dtmodsyms_symbols[i];

			char* name = symbol->dtsym_name;
			
			/* Lop off omnipresent leading underscore. */			
			if (*name == '_')
				name += 1;
			
			/*
			 * We're only blacklisting functions in the kernel for now.
			 */
                        if (MOD_IS_MACH_KERNEL(ctl) && !is_symbol_valid(name))
			        continue;
			
			__provide_probe_64(ctl, (uintptr_t)symbol->dtsym_addr, (uintptr_t)(symbol->dtsym_addr + symbol->dtsym_size), modname, name, (machine_inst_t*)(uintptr_t)symbol->dtsym_addr);
		}
	}
}

extern int dtrace_kernel_symbol_mode;

/*ARGSUSED*/
void
fbt_provide_module(void *arg, struct modctl *ctl)
{
	ASSERT(ctl != NULL);
	ASSERT(dtrace_kernel_symbol_mode != DTRACE_KERNEL_SYMBOLS_NEVER);
	lck_mtx_assert(&mod_lock, LCK_MTX_ASSERT_OWNED);

	if (MOD_FBT_DONE(ctl))
		return;
	
	if (!is_module_valid(ctl)) {
		ctl->mod_flags |= MODCTL_FBT_INVALID;
		return;
	}
	
	if (MOD_HAS_KERNEL_SYMBOLS(ctl)) {
		__kernel_syms_provide_module(arg, ctl);
		ctl->mod_flags |= MODCTL_FBT_PROBES_PROVIDED;
		return;
	}
	
	if (MOD_HAS_USERSPACE_SYMBOLS(ctl)) {
		__user_syms_provide_module(arg, ctl);
		ctl->mod_flags |= MODCTL_FBT_PROBES_PROVIDED;
		return;
	}	
}
