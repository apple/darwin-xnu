/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* #pragma ident	"@(#)fbt.c	1.18	07/01/10 SMI" */

#ifdef KERNEL
#ifndef _KERNEL
#define _KERNEL /* Solaris vs. Darwin */
#endif
#endif

#include <mach-o/loader.h>
#include <libkern/kernel_mach_header.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysctl.h>
#include <sys/errno.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/conf.h>
#include <sys/fcntl.h>
#include <miscfs/devfs/devfs.h>
#include <pexpert/pexpert.h>

#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <sys/fbt.h>

#include <sys/dtrace_glue.h>
#include <san/kasan.h>

/* #include <machine/trap.h> */
struct savearea_t; /* Used anonymously */

#if defined(__arm__) || defined(__arm64__)
typedef kern_return_t (*perfCallback)(int, struct savearea_t *, __unused int, __unused int);
extern perfCallback tempDTraceTrapHook;
extern kern_return_t fbt_perfCallback(int, struct savearea_t *, __unused int, __unused int);
#elif defined(__x86_64__)
typedef kern_return_t (*perfCallback)(int, struct savearea_t *, uintptr_t *, __unused int);
extern perfCallback tempDTraceTrapHook;
extern kern_return_t fbt_perfCallback(int, struct savearea_t *, uintptr_t *, __unused int);
#else
#error Unknown architecture
#endif

__private_extern__
void
qsort(void *a, size_t n, size_t es, int (*cmp)(const void *, const void *));

#define	FBT_ADDR2NDX(addr)	((((uintptr_t)(addr)) >> 4) & fbt_probetab_mask)
#define	FBT_PROBETAB_SIZE	0x8000		/* 32k entries -- 128K total */

static int				fbt_probetab_size;
dtrace_provider_id_t	fbt_id;
fbt_probe_t				**fbt_probetab;
int						fbt_probetab_mask;
static int				fbt_verbose = 0;

int ignore_fbt_blacklist = 0;

extern int dtrace_kernel_symbol_mode;


void fbt_init( void );

/*
 * Critical routines that must not be probed. PR_5221096, PR_5379018.
 * The blacklist must be kept in alphabetic order for purposes of bsearch().
 */
static const char * critical_blacklist[] =
{
	"Call_DebuggerC",
	"DebuggerCall",
	"DebuggerTrapWithState",
	"DebuggerXCallEnter",
	"IOCPURunPlatformPanicActions",
	"PEARMDebugPanicHook",
	"PEHaltRestart",
	"SavePanicInfo",
	"SysChoked",
	"_ZN9IOService14newTemperatureElPS_", /* IOService::newTemperature */
	"_ZN9IOService26temperatureCriticalForZoneEPS_", /* IOService::temperatureCriticalForZone */
	"_ZNK6OSData14getBytesNoCopyEv", /* Data::getBytesNoCopy, IOHibernateSystemWake path */
	"__ZN16IOPlatformExpert11haltRestartEj",
	"__ZN18IODTPlatformExpert11haltRestartEj",
	"__ZN9IODTNVRAM13savePanicInfoEPhy"
	"_disable_preemption",
	"_enable_preemption",
	"alternate_debugger_enter",
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
	"dtrace_invop",
	"enter_lohandler",
	"fbt_invop",
	"fbt_perfCallback",
	"get_preemption_level"
	"get_threadtask",
	"handle_pending_TLB_flushes",
	"hw_compare_and_store",
	"interrupt",
	"is_saved_state32",
	"kernel_preempt_check",
	"kernel_trap",
	"kprintf",
	"ks_dispatch_kernel",
	"ks_dispatch_user",
	"ks_kernel_trap",
	"lo_alltraps",
	"lock_debugger",
	"machine_idle_cstate",
	"machine_thread_get_kern_state",
	"mca_cpu_alloc",
	"mca_cpu_init",
	"ml_nofault_copy",
	"nanoseconds_to_absolutetime",
	"nanotime_to_absolutetime",
	"packA",
	"panic",
	"phystokv",
	"phystokv_range",
	"pltrace",
	"pmKextRegister",
	"pmMarkAllCPUsOff",
	"pmSafeMode",
	"pmTimerRestore",
	"pmTimerSave",
	"pmUnRegister",
	"pmap_cpu_alloc",
	"pmap_cpu_free",
	"pmap_cpu_high_map_vaddr",
	"pmap_cpu_high_shared_remap",
	"pmap_cpu_init",
	"power_management_init",
	"preemption_underflow_panic",
	"register_cpu_setup_func",
	"ret64_iret"
	"ret_to_user"
	"return_to_kernel",
	"return_to_user",
	"saved_state64",
	"sdt_invop",
	"sprlock",
	"sprunlock",
	"strlen",
	"strncmp",
	"t_invop",
	"tmrCvt",
	"trap_from_kernel",
	"uart_putc",
	"unlock_debugger",
	"unpackA",
	"unregister_cpu_setup_func",
	"uread",
	"uwrite",
	"vstart"
};

#define CRITICAL_BLACKLIST_COUNT (sizeof(critical_blacklist)/sizeof(critical_blacklist[0]))

/*
 * The transitive closure of entry points that can be reached from probe context.
 * (Apart from routines whose names begin with dtrace_).
 */
static const char * probe_ctx_closure[] =
{
	"ClearIdlePop",
	"Debugger",
	"IS_64BIT_PROCESS",
	"OSCompareAndSwap",
	"SetIdlePop",
	"__dtrace_probe",
	"absolutetime_to_microtime",
	"act_set_astbsd",
	"arm_init_idle_cpu",
	"ast_dtrace_on",
	"ast_pending",
	"clean_dcache",
	"clean_mmu_dcache",
	"clock_get_calendar_nanotime_nowait",
	"copyin",
	"copyin_kern",
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
	"drain_write_buffer",
	"find_user_regs",
	"flush_dcache",
	"flush_tlb64",
	"get_bsdtask_info",
	"get_bsdthread_info",
	"hertz_tick",
	"hw_atomic_and",
	"invalidate_mmu_icache",
	"kauth_cred_get",
	"kauth_getgid",
	"kauth_getuid",
	"kernel_preempt_check",
	"kvtophys",
	"mach_absolute_time",
	"max_valid_stack_address",
	"memcpy",
	"memmove",
	"ml_at_interrupt_context",
	"ml_phys_write_byte_64",
	"ml_phys_write_half_64",
	"ml_phys_write_word_64",
	"ml_set_interrupts_enabled",
	"mt_core_snap",
	"mt_cur_cpu_cycles",
	"mt_cur_cpu_instrs",
	"mt_cur_thread_cycles",
	"mt_cur_thread_instrs",
	"mt_fixed_counts",
	"mt_fixed_counts_internal",
	"mt_mtc_update_count",
	"mt_update_thread",
	"ovbcopy",
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
	"setPop",
	"strlcpy",
	"sync_iss_to_iks_unconditionally",
	"systrace_stub",
	"timer_grab"
};
#define PROBE_CTX_CLOSURE_COUNT (sizeof(probe_ctx_closure)/sizeof(probe_ctx_closure[0]))

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
static int _cmp(const void *a, const void *b)
{
    return strncmp((const char *)a, *(const char **)b, strlen((const char *)a) + 1);
}
#pragma clang diagnostic pop
/*
 * Module validation
 */
int
fbt_module_excluded(struct modctl* ctl)
{
	ASSERT(!MOD_FBT_DONE(ctl));

	if (ctl->mod_address == 0 || ctl->mod_size == 0) {
		return TRUE;
	}

	if (ctl->mod_loaded == 0) {
	        return TRUE;
	}

        /*
	 * If the user sets this, trust they know what they are doing.
	 */
	if (ignore_fbt_blacklist)
		return FALSE;

	/*
	 * These drivers control low level functions that when traced
	 * cause problems often in the sleep/wake paths as well as
	 * critical debug and panic paths.
	 * If somebody really wants to drill in on one of these kexts, then
	 * they can override blacklisting using the boot-arg above.
	 */

#ifdef __x86_64__
	if (strstr(ctl->mod_modname, "AppleACPIEC") != NULL)
		return TRUE;

	if (strstr(ctl->mod_modname, "AppleACPIPlatform") != NULL)
		return TRUE;

	if (strstr(ctl->mod_modname, "AppleRTC") != NULL)
		return TRUE;

	if (strstr(ctl->mod_modname, "IOACPIFamily") != NULL)
		return TRUE;

	if (strstr(ctl->mod_modname, "AppleIntelCPUPowerManagement") != NULL)
		return TRUE;

	if (strstr(ctl->mod_modname, "AppleProfile") != NULL)
		return TRUE;

	if (strstr(ctl->mod_modname, "AppleIntelProfile") != NULL)
		return TRUE;

	if (strstr(ctl->mod_modname, "AppleEFI") != NULL)
		return TRUE;

#elif __arm__ || __arm64__
	if (LIT_STRNEQL(ctl->mod_modname, "com.apple.driver.AppleARMPlatform") ||
	LIT_STRNEQL(ctl->mod_modname, "com.apple.driver.AppleARMPL192VIC") ||
	LIT_STRNEQL(ctl->mod_modname, "com.apple.driver.AppleInterruptController"))
		return TRUE;
#endif

	return FALSE;
}

/*
 * FBT probe name validation
 */
int
fbt_excluded(const char* name)
{
	/*
	 * If the user set this, trust they know what they are doing.
	 */
	if (ignore_fbt_blacklist)
		return FALSE;

	if (LIT_STRNSTART(name, "dtrace_") && !LIT_STRNSTART(name, "dtrace_safe_")) {
		/*
		 * Anything beginning with "dtrace_" may be called
		 * from probe context unless it explitly indicates
		 * that it won't be called from probe context by
		 * using the prefix "dtrace_safe_".
		 */
		return TRUE;
	}

	/*
	* Place no probes on critical routines (5221096)
	*/
	if (bsearch( name, critical_blacklist, CRITICAL_BLACKLIST_COUNT, sizeof(name), _cmp ) != NULL)
		return TRUE;

	/*
	* Place no probes that could be hit in probe context.
	*/
	if (bsearch( name, probe_ctx_closure, PROBE_CTX_CLOSURE_COUNT, sizeof(name), _cmp ) != NULL) {
		return TRUE;
	}

	/*
	* Place no probes that could be hit in probe context.
	* In the interests of safety, some of these may be overly cautious.
	* Also exclude very low-level "firmware" class calls.
	*/
	if (LIT_STRNSTART(name, "cpu_") ||	/* Coarse */
		LIT_STRNSTART(name, "platform_") ||	/* Coarse */
		LIT_STRNSTART(name, "machine_") ||	/* Coarse */
		LIT_STRNSTART(name, "ml_") ||	/* Coarse */
		LIT_STRNSTART(name, "PE_") ||	/* Coarse */
		LIT_STRNSTART(name, "rtc_") ||	/* Coarse */
		LIT_STRNSTART(name, "_rtc_") ||
		LIT_STRNSTART(name, "rtclock_") ||
		LIT_STRNSTART(name, "clock_") ||
		LIT_STRNSTART(name, "bcopy") ||
		LIT_STRNSTART(name, "pmap_") ||
		LIT_STRNSTART(name, "hw_") ||	/* Coarse */
		LIT_STRNSTART(name, "lapic_") ||	/* Coarse */
		LIT_STRNSTART(name, "OSAdd") ||
		LIT_STRNSTART(name, "OSBit") ||
		LIT_STRNSTART(name, "OSDecrement") ||
		LIT_STRNSTART(name, "OSIncrement") ||
		LIT_STRNSTART(name, "OSCompareAndSwap") ||
		LIT_STRNSTART(name, "etimer_") ||
		LIT_STRNSTART(name, "dtxnu_kern_") ||
		LIT_STRNSTART(name, "flush_mmu_tlb_"))
		return TRUE;
	/*
	 * Fasttrap inner-workings we can't instrument
	 * on Intel (6230149)
	*/
	if (LIT_STRNSTART(name, "fasttrap_") ||
		LIT_STRNSTART(name, "fuword") ||
		LIT_STRNSTART(name, "suword"))
		return TRUE;

	if (LIT_STRNSTART(name, "_dtrace"))
		return TRUE; /* Shims in dtrace.c */

	if (LIT_STRNSTART(name, "hibernate_"))
		return TRUE;

	/*
	 * Place no probes in the exception handling path
	 */
#if __arm__ || __arm64__
	if (LIT_STRNSTART(name, "fleh_") ||
		LIT_STRNSTART(name, "sleh_") ||
		LIT_STRNSTART(name, "timer_state_event") ||
		LIT_STRNEQL(name, "get_vfp_enabled"))
		return TRUE;

	if (LIT_STRNSTART(name, "_ZNK15OSMetaClassBase8metaCastEPK11OSMetaClass") ||
		LIT_STRNSTART(name, "_ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass") ||
		LIT_STRNSTART(name, "_ZNK11OSMetaClass13checkMetaCastEPK15OSMetaClassBase"))
		return TRUE;
#endif

#ifdef __x86_64__
	if (LIT_STRNSTART(name, "machine_") ||
		LIT_STRNSTART(name, "idt64") ||
		LIT_STRNSTART(name, "ks_") ||
		LIT_STRNSTART(name, "hndl_") ||
		LIT_STRNSTART(name, "_intr_") ||
		LIT_STRNSTART(name, "mapping_") ||
		LIT_STRNSTART(name, "tsc_") ||
		LIT_STRNSTART(name, "pmCPU") ||
		LIT_STRNSTART(name, "pms") ||
		LIT_STRNSTART(name, "usimple_") ||
		LIT_STRNSTART(name, "lck_spin_lock") ||
		LIT_STRNSTART(name, "lck_spin_unlock") ||
		LIT_STRNSTART(name, "absolutetime_to_") ||
		LIT_STRNSTART(name, "commpage_") ||
		LIT_STRNSTART(name, "ml_") ||
		LIT_STRNSTART(name, "PE_") ||
		LIT_STRNSTART(name, "act_machine") ||
		LIT_STRNSTART(name, "acpi_")  ||
		LIT_STRNSTART(name, "pal_")) {
		return TRUE;
	}
	// Don't Steal Mac OS X
	if (LIT_STRNSTART(name, "dsmos_"))
		return TRUE;

#endif

	/*
	* Place no probes that could be hit on the way to the debugger.
	*/
	if (LIT_STRNSTART(name, "kdp_") ||
		LIT_STRNSTART(name, "kdb_") ||
		LIT_STRNSTART(name, "debug_")) {
		return TRUE;
	}

#if KASAN
	if (LIT_STRNSTART(name, "kasan") ||
		LIT_STRNSTART(name, "__kasan") ||
		LIT_STRNSTART(name, "__asan")) {
		return TRUE;
	}
#endif

	/*
	 * Place no probes that could be hit on the way to a panic.
	 */
	if (NULL != strstr(name, "panic_"))
		return TRUE;

	return FALSE;
}


/*ARGSUSED*/
static void
fbt_destroy(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg, *next, *hash, *last;
	int ndx;

	do {
		/*
		 * Now we need to remove this probe from the fbt_probetab.
		 */
		ndx = FBT_ADDR2NDX(fbt->fbtp_patchpoint);
		last = NULL;
		hash = fbt_probetab[ndx];

		while (hash != fbt) {
			ASSERT(hash != NULL);
			last = hash;
			hash = hash->fbtp_hashnext;
		}

		if (last != NULL) {
			last->fbtp_hashnext = fbt->fbtp_hashnext;
		} else {
			fbt_probetab[ndx] = fbt->fbtp_hashnext;
		}

		next = fbt->fbtp_next;
		kmem_free(fbt, sizeof (fbt_probe_t));

		fbt = next;
	} while (fbt != NULL);
}

/*ARGSUSED*/
int
fbt_enable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = NULL;

    for (; fbt != NULL; fbt = fbt->fbtp_next) {

	ctl = fbt->fbtp_ctl;

	if (!ctl->mod_loaded) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(module %s unloaded)",
			    fbt->fbtp_name, ctl->mod_modname);
		}

		continue;
	}

	/*
	 * Now check that our modctl has the expected load count.  If it
	 * doesn't, this module must have been unloaded and reloaded -- and
	 * we're not going to touch it.
	 */
	if (ctl->mod_loadcnt != fbt->fbtp_loadcnt) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt is failing for probe %s "
			    "(module %s reloaded)",
			    fbt->fbtp_name, ctl->mod_modname);
		}

		continue;
	}

	dtrace_casptr(&tempDTraceTrapHook, NULL, fbt_perfCallback);
	if (tempDTraceTrapHook != (perfCallback)fbt_perfCallback) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt_enable is failing for probe %s "
			    "in module %s: tempDTraceTrapHook already occupied.",
			    fbt->fbtp_name, ctl->mod_modname);
		}
		continue;
	}

	if (fbt->fbtp_currentval != fbt->fbtp_patchval) {
#if KASAN
		/* Since dtrace probes can call into KASan and vice versa, things can get
		 * very slow if we have a lot of probes. This call will disable the KASan
		 * fakestack after a threshold of probes is reached. */
		kasan_fakestack_suspend();
#endif

		(void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_patchval, (vm_offset_t)fbt->fbtp_patchpoint,
								sizeof(fbt->fbtp_patchval));
		/*
		 * Make the patched instruction visible via a data + instruction
		 * cache flush for the platforms that need it
		 */
		flush_dcache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_patchval), 0);
		invalidate_icache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_patchval), 0);
                fbt->fbtp_currentval = fbt->fbtp_patchval;

		ctl->mod_nenabled++;
	}

    }

    dtrace_membar_consumer();

    return (0);
}

/*ARGSUSED*/
static void
fbt_disable(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = NULL;

	for (; fbt != NULL; fbt = fbt->fbtp_next) {
	    ctl = fbt->fbtp_ctl;

	    if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		continue;

	    if (fbt->fbtp_currentval != fbt->fbtp_savedval) {
		(void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_savedval, (vm_offset_t)fbt->fbtp_patchpoint,
								sizeof(fbt->fbtp_savedval));
		/*
		 * Make the patched instruction visible via a data + instruction
		 * cache flush for the platforms that need it
		 */
		flush_dcache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_patchval), 0);
		invalidate_icache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_patchval), 0);

		fbt->fbtp_currentval = fbt->fbtp_savedval;
		ASSERT(ctl->mod_nenabled > 0);
		ctl->mod_nenabled--;

#if KASAN
		kasan_fakestack_resume();
#endif
	    }
	}
	dtrace_membar_consumer();
}

/*ARGSUSED*/
static void
fbt_suspend(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = NULL;

	for (; fbt != NULL; fbt = fbt->fbtp_next) {
	    ctl = fbt->fbtp_ctl;

	    ASSERT(ctl->mod_nenabled > 0);
	    if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		continue;

	    (void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_savedval, (vm_offset_t)fbt->fbtp_patchpoint,
								sizeof(fbt->fbtp_savedval));

		/*
		 * Make the patched instruction visible via a data + instruction
		 * cache flush for the platforms that need it
		 */
		flush_dcache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_savedval), 0);
		invalidate_icache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_savedval), 0);

		fbt->fbtp_currentval = fbt->fbtp_savedval;
	}

	dtrace_membar_consumer();
}

/*ARGSUSED*/
static void
fbt_resume(void *arg, dtrace_id_t id, void *parg)
{
#pragma unused(arg,id)
	fbt_probe_t *fbt = parg;
	struct modctl *ctl = NULL;

	for (; fbt != NULL; fbt = fbt->fbtp_next) {
	    ctl = fbt->fbtp_ctl;

	    ASSERT(ctl->mod_nenabled > 0);
	    if (!ctl->mod_loaded || (ctl->mod_loadcnt != fbt->fbtp_loadcnt))
		continue;

	    dtrace_casptr(&tempDTraceTrapHook, NULL, fbt_perfCallback);
	    if (tempDTraceTrapHook != (perfCallback)fbt_perfCallback) {
		if (fbt_verbose) {
			cmn_err(CE_NOTE, "fbt_resume is failing for probe %s "
			    "in module %s: tempDTraceTrapHook already occupied.",
			    fbt->fbtp_name, ctl->mod_modname);
		}
		return;
	    }

	    (void)ml_nofault_copy( (vm_offset_t)&fbt->fbtp_patchval, (vm_offset_t)fbt->fbtp_patchpoint,
								sizeof(fbt->fbtp_patchval));

		/*
		 * Make the patched instruction visible via a data + instruction cache flush.
		 */
		flush_dcache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_patchval), 0);
		invalidate_icache((vm_offset_t)fbt->fbtp_patchpoint,(vm_size_t)sizeof(fbt->fbtp_patchval), 0);

  	    fbt->fbtp_currentval = fbt->fbtp_patchval;
	}

	dtrace_membar_consumer();
}

static void
fbt_provide_module_user_syms(struct modctl *ctl)
{
	unsigned int i;
	char *modname = ctl->mod_modname;

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

			if (MOD_IS_MACH_KERNEL(ctl) && fbt_excluded(name))
				continue;

			/*
			 * Ignore symbols with a null address
			 */
			if (!symbol->dtsym_addr)
				continue;

			/*
			 * Ignore symbols not part of this module
			 */
			if (!dtrace_addr_in_module((void*)symbol->dtsym_addr, ctl))
				continue;

			fbt_provide_probe(ctl, modname, name, (machine_inst_t*)(uintptr_t)symbol->dtsym_addr, (machine_inst_t*)(uintptr_t)(symbol->dtsym_addr + symbol->dtsym_size));
		}
	}
}
static void
fbt_provide_kernel_section(struct modctl *ctl, kernel_section_t *sect, kernel_nlist_t *sym, uint32_t nsyms, const char *strings)
{
	uintptr_t sect_start = (uintptr_t)sect->addr;
	uintptr_t sect_end = (uintptr_t)sect->size + sect->addr;
	unsigned int i;

	if ((sect->flags & S_ATTR_PURE_INSTRUCTIONS) != S_ATTR_PURE_INSTRUCTIONS) {
		return;
	}

	for (i = 0; i < nsyms; i++) {
		uint8_t         n_type = sym[i].n_type & (N_TYPE | N_EXT);
		const char           *name = strings + sym[i].n_un.n_strx;
		uint64_t limit;

		if (sym[i].n_value < sect_start || sym[i].n_value > sect_end)
			continue;

		/* Check that the symbol is a global and that it has a name. */
		if (((N_SECT | N_EXT) != n_type && (N_ABS | N_EXT) != n_type))
			continue;

		if (0 == sym[i].n_un.n_strx)	/* iff a null, "", name. */
			continue;

		/* Lop off omnipresent leading underscore. */
		if (*name == '_')
			name += 1;

#if defined(__arm__)
		// Skip non-thumb functions on arm32
		if (sym[i].n_sect == 1 && !(sym[i].n_desc & N_ARM_THUMB_DEF)) {
			continue;
		}
#endif /* defined(__arm__) */

		if (MOD_IS_MACH_KERNEL(ctl) && fbt_excluded(name))
			continue;

		/*
		 * Find the function boundary by looking at either the
		 * end of the section or the beginning of the next symbol
		 */
		if (i == nsyms - 1) {
			limit = sect_end;
		}
		else {
			limit = sym[i + 1].n_value;
		}

		fbt_provide_probe(ctl, ctl->mod_modname, name, (machine_inst_t*)sym[i].n_value, (machine_inst_t*)limit);
	}

}

static int
fbt_sym_cmp(const void *ap, const void *bp)
{
	return (int)(((const kernel_nlist_t*)ap)->n_value - ((const kernel_nlist_t*)bp)->n_value);
}

static void
fbt_provide_module_kernel_syms(struct modctl *ctl)
{
	kernel_mach_header_t *mh = (kernel_mach_header_t *)(ctl->mod_address);
	kernel_segment_command_t *seg;
	struct load_command *cmd;
	kernel_segment_command_t *linkedit = NULL;
	struct symtab_command *symtab = NULL;
	kernel_nlist_t *syms = NULL, *sorted_syms = NULL;
	const char *strings;
	unsigned int i;
	size_t symlen;

	if (mh->magic != MH_MAGIC_KERNEL)
		return;

	cmd = (struct load_command *) &mh[1];
	for (i = 0; i < mh->ncmds; i++) {
		if (cmd->cmd == LC_SEGMENT_KERNEL) {
			kernel_segment_command_t *orig_sg = (kernel_segment_command_t *) cmd;
			if (LIT_STRNEQL(orig_sg->segname, SEG_LINKEDIT))
				linkedit = orig_sg;
		} else if (cmd->cmd == LC_SYMTAB) {
			symtab = (struct symtab_command *) cmd;
		}
		if (symtab && linkedit) {
			break;
		}
		cmd = (struct load_command *) ((caddr_t) cmd + cmd->cmdsize);
	}

	if ((symtab == NULL) || (linkedit == NULL)) {
		return;
	}

	syms = (kernel_nlist_t *)(linkedit->vmaddr + symtab->symoff - linkedit->fileoff);
	strings = (const char *)(linkedit->vmaddr + symtab->stroff - linkedit->fileoff);

	/*
	 * Make a copy of the symbol table and sort it to not cross into the next function
	 * when disassembling the function
	 */
	symlen = sizeof(kernel_nlist_t) * symtab->nsyms;
	sorted_syms = kmem_alloc(symlen, KM_SLEEP);
	bcopy(syms, sorted_syms, symlen);
	qsort(sorted_syms, symtab->nsyms, sizeof(kernel_nlist_t), fbt_sym_cmp);

	for (seg = firstsegfromheader(mh); seg != NULL; seg = nextsegfromheader(mh, seg)) {
		kernel_section_t *sect = firstsect(seg);

		if (strcmp(seg->segname, "__KLD") == 0) {
			continue;
		}

		for (sect = firstsect(seg); sect != NULL; sect = nextsect(seg, sect)) {
			fbt_provide_kernel_section(ctl, sect, sorted_syms, symtab->nsyms, strings);
		}
	}

	kmem_free(sorted_syms, symlen);
}

void
fbt_provide_module(void *arg, struct modctl *ctl)
{
#pragma unused(arg)
	ASSERT(ctl != NULL);
	ASSERT(dtrace_kernel_symbol_mode != DTRACE_KERNEL_SYMBOLS_NEVER);
	LCK_MTX_ASSERT(&mod_lock, LCK_MTX_ASSERT_OWNED);

	// Update the "ignore blacklist" bit
	if (ignore_fbt_blacklist)
		ctl->mod_flags |= MODCTL_FBT_PROVIDE_BLACKLISTED_PROBES;

	if (MOD_FBT_DONE(ctl))
		return;

	if (fbt_module_excluded(ctl)) {
		ctl->mod_flags |= MODCTL_FBT_INVALID;
		return;
	}

	if (MOD_HAS_KERNEL_SYMBOLS(ctl)) {
		fbt_provide_module_kernel_syms(ctl);
		ctl->mod_flags |= MODCTL_FBT_PROBES_PROVIDED;
		if (MOD_FBT_PROVIDE_BLACKLISTED_PROBES(ctl))
			ctl->mod_flags |= MODCTL_FBT_BLACKLISTED_PROBES_PROVIDED;
		return;
	}

	if (MOD_HAS_USERSPACE_SYMBOLS(ctl)) {
		fbt_provide_module_user_syms(ctl);
		ctl->mod_flags |= MODCTL_FBT_PROBES_PROVIDED;
		if (MOD_FBT_PROVIDE_PRIVATE_PROBES(ctl))
			ctl->mod_flags |= MODCTL_FBT_PRIVATE_PROBES_PROVIDED;
		if (MOD_FBT_PROVIDE_BLACKLISTED_PROBES(ctl))
			ctl->mod_flags |= MODCTL_FBT_BLACKLISTED_PROBES_PROVIDED;
		return;
	}
}

static dtrace_pattr_t fbt_attr = {
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_UNKNOWN },
{ DTRACE_STABILITY_EVOLVING, DTRACE_STABILITY_EVOLVING, DTRACE_CLASS_ISA },
{ DTRACE_STABILITY_PRIVATE, DTRACE_STABILITY_PRIVATE, DTRACE_CLASS_ISA },
};

static dtrace_pops_t fbt_pops = {
	.dtps_provide =		NULL,
	.dtps_provide_module =	fbt_provide_module,
	.dtps_enable =		fbt_enable,
	.dtps_disable =		fbt_disable,
	.dtps_suspend =		fbt_suspend,
	.dtps_resume =		fbt_resume,
	.dtps_getargdesc =	NULL, /* APPLE NOTE: fbt_getargdesc implemented in userspace */
	.dtps_getargval =	NULL,
	.dtps_usermode =	NULL,
	.dtps_destroy =		fbt_destroy
};

static void
fbt_cleanup(dev_info_t *devi)
{
	dtrace_invop_remove(fbt_invop);
	ddi_remove_minor_node(devi, NULL);
	kmem_free(fbt_probetab, fbt_probetab_size * sizeof (fbt_probe_t *));
	fbt_probetab = NULL;
	fbt_probetab_mask = 0;
}

static int
fbt_attach(dev_info_t *devi)
{
	if (fbt_probetab_size == 0)
		fbt_probetab_size = FBT_PROBETAB_SIZE;

	fbt_probetab_mask = fbt_probetab_size - 1;
	fbt_probetab =
	    kmem_zalloc(fbt_probetab_size * sizeof (fbt_probe_t *), KM_SLEEP);

	dtrace_invop_add(fbt_invop);

	if (ddi_create_minor_node(devi, "fbt", S_IFCHR, 0,
	    DDI_PSEUDO, 0) == DDI_FAILURE ||
	    dtrace_register("fbt", &fbt_attr, DTRACE_PRIV_KERNEL, NULL,
	    &fbt_pops, NULL, &fbt_id) != 0) {
		fbt_cleanup(devi);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static d_open_t _fbt_open;

static int
_fbt_open(dev_t dev, int flags, int devtype, struct proc *p)
{
#pragma unused(dev,flags,devtype,p)
	return 0;
}

#define FBT_MAJOR  -24 /* let the kernel pick the device number */

SYSCTL_DECL(_kern_dtrace);

static int
sysctl_dtrace_ignore_fbt_blacklist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int err;
	int value = *(int*)arg1;

	err = sysctl_io_number(req, value, sizeof(value), &value, NULL);
	if (err)
		return (err);
	if (req->newptr) {
		if (!(value == 0 || value == 1))
			return (ERANGE);

		/*
		 * We do not allow setting the blacklist back to on, as we have no way
		 * of knowing if those unsafe probes are still used.
		 *
		 * If we are using kernel symbols, we also do not allow any change,
		 * since the symbols are jettison'd after the first pass.
		 *
		 * We do not need to take any locks here because those symbol modes
		 * are permanent and do not change after boot.
		 */
		if (value != 1 || dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_NEVER ||
		  dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_ALWAYS_FROM_KERNEL)
			return (EPERM);

		ignore_fbt_blacklist = 1;
	}

	return (0);
}

SYSCTL_PROC(_kern_dtrace, OID_AUTO, ignore_fbt_blacklist,
	CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
	&ignore_fbt_blacklist, 0,
	sysctl_dtrace_ignore_fbt_blacklist, "I", "fbt provider ignore blacklist");

/*
 * A struct describing which functions will get invoked for certain
 * actions.
 */
static struct cdevsw fbt_cdevsw =
{
	_fbt_open,		/* open */
	eno_opcl,			/* close */
	eno_rdwrt,			/* read */
	eno_rdwrt,			/* write */
	eno_ioctl,			/* ioctl */
	(stop_fcn_t *)nulldev, /* stop */
	(reset_fcn_t *)nulldev, /* reset */
	NULL,				/* tty's */
	eno_select,			/* select */
	eno_mmap,			/* mmap */
	eno_strat,			/* strategy */
	eno_getc,			/* getc */
	eno_putc,			/* putc */
	0					/* type */
};

#undef kmem_alloc /* from its binding to dt_kmem_alloc glue */
#undef kmem_free /* from its binding to dt_kmem_free glue */
#include <vm/vm_kern.h>

void
fbt_init( void )
{
	int majdevno = cdevsw_add(FBT_MAJOR, &fbt_cdevsw);

	if (majdevno < 0) {
		printf("fbt_init: failed to allocate a major number!\n");
		return;
	}

	PE_parse_boot_argn("IgnoreFBTBlacklist", &ignore_fbt_blacklist, sizeof (ignore_fbt_blacklist));

	fbt_attach((dev_info_t*)(uintptr_t)majdevno);
}
#undef FBT_MAJOR
