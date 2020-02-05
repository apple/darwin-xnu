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

#include <sys/dtrace_impl.h>
#include <sys/fbt.h>
#include <sys/sysctl.h>

#define CLOSURE(s) #s,
#define CRITICAL(s) #s,

#if KASAN
#define KASAN_ONLY(s) #s,
#else
#define KASAN_ONLY(s)
#endif /* KASAN */

#if defined(__arm__) || defined(__arm64__)
#define ARM_ONLY(s) #s,
#else
#define ARM_ONLY(s)
#endif /* defined(__arm__) || defined(__arm64__) */
#if defined(__x86_64__)
#define X86_ONLY(s) #s,
#else
#define X86_ONLY(s)
#endif /* defined(__x86_64__) */

/*
 * Routine prefixes that must not be probed, either because they are used in
 * the exception path, by dtrace code in probe context, or are general
 * critical routines that must never be probed.
 *
 * All routines whose name start with one of these will be ignored.
 *
 * This must be kept in asciibetical order for purposes of bsearch().
 */
const char * fbt_blacklist[] =
{
	CRITICAL(Call_DebuggerC)
	CLOSURE(ClearIdlePop)
	CLOSURE(Debugger)
	CRITICAL(IOCPURunPlatformPanicActions)
	CLOSURE(IS_64BIT_PROCESS)
	CRITICAL(OSAdd)
	CRITICAL(OSBit)
	CLOSURE(OSCompareAndSwap)
	CRITICAL(OSDecrement)
	CRITICAL(OSIncrement)
	CRITICAL(PEARMDebugPanicHook)
	CRITICAL(PEHaltRestart)
	CRITICAL(PE_)
	CRITICAL(SavePanicInfo)
	CLOSURE(SetIdlePop)
	CRITICAL(SysChoked)
	CRITICAL(_ZN15OSMetaClassBase12safeMetaCastEPKS_PK11OSMetaClass) /* OSMetaClassBase::safeMetaCast */
	CRITICAL(_ZN16IOPlatformExpert11haltRestartEj) /* IOPlatformExpert::haltRestart */
	CRITICAL(_ZN18IODTPlatformExpert11haltRestartEj) /* IODTPlatformExpert::haltRestart */
	ARM_ONLY(_ZN8ASPNVRAM4syncEv) /* ASPNVRAM::sync */
	CRITICAL(_ZN9IODTNVRAM13savePanicInfoEPhy) /* IODTNVRAM::savePanicInfo */
	CRITICAL(_ZN9IOService14newTemperatureElPS_) /* IOService::newTemperature */
	CRITICAL(_ZN9IOService26temperatureCriticalForZoneEPS_) /* IOService::temperatureCriticalForZone */
	CRITICAL(_ZNK11OSMetaClass13checkMetaCastEPK15OSMetaClassBase) /* OSMetaClass::checkMetaCast */
	CRITICAL(_ZNK15OSMetaClassBase8metaCastEPK11OSMetaClass) /* OSMetaClassBase::metaCast */
	CRITICAL(_ZNK6OSData14getBytesNoCopyEv) /* Data::getBytesNoCopy, IOHibernateSystemWake path */
	KASAN_ONLY(__asan)
	ARM_ONLY(__div)
	CLOSURE(__dtrace_probe)
	KASAN_ONLY(__kasan)
	ARM_ONLY(__mod)
	CRITICAL(__strlcpy_chk)
	ARM_ONLY(__udiv)
	ARM_ONLY(__umod)
	CRITICAL(_disable_preemption)
	CRITICAL(_enable_preemption)
	CLOSURE(absolutetime_to_microtime)
	X86_ONLY(acpi_)
	X86_ONLY(act_machine)
	CLOSURE(act_set_astbsd)
	ARM_ONLY(alternate_debugger_enter)
	ARM_ONLY(arm_init_idle_cpu)
	CLOSURE(ast_dtrace_on)
	CLOSURE(ast_pending)
	CRITICAL(bcopy)
	CLOSURE(clean_dcache)
	CLOSURE(clean_mmu_dcache)
	CRITICAL(clock_)
	X86_ONLY(commpage_)
	CRITICAL(console_cpu_alloc)
	CRITICAL(console_cpu_free)
	CLOSURE(copyin)
	CLOSURE(copyout)
	CRITICAL(cpu_)
	CLOSURE(current_proc)
	CLOSURE(current_processor)
	CLOSURE(current_task)
	CLOSURE(current_thread)
	CLOSURE(debug_)
	X86_ONLY(dsmos_)
	CLOSURE(dtrace_)
	CRITICAL(enter_lohandler)
	CRITICAL(fasttrap_)
	CRITICAL(fbt_invop)
	CRITICAL(fbt_perfCallback)
	CLOSURE(find_user_regs)
	ARM_ONLY(fleh_)
	CLOSURE(flush_dcache)
	ARM_ONLY(flush_mmu_tlb_)
	CLOSURE(flush_tlb64)
	CRITICAL(fuword)
	CLOSURE(get_bsdtask_info)
	CLOSURE(get_bsdthread_info)
	CRITICAL(get_preemption_level)
	CRITICAL(get_threadtask)
	ARM_ONLY(get_vfp_enabled)
	CRITICAL(getminor)
	CRITICAL(handle_pending_TLB_flushes)
	CRITICAL(hibernate_)
	X86_ONLY(hndl_)
	CRITICAL(hw_)
	X86_ONLY(idt64)
	CRITICAL(interrupt)
	CRITICAL(invalidate_mmu_icache)
	CRITICAL(is_saved_state32)
	KASAN_ONLY(kasan)
	CLOSURE(kauth_cred_get)
	CLOSURE(kauth_getgid)
	CLOSURE(kauth_getuid)
	CRITICAL(kdb_)
	CRITICAL(kdp_)
	CRITICAL(kernel_preempt_check)
	CRITICAL(kernel_trap)
	CRITICAL(kprintf)
	CRITICAL(ks_)
	CLOSURE(kvtophys)
	X86_ONLY(lapic_)
	CRITICAL(lo_alltraps)
	CRITICAL(lock_debugger)
	CLOSURE(mach_absolute_time)
	CRITICAL(machine_)
	X86_ONLY(mapping_)
	CRITICAL(mca_cpu_alloc)
	CRITICAL(mca_cpu_init)
	CLOSURE(memcpy)
	CLOSURE(memmove)
	CRITICAL(ml_)
	CLOSURE(mt_core_snap)
	CLOSURE(mt_cur_cpu_cycles)
	CLOSURE(mt_cur_cpu_instrs)
	CLOSURE(mt_cur_thread_cycles)
	CLOSURE(mt_cur_thread_instrs)
	CLOSURE(mt_fixed_counts)
	CLOSURE(mt_fixed_counts_internal)
	CLOSURE(mt_mtc_update_count)
	CLOSURE(mt_update_thread)
	CRITICAL(nanoseconds_to_absolutetime)
	CRITICAL(nanotime_to_absolutetime)
	CRITICAL(ovbcopy)
	CRITICAL(packA)
	X86_ONLY(pal_)
	CLOSURE(panic)
	CRITICAL(phystokv)
	CRITICAL(platform_)
	X86_ONLY(pltrace)
	X86_ONLY(pmCPU)
	X86_ONLY(pmKextRegister)
	X86_ONLY(pmMarkAllCPUsOff)
	X86_ONLY(pmSafeMode)
	X86_ONLY(pmTimerRestore)
	X86_ONLY(pmTimerSave)
	X86_ONLY(pmUnRegister)
	X86_ONLY(pmap64_pdpt)
	CLOSURE(pmap_find_phys)
	CLOSURE(pmap_get_mapwindow)
	CLOSURE(pmap_pde)
	CLOSURE(pmap_pde_internal0)
	CLOSURE(pmap_pde_internal1)
	CLOSURE(pmap_pte)
	CLOSURE(pmap_pte_internal)
	CLOSURE(pmap_put_mapwindow)
	CLOSURE(pmap_valid_page)
	X86_ONLY(pms)
	CRITICAL(power_management_init)
	CRITICAL(preemption_underflow_panic)
	CLOSURE(prf)
	CLOSURE(proc_is64bit)
	CLOSURE(proc_selfname)
	CRITICAL(register_cpu_setup_func)
	CRITICAL(ret64_iret)
	CRITICAL(ret_to_user)
	CRITICAL(return_to_kernel)
	CRITICAL(return_to_user)
	CRITICAL(rtc_)
	CRITICAL(rtclock_)
	CRITICAL(saved_state64)
	CLOSURE(sdt_getargdesc)
	CRITICAL(sdt_invop)
	CLOSURE(setPop)
	ARM_ONLY(sleh_)
	CRITICAL(sprlock)
	CRITICAL(sprunlock)
	CLOSURE(strlcpy)
	CRITICAL(strlen)
	CRITICAL(strncmp)
	CRITICAL(suword)
	X86_ONLY(sync_iss_to_iks_unconditionally)
	CLOSURE(systrace_stub)
	CRITICAL(t_invop)
	CLOSURE(timer_grab)
	ARM_ONLY(timer_state_event)
	CRITICAL(tmrCvt)
	CRITICAL(trap_from_kernel)
	CRITICAL(tsc_)
	CRITICAL(uart_putc)
	CRITICAL(unlock_debugger)
	CRITICAL(unpackA)
	CRITICAL(unregister_cpu_setup_func)
	CRITICAL(uread)
	CRITICAL(uwrite)
	CRITICAL(vstart)
};
#define BLACKLIST_COUNT (sizeof(fbt_blacklist)/sizeof(fbt_blacklist[0]))

/*
 * Modules that should not be probed.
 *
 * This must be kept in asciibetical order for purposes of bsearch().
 */
static const char* fbt_module_blacklist[] = {
	X86_ONLY(com.apple.driver.AppleACPIEC)
	X86_ONLY(com.apple.driver.AppleACPIPlatform)
	ARM_ONLY(com.apple.driver.AppleARMPlatform)
	X86_ONLY(com.apple.driver.AppleEFI)
	X86_ONLY(com.apple.driver.AppleIntelCPUPowerManagement)
	ARM_ONLY(com.apple.driver.AppleInterruptController)
	X86_ONLY(com.apple.driver.AppleRTC)
	X86_ONLY(com.apple.iokit.IOACPIFamily)
};
#define MODULE_BLACKLIST_COUNT (sizeof(fbt_module_blacklist)/sizeof(fbt_module_blacklist[0]))

int ignore_fbt_blacklist = 0;
extern int dtrace_kernel_symbol_mode;

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wcast-qual"
static int
_cmp(const void *a, const void *b)
{
	const char *v = *(const char **)b;
	return strncmp((const char *)a, v, strlen(v));
}


#pragma clang diagnostic pop
/*
 * Module validation
 */
bool
fbt_module_excluded(struct modctl* ctl)
{
	const char *excluded;

	ASSERT(!MOD_FBT_DONE(ctl));

	if (ctl->mod_address == 0 || ctl->mod_size == 0 || !ctl->mod_loaded) {
		return true;
	}

	if (ignore_fbt_blacklist) {
		return false;
	}

	excluded = bsearch(ctl->mod_modname, fbt_module_blacklist,
	    MODULE_BLACKLIST_COUNT, sizeof(fbt_module_blacklist[0]), _cmp);
	return excluded;
}

/*
 * FBT probe name validation
 */
bool
fbt_excluded(const char* name)
{
	const char *excluded;

	if (ignore_fbt_blacklist) {
		return false;
	}

	excluded = bsearch(name, fbt_blacklist, BLACKLIST_COUNT, sizeof(name),
	    _cmp );
	return excluded;
}

SYSCTL_DECL(_kern_dtrace);

static int
sysctl_dtrace_ignore_fbt_blacklist SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int err;
	int value = *(int*)arg1;

	err = sysctl_io_number(req, value, sizeof(value), &value, NULL);
	if (err) {
		return err;
	}
	if (req->newptr) {
		if (!(value == 0 || value == 1)) {
			return ERANGE;
		}

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
		    dtrace_kernel_symbol_mode == DTRACE_KERNEL_SYMBOLS_ALWAYS_FROM_KERNEL) {
			return EPERM;
		}

		ignore_fbt_blacklist = 1;
	}

	return 0;
}

SYSCTL_PROC(_kern_dtrace, OID_AUTO, ignore_fbt_blacklist,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    &ignore_fbt_blacklist, 0,
    sysctl_dtrace_ignore_fbt_blacklist, "I", "fbt provider ignore blacklist");

void
fbt_blacklist_init(void)
{
	PE_parse_boot_argn("IgnoreFBTBlacklist", &ignore_fbt_blacklist, sizeof(ignore_fbt_blacklist));
#if DEBUG || DEVELOPMENT
	for (size_t i = 1; i < BLACKLIST_COUNT; i++) {
		if (strcmp(fbt_blacklist[i - 1], fbt_blacklist[i]) > 0) {
			panic("unordered fbt blacklist %s > %s", fbt_blacklist[i - 1], fbt_blacklist[i]);
		}
	}
#endif /* DEBUG || DEVELOPMENT */
}
