/*
 * Copyright (c) 2014 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <pexpert/pexpert.h>
#include <sys/csr.h>
#include <sys/errno.h>
#include <sys/sysproto.h>
#include <sys/systm.h>
#include <sys/types.h>

#if CONFIG_CSR_FROM_DT

/*
 * New style CSR for non-x86 platforms, using Per-OS Security Policy
 * (POSP)
 */

#include <libkern/section_keywords.h>
#include <pexpert/device_tree.h>

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
#include <arm64/amcc_rorgn.h>
#endif

static SECURITY_READ_ONLY_LATE(csr_config_t) csr_config = 0;

// WARNING: Used extremely early during boot. See csr_bootstrap().
static bool
_csr_get_dt_bool(DTEntry *entry, char const *name, bool *out)
{
	const uint32_t     *value;
	unsigned int size;

	if (SecureDTGetProperty(*entry, name, (const void**)&value, &size) != kSuccess) {
		return false;
	}

	if (size != sizeof(uint32_t)) {
		panic("unexpected size %xu for bool property '%s'", size, name);
	}

	*out = (bool)*value;
	return true;
}

// WARNING: Used extremely early during boot. See csr_bootstrap().
static bool
_csr_get_dt_uint64(DTEntry *entry, char const *name, uint64_t *out)
{
	const uint64_t     *value;
	unsigned int size;

	if (SecureDTGetProperty(*entry, name, (const void**)&value, &size) != kSuccess) {
		return false;
	}

	if (size != sizeof(uint64_t)) {
		panic("unexpected size %xu for uint64 property '%s'", size, name);
	}

	*out = *value;
	return true;
}

// WARNING: Used extremely early during boot. See csr_bootstrap().
static bool
_csr_dt_string_is_equal(DTEntry *entry, const char *name, const char *str)
{
	const void       *value;
	unsigned         size;
	size_t           str_size;

	str_size = strlen(str) + 1;
	return entry != NULL &&
	       SecureDTGetProperty(*entry, name, &value, &size) == kSuccess &&
	       value != NULL &&
	       size == str_size &&
	       strncmp(str, value, str_size) == 0;
}

static bool
_csr_is_recovery_environment(void)
{
	DTEntry chosen;

	return SecureDTLookupEntry(0, "/chosen", &chosen) == kSuccess &&
	       _csr_dt_string_is_equal(&chosen, "osenvironment", "recoveryos");
}

static bool
_csr_is_iuou_or_iuos_device(void)
{
	DTEntry entry;
	bool    bool_value;

	return (SecureDTLookupEntry(0, "/chosen", &entry) == kSuccess &&
	       (_csr_get_dt_bool(&entry, "internal-use-only-unit", &bool_value) && bool_value)) ||
	       (SecureDTLookupEntry(0, "/chosen/manifest-properties", &entry) == kSuccess &&
	       (_csr_get_dt_bool(&entry, "iuos", &bool_value) && bool_value));
}

static bool
_csr_should_allow_device_configuration(void)
{
	/*
	 * Allow CSR_ALLOW_DEVICE_CONFIGURATION if the device is running in a
	 * restore environment, or if the "csr-allow-device-configuration"
	 * property is set in the device tree.
	 */
	DTEntry chosen;
	bool    bool_value;

	return _csr_is_recovery_environment() || (
		SecureDTLookupEntry(0, "/chosen", &chosen) == kSuccess &&
		_csr_get_dt_bool(&chosen, "csr-allow-device-configuration", &bool_value) && bool_value);
}

/*
 * Initialize CSR from the Device Tree.
 *
 * WARNING: csr_bootstrap() is called extremely early in the kernel
 * startup process in kernel_startup_bootstrap(), which happens
 * before even the vm or pmap layer are initialized.
 *
 * It is marked as STARTUP_RANK_FIRST so that it is called before panic_init(),
 * which runs during STARTUP_RANK_MIDDLE. This is necessary because panic_init()
 * calls csr_check() to determine whether the device is configured to allow
 * kernel debugging.
 *
 * Only do things here that don't require any dynamic memory (other
 * than the stack). Parsing boot-args, walking the device tree and
 * setting global variables is fine, most other things are not. Defer
 * those other things with global variables, if necessary.
 *
 */
__startup_func
static void
csr_bootstrap(void)
{
	DTEntry         entry;
	uint64_t        uint64_value;
	bool            config_active   = false;
	bool            bool_value;

	csr_config = 0;                // start out fully restrictive

	if (SecureDTLookupEntry(0, "/chosen/asmb", &entry) == kSuccess &&
	    _csr_get_dt_uint64(&entry, "lp-sip0", &uint64_value)) {
		csr_config = (uint32_t)uint64_value;    // Currently only 32 bits used.
		config_active = true;
	}

	/*
	 * If the device is an Internal Use Only Unit (IUOU) or if it is running a
	 * build that is signed with the Internal Use Only Software (IUOS) tag, then
	 * allow the preservation of the CSR_ALLOW_APPLE_INTERNAL bit. Otherwise,
	 * forcefully remove the bit on boot.
	 */
	if (!_csr_is_iuou_or_iuos_device()) {
		csr_config &= ~CSR_ALLOW_APPLE_INTERNAL;
	} else if (!config_active) {
		// If there is no custom configuration present, infer the AppleInternal
		// bit on IUOU or IUOS devices.
		csr_config |= CSR_ALLOW_APPLE_INTERNAL;
	}

	if (_csr_should_allow_device_configuration()) {
		csr_config |= CSR_ALLOW_DEVICE_CONFIGURATION;
	}

	// The CSR_ALLOW_UNAUTHENTICATED_ROOT flag must be synthesized from sip1
	// in the local boot policy.
	if (_csr_get_dt_bool(&entry, "lp-sip1", &bool_value) && bool_value) {
		csr_config |= CSR_ALLOW_UNAUTHENTICATED_ROOT;
	} else {
		csr_config &= ~CSR_ALLOW_UNAUTHENTICATED_ROOT;
	}

#if defined(KERNEL_INTEGRITY_KTRR) || defined(KERNEL_INTEGRITY_CTRR)
	// Check whether we have to disable CTRR.
	// lp-sip2 in the local boot policy is the bit driving this,
	// which csrutil also sets implicitly when e.g. requesting kernel debugging.
	csr_unsafe_kernel_text = _csr_get_dt_bool(&entry, "lp-sip2", &bool_value) && bool_value;
#endif
}
STARTUP(TUNABLES, STARTUP_RANK_FIRST, csr_bootstrap);

int
csr_get_active_config(csr_config_t * config)
{
	*config = (csr_config & CSR_VALID_FLAGS);

	return 0;
}

int
csr_check(csr_config_t mask)
{
	csr_config_t config;
	int ret = csr_get_active_config(&config);

	if (ret != 0) {
		return ret;
	}

	// CSR_ALLOW_KERNEL_DEBUGGER needs to be allowed when SIP is disabled
	// to allow 3rd-party developers to debug their kexts.  Use
	// CSR_ALLOW_UNTRUSTED_KEXTS as a proxy for "SIP is disabled" on the
	// grounds that you can do the same damage with a kernel debugger as
	// you can with an untrusted kext.
	if ((config & (CSR_ALLOW_UNTRUSTED_KEXTS | CSR_ALLOW_APPLE_INTERNAL)) != 0) {
		config |= CSR_ALLOW_KERNEL_DEBUGGER;
	}

	return ((config & mask) == mask) ? 0 : EPERM;
}

#else

/*
 * Old style CSR for x86 platforms, using NVRAM values
 */

#include <libkern/section_keywords.h>

/* enable enforcement by default */
static SECURITY_READ_ONLY_LATE(int) csr_allow_all = 0;

/*
 * Initialize csr_allow_all from device boot state.
 *
 * Needs to be run before panic_init() since panic_init()
 * calls into csr_check() and runs during STARTUP_RANK_MIDDLE.
 */
__startup_func
static void
csr_bootstrap(void)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;
	if (args->flags & kBootArgsFlagCSRBoot) {
		/* special booter; allow everything */
		csr_allow_all = 1;
	}
}
STARTUP(TUNABLES, STARTUP_RANK_FIRST, csr_bootstrap);


int
csr_get_active_config(csr_config_t *config)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;
	if (args->flags & kBootArgsFlagCSRActiveConfig) {
		*config = args->csrActiveConfig & CSR_VALID_FLAGS;
	} else {
		*config = 0;
	}

	return 0;
}

int
csr_check(csr_config_t mask)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;
	if (mask & CSR_ALLOW_DEVICE_CONFIGURATION) {
		return (args->flags & kBootArgsFlagCSRConfigMode) ? 0 : EPERM;
	}

	csr_config_t config;
	int ret = csr_get_active_config(&config);
	if (ret) {
		return ret;
	}

	// CSR_ALLOW_KERNEL_DEBUGGER needs to be allowed when SIP is disabled
	// to allow 3rd-party developers to debug their kexts.  Use
	// CSR_ALLOW_UNTRUSTED_KEXTS as a proxy for "SIP is disabled" on the
	// grounds that you can do the same damage with a kernel debugger as
	// you can with an untrusted kext.
	if ((config & (CSR_ALLOW_UNTRUSTED_KEXTS | CSR_ALLOW_APPLE_INTERNAL)) != 0) {
		config |= CSR_ALLOW_KERNEL_DEBUGGER;
	}

	ret = ((config & mask) == mask) ? 0 : EPERM;
	if (ret == EPERM) {
		// Override the return value if booted from the BaseSystem and the mask does not contain any flag that should always be enforced.
		if (csr_allow_all && (mask & CSR_ALWAYS_ENFORCED_FLAGS) == 0) {
			ret = 0;
		}
	}

	return ret;
}

#endif /* CONFIG_CSR_FROM_DT */

/*
 * Syscall stubs
 */

int syscall_csr_check(struct csrctl_args *args);
int syscall_csr_get_active_config(struct csrctl_args *args);


int
syscall_csr_check(struct csrctl_args *args)
{
	csr_config_t mask = 0;
	int error = 0;

	if (args->useraddr == 0 || args->usersize != sizeof(mask)) {
		return EINVAL;
	}

	error = copyin(args->useraddr, &mask, sizeof(mask));
	if (error) {
		return error;
	}

	return csr_check(mask);
}

int
syscall_csr_get_active_config(struct csrctl_args *args)
{
	csr_config_t config = 0;
	int error = 0;

	if (args->useraddr == 0 || args->usersize != sizeof(config)) {
		return EINVAL;
	}

	error = csr_get_active_config(&config);
	if (error) {
		return error;
	}

	return copyout(&config, args->useraddr, sizeof(config));
}

/*
 * Syscall entrypoint
 */

int
csrctl(__unused proc_t p, struct csrctl_args *args, __unused int32_t *retval)
{
	switch (args->op) {
	case CSR_SYSCALL_CHECK:
		return syscall_csr_check(args);
	case CSR_SYSCALL_GET_ACTIVE_CONFIG:
		return syscall_csr_get_active_config(args);
	default:
		return ENOSYS;
	}
}
