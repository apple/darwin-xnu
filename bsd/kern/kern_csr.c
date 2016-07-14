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

/* enable enforcement by default */
static int csr_allow_all = 0;

void
csr_init(void)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;
	if (args->flags & kBootArgsFlagCSRBoot) {
		/* special booter; allow everything */
		csr_allow_all = 1;
	}
}

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
	if ((mask & CSR_ALLOW_DEVICE_CONFIGURATION) && !(args->flags & kBootArgsFlagCSRConfigMode))
		return EPERM;

	if (csr_allow_all) {
		return 0;
	}

	csr_config_t config;
	int error = csr_get_active_config(&config);
	if (error) {
		return error;
	}

	if (mask == 0) {
		/* pass 0 to check if Rootless enforcement is active */
		return -1;
	}

	error = (config & mask) ? 0 : EPERM;
	return error;
}

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

	if (args->useraddr == 0 || args->usersize != sizeof(mask))
		return EINVAL;

	error = copyin(args->useraddr, &mask, sizeof(mask));
	if (error)
		return error;

	return csr_check(mask);
}

int
syscall_csr_get_active_config(struct csrctl_args *args)
{
	csr_config_t config = 0;
	int error = 0;

	if (args->useraddr == 0 || args->usersize != sizeof(config))
		return EINVAL;

	error = csr_get_active_config(&config);
	if (error)
		return error;

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
