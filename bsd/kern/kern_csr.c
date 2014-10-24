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

/* allow everything by default? */
/* XXX: set this to 0 later: <rdar://problem/16040413> */
static int csr_allow_all = 1;

/* allow everything if CSR_ALLOW_APPLE_INTERNAL is set */
static int csr_allow_internal = 1;

/* Current boot-arg policy:
 * rootless=0
 *    csr_allow_all = 1
 * rootless=1
 *    csr_allow_all = 0
 *    csr_allow_internal = 0
 *
 * After <rdar://problem/16239861>:
 * rootless=0
 *    no effect
 * rootless=1
 *    csr_allow_internal = 0
 *
 * Enforcement policy:
 * ===============================
 *            | csr_allow_internal
 *            |   0         1
 * ===============================
 *   csr_   0 | always   customer
 *  allow_    |
 *   all    1 | never    never
 * ===============================
 * NB: "customer" means enforce when
 * CSR_ALLOW_APPLE_INTERNAL not set */

void
csr_init(void)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;
	if (args->flags & kBootArgsFlagCSRBoot) {
		/* special booter; allow everything */
		csr_allow_all = 1;
	}

	int rootless_boot_arg;
	if (PE_parse_boot_argn("rootless", &rootless_boot_arg, sizeof(rootless_boot_arg))) {
		/* XXX: set csr_allow_all to boot arg value for now
		 * (to be removed by <rdar://problem/16239861>) */
		csr_allow_all = !rootless_boot_arg;
		/* if rootless=1, do not allow everything when CSR_ALLOW_APPLE_INTERNAL is set */
		csr_allow_internal &= !rootless_boot_arg;
	}
}

int
csrctl(__unused proc_t p, struct csrctl_args *uap, __unused int32_t *retval)
{
	int error = 0;

	if (uap->useraddr == 0)
		return EINVAL;
	if (uap->usersize != sizeof(csr_config_t))
		return EINVAL;

	switch (uap->op) {
		case CSR_OP_CHECK:
		{
			csr_config_t mask;
			error = copyin(uap->useraddr, &mask, sizeof(csr_config_t));

			if (error)
				return error;

			error = csr_check(mask);
			break;
		}

		case CSR_OP_GET_ACTIVE_CONFIG:
		case CSR_OP_GET_PENDING_CONFIG: /* fall through */
		{
			csr_config_t config = 0;
			if (uap->op == CSR_OP_GET_ACTIVE_CONFIG)
				error = csr_get_active_config(&config);
			else
				error = csr_get_pending_config(&config);

			if (error)
				return error;

			error = copyout(&config, uap->useraddr, sizeof(csr_config_t));
			break;
		}

		default:
			error = EINVAL;
			break;
	}

	return error;
}

int
csr_get_active_config(csr_config_t *config)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;
	if (args->flags & kBootArgsFlagCSRActiveConfig) {
		*config = args->csrActiveConfig & CSR_VALID_FLAGS;
	} else {
		/* XXX: change to 0 when <rdar://problem/16239698> is in the build */
		*config = CSR_ALLOW_APPLE_INTERNAL;
	}

	return 0;
}

int
csr_get_pending_config(csr_config_t *config)
{
	boot_args *args = (boot_args *)PE_state.bootArgs;
	if (args->flags & kBootArgsFlagCSRPendingConfig) {
		*config = args->csrPendingConfig & CSR_VALID_FLAGS;
		return 0;
	} else {
		return ENOENT;
	}
}

int
csr_check(csr_config_t mask)
{
	if (csr_allow_all) {
		return 0;
	}

	csr_config_t config;
	int error = csr_get_active_config(&config);
	if (error) {
		return error;
	}

	if (csr_allow_internal && (config & CSR_ALLOW_APPLE_INTERNAL)) {
		return 0;
	}

	if (mask == 0) {
		/* pass 0 to check if Rootless enforcement is active */
		return -1;
	}

	error = (config & mask) ? 0 : EPERM;
	return error;
}

void
csr_set_allow_all(int value)
{
	csr_allow_all = !!value; // force value to 0 or 1
}
