/*
 * Copyright (c) 2007 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 2006 SPARTA, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/queue.h>
#include <bsd/bsm/audit.h>
#include <bsd/security/audit/audit.h>
#include <bsd/sys/malloc.h>
#include <vm/vm_kern.h>
#include <kern/kalloc.h>

#include <security/mac_framework.h>
#include <security/mac_internal.h>

int
mac_iokit_check_device(char *devtype, struct mac_module_data *mdata)
{
	int error;

	MAC_CHECK(iokit_check_device, devtype, mdata);
	return error;
}

int
mac_iokit_check_open(kauth_cred_t cred, io_object_t user_client, unsigned int user_client_type)
{
	int error;

	MAC_CHECK(iokit_check_open, cred, user_client, user_client_type);
	return error;
}

int
mac_iokit_check_set_properties(kauth_cred_t cred, io_object_t registry_entry, io_object_t properties)
{
	int error;

	MAC_CHECK(iokit_check_set_properties, cred, registry_entry, properties);
	return error;
}

int
mac_iokit_check_filter_properties(kauth_cred_t cred, io_object_t registry_entry)
{
	int error;

	MAC_CHECK(iokit_check_filter_properties, cred, registry_entry);
	return error;
}

int
mac_iokit_check_get_property(kauth_cred_t cred, io_object_t registry_entry, const char *name)
{
	int error;

	MAC_CHECK(iokit_check_get_property, cred, registry_entry, name);
	return error;
}

int
mac_iokit_check_hid_control(kauth_cred_t cred)
{
	int error;

	MAC_CHECK(iokit_check_hid_control, cred);
	return error;
}
