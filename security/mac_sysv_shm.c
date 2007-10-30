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
 * Copyright (c) 2003-2004 Networks Associates Technology, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
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

#include <sys/cdefs.h>

#include <sys/cdefs.h>

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/file.h>
#include <sys/namei.h>
#include <sys/sysctl.h>
#include <sys/shm.h>
#include <sys/shm_internal.h>

#include <security/mac_internal.h>


static struct label *
mac_sysv_shm_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL)
		return (NULL);
	MAC_PERFORM(sysvshm_label_init, label);
	return (label);
}

void
mac_sysvshm_label_init(struct shmid_kernel *shmsegptr)
{

	shmsegptr->label = mac_sysv_shm_label_alloc();
}

static void
mac_sysv_shm_label_free(struct label *label)
{

	MAC_PERFORM(sysvshm_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_sysvshm_label_destroy(struct shmid_kernel *shmsegptr)
{

	mac_sysv_shm_label_free(shmsegptr->label);
	shmsegptr->label = NULL;
}

void
mac_sysvshm_label_associate(struct ucred *cred, struct shmid_kernel *shmsegptr)
{

	MAC_PERFORM(sysvshm_label_associate, cred, shmsegptr, shmsegptr->label);
}

void
mac_sysvshm_label_recycle(struct shmid_kernel *shmsegptr)
{

	MAC_PERFORM(sysvshm_label_recycle, shmsegptr->label);
}

int
mac_sysvshm_check_shmat(struct ucred *cred, struct shmid_kernel *shmsegptr,
    int shmflg)
{
	int error;

	if (!mac_sysvshm_enforce)
		return 0;

	MAC_CHECK(sysvshm_check_shmat, cred, shmsegptr, shmsegptr->label,
	    shmflg);

	return(error);
}

int
mac_sysvshm_check_shmctl(struct ucred *cred, struct shmid_kernel *shmsegptr,
    int cmd)
{
	int error;

	if (!mac_sysvshm_enforce)
		return 0;

	MAC_CHECK(sysvshm_check_shmctl, cred, shmsegptr, shmsegptr->label,
	    cmd);

	return(error);
}

int
mac_sysvshm_check_shmdt(struct ucred *cred, struct shmid_kernel *shmsegptr)
{
	int error;

	if (!mac_sysvshm_enforce)
		return 0;

	MAC_CHECK(sysvshm_check_shmdt, cred, shmsegptr, shmsegptr->label);

	return(error);
}

int
mac_sysvshm_check_shmget(struct ucred *cred, struct shmid_kernel *shmsegptr,
    int shmflg)
{
	int error;

	if (!mac_sysvshm_enforce)
		return 0;

	MAC_CHECK(sysvshm_check_shmget, cred, shmsegptr, shmsegptr->label,
	    shmflg);

	return(error);
}
