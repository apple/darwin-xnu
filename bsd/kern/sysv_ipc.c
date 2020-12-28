/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/*	$NetBSD: sysv_ipc.c,v 1.7 1994/06/29 06:33:11 cgd Exp $	*/

/*
 * Copyright (c) 1994 Herb Peyerl <hpeyerl@novatel.ca>
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
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by Herb Peyerl.
 * 4. The name of Herb Peyerl may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/param.h>
#include <sys/ipc.h>
#include <sys/stat.h>   /* mode constants */
#include <sys/ucred.h>
#include <sys/kauth.h>


/*
 * Check for ipc permission
 */


/*
 * ipc_perm
 *
 *	perm->mode			mode of the object
 *	mode				mode bits we want to test
 *
 * Returns:	0			Success
 *		EPERM
 *		EACCES
 *
 * Notes:	The IPC_M bit is special, in that it may only be granted to
 *		root, the creating user, or the owning user.
 *
 *		This code does not use posix_cred_access() because of the
 *		need to check both creator and owner separately when we are
 *		considering a rights grant.  Because of this, we need to do
 *		two evaluations when the values are inequal, which can lead
 *		us to defeat the callout avoidance optimization.  So we do
 *		the work here, inline.  This is less than optimal for any
 *		future work involving opacity of of POSIX credentials.
 *
 *		Setting up the mode_owner / mode_group / mode_world implicitly
 *		masks the IPC_M bit off.  This is intentional.
 *
 *		See the posix_cred_access() implementation for algorithm
 *		information.
 */
int
ipcperm(kauth_cred_t cred, struct ipc_perm *perm, int mode_req)
{
	uid_t   uid = kauth_cred_getuid(cred);  /* avoid multiple calls */
	int     want_mod_controlinfo = (mode_req & IPC_M);
	int     is_member;
	mode_t  mode_owner = (perm->mode & S_IRWXU);
	mode_t  mode_group = (perm->mode & S_IRWXG) << 3;
	mode_t  mode_world = (perm->mode & S_IRWXO) << 6;

	/* Grant all rights to super user */
	if (!suser(cred, (u_short *)NULL)) {
		return 0;
	}

	/* Grant or deny rights based on ownership */
	if (uid == perm->cuid || uid == perm->uid) {
		if (want_mod_controlinfo) {
			return 0;
		}

		return (mode_req & mode_owner) == mode_req ? 0 : EACCES;
	} else {
		/* everyone else who wants to modify control info is denied */
		if (want_mod_controlinfo) {
			return EPERM;
		}
	}

	/*
	 * Combined group and world rights check, if no owner rights; positive
	 * asssertion of gid/cgid equality avoids an extra callout in the
	 * common case.
	 */
	if ((mode_req & mode_group & mode_world) == mode_req) {
		return 0;
	} else {
		if ((mode_req & mode_group) != mode_req) {
			if ((!kauth_cred_ismember_gid(cred, perm->gid, &is_member) && is_member) &&
			    ((perm->gid == perm->cgid) ||
			    (!kauth_cred_ismember_gid(cred, perm->cgid, &is_member) && is_member))) {
				return EACCES;
			} else {
				if ((mode_req & mode_world) != mode_req) {
					return EACCES;
				} else {
					return 0;
				}
			}
		} else {
			if ((!kauth_cred_ismember_gid(cred, perm->gid, &is_member) && is_member) ||
			    ((perm->gid != perm->cgid) &&
			    (!kauth_cred_ismember_gid(cred, perm->cgid, &is_member) && is_member))) {
				return 0;
			} else {
				if ((mode_req & mode_world) != mode_req) {
					return EACCES;
				} else {
					return 0;
				}
			}
		}
	}
}
