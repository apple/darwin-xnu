/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <sys/ucred.h>


/*
 * Check for ipc permission
 *
 * XXX: Should pass proc argument so that we can pass 
 * XXX: proc->p_acflag to suser()
 */

int
ipcperm(cred, perm, mode)
	struct ucred *cred;
	struct ipc_perm *perm;
	int mode;
{

	if (!suser(cred, (u_short *)NULL))
		return (0);

	/* Check for user match. */
	if (cred->cr_uid != perm->cuid && cred->cr_uid != perm->uid) {
		if (mode & IPC_M)
			return (EPERM);
		/* Check for group match. */
		mode >>= 3;
		if (!groupmember(perm->gid, cred) &&
		    !groupmember(perm->cgid, cred))
			/* Check for `other' match. */
			mode >>= 3;
	}

	if (mode & IPC_M)
		return (0);
	return ((mode & perm->mode) == mode ? 0 : EACCES);
}



/*
 * SYSVMSG stubs
 */

int
msgsys(p, uap)
	struct proc *p;
	/* XXX actually varargs. */
#if 0
	struct msgsys_args *uap;
#else
	void *uap;
#endif
{
	return(EOPNOTSUPP);
};

int
msgctl(p, uap)
	struct proc *p;
#if 0
	register struct msgctl_args *uap;
#else
	void *uap;
#endif
{
	return(EOPNOTSUPP);
};

int
msgget(p, uap)
	struct proc *p;
#if 0
	register struct msgget_args *uap;
#else
	void *uap;
#endif
{
	return(EOPNOTSUPP);
};

int
msgsnd(p, uap)
	struct proc *p;
#if 0
	register struct msgsnd_args *uap;
#else
	void *uap;
#endif
{
	return(EOPNOTSUPP);
};

int
msgrcv(p, uap)
	struct proc *p;
#if 0
	register struct msgrcv_args *uap;
#else
	void *uap;
#endif
{
	return(EOPNOTSUPP);
};
