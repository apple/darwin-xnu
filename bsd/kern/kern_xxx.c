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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)kern_xxx.c	8.2 (Berkeley) 11/14/93
 */

#include <cputypes.h> 

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/reboot.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/buf.h>

#include <sys/mount.h>

#if COMPAT_43
/* ARGSUSED */
int
ogethostid(p, uap, retval)
struct proc *p;
void *uap;
register_t *retval;
{

	*retval = hostid;
	return 0;
}

struct osethostid_args {
	long hostid;
};
/* ARGSUSED */
int
osethostid(p, uap, retval)
struct proc *p;
register struct osethostid_args *uap;
register_t *retval;
{
	int error;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	hostid = uap->hostid;
	return (0);

}

struct ogethostname_args {
		char	*hostname;
		u_int	len;
};
/* ARGSUSED */
int
ogethostname(p, uap, retval)
struct proc *p;
register struct ogethostname_args *uap;
register_t *retval;
{
	int name;

	name = KERN_HOSTNAME;

	return (kern_sysctl(&name, 1, uap->hostname, &uap->len),
	    0, 0);
}

struct osethostname_args {
		char	*hostname;
		u_int	len;
};
/* ARGSUSED */
int
osethostname(p, uap, retval)
struct proc *p;
register struct osethostname_args *uap;
register_t *retval;
{
	int name;
	int error;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
		
	name = KERN_HOSTNAME;
	return (kern_sysctl(&name, 1, 0, 0, uap->hostname,
	    uap->len));
}

struct ogetdomainname_args {
		char	*domainname;
		int	len;
};
/* ARGSUSED */
int
ogetdomainname(p, uap, retval)
struct proc *p;
register struct ogetdomainname_args *uap;
register_t *retval;
{
	int name;
	
	name = KERN_DOMAINNAME;
	return (kern_sysctl(&name, 1, uap->domainname,
	    &uap->len, 0, 0));
}

struct osetdomainname_args {
		char	*domainname;
		u_int	len;
};
/* ARGSUSED */
int
osetdomainname(p, uap, retval)
struct proc *p;
register struct osetdomainname_args *uap;
register_t *retval;
{
	int name;
	int error;

	if (error = suser(p->p_ucred, &p->p_acflag))
		return (error);
	name = KERN_DOMAINNAME;
	return (kern_sysctl(&name, 1, 0, 0, uap->domainname,
	    uap->len));
}
#endif /* COMPAT_43 */

struct reboot_args {
		int	opt;
		char	*command;
};

reboot(p, uap, retval)
struct proc *p;
register struct reboot_args *uap;
register_t *retval;
{
	char command[64];
	int error;
	int dummy=0;

	command[0] = '\0';

	if (error = suser(p->p_cred->pc_ucred, &p->p_acflag))
		return(error);	
	
	if (uap->opt & RB_COMMAND)
		error = copyinstr(uap->command,
					command, sizeof(command), &dummy);
	if (!error) {
		SET(p->p_flag, P_REBOOT);	/* No more signals for this proc */
		boot(RB_BOOT, uap->opt, command);
	}
	return(error);
}

