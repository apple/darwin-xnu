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
/*
 * Copyright (c) 1997 by Apple Computer, Inc., all rights reserved
 * Copyright (c) 1993 NeXT Computer, Inc.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/kauth.h>
#include <sys/ucred.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <kern/task.h>
#include <kern/thread.h>
#include <vm/vm_map.h>
#include <machine/machine_routines.h>

/* XXX should be elsewhere (cpeak) */
extern struct proc *i386_current_proc(void);
extern void	*get_bsduthreadarg(thread_t);
extern int	*get_bsduthreadrval(thread_t);
extern void	*find_user_regs(thread_t);

/* 
 * copy a null terminated string from the kernel address space into
 * the user address space.
 *   - if the user is denied write access, return EFAULT.
 *   - if the end of string isn't found before
 *     maxlen bytes are copied,  return ENAMETOOLONG,
 *     indicating an incomplete copy.
 *   - otherwise, return 0, indicating success.
 * the number of bytes copied is always returned in lencopied.
 */
int
copyoutstr(const void *from, user_addr_t to, size_t maxlen, size_t *lencopied)
{
	size_t	slen;
	size_t	len;
	int	error = 0;

	slen = strlen(from) + 1;
	if (slen > maxlen)
		error = ENAMETOOLONG;

	len = min(maxlen,slen);
	if (copyout(from, to, len))
		error = EFAULT;
	*lencopied = len;

	return error;
}


/* 
 * copy a null terminated string from one point to another in 
 * the kernel address space.
 *   - no access checks are performed.
 *   - if the end of string isn't found before
 *     maxlen bytes are copied,  return ENAMETOOLONG,
 *     indicating an incomplete copy.
 *   - otherwise, return 0, indicating success.
 * the number of bytes copied is always returned in lencopied.
 */
/* from ppc/fault_copy.c -Titan1T4 VERSION  */
int
copystr(const void *vfrom, void *vto, size_t maxlen, size_t *lencopied)
{
	size_t		l;
	char const	*from = (char const *) vfrom;
	char		*to = (char *) vto;

	for (l = 0; l < maxlen; l++) {
		if ((*to++ = *from++) == '\0') {
			if (lencopied)
				*lencopied = l + 1;
			return 0;
		}
	}
	if (lencopied)
		*lencopied = maxlen;
	return ENAMETOOLONG;
}

int
copywithin(void *src, void *dst, size_t count)
{
	bcopy(src,dst,count);
	return 0;
}

/*
 * This is just current_proc() from bsd/kern/bsd_stubs.c, but instead of
 * returning kernproc in the non-vfork() case, it can return NULL.  This is
 * needed because the system call entry point is in osfmk/i386/bsd_i386.c
 * instead of bsd/dev/i386, and therefore cannot see some BSD thread
 * internals.  We need to distinguish kernproc defaulting in the vfork and
 * non-vfork cases vs. actually being the real process context.
 */     
struct proc *
i386_current_proc(void)
{       
	struct uthread * ut;
	struct proc *p; 
	thread_t thr_act = current_thread();

	ut = (struct uthread *)get_bsdthread_info(thr_act);
	if (ut &&  (ut->uu_flag & UT_VFORK)) { 
		if (ut->uu_proc) {
			p = ut->uu_proc; 
			if ((p->p_flag & P_INVFORK) == 0)
				panic("returning child proc not under vfork");
			if (p->p_vforkact != (void *)thr_act)
				panic("returning child proc which is not cur_act");
			return(p);
		} else {
			return (kernproc);
		}
	}

	/* Not in vfork - may return NULL */
	p = (struct proc *)get_bsdtask_info(current_task());

	return (p);
}

void *
get_bsduthreadarg(thread_t th)
{
        void	*arg_ptr;
	struct uthread *ut;
  
	ut = get_bsdthread_info(th);

	if (ml_thread_is64bit(th) == TRUE)
	        arg_ptr = (void *)saved_state64(find_user_regs(th));
	else
		arg_ptr = (void *)(ut->uu_arg);

	return(arg_ptr);
}

int *
get_bsduthreadrval(thread_t th)
{
        struct uthread *ut;

	ut = get_bsdthread_info(th);
	return(&ut->uu_rval[0]);
}
