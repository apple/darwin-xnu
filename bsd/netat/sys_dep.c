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
 *	Copyright (c) 1995-1998 Apple Computer, Inc. 
 *
 *  Change Log:
 *    Created February 20, 1995 by Tuyen Nguyen
 *    Modified for MP, 1996 by Tuyen Nguyen
 *    Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 */
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>	/* for p_fd in fdflags */
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/file_internal.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sysproto.h>
#include <sys/kdebug.h>
#include <net/if_var.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>

int (*sys_ATsocket)() = 0;
int (*sys_ATgetmsg)() = 0;
int (*sys_ATputmsg)() = 0;
int (*sys_ATPsndreq)() = 0;
int (*sys_ATPsndrsp)() = 0;
int (*sys_ATPgetreq)() = 0;
int (*sys_ATPgetrsp)() = 0;

extern at_state_t at_state;	/* global state of AT network */
extern at_ifaddr_t *ifID_home;	/* default interface */
extern lck_mtx_t * atalk_mutex;

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data

int ATsocket(proc, uap, retval)
	struct proc *proc;
	struct ATsocket_args *uap;
	int *retval;
{
	int err;
	atalk_lock();
	if (sys_ATsocket) {
		/* required check for all AppleTalk system calls */
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
			*retval = -1;
			err = ENOTREADY;
		} else {
			*retval = (*sys_ATsocket)(uap->proto, &err, proc);
		}
	} else {
		*retval = -1;
		err = ENXIO;
	}
	atalk_unlock();
	return err;
}

int ATgetmsg(proc, uap, retval)
	struct proc *proc;
	struct ATgetmsg_args *uap;
	int *retval;
{
	int err;

	atalk_lock();
	if (sys_ATgetmsg) {
		/* required check for all AppleTalk system calls */
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
			*retval = -1;
			err = ENOTREADY;
		} else {
			*retval = 
			  (*sys_ATgetmsg)(uap->fd, uap->ctlptr, uap->datptr, 
					  uap->flags, &err, proc);
		}
	} else {
		*retval = -1;
		err = ENXIO;
	}
	atalk_unlock();
	return err;
}

int ATputmsg(proc, uap, retval)
	struct proc *proc;
	struct ATputmsg_args *uap;
	int *retval;
{
	int err;

	atalk_lock();
	if (sys_ATputmsg) {
		/* required check for all AppleTalk system calls */
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
			*retval = -1;
			err = ENOTREADY;
		} else {
			*retval = 
			  (*sys_ATputmsg)(uap->fd, uap->ctlptr, uap->datptr, 
					  uap->flags, &err, proc);
		}
	} else {
		*retval = -1;
		err = ENXIO;
	}
	atalk_unlock();
	return err;
}

int ATPsndreq(proc, uap, retval)
	struct proc *proc;
	struct ATPsndreq_args *uap;
	int *retval;
{
	int err;

	atalk_lock();
	if (sys_ATPsndreq) {
		/* required check for all AppleTalk system calls */
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
			*retval = -1;
			err = ENOTREADY;
		} else {
			*retval = 
			  (*sys_ATPsndreq)(uap->fd, uap->buf, uap->len, 
					   uap->nowait, &err, proc);
		}
	} else {
		*retval = -1;
		err= ENXIO;
	}
	atalk_unlock();
	return err;
}

int ATPsndrsp(proc, uap, retval)
	struct proc *proc;
	struct ATPsndrsp_args *uap;
	int *retval;
{
	int err;

	atalk_lock();
	if (sys_ATPsndrsp) {
		/* required check for all AppleTalk system calls */
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
			*retval = -1;
			err = ENOTREADY;
		} else { 
			*retval = 
			  (*sys_ATPsndrsp)(uap->fd, uap->respbuff, 
					   uap->resplen, uap->datalen, &err, proc);
		}
	} else {
		*retval = -1;
		err = ENXIO;
	}
	atalk_unlock();
	return err;
}

int ATPgetreq(proc, uap, retval)
	struct proc *proc;
	struct ATPgetreq_args *uap;
	int *retval;
{
	int err;

	atalk_lock();
	if (sys_ATPgetreq) {
		/* required check for all AppleTalk system calls */
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
			*retval = -1;
			err = ENOTREADY;
		} else {
			*retval = 
			  (*sys_ATPgetreq)(uap->fd, uap->buf, uap->buflen, 
					   &err, proc);
		}
	} else {
		*retval = -1;
		err = ENXIO;
	}
	atalk_unlock();
	return err;
}

int ATPgetrsp(proc, uap, retval)
	struct proc *proc;
	struct ATPgetrsp_args *uap;
	int *retval;
{
	int err = 0;

	atalk_lock();
	if (sys_ATPgetrsp) {
		/* required check for all AppleTalk system calls */
		if (!(at_state.flags & AT_ST_STARTED) || !ifID_home) {
			*retval = -1;
			err = ENOTREADY;
		} else {
			*retval = 
			  (*sys_ATPgetrsp)(uap->fd, uap->bdsp, &err, proc);
		}
	} else {
		*retval = -1;
		err = ENXIO;
	}
	atalk_unlock();
	return err;
}

int atalk_closeref(fg, grefp)
	struct fileglob *fg;
	gref_t **grefp;
{
	if ((*grefp = (gref_t *)fg->fg_data)) {
		fg->fg_data = 0;
		return(0);
	}
	return(EBADF);
}

int atalk_openref(gref, retfd, proc)
	gref_t *gref;
	int *retfd;
	struct proc *proc;
{
	extern int _ATread(), _ATwrite(),_ATioctl(), _ATselect(), _ATclose(), _ATkqfilter();
	static struct fileops fileops = 
		{_ATread, _ATwrite, _ATioctl, _ATselect, _ATclose, _ATkqfilter, 0};
	int err, fd;
	struct fileproc *fp;
	
	lck_mtx_assert(atalk_mutex, LCK_MTX_ASSERT_OWNED);
	
	proc_fdlock(proc);
	if ((err = falloc_locked(proc, &fp, &fd, 1)) != 0) {
		proc_fdunlock(proc);
		return err;
	}

	fp->f_flag = FREAD|FWRITE;
	/*##### LD 5/7/96 Warning: we don't have a "DTYPE_OTHER" for
	 * MacOSX, so defines DTYPE_ATALK as DTYPE_SOCKET...
	 */
	fp->f_type = DTYPE_ATALK+1;
	fp->f_ops = &fileops;
	fp->f_data = (void *)gref;

	*fdflags(proc, fd) &= ~UF_RESERVED;
	*retfd = fd;
	fp_drop(proc, fd, fp, 1);
	proc_fdunlock(proc);
/*
	kprintf("atalk_openref: fp = 0x%x, gref = 0x%x\n", (u_int)fp, (u_int)gref);
*/
	return 0;
}

/* 
 * go from file descriptor to gref, which has been saved in fp->f_data 
 *
 * This routine returns with an iocount on the fileproc when the fp is null
 * as it converts fd to fileproc. Callers of this api who pass fp as null
 * need to drop the iocount when they are done with the fp
 */
int atalk_getref(fp, fd, grefp, proc, droponerr)
struct fileproc *fp;
int fd;
gref_t **grefp;
struct proc *proc;
int droponerr;
{
	int error;

	proc_fdlock(proc);
	error = atalk_getref_locked(fp, fd, grefp, proc, droponerr);
	proc_fdunlock(proc);
	return error;
}

int atalk_getref_locked(fp, fd, grefp, proc, droponerr)
struct fileproc *fp;
int fd;
gref_t **grefp;
struct proc *proc;
int droponerr;
{
	lck_mtx_assert(atalk_mutex, LCK_MTX_ASSERT_OWNED);
	if (fp == 0) {
		int error = fp_lookup(proc, fd, &fp, 1);
	
		if (error) {
		   
			*grefp = (gref_t *) 0;
		   return EBADF;
		}
	}
	*grefp = (gref_t *)fp->f_data;
	if (*grefp == 0 || *grefp == (gref_t *)(-1)) {
		if (droponerr)
			fp_drop(proc, fd, fp, 1);
		printf("atalk_getref_locked EBADF f_data: %x\n", fp->f_data);
		return EBADF;
	}
	
	if ((*grefp)->errno) {
		if (droponerr)
			fp_drop(proc, fd, fp, 1);
		return (int)(*grefp)->errno;
	}
	return 0;
}
