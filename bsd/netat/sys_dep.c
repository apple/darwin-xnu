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
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
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

struct ATsocket_args {
    int proto;
};
int ATsocket(proc, uap, retval)
	void *proc;
	struct ATsocket_args *uap;
	int *retval;
{
	int err;

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
	return err;
}

struct ATgetmsg_args {
    int fd;
    void *ctlptr;
    void *datptr;
    int *flags;
};
int ATgetmsg(proc, uap, retval)
	void *proc;
	struct ATgetmsg_args *uap;
	int *retval;
{
	int err;

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
	return err;
}

struct ATputmsg_args {
	int fd;
	void *ctlptr;
	void *datptr;
	int flags;
};
int ATputmsg(proc, uap, retval)
	void *proc;
	struct ATputmsg_args *uap;
	int *retval;
{
	int err;

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
	return err;
}

struct ATPsndreq_args {
    int fd;
    unsigned char *buf;
    int len;
    int nowait;
};
int ATPsndreq(proc, uap, retval)
	void *proc;
	struct ATPsndreq_args *uap;
	int *retval;
{
	int err;

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
	return err;
}

struct ATPsndrsp_args {
	  int fd;
	  unsigned char *respbuff;
	  int resplen;
	  int datalen;
};
int ATPsndrsp(proc, uap, retval)
	void *proc;
	struct ATPsndrsp_args *uap;
	int *retval;
{
	int err;

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
	return err;
}

struct ATPgetreq_args {
	  int fd;
	  unsigned char *buf;
	  int buflen;
};
int ATPgetreq(proc, uap, retval)
	void *proc;
	struct ATPgetreq_args *uap;
	int *retval;
{
	int err;

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
	return err;
}

struct ATPgetrsp_args {
	  int fd;
	  unsigned char *bdsp;
};
int ATPgetrsp(proc, uap, retval)
	void *proc;
	struct ATPgetrsp_args *uap;
	int *retval;
{
	int err = 0;

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
	return err;
}

int atalk_closeref(fp, grefp)
	struct file *fp;
	gref_t **grefp;
{
	if ((*grefp = (gref_t *)fp->f_data)) {
		fp->f_data = 0;
/*
		kprintf("atalk_closeref: fp = 0x%x, gref = 0x%x\n", (u_int)fp, 
			(u_int)*grefp);
*/
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
		{_ATread, _ATwrite, _ATioctl, _ATselect, _ATclose, _ATkqfilter};
	int err, fd;
	struct file *fp;

	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

	if ((err = falloc(proc, &fp, &fd)) != 0) {
	     thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
		return err;
	}

	fp->f_flag = FREAD|FWRITE;
	/*##### LD 5/7/96 Warning: we don't have a "DTYPE_OTHER" for
	 * MacOSX, so defines DTYPE_ATALK as DTYPE_SOCKET...
	 */
	fp->f_type = DTYPE_ATALK+1;
	fp->f_ops = &fileops;
	*fdflags(proc, fd) &= ~UF_RESERVED;
	*retfd = fd;
	fp->f_data = (void *)gref;
/*
	kprintf("atalk_openref: fp = 0x%x, gref = 0x%x\n", (u_int)fp, (u_int)gref);
*/
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	return 0;
}

/* go from file descriptor to gref, which has been saved in fp->f_data */
int atalk_getref(fp, fd, grefp, proc)
struct file *fp;
int fd;
gref_t **grefp;
struct proc *proc;
{
     thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
     if (fp == 0) {
	  int error = fdgetf(proc, fd, &fp);

	  if (error) {
	       
	       *grefp = (gref_t *) 0;
	       thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	       return EBADF;
	  }
     }
     *grefp = (gref_t *)fp->f_data;
     if (*grefp == 0 || *grefp == (gref_t *)(-1)) {
	  thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	  return EBADF;
     }

     if ((*grefp)->errno) {
	  thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	  return (int)(*grefp)->errno;
     }

     thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
     return 0;
}
