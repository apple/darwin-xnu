/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1990, 1993, 1995
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
 *	@(#)fifo_vnops.c	8.4 (Berkeley) 8/10/94
 */

#include <sys/param.h>
#include <sys/proc.h>
#include <sys/time.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/stat.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/file_internal.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <miscfs/fifofs/fifo.h>
#include <vfs/vfs_support.h>

#define VOPFUNC int (*)(void *)

extern int	soo_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, struct proc *p);
extern int	soo_select(struct fileproc *fp, int which, void * wql, struct proc *p);

int (**fifo_vnodeop_p)(void *);
struct vnodeopv_entry_desc fifo_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)fifo_lookup },		/* lookup */
	{ &vnop_create_desc, (VOPFUNC)err_create },		/* create */
	{ &vnop_mknod_desc, (VOPFUNC)err_mknod },		/* mknod */
	{ &vnop_open_desc, (VOPFUNC)fifo_open },			/* open */
	{ &vnop_close_desc, (VOPFUNC)fifo_close },		/* close */
	{ &vnop_access_desc, (VOPFUNC)fifo_access },		/* access */
	{ &vnop_getattr_desc, (VOPFUNC)fifo_getattr },		/* getattr */
	{ &vnop_setattr_desc, (VOPFUNC)fifo_setattr },		/* setattr */
	{ &vnop_read_desc, (VOPFUNC)fifo_read },			/* read */
	{ &vnop_write_desc, (VOPFUNC)fifo_write },		/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)fifo_ioctl },		/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)fifo_select },		/* select */
	{ &vnop_revoke_desc, (VOPFUNC)fifo_revoke },		/* revoke */
	{ &vnop_mmap_desc, (VOPFUNC)err_mmap },			/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)fifo_fsync },		/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)err_remove },		/* remove */
	{ &vnop_link_desc, (VOPFUNC)err_link },			/* link */
	{ &vnop_rename_desc, (VOPFUNC)err_rename },		/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)err_mkdir },		/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)err_rmdir },		/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)err_symlink },		/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)err_readdir },		/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)err_readlink },		/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)fifo_inactive },		/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)fifo_reclaim },		/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)err_strategy },		/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)fifo_pathconf },		/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)fifo_advlock },		/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)fifo_bwrite },		/* bwrite */
	{ &vnop_pagein_desc, (VOPFUNC)err_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)err_pageout },		/* Pageout */
        { &vnop_copyfile_desc, (VOPFUNC)err_copyfile },		/* Copyfile */
	{ &vnop_blktooff_desc, (VOPFUNC)err_blktooff },		/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)err_offtoblk },		/* offtoblk */
	{ &vnop_blockmap_desc, (VOPFUNC)err_blockmap },			/* blockmap */
	{ (struct vnodeop_desc*)NULL, (int(*)())NULL }
};
struct vnodeopv_desc fifo_vnodeop_opv_desc =
	{ &fifo_vnodeop_p, fifo_vnodeop_entries };

/*
 * Trivial lookup routine that always fails.
 */
/* ARGSUSED */
int
fifo_lookup(ap)
	struct vnop_lookup_args /* {
		struct vnode * a_dvp;
		struct vnode ** a_vpp;
		struct componentname * a_cnp;
		vfs_context_t a_context;
	} */ *ap;
{
	
	*ap->a_vpp = NULL;
	return (ENOTDIR);
}

/*
 * Open called to set up a new instance of a fifo or
 * to find an active instance of a fifo.
 */
/* ARGSUSED */
int
fifo_open(ap)
	struct vnop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		vfs_context_t a_context;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct fifoinfo *fip;
	struct socket *rso, *wso;
	int error;

	vnode_lock(vp);

retry:

	fip = vp->v_fifoinfo;

	if (fip == (struct fifoinfo *)0)
		panic("fifo_open with no fifoinfo");

	if ((fip->fi_flags & FIFO_CREATED) == 0) {
		if (fip->fi_flags & FIFO_INCREATE) {
			fip->fi_flags |= FIFO_CREATEWAIT;	
			error = msleep(&fip->fi_flags, &vp->v_lock, PRIBIO | PCATCH, "fifocreatewait", 0);
			if (error) {
				vnode_unlock(vp);
				return(error);
			}
			goto retry;
		} else {
			fip->fi_flags |= FIFO_INCREATE;	
			vnode_unlock(vp);
			if ( (error = socreate(AF_LOCAL, &rso, SOCK_STREAM, 0)) ) {
			        goto bad1;
			}
			fip->fi_readsock = rso;

			if ( (error = socreate(AF_LOCAL, &wso, SOCK_STREAM, 0)) ) {
				(void)soclose(rso);
			        goto bad1;
			}
			fip->fi_writesock = wso;

			if ( (error = soconnect2(wso, rso)) ) {
				(void)soclose(wso);
				(void)soclose(rso);
			        goto bad1;
			}
			fip->fi_readers = fip->fi_writers = 0;

	        socket_lock(wso, 1);
			wso->so_state |= SS_CANTRCVMORE;
			wso->so_snd.sb_lowat = PIPE_BUF;
#if 0
			/* Because all the unp is protected by single mutex 
			 * doing it in two step may actually cause problems
			 * as it opens up window between the drop and acquire
			 */
	        socket_unlock(wso, 1);

	        socket_lock(rso, 1);
#endif
			rso->so_state |= SS_CANTSENDMORE;
	        socket_unlock(wso, 1);

			vnode_lock(vp);
			fip->fi_flags |= FIFO_CREATED;
			fip->fi_flags &= ~FIFO_INCREATE;
			
			if ((fip->fi_flags & FIFO_CREATEWAIT)) {
				fip->fi_flags &= ~FIFO_CREATEWAIT;
				wakeup(&fip->fi_flags);
			}
			/* vnode lock is held  to process further */
		}
	}

	/* vnode is locked at this point */
	/* fifo in created already */
	if (ap->a_mode & FREAD) {
		fip->fi_readers++;
		if (fip->fi_readers == 1) {
			socket_lock(fip->fi_writesock, 1);
			fip->fi_writesock->so_state &= ~SS_CANTSENDMORE;
			socket_unlock(fip->fi_writesock, 1);

			if (fip->fi_writers > 0)
				wakeup((caddr_t)&fip->fi_writers);
		}
	}
	if (ap->a_mode & FWRITE) {
		fip->fi_writers++;
		if (fip->fi_writers == 1) {
			socket_lock(fip->fi_readsock, 1);
			fip->fi_readsock->so_state &= ~SS_CANTRCVMORE;
			socket_unlock(fip->fi_readsock, 1);
	
			if (fip->fi_readers > 0)
				wakeup((caddr_t)&fip->fi_readers);
		}
	}
	if ((ap->a_mode & FREAD) && (ap->a_mode & O_NONBLOCK) == 0) {
		if (fip->fi_writers == 0) {
			error = msleep((caddr_t)&fip->fi_readers, &vp->v_lock,
					PCATCH | PSOCK, "fifoor", 0);
			if (error)
				goto bad;
			if (fip->fi_readers == 1) {
				if (fip->fi_writers > 0)
					wakeup((caddr_t)&fip->fi_writers);
			}
		}
	}
	if (ap->a_mode & FWRITE) {
		if (ap->a_mode & O_NONBLOCK) {
			if (fip->fi_readers == 0) {
					error = ENXIO;
					goto bad;
			}
		} else {
			if (fip->fi_readers == 0) {
				error = msleep((caddr_t)&fip->fi_writers,&vp->v_lock,
						PCATCH | PSOCK, "fifoow", 0);
				if (error)
					goto bad;
				if (fip->fi_writers == 1) {
					if (fip->fi_readers > 0)
						wakeup((caddr_t)&fip->fi_readers);
				}
			}
		}
	}

	vnode_unlock(vp);
	return (0);
bad:
	fifo_close_internal(vp, ap->a_mode, ap->a_context, 1);

	vnode_unlock(vp);
	return (error);
bad1:
	vnode_lock(vp);

	fip->fi_flags &= ~FIFO_INCREATE;
			
	if ((fip->fi_flags & FIFO_CREATEWAIT)) {
		fip->fi_flags &= ~FIFO_CREATEWAIT;
		wakeup(&fip->fi_flags);
	}
	vnode_unlock(vp);

	return (error);
}

/*
 * Vnode op for read
 */
int
fifo_read(ap)
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	struct uio *uio = ap->a_uio;
	struct socket *rso = ap->a_vp->v_fifoinfo->fi_readsock;
	int error, startresid;
	int rflags;

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ)
		panic("fifo_read mode");
#endif
	if (uio_resid(uio) == 0)
		return (0);

	rflags = (ap->a_ioflag & IO_NDELAY) ? MSG_NBIO : 0;

	// LP64todo - fix this!
	startresid = uio_resid(uio);

	/* fifo conformance - if we have a reader open on the fifo but no 
	 * writers then we need to make sure we do not block.  We do that by 
	 * checking the receive buffer and if empty set error to EWOULDBLOCK.
	 * If error is set to EWOULDBLOCK we skip the call into soreceive
	 */
	error = 0;
	if (ap->a_vp->v_fifoinfo->fi_writers < 1) {
		socket_lock(rso, 1);
		error = (rso->so_rcv.sb_cc == 0) ? EWOULDBLOCK : 0;
		socket_unlock(rso, 1);
	}

	/* skip soreceive to avoid blocking when we have no writers */
	if (error != EWOULDBLOCK) {
		error = soreceive(rso, (struct sockaddr **)0, uio, (struct mbuf **)0,
	    					(struct mbuf **)0, &rflags);
	}
	else {
		/* clear EWOULDBLOCK and return EOF (zero) */
		error = 0;
	}
	/*
	 * Clear EOF indication after first such return.
	 */
	if (uio_resid(uio) == startresid) {
		socket_lock(rso, 1);
		rso->so_state &= ~SS_CANTRCVMORE;
		socket_unlock(rso, 1);
	}
	return (error);
}

/*
 * Vnode op for write
 */
int
fifo_write(ap)
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int  a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
	struct socket *wso = ap->a_vp->v_fifoinfo->fi_writesock;
	int error;

#if DIAGNOSTIC
	if (ap->a_uio->uio_rw != UIO_WRITE)
		panic("fifo_write mode");
#endif
	error = sosend(wso, (struct sockaddr *)0, ap->a_uio, 0,
		       (struct mbuf *)0, (ap->a_ioflag & IO_NDELAY) ? MSG_NBIO : 0);

	return (error);
}

/*
 * Device ioctl operation.
 */
int
fifo_ioctl(ap)
	struct vnop_ioctl_args /* {
		struct vnode *a_vp;
		int  a_command;
		caddr_t  a_data;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	struct proc *p = vfs_context_proc(ap->a_context);
	struct fileproc filetmp;
	struct fileglob filefg;
	int error;

	if (ap->a_command == FIONBIO)
		return (0);
	bzero(&filetmp, sizeof(struct fileproc));
	filetmp.f_fglob = &filefg;
	if (ap->a_fflag & FREAD) {
		filetmp.f_fglob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_readsock;
		error = soo_ioctl(&filetmp, ap->a_command, ap->a_data, p);
		if (error)
			return (error);
	}
	if (ap->a_fflag & FWRITE) {
		filetmp.f_fglob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_writesock;
		error = soo_ioctl(&filetmp, ap->a_command, ap->a_data, p);
		if (error)
			return (error);
	}
	return (0);
}

int
fifo_select(ap)
	struct vnop_select_args /* {
		struct vnode *a_vp;
		int  a_which;
		int  a_fflags;
		void * a_wql;
		vfs_context_t a_context;
	} */ *ap;
{
	struct proc *p = vfs_context_proc(ap->a_context);
	struct fileproc filetmp;
	struct fileglob filefg;
	int ready;

	bzero(&filetmp, sizeof(struct fileproc));
	filetmp.f_fglob = &filefg;
	if (ap->a_which & FREAD) {
		filetmp.f_fglob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_readsock;
		ready = soo_select(&filetmp, ap->a_which, ap->a_wql, p);
		if (ready)
			return (ready);
	}
	if (ap->a_which & FWRITE) {
		filetmp.f_fglob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_writesock;
		ready = soo_select(&filetmp, ap->a_which, ap->a_wql, p);
		if (ready)
			return (ready);
	}
	return (0);
}

int
fifo_inactive(__unused struct vnop_inactive_args *ap)
{
	return (0);
}


/*
 * Device close routine
 */
int
fifo_close(ap)
	struct vnop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		vfs_context_t a_context;
	} */ *ap;
{
	return fifo_close_internal(ap->a_vp, ap->a_fflag, ap->a_context, 0);
}

int
fifo_close_internal(vnode_t vp, int fflag, __unused vfs_context_t context, int locked)
{
	register struct fifoinfo *fip = vp->v_fifoinfo;
	int error1, error2;
	struct socket *rso;
	struct socket *wso;

	if (!locked)
		vnode_lock(vp);

	if ((fip->fi_flags & FIFO_CREATED) == 0) {
		if (!locked)
			vnode_unlock(vp);
		return(0);

	}
		
	if (fflag & FREAD) {
		fip->fi_readers--;
		if (fip->fi_readers == 0){
			socket_lock(fip->fi_writesock, 1);
			socantsendmore(fip->fi_writesock);
			socket_unlock(fip->fi_writesock, 1);
		}
	}

	if (fflag & FWRITE) {
		fip->fi_writers--;
		if (fip->fi_writers == 0) {
			socket_lock(fip->fi_readsock, 1);
			socantrcvmore(fip->fi_readsock);
			socket_unlock(fip->fi_readsock, 1);
		}
	}
#if 0
	if (vnode_isinuse_locked(vp, 0, 1)) {
		if (!locked)
			vnode_unlock(vp);
		return (0);
	}
#endif

	if (fip->fi_writers || fip->fi_readers) {
		if (!locked)
			vnode_unlock(vp);
		return (0);
	}

	wso = fip->fi_writesock;
	rso = fip->fi_readsock;
	fip->fi_readsock = 0;
	fip->fi_writesock = 0;
	fip->fi_flags &= ~FIFO_CREATED;
	if (!locked)
		vnode_unlock(vp);
	error1 = soclose(rso);
	error2 = soclose(wso);

	if (error1)
		return (error1);
	return (error2);
}


/*
 * Print out internal contents of a fifo vnode.
 */
void
fifo_printinfo(vp)
	struct vnode *vp;
{
	register struct fifoinfo *fip = vp->v_fifoinfo;

	printf(", fifo with %d readers and %d writers",
		fip->fi_readers, fip->fi_writers);
}

/*
 * Return POSIX pathconf information applicable to fifo's.
 */
int
fifo_pathconf(ap)
	struct vnop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		int *a_retval;
		vfs_context_t a_context;
	} */ *ap;
{

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = LINK_MAX;
		return (0);
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	default:
		return (EINVAL);
	}
	/* NOTREACHED */
}

/*
 * Fifo failed operation
 */
int
fifo_ebadf(__unused void *dummy)
{

	return (EBADF);
}

/*
 * Fifo advisory byte-level locks.
 */
int
fifo_advlock(__unused struct vnop_advlock_args *ap)
{

	return (ENOTSUP);
}

