/*
 * Copyright (c) 2000-2019 Apple Inc. All rights reserved.
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

int(**fifo_vnodeop_p)(void *);
const struct vnodeopv_entry_desc fifo_vnodeop_entries[] = {
	{ .opve_op = &vnop_default_desc, .opve_impl = (VOPFUNC)vn_default_error },
	{ .opve_op = &vnop_lookup_desc, .opve_impl = (VOPFUNC)fifo_lookup },            /* lookup */
	{ .opve_op = &vnop_create_desc, .opve_impl = (VOPFUNC)err_create },             /* create */
	{ .opve_op = &vnop_mknod_desc, .opve_impl = (VOPFUNC)err_mknod },               /* mknod */
	{ .opve_op = &vnop_open_desc, .opve_impl = (VOPFUNC)fifo_open },                        /* open */
	{ .opve_op = &vnop_close_desc, .opve_impl = (VOPFUNC)fifo_close },              /* close */
	{ .opve_op = &vnop_access_desc, .opve_impl = (VOPFUNC)fifo_access },            /* access */
	{ .opve_op = &vnop_getattr_desc, .opve_impl = (VOPFUNC)fifo_getattr },          /* getattr */
	{ .opve_op = &vnop_setattr_desc, .opve_impl = (VOPFUNC)fifo_setattr },          /* setattr */
	{ .opve_op = &vnop_read_desc, .opve_impl = (VOPFUNC)fifo_read },                        /* read */
	{ .opve_op = &vnop_write_desc, .opve_impl = (VOPFUNC)fifo_write },              /* write */
	{ .opve_op = &vnop_ioctl_desc, .opve_impl = (VOPFUNC)fifo_ioctl },              /* ioctl */
	{ .opve_op = &vnop_select_desc, .opve_impl = (VOPFUNC)fifo_select },            /* select */
	{ .opve_op = &vnop_revoke_desc, .opve_impl = (VOPFUNC)fifo_revoke },            /* revoke */
	{ .opve_op = &vnop_mmap_desc, .opve_impl = (VOPFUNC)err_mmap },                 /* mmap */
	{ .opve_op = &vnop_fsync_desc, .opve_impl = (VOPFUNC)fifo_fsync },              /* fsync */
	{ .opve_op = &vnop_remove_desc, .opve_impl = (VOPFUNC)err_remove },             /* remove */
	{ .opve_op = &vnop_link_desc, .opve_impl = (VOPFUNC)err_link },                 /* link */
	{ .opve_op = &vnop_rename_desc, .opve_impl = (VOPFUNC)err_rename },             /* rename */
	{ .opve_op = &vnop_mkdir_desc, .opve_impl = (VOPFUNC)err_mkdir },               /* mkdir */
	{ .opve_op = &vnop_rmdir_desc, .opve_impl = (VOPFUNC)err_rmdir },               /* rmdir */
	{ .opve_op = &vnop_symlink_desc, .opve_impl = (VOPFUNC)err_symlink },           /* symlink */
	{ .opve_op = &vnop_readdir_desc, .opve_impl = (VOPFUNC)err_readdir },           /* readdir */
	{ .opve_op = &vnop_readlink_desc, .opve_impl = (VOPFUNC)err_readlink },         /* readlink */
	{ .opve_op = &vnop_inactive_desc, .opve_impl = (VOPFUNC)fifo_inactive },                /* inactive */
	{ .opve_op = &vnop_reclaim_desc, .opve_impl = (VOPFUNC)fifo_reclaim },          /* reclaim */
	{ .opve_op = &vnop_strategy_desc, .opve_impl = (VOPFUNC)err_strategy },         /* strategy */
	{ .opve_op = &vnop_pathconf_desc, .opve_impl = (VOPFUNC)fifo_pathconf },                /* pathconf */
	{ .opve_op = &vnop_advlock_desc, .opve_impl = (VOPFUNC)fifo_advlock },          /* advlock */
	{ .opve_op = &vnop_bwrite_desc, .opve_impl = (VOPFUNC)fifo_bwrite },            /* bwrite */
	{ .opve_op = &vnop_pagein_desc, .opve_impl = (VOPFUNC)err_pagein },             /* Pagein */
	{ .opve_op = &vnop_pageout_desc, .opve_impl = (VOPFUNC)err_pageout },           /* Pageout */
	{ .opve_op = &vnop_copyfile_desc, .opve_impl = (VOPFUNC)err_copyfile },         /* Copyfile */
	{ .opve_op = &vnop_blktooff_desc, .opve_impl = (VOPFUNC)err_blktooff },         /* blktooff */
	{ .opve_op = &vnop_offtoblk_desc, .opve_impl = (VOPFUNC)err_offtoblk },         /* offtoblk */
	{ .opve_op = &vnop_blockmap_desc, .opve_impl = (VOPFUNC)err_blockmap },                 /* blockmap */
	{ .opve_op = (struct vnodeop_desc*)NULL, .opve_impl = (int (*)(void *))NULL }
};
const struct vnodeopv_desc fifo_vnodeop_opv_desc =
{ .opv_desc_vector_p = &fifo_vnodeop_p, .opv_desc_ops = fifo_vnodeop_entries };

/*
 * Trivial lookup routine that always fails.
 */
/* ARGSUSED */
int
fifo_lookup(struct vnop_lookup_args *ap)
{
	*ap->a_vpp = NULL;
	return ENOTDIR;
}

/*
 * Open called to set up a new instance of a fifo or
 * to find an active instance of a fifo.
 */
/* ARGSUSED */
int
fifo_open(struct vnop_open_args *ap)
{
	struct vnode *vp = ap->a_vp;
	struct fifoinfo *fip;
	struct socket *rso, *wso;
	int error;

	vnode_lock(vp);

retry:

	fip = vp->v_fifoinfo;

	if (fip == (struct fifoinfo *)0) {
		panic("fifo_open with no fifoinfo");
	}

	if ((fip->fi_flags & FIFO_CREATED) == 0) {
		if (fip->fi_flags & FIFO_INCREATE) {
			fip->fi_flags |= FIFO_CREATEWAIT;
			error = msleep(&fip->fi_flags, &vp->v_lock, PRIBIO | PCATCH, "fifocreatewait", NULL);
			if (error) {
				vnode_unlock(vp);
				return error;
			}
			goto retry;
		} else {
			fip->fi_flags |= FIFO_INCREATE;
			vnode_unlock(vp);
			if ((error = socreate(AF_LOCAL, &rso, SOCK_STREAM, 0))) {
				goto bad1;
			}

			if ((error = socreate(AF_LOCAL, &wso, SOCK_STREAM, 0))) {
				(void)soclose(rso);
				goto bad1;
			}

			if ((error = soconnect2(wso, rso))) {
				(void)soclose(wso);
				(void)soclose(rso);
				goto bad1;
			}
			fip->fi_readers = fip->fi_writers = 0;

			/* Lock ordering between wso and rso does not matter here
			 * because they are just created and no one has a reference to them
			 */
			socket_lock(wso, 1);
			wso->so_state |= SS_CANTRCVMORE;
			wso->so_snd.sb_lowat = PIPE_BUF;
			socket_unlock(wso, 1);

			socket_lock(rso, 1);
			rso->so_state |= SS_CANTSENDMORE;
			socket_unlock(rso, 1);

			vnode_lock(vp);
			fip->fi_readsock = rso;
			fip->fi_writesock = wso;

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

			if (fip->fi_writers > 0) {
				wakeup((caddr_t)&fip->fi_writers);
			}
		}
	}
	if (ap->a_mode & FWRITE) {
		fip->fi_writers++;
		if (fip->fi_writers == 1) {
			socket_lock(fip->fi_readsock, 1);
			fip->fi_readsock->so_state &= ~SS_CANTRCVMORE;
			socket_unlock(fip->fi_readsock, 1);

			if (fip->fi_readers > 0) {
				wakeup((caddr_t)&fip->fi_readers);
			}
		}
	}
	if ((ap->a_mode & FREAD) && (ap->a_mode & O_NONBLOCK) == 0) {
		if (fip->fi_writers == 0) {
			error = msleep((caddr_t)&fip->fi_readers, &vp->v_lock,
			    PCATCH | PSOCK, "fifoor", NULL);
			if (error) {
				goto bad;
			}
			if (fip->fi_readers == 1) {
				if (fip->fi_writers > 0) {
					wakeup((caddr_t)&fip->fi_writers);
				}
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
				error = msleep((caddr_t)&fip->fi_writers, &vp->v_lock,
				    PCATCH | PSOCK, "fifoow", NULL);
				if (error) {
					goto bad;
				}
				if (fip->fi_writers == 1) {
					if (fip->fi_readers > 0) {
						wakeup((caddr_t)&fip->fi_readers);
					}
				}
			}
		}
	}

	vnode_unlock(vp);
	return 0;
bad:
	fifo_close_internal(vp, ap->a_mode, ap->a_context, 1);

	vnode_unlock(vp);
	return error;
bad1:
	vnode_lock(vp);

	fip->fi_flags &= ~FIFO_INCREATE;

	if ((fip->fi_flags & FIFO_CREATEWAIT)) {
		fip->fi_flags &= ~FIFO_CREATEWAIT;
		wakeup(&fip->fi_flags);
	}
	vnode_unlock(vp);

	return error;
}

/*
 * Vnode op for read
 */
int
fifo_read(struct vnop_read_args *ap)
{
	struct uio *uio = ap->a_uio;
	struct socket *rso = ap->a_vp->v_fifoinfo->fi_readsock;
	user_ssize_t startresid;
	int error;
	int rflags;

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ) {
		panic("fifo_read mode");
	}
#endif
	if (uio_resid(uio) == 0) {
		return 0;
	}

	rflags = (ap->a_ioflag & IO_NDELAY) ? MSG_NBIO : 0;

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
		if (error == 0) {
			lock_vnode_and_post(ap->a_vp, 0);
		}
	} else {
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
	return error;
}

/*
 * Vnode op for write
 */
int
fifo_write(struct vnop_write_args *ap)
{
	struct socket *wso = ap->a_vp->v_fifoinfo->fi_writesock;
	int error;

#if DIAGNOSTIC
	if (ap->a_uio->uio_rw != UIO_WRITE) {
		panic("fifo_write mode");
	}
#endif
	error = sosend(wso, (struct sockaddr *)0, ap->a_uio, NULL,
	    (struct mbuf *)0, (ap->a_ioflag & IO_NDELAY) ? MSG_NBIO : 0);
	if (error == 0) {
		lock_vnode_and_post(ap->a_vp, 0);
	}

	return error;
}

/*
 * Device ioctl operation.
 */
int
fifo_ioctl(struct vnop_ioctl_args *ap)
{
	struct fileproc filetmp;
	struct fileglob filefg;
	int error;

	if (ap->a_command == FIONBIO) {
		return 0;
	}
	bzero(&filetmp, sizeof(struct fileproc));
	filetmp.fp_glob = &filefg;
	if (ap->a_fflag & FREAD) {
		filetmp.fp_glob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_readsock;
		error = soo_ioctl(&filetmp, ap->a_command, ap->a_data, ap->a_context);
		if (error) {
			return error;
		}
	}
	if (ap->a_fflag & FWRITE) {
		filetmp.fp_glob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_writesock;
		error = soo_ioctl(&filetmp, ap->a_command, ap->a_data, ap->a_context);
		if (error) {
			return error;
		}
	}
	return 0;
}

int
fifo_select(struct vnop_select_args *ap)
{
	struct fileproc filetmp;
	struct fileglob filefg;
	int ready;

	bzero(&filetmp, sizeof(struct fileproc));
	filetmp.fp_glob = &filefg;
	if (ap->a_which & FREAD) {
		filetmp.fp_glob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_readsock;
		ready = soo_select(&filetmp, ap->a_which, ap->a_wql, ap->a_context);
		if (ready) {
			return ready;
		}
	}
	if (ap->a_which & FWRITE) {
		filetmp.fp_glob->fg_data = (caddr_t)ap->a_vp->v_fifoinfo->fi_writesock;
		ready = soo_select(&filetmp, ap->a_which, ap->a_wql, ap->a_context);
		if (ready) {
			return ready;
		}
	}
	return 0;
}

int
fifo_inactive(__unused struct vnop_inactive_args *ap)
{
	return 0;
}


/*
 * Device close routine
 */
int
fifo_close(struct vnop_close_args *ap)
{
	return fifo_close_internal(ap->a_vp, ap->a_fflag, ap->a_context, 0);
}

int
fifo_close_internal(vnode_t vp, int fflag, __unused vfs_context_t context, int locked)
{
	struct fifoinfo *fip = vp->v_fifoinfo;
	int error1, error2;
	struct socket *rso;
	struct socket *wso;

	if (!locked) {
		vnode_lock(vp);
	}

	if ((fip->fi_flags & FIFO_CREATED) == 0) {
		if (!locked) {
			vnode_unlock(vp);
		}
		return 0;
	}

	if (fflag & FREAD) {
		fip->fi_readers--;
		if (fip->fi_readers == 0) {
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
		if (!locked) {
			vnode_unlock(vp);
		}
		return 0;
	}
#endif

	if (fip->fi_writers || fip->fi_readers) {
		if (!locked) {
			vnode_unlock(vp);
		}
		return 0;
	}

	wso = fip->fi_writesock;
	rso = fip->fi_readsock;
	fip->fi_readsock = NULL;
	fip->fi_writesock = NULL;
	fip->fi_flags &= ~FIFO_CREATED;
	if (!locked) {
		vnode_unlock(vp);
	}
	error1 = soclose(rso);
	error2 = soclose(wso);

	if (error1) {
		return error1;
	}
	return error2;
}

/*
 * Print out internal contents of a fifo vnode.
 */
void
fifo_printinfo(struct vnode *vp)
{
	struct fifoinfo *fip = vp->v_fifoinfo;

	printf(", fifo with %ld readers and %ld writers",
	    fip->fi_readers, fip->fi_writers);
}

/*
 * Return POSIX pathconf information applicable to fifo's.
 */
int
fifo_pathconf(struct vnop_pathconf_args *ap)
{
	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = LINK_MAX;
		return 0;
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		return 0;
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 200112;         /* _POSIX_CHOWN_RESTRICTED */
		return 0;
	default:
		return EINVAL;
	}
	/* NOTREACHED */
}

/*
 * Fifo failed operation
 */
int
fifo_ebadf(__unused void *dummy)
{
	return EBADF;
}

/*
 * Fifo advisory byte-level locks.
 */
int
fifo_advlock(__unused struct vnop_advlock_args *ap)
{
	return ENOTSUP;
}


/* You'd certainly better have an iocount on the vnode! */
int
fifo_freespace(struct vnode *vp, long *count)
{
	struct socket *rsock;
	rsock = vp->v_fifoinfo->fi_readsock;
	socket_lock(rsock, 1);
	*count = sbspace(&rsock->so_rcv);
	socket_unlock(rsock, 1);
	return 0;
}

int
fifo_charcount(struct vnode *vp, int *count)
{
	int mcount;
	int err = sock_ioctl(vp->v_fifoinfo->fi_readsock, FIONREAD, (void*)&mcount);
	if (err == 0) {
		*count = mcount;
	}
	return err;
}
