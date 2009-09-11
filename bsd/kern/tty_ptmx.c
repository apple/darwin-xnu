/*
 * Copyright (c) 1997-2006 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1982, 1986, 1989, 1993
 *      The Regents of the University of California.  All rights reserved.
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
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
 *	@(#)tty_pty.c	8.4 (Berkeley) 2/20/95
 */

/*
 * Pseudo-teletype Driver
 * (Actually two drivers, requiring two entries in 'cdevsw')
 */
#include "pty.h"		/* XXX */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/tty.h>
#include <sys/conf.h>
#include <sys/file_internal.h>
#include <sys/uio_internal.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>		/* _devfs_setattr() */
#include <sys/stat.h>			/* _devfs_setattr() */
#include <sys/user.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <miscfs/devfs/devfs.h>
#include <miscfs/devfs/devfsdefs.h>	/* DEVFS_LOCK()/DEVFS_UNLOCK() */

/* XXX belongs in devfs somewhere - LATER */
int _devfs_setattr(void *, unsigned short, uid_t, gid_t);


#define FREE_BSDSTATIC __private_extern__
#define d_devtotty_t    struct tty **

/*
 * Forward declarations
 */
int ptmx_init(int n_ptys);
static void ptsd_start(struct tty *tp);
static void ptmx_wakeup(struct tty *tp, int flag);
FREE_BSDSTATIC	d_open_t	ptsd_open;
FREE_BSDSTATIC	d_close_t	ptsd_close;
FREE_BSDSTATIC	d_read_t	ptsd_read;
FREE_BSDSTATIC	d_write_t	ptsd_write;
FREE_BSDSTATIC	d_ioctl_t	cptyioctl;	/* common ioctl */
FREE_BSDSTATIC	d_stop_t	ptsd_stop;
FREE_BSDSTATIC	d_reset_t	ptsd_reset;
FREE_BSDSTATIC	d_devtotty_t	ptydevtotty;
FREE_BSDSTATIC	d_open_t	ptmx_open;
FREE_BSDSTATIC	d_close_t	ptmx_close;
FREE_BSDSTATIC	d_read_t	ptmx_read;
FREE_BSDSTATIC	d_write_t	ptmx_write;
FREE_BSDSTATIC	d_stop_t	ptmx_stop;	/* NO-OP */
FREE_BSDSTATIC	d_reset_t	ptmx_reset;
FREE_BSDSTATIC	d_select_t	ptmx_select;
FREE_BSDSTATIC	d_select_t	ptsd_select;

static int ptmx_major;		/* dynamically assigned major number */
static struct cdevsw ptmx_cdev = {
	ptmx_open,	ptmx_close,	ptmx_read,	ptmx_write,
	cptyioctl,	ptmx_stop,	ptmx_reset,	0,
	ptmx_select,	eno_mmap,	eno_strat,	eno_getc,
	eno_putc,	D_TTY
};

static int ptsd_major;		/* dynamically assigned major number */
static struct cdevsw ptsd_cdev = {
	ptsd_open,	ptsd_close,	ptsd_read,	ptsd_write,
	cptyioctl,	ptsd_stop,	ptsd_reset,	0,
	ptsd_select,	eno_mmap,	eno_strat,	eno_getc,
	eno_putc,	D_TTY
};

/*
 * XXX Should be devfs function... and use VATTR mechanisms, per
 * XXX vnode_setattr2(); only we maybe can't really get back to the
 * XXX vnode here for cloning devices (but it works for *cloned* devices
 * XXX that are not themselves cloning).
 *
 * Returns:	0			Success
 *	namei:???
 *	vnode_setattr:???
 */
int
_devfs_setattr(void * handle, unsigned short mode, uid_t uid, gid_t gid)
{
	devdirent_t		*direntp = (devdirent_t *)handle;
	devnode_t		*devnodep;
	int			error = EACCES;
	vfs_context_t		ctx = vfs_context_current();;
	struct vnode_attr	va;

	VATTR_INIT(&va);
	VATTR_SET(&va, va_uid, uid);
	VATTR_SET(&va, va_gid, gid);
	VATTR_SET(&va, va_mode, mode & ALLPERMS);

	/*
	 * If the TIOCPTYGRANT loses the race with the clone operation because
	 * this function is not part of devfs, and therefore can't take the
	 * devfs lock to protect the direntp update, then force user space to
	 * redrive the grant request.
	 */
	if (direntp == NULL || (devnodep = direntp->de_dnp) == NULL) {
		error = ERESTART;
		goto out;
	}

	/*
	 * Only do this if we are operating on device that doesn't clone
	 * each time it's referenced.  We perform a lookup on the device
	 * to insure we get the right instance.  We can't just use the call
	 * to devfs_dntovn() to get the vp for the operation, because
	 * dn_dvm may not have been initialized.
	 */
	if (devnodep->dn_clone == NULL) {
		struct nameidata nd;
		char name[128];

		snprintf(name, sizeof(name), "/dev/%s", direntp->de_name);
		NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, CAST_USER_ADDR_T(name), ctx);
		error = namei(&nd);
		if (error)
			goto out;
		error = vnode_setattr(nd.ni_vp, &va, ctx);
		vnode_put(nd.ni_vp);
		nameidone(&nd);
		goto out;
	}

out:
	return(error);
}



#define BUFSIZ 100		/* Chunk size iomoved to/from user */

/*
 * ptmx == /dev/ptmx
 * ptsd == /dev/pts[0123456789]{3}
 */
#define	PTMX_TEMPLATE	"ptmx"
#define PTSD_TEMPLATE	"ttys%03d"

/*
 * System-wide limit on the max number of cloned ptys
 */
#define	PTMX_MAX_DEFAULT	127	/* 128 entries */
#define	PTMX_MAX_HARD		999	/* 1000 entries, due to PTSD_TEMPLATE */

static int ptmx_max = PTMX_MAX_DEFAULT;	/* default # of clones we allow */

/* Range enforcement for the sysctl */
static int
sysctl_ptmx_max(__unused struct sysctl_oid *oidp, __unused void *arg1,
		__unused int arg2, struct sysctl_req *req)
{
	int new_value, changed;
	int error = sysctl_io_number(req, ptmx_max, sizeof(int), &new_value, &changed);
	if (changed) {
		if (new_value > 0 && new_value <= PTMX_MAX_HARD)
			ptmx_max = new_value;
		else
			error = EINVAL;
	}
	return(error);
}

SYSCTL_NODE(_kern, KERN_TTY, tty, CTLFLAG_RW|CTLFLAG_LOCKED, 0, "TTY");
SYSCTL_PROC(_kern_tty, OID_AUTO, ptmx_max,
		CTLTYPE_INT | CTLFLAG_RW,
		&ptmx_max, 0, &sysctl_ptmx_max, "I", "ptmx_max");


/*
 * ptmx_ioctl is a pointer to a list of pointers to tty structures which is
 * grown, as necessary, copied, and replaced, but never shrunk.  The ioctl
 * structures themselves pointed to from this list come and go as needed.
 */
struct ptmx_ioctl {
	struct tty	*pt_tty;	/* pointer to ttymalloc()'ed data */
	int		pt_flags;
	struct selinfo	pt_selr;
	struct selinfo	pt_selw;
	u_char		pt_send;
	u_char		pt_ucntl;
	void		*pt_devhandle;	/* cloned slave device handle */
};

#define	PF_PKT		0x0008		/* packet mode */
#define	PF_STOPPED	0x0010		/* user told stopped */
#define	PF_REMOTE	0x0020		/* remote and flow controlled input */
#define	PF_NOSTOP	0x0040
#define PF_UCNTL	0x0080		/* user control mode */
#define	PF_UNLOCKED	0x0100		/* slave unlock (master open resets) */
#define	PF_OPEN_M	0x0200		/* master is open */
#define	PF_OPEN_S	0x0400		/* slave is open */

static int	ptmx_clone(dev_t dev, int minor);

int
ptmx_init( __unused int config_count)
{
	/*
	 * We start looking at slot 10, since there are inits that will
	 * stomp explicit slots (e.g. vndevice stomps 1) below that.
	 */

	/* Get a major number for /dev/ptmx */
	if((ptmx_major = cdevsw_add(-15, &ptmx_cdev)) == -1) {
		printf("ptmx_init: failed to obtain /dev/ptmx major number\n");
		return (ENOENT);
	}

	/* Get a major number for /dev/pts/nnn */
	if ((ptsd_major = cdevsw_add(-15, &ptsd_cdev)) == -1) {
		(void)cdevsw_remove(ptmx_major, &ptmx_cdev);
		printf("ptmx_init: failed to obtain /dev/ptmx major number\n");
		return (ENOENT);
	}

	/* Create the /dev/ptmx device {<major>,0} */
	(void)devfs_make_node_clone(makedev(ptmx_major, 0),
				DEVFS_CHAR, UID_ROOT, GID_TTY, 0666,
				ptmx_clone, PTMX_TEMPLATE);
    return (0);
}


static struct _ptmx_ioctl_state {
	struct ptmx_ioctl	**pis_ioctl_list;	/* pointer vector */
	int			pis_total;		/* total slots */
	int			pis_free;		/* free slots */
} _state;
#define	PTMX_GROW_VECTOR	16	/* Grow by this many slots at a time */

/*
 * Given a minor number, return the corresponding structure for that minor
 * number.  If there isn't one, and the create flag is specified, we create
 * one if possible.
 *
 * Parameters:	minor			Minor number of ptmx device
 *		open_flag		PF_OPEN_M	First open of master
 *					PF_OPEN_S	First open of slave
 *					0		Just want ioctl struct
 *
 * Returns:	NULL			Did not exist/could not create
 *		!NULL			structure corresponding minor number
 *
 * Locks:	tty_lock() on ptmx_ioctl->pt_tty NOT held on entry or exit.
 */
static struct ptmx_ioctl *
ptmx_get_ioctl(int minor, int open_flag)
{
	struct ptmx_ioctl *new_ptmx_ioctl;

	if (open_flag & PF_OPEN_M) {

		/*
		 * If we are about to allocate more memory, but we have
		 * already hit the administrative limit, then fail the
		 * operation.
		 *
		 * Note:	Subtract free from total when making this
		 *		check to allow unit increments, rather than
		 *		snapping to the nearest PTMX_GROW_VECTOR...
		 */
		if ((_state.pis_total - _state.pis_free) >= ptmx_max) {
			return (NULL);
		}

		MALLOC(new_ptmx_ioctl, struct ptmx_ioctl *, sizeof(struct ptmx_ioctl), M_TTYS, M_WAITOK|M_ZERO);
		if (new_ptmx_ioctl == NULL) {
			return (NULL);
		}

		if ((new_ptmx_ioctl->pt_tty = ttymalloc()) == NULL) {
			FREE(new_ptmx_ioctl, M_TTYS);
			return (NULL);
		}
	
		/*
		 * Hold the DEVFS_LOCK() over this whole operation; devfs
		 * itself does this over malloc/free as well, so this should
		 * be safe to do.  We hold it longer than we want to, but
		 * doing so avoids a reallocation race on the minor number.
		 */
		DEVFS_LOCK();
		/* Need to allocate a larger vector? */
		if (_state.pis_free == 0) {
			struct ptmx_ioctl **new_pis_ioctl_list;
			struct ptmx_ioctl **old_pis_ioctl_list = NULL;

			/* Yes. */
			MALLOC(new_pis_ioctl_list, struct ptmx_ioctl **, sizeof(struct ptmx_ioctl *) * (_state.pis_total + PTMX_GROW_VECTOR), M_TTYS, M_WAITOK|M_ZERO);
			if (new_pis_ioctl_list == NULL) {
				ttyfree(new_ptmx_ioctl->pt_tty);
				DEVFS_UNLOCK();
				FREE(new_ptmx_ioctl, M_TTYS);
				return (NULL);
			}

			/* If this is not the first time, copy the old over */
			bcopy(_state.pis_ioctl_list, new_pis_ioctl_list, sizeof(struct ptmx_ioctl *) * _state.pis_total);
			old_pis_ioctl_list = _state.pis_ioctl_list;
			_state.pis_ioctl_list = new_pis_ioctl_list;
			_state.pis_free += PTMX_GROW_VECTOR;
			_state.pis_total += PTMX_GROW_VECTOR;
			if (old_pis_ioctl_list)
				FREE(old_pis_ioctl_list, M_TTYS);
		} 
		
		if (_state.pis_ioctl_list[minor] != NULL) {
			ttyfree(new_ptmx_ioctl->pt_tty);
			DEVFS_UNLOCK();
			FREE(new_ptmx_ioctl, M_TTYS);

			/* Special error value so we know to redrive the open, we've been raced */
			return (struct ptmx_ioctl*)-1; 

		}

		/* Vector is large enough; grab a new ptmx_ioctl */

		/* Now grab a free slot... */
		_state.pis_ioctl_list[minor] = new_ptmx_ioctl;

		/* reduce free count */
		_state.pis_free--;

		_state.pis_ioctl_list[minor]->pt_flags |= PF_OPEN_M;
		DEVFS_UNLOCK();

		/* Create the /dev/ttysXXX device {<major>,XXX} */
		_state.pis_ioctl_list[minor]->pt_devhandle = devfs_make_node(
				makedev(ptsd_major, minor),
				DEVFS_CHAR, UID_ROOT, GID_TTY, 0620,
				PTSD_TEMPLATE, minor);
		if (_state.pis_ioctl_list[minor]->pt_devhandle == NULL) {
			printf("devfs_make_node() call failed for ptmx_get_ioctl()!!!!\n");
		}
	} else if (open_flag & PF_OPEN_S) {
		DEVFS_LOCK();
		_state.pis_ioctl_list[minor]->pt_flags |= PF_OPEN_S;
		DEVFS_UNLOCK();
	}
	return (_state.pis_ioctl_list[minor]);
}

/*
 * Locks:	tty_lock() of old_ptmx_ioctl->pt_tty NOT held for this call.
 */
static int
ptmx_free_ioctl(int minor, int open_flag)
{
	struct ptmx_ioctl *old_ptmx_ioctl = NULL;

	DEVFS_LOCK();
	_state.pis_ioctl_list[minor]->pt_flags &= ~(open_flag);

	/*
	 * Was this the last close?  We will recognize it because we only get
	 * a notification on the last close of a device, and we will have
	 * cleared both the master and the slave open bits in the flags.
	 */
	if (!(_state.pis_ioctl_list[minor]->pt_flags & (PF_OPEN_M|PF_OPEN_S))) {
		/* Mark as free so it can be reallocated later */
		old_ptmx_ioctl = _state.pis_ioctl_list[ minor];
	}
	DEVFS_UNLOCK();

	/* Free old after dropping lock */
	if (old_ptmx_ioctl != NULL) {
		/*
		 * XXX See <rdar://5348651> and <rdar://4854638>
		 *
		 * XXX Conditional to be removed when/if tty/pty reference
		 * XXX counting and mutex implemented.
		 */
		if (old_ptmx_ioctl->pt_devhandle != NULL)
			devfs_remove(old_ptmx_ioctl->pt_devhandle);
		ttyfree(old_ptmx_ioctl->pt_tty);
		FREE(old_ptmx_ioctl, M_TTYS);

		/* Don't remove the entry until the devfs slot is free */
		DEVFS_LOCK();
		_state.pis_ioctl_list[ minor] = NULL;
		_state.pis_free++;
		DEVFS_UNLOCK();
	}

	return (0);	/* Success */
}




/*
 * Given the dev entry that's being opened, we clone the device.  This driver
 * doesn't actually use the dev entry, since we alreaqdy know who we are by
 * being called from this code.  This routine is a callback registered from
 * devfs_make_node_clone() in ptmx_init(); it's purpose is to provide a new
 * minor number, or to return -1, if one can't be provided.
 *
 * Parameters:	dev			The device we are cloning from
 *
 * Returns:	>= 0			A new minor device number
 *		-1			Error: ENOMEM ("Can't alloc device")
 *
 * NOTE:	Called with DEVFS_LOCK() held
 */
static int
ptmx_clone(__unused dev_t dev, int action)
{
	int i;

	if (action == DEVFS_CLONE_ALLOC) {
		/* First one */
		if (_state.pis_total == 0)
			return (0);

		/*
		 * Note: We can add hinting on free slots, if this linear search
		 * ends up being a performance bottleneck...
		 */
		for(i = 0; i < _state.pis_total; i++) {
			if (_state.pis_ioctl_list[ i] == NULL)
				break;
		}

		/*
		 * XXX We fall off the end here; if we did this twice at the
		 * XXX same time, we could return the same minor to two
		 * XXX callers; we should probably exand the pointer vector
		 * XXX here, but I need more information on the MALLOC/FREE
		 * XXX locking to ensure against a deadlock.  Maybe we can
		 * XXX just high watermark it at 1/2 of PTMX_GROW_VECTOR?
		 * XXX That would require returning &minor as implict return
		 * XXX and an error code ("EAGAIN/ERESTART") or 0 as our
		 * XXX explicit return.
		 */

		return (i);	/* empty slot or next slot */
	}
	return(-1);
}

FREE_BSDSTATIC int
ptsd_open(dev_t dev, int flag, __unused int devtype, __unused proc_t p)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	int error;

	if ((pti = ptmx_get_ioctl(minor(dev), 0)) == NULL) {
	        return (ENXIO);
	}

	if (!(pti->pt_flags & PF_UNLOCKED)) {
		return (EAGAIN);
	}

	tp = pti->pt_tty;
	tty_lock(tp);

	if ((tp->t_state & TS_ISOPEN) == 0) {
		termioschars(&tp->t_termios);	/* Set up default chars */
		tp->t_iflag = TTYDEF_IFLAG;
		tp->t_oflag = TTYDEF_OFLAG;
		tp->t_lflag = TTYDEF_LFLAG;
		tp->t_cflag = TTYDEF_CFLAG;
		tp->t_ispeed = tp->t_ospeed = TTYDEF_SPEED;
		ttsetwater(tp);		/* would be done in xxparam() */
	} else if (tp->t_state&TS_XCLUDE && suser(kauth_cred_get(), NULL)) {
	        error = EBUSY;
		goto out;
	}
	if (tp->t_oproc)			/* Ctrlr still around. */
		(void)(*linesw[tp->t_line].l_modem)(tp, 1);
	while ((tp->t_state & TS_CARR_ON) == 0) {
		if (flag&FNONBLOCK)
			break;
		error = ttysleep(tp, TSA_CARR_ON(tp), TTIPRI | PCATCH,
				 "ptsd_opn", 0);
		if (error)
			goto out;
	}
	error = (*linesw[tp->t_line].l_open)(dev, tp);
	/* Successful open; mark as open by the slave */
	pti->pt_flags |= PF_OPEN_S;
	if (error == 0)
		ptmx_wakeup(tp, FREAD|FWRITE);
out:
	tty_unlock(tp);
	return (error);
}

FREE_BSDSTATIC int
ptsd_close(dev_t dev, int flag, __unused int mode, __unused proc_t p)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	int err;

	/*
	 * This is temporary until the VSX conformance tests
	 * are fixed.  They are hanging with a deadlock
	 * where close(ptsd) will not complete without t_timeout set
	 */
#define	FIX_VSX_HANG	1
#ifdef	FIX_VSX_HANG
	int save_timeout;
#endif
	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

#ifdef	FIX_VSX_HANG
	save_timeout = tp->t_timeout;
	tp->t_timeout = 60;
#endif
	err = (*linesw[tp->t_line].l_close)(tp, flag);
	ptsd_stop(tp, FREAD|FWRITE);
	(void) ttyclose(tp);
#ifdef	FIX_VSX_HANG
	tp->t_timeout = save_timeout;
#endif

	tty_unlock(tp);

	/* unconditional, just like ttyclose() */
	ptmx_free_ioctl(minor(dev), PF_OPEN_S);

	return (err);
}

FREE_BSDSTATIC int
ptsd_read(dev_t dev, struct uio *uio, int flag)
{
	proc_t p = current_proc();

	struct tty *tp;
	struct ptmx_ioctl *pti;
	int error = 0;
	struct uthread *ut;
	struct pgrp * pg;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

	ut = (struct uthread *)get_bsdthread_info(current_thread());
again:
	if (pti->pt_flags & PF_REMOTE) {
		while (isbackground(p, tp)) {
			if ((p->p_sigignore & sigmask(SIGTTIN)) ||
			    (ut->uu_sigmask & sigmask(SIGTTIN)) ||
			    p->p_lflag & P_LPPWAIT) {
				error = EIO;
				goto out;
			}
			pg = proc_pgrp(p);
			if (pg == PGRP_NULL) {
				error = EIO;
				goto out;
			}
			/*
			 * SAFE: We about to drop the lock ourselves by
			 * SAFE: erroring out or sleeping anyway.
			 */
			tty_unlock(tp);
			if (pg->pg_jobc == 0) {
				pg_rele(pg);
				tty_lock(tp);
				error = EIO;
				goto out;
			}
			pgsignal(pg, SIGTTIN, 1);
			pg_rele(pg);
			tty_lock(tp);

			error = ttysleep(tp, &lbolt, TTIPRI | PCATCH | PTTYBLOCK, "ptsd_bg",
					 0);
			if (error)
			        goto out;
		}
		if (tp->t_canq.c_cc == 0) {
			if (flag & IO_NDELAY) {
				error = EWOULDBLOCK;
				goto out;
			}
			error = ttysleep(tp, TSA_PTS_READ(tp), TTIPRI | PCATCH,
					 "ptsd_in", 0);
			if (error)
			        goto out;
			goto again;
		}
		while (tp->t_canq.c_cc > 1 && uio_resid(uio) > 0) {
			int cc;
			char buf[BUFSIZ];

			cc = min(uio_resid(uio), BUFSIZ);
			// Don't copy the very last byte
			cc = min(cc, tp->t_canq.c_cc - 1);
			cc = q_to_b(&tp->t_canq, (u_char *)buf, cc);
			error = uiomove(buf, cc, uio);
			if (error)
				break;
		}
		if (tp->t_canq.c_cc == 1)
			(void) getc(&tp->t_canq);
		if (tp->t_canq.c_cc)
		        goto out;
	} else
		if (tp->t_oproc)
			error = (*linesw[tp->t_line].l_read)(tp, uio, flag);
	ptmx_wakeup(tp, FWRITE);
out:
	tty_unlock(tp);
	return (error);
}

/*
 * Write to pseudo-tty.
 * Wakeups of controlling tty will happen
 * indirectly, when tty driver calls ptsd_start.
 */
FREE_BSDSTATIC int
ptsd_write(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	int error;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

	if (tp->t_oproc == 0)
		error = EIO;
	else
	        error = (*linesw[tp->t_line].l_write)(tp, uio, flag);

	tty_unlock(tp);
	return (error);
}

/*
 * Start output on pseudo-tty.
 * Wake up process selecting or sleeping for input from controlling tty.
 *
 * t_oproc for this driver; called from within the line discipline
 *
 * Locks:	Assumes tp is locked on entry, remains locked on exit
 */
static void
ptsd_start(struct tty *tp)
{
	struct ptmx_ioctl *pti;

	pti = ptmx_get_ioctl(minor(tp->t_dev), 0);

	if (tp->t_state & TS_TTSTOP)
	        goto out;
	if (pti->pt_flags & PF_STOPPED) {
		pti->pt_flags &= ~PF_STOPPED;
		pti->pt_send = TIOCPKT_START;
	}
	ptmx_wakeup(tp, FREAD);
out:
	return;
}

/*
 * Locks:	Assumes tty_lock() is held over this call.
 */
static void
ptmx_wakeup(struct tty *tp, int flag)
{
	struct ptmx_ioctl *pti;

	pti = ptmx_get_ioctl(minor(tp->t_dev), 0);

	if (flag & FREAD) {
		selwakeup(&pti->pt_selr);
		wakeup(TSA_PTC_READ(tp));
	}
	if (flag & FWRITE) {
		selwakeup(&pti->pt_selw);
		wakeup(TSA_PTC_WRITE(tp));
	}
}

FREE_BSDSTATIC int
ptmx_open(dev_t dev, __unused int flag, __unused int devtype, __unused proc_t p)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	int error = 0;

	pti = ptmx_get_ioctl(minor(dev), PF_OPEN_M);
	if (pti == NULL) {
	        return (ENXIO);
	} else if (pti == (struct ptmx_ioctl*)-1) {
		return (EREDRIVEOPEN);
	}

	tp = pti->pt_tty;
	tty_lock(tp);

	/* If master is open OR slave is still draining, pty is still busy */
	if (tp->t_oproc || (tp->t_state & TS_ISOPEN)) {
		tty_unlock(tp);
		/*
		 * If master is closed, we are the only reference, so we
		 * need to clear the master open bit
		 */
		if (!tp->t_oproc)
			ptmx_free_ioctl(minor(dev), PF_OPEN_M);
		error = EBUSY;
		goto err;
	}
	tp->t_oproc = ptsd_start;
	CLR(tp->t_state, TS_ZOMBIE);
#ifdef sun4c
	tp->t_stop = ptsd_stop;
#endif
	(void)(*linesw[tp->t_line].l_modem)(tp, 1);
	tp->t_lflag &= ~EXTPROC;

	tty_unlock(tp);
err:
	return (error);
}

FREE_BSDSTATIC int
ptmx_close(dev_t dev, __unused int flags, __unused int fmt, __unused proc_t p)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

	(void)(*linesw[tp->t_line].l_modem)(tp, 0);

	/*
	 * XXX MDMBUF makes no sense for ptys but would inhibit the above
	 * l_modem().  CLOCAL makes sense but isn't supported.   Special
	 * l_modem()s that ignore carrier drop make no sense for ptys but
	 * may be in use because other parts of the line discipline make
	 * sense for ptys.  Recover by doing everything that a normal
	 * ttymodem() would have done except for sending a SIGHUP.
	 */
	if (tp->t_state & TS_ISOPEN) {
		tp->t_state &= ~(TS_CARR_ON | TS_CONNECTED);
		tp->t_state |= TS_ZOMBIE;
		ttyflush(tp, FREAD | FWRITE);
	}

	tp->t_oproc = 0;		/* mark closed */

	tty_unlock(tp);

	ptmx_free_ioctl(minor(dev), PF_OPEN_M);

	return (0);
}

FREE_BSDSTATIC int
ptmx_read(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	char buf[BUFSIZ];
	int error = 0, cc;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

	/*
	 * We want to block until the slave
	 * is open, and there's something to read;
	 * but if we lost the slave or we're NBIO,
	 * then return the appropriate error instead.
	 */
	for (;;) {
		if (tp->t_state&TS_ISOPEN) {
			if (pti->pt_flags & PF_PKT && pti->pt_send) {
				error = ureadc((int)pti->pt_send, uio);
				if (error)
					goto out;
				if (pti->pt_send & TIOCPKT_IOCTL) {
					cc = min(uio_resid(uio),
						sizeof(tp->t_termios));
					uiomove((caddr_t)&tp->t_termios, cc,
						uio);
				}
				pti->pt_send = 0;
				goto out;
			}
			if (pti->pt_flags & PF_UCNTL && pti->pt_ucntl) {
				error = ureadc((int)pti->pt_ucntl, uio);
				if (error)
					goto out;
				pti->pt_ucntl = 0;
				goto out;
			}
			if (tp->t_outq.c_cc && (tp->t_state&TS_TTSTOP) == 0)
				break;
		}
		if ((tp->t_state & TS_CONNECTED) == 0)
			goto out;	/* EOF */
		if (flag & IO_NDELAY) {
			error = EWOULDBLOCK;
			goto out;
		}
		error = ttysleep(tp, TSA_PTC_READ(tp), TTIPRI | PCATCH, "ptmx_in", 0);
		if (error)
		        goto out;
	}
	if (pti->pt_flags & (PF_PKT|PF_UCNTL))
		error = ureadc(0, uio);
	while (uio_resid(uio) > 0 && error == 0) {
		cc = q_to_b(&tp->t_outq, (u_char *)buf, min(uio_resid(uio), BUFSIZ));
		if (cc <= 0)
			break;
		error = uiomove(buf, cc, uio);
	}
	(*linesw[tp->t_line].l_start)(tp);

out:
	tty_unlock(tp);
	return (error);
}

/*
 * Line discipline callback
 *
 * Locks:	tty_lock() is assumed held on entry and exit.
 */
FREE_BSDSTATIC int
ptsd_stop(struct tty *tp, int flush)
{
	struct ptmx_ioctl *pti;
	int flag;

	pti = ptmx_get_ioctl(minor(tp->t_dev), 0);

	/* note: FLUSHREAD and FLUSHWRITE already ok */
	if (flush == 0) {
		flush = TIOCPKT_STOP;
		pti->pt_flags |= PF_STOPPED;
	} else
		pti->pt_flags &= ~PF_STOPPED;
	pti->pt_send |= flush;
	/* change of perspective */
	flag = 0;
	if (flush & FREAD)
		flag |= FWRITE;
	if (flush & FWRITE)
		flag |= FREAD;
	ptmx_wakeup(tp, flag);

	return (0);
}

FREE_BSDSTATIC int
ptsd_reset(__unused int uban)
{
	return (0);
}

/*
 * Reinput pending characters after state switch
 * call at spltty().
 *
 * XXX Code duplication: static function, should be inlined
 */
static void
ttypend(struct tty *tp)
{
	struct clist tq;
	int c;

	CLR(tp->t_lflag, PENDIN);
	SET(tp->t_state, TS_TYPEN);
	tq = tp->t_rawq;
	tp->t_rawq.c_cc = 0;
	tp->t_rawq.c_cf = tp->t_rawq.c_cl = 0;
	while ((c = getc(&tq)) >= 0)
		ttyinput(c, tp);
	CLR(tp->t_state, TS_TYPEN);
}

/*
 * Must be called at spltty().
 *
 * XXX Code duplication: static function, should be inlined
 */
static int
ttnread(struct tty *tp)
{
	int nread;

	if (ISSET(tp->t_lflag, PENDIN))
		ttypend(tp);
	nread = tp->t_canq.c_cc;
	if (!ISSET(tp->t_lflag, ICANON)) {
		nread += tp->t_rawq.c_cc;
		if (nread < tp->t_cc[VMIN] && tp->t_cc[VTIME] == 0)
			nread = 0;
	}
	return (nread);
}

int
ptsd_select(dev_t dev, int rw, void *wql, proc_t p)
{
	struct ptmx_ioctl *pti;
	struct tty *tp;
	int retval = 0;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;

	if (tp == NULL)
		return (ENXIO);

	tty_lock(tp);

	switch (rw) {
	case FREAD:
		if (ttnread(tp) > 0 || ISSET(tp->t_state, TS_ZOMBIE)) {
			retval = 1;
			break;
		}
		selrecord(p, &tp->t_rsel, wql);
		break;
	case FWRITE:
		if ((tp->t_outq.c_cc <= tp->t_lowat &&
		     ISSET(tp->t_state, TS_CONNECTED))
		    || ISSET(tp->t_state, TS_ZOMBIE)) {
			retval = 1;
			break;
		}
		selrecord(p, &tp->t_wsel, wql);
		break;
	}

	tty_unlock(tp);
	return (retval);
}

FREE_BSDSTATIC int
ptmx_select(dev_t dev, int rw, void *wql, proc_t p)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	int retval = 0;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

	if ((tp->t_state & TS_CONNECTED) == 0) {
		retval = 1;
		goto out;
	}
	switch (rw) {
	case FREAD:
		/*
		 * Need to block timeouts (ttrstart).
		 */
		if ((tp->t_state&TS_ISOPEN) &&
		     tp->t_outq.c_cc && (tp->t_state&TS_TTSTOP) == 0) {
			retval = 1;
			break;
		}
		/* FALLTHROUGH */

	case 0:					/* exceptional */
		if ((tp->t_state&TS_ISOPEN) &&
		    ((pti->pt_flags & PF_PKT && pti->pt_send) ||
		     (pti->pt_flags & PF_UCNTL && pti->pt_ucntl))) {
			retval = 1;
			break;
		}
		selrecord(p, &pti->pt_selr, wql);
		break;

	case FWRITE:
		if (tp->t_state&TS_ISOPEN) {
			if (pti->pt_flags & PF_REMOTE) {
			    if (tp->t_canq.c_cc == 0) {
				retval = 1;
				break;
			    }
			} else {
			    if (tp->t_rawq.c_cc + tp->t_canq.c_cc < TTYHOG-2) {
				    retval = 1;
				    break;
			    }
			    if (tp->t_canq.c_cc == 0 && (tp->t_lflag&ICANON)) {
				    retval = 1;
				    break;
			    }
			}
		}
		selrecord(p, &pti->pt_selw, wql);
		break;

	}
out:
	tty_unlock(tp);
	return (retval);
}

FREE_BSDSTATIC int
ptmx_stop(__unused struct tty *tp, __unused int flush)
{
	return (0);
}

FREE_BSDSTATIC int
ptmx_reset(__unused int uban)
{
	return (0);
}

FREE_BSDSTATIC int
ptmx_write(dev_t dev, struct uio *uio, int flag)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	u_char *cp = NULL;
	int cc = 0;
	u_char locbuf[BUFSIZ];
	int wcnt = 0;
	int error = 0;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

again:
	if ((tp->t_state&TS_ISOPEN) == 0)
		goto block;
	if (pti->pt_flags & PF_REMOTE) {
		if (tp->t_canq.c_cc)
			goto block;
		while ((uio_resid(uio) > 0 || cc > 0) &&
		       tp->t_canq.c_cc < TTYHOG - 1) {
			if (cc == 0) {
				cc = min(uio_resid(uio), BUFSIZ);
				cc = min(cc, TTYHOG - 1 - tp->t_canq.c_cc);
				cp = locbuf;
				error = uiomove((caddr_t)cp, cc, uio);
				if (error)
					goto out;
				/* check again for safety */
				if ((tp->t_state & TS_ISOPEN) == 0) {
					/* adjust as usual */
					uio_setresid(uio, (uio_resid(uio) + cc));
					error = EIO;
					goto out;
				}
			}
			if (cc > 0) {
				cc = b_to_q((u_char *)cp, cc, &tp->t_canq);
				/*
				 * XXX we don't guarantee that the canq size
				 * is >= TTYHOG, so the above b_to_q() may
				 * leave some bytes uncopied.  However, space
				 * is guaranteed for the null terminator if
				 * we don't fail here since (TTYHOG - 1) is
				 * not a multiple of CBSIZE.
				 */
				if (cc > 0)
					break;
			}
		}
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		(void) putc(0, &tp->t_canq);
		ttwakeup(tp);
		wakeup(TSA_PTS_READ(tp));
		goto out;
	}
	while (uio_resid(uio) > 0 || cc > 0) {
		if (cc == 0) {
			cc = min(uio_resid(uio), BUFSIZ);
			cp = locbuf;
			error = uiomove((caddr_t)cp, cc, uio);
			if (error)
				goto out;
			/* check again for safety */
			if ((tp->t_state & TS_ISOPEN) == 0) {
				/* adjust for data copied in but not written */
				uio_setresid(uio, (uio_resid(uio) + cc));
				error = EIO;
				goto out;
			}
		}
		while (cc > 0) {
			if ((tp->t_rawq.c_cc + tp->t_canq.c_cc) >= TTYHOG - 2 &&
			   (tp->t_canq.c_cc > 0 || !(tp->t_lflag&ICANON))) {
				wakeup(TSA_HUP_OR_INPUT(tp));
				goto block;
			}
			(*linesw[tp->t_line].l_rint)(*cp++, tp);
			wcnt++;
			cc--;
		}
		cc = 0;
	}

out:
	tty_unlock(tp);
	return (error);

block:
	/*
	 * Come here to wait for slave to open, for space
	 * in outq, or space in rawq, or an empty canq.
	 */
	if ((tp->t_state & TS_CONNECTED) == 0) {
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		error = EIO;
		goto out;
	}
	if (flag & IO_NDELAY) {
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		if (wcnt == 0)
			error = EWOULDBLOCK;
		goto out;
	}
	error = ttysleep(tp, TSA_PTC_WRITE(tp), TTOPRI | PCATCH, "ptmx_out", 0);
	if (error) {
		/* adjust for data copied in but not written */
		uio_setresid(uio, (uio_resid(uio) + cc));
		goto out;
	}
	goto again;
}


FREE_BSDSTATIC int
cptyioctl(dev_t dev, u_long cmd, caddr_t data, int flag, proc_t p)
{
	struct tty *tp;
	struct ptmx_ioctl *pti;
	u_char *cc;
	int stop, error = 0;

	pti = ptmx_get_ioctl(minor(dev), 0);

	tp = pti->pt_tty;
	tty_lock(tp);

	cc = tp->t_cc;

	/*
	 * IF CONTROLLER STTY THEN MUST FLUSH TO PREVENT A HANG.
	 * ttywflush(tp) will hang if there are characters in the outq.
	 */
	if (cmd == TIOCEXT) {
		/*
		 * When the EXTPROC bit is being toggled, we need
		 * to send an TIOCPKT_IOCTL if the packet driver
		 * is turned on.
		 */
		if (*(int *)data) {
			if (pti->pt_flags & PF_PKT) {
				pti->pt_send |= TIOCPKT_IOCTL;
				ptmx_wakeup(tp, FREAD);
			}
			tp->t_lflag |= EXTPROC;
		} else {
			if ((tp->t_lflag & EXTPROC) &&
			    (pti->pt_flags & PF_PKT)) {
				pti->pt_send |= TIOCPKT_IOCTL;
				ptmx_wakeup(tp, FREAD);
			}
			tp->t_lflag &= ~EXTPROC;
		}
		goto out;
	} else
	if (cdevsw[major(dev)].d_open == ptmx_open)
		switch (cmd) {

		case TIOCGPGRP:
			/*
			 * We aviod calling ttioctl on the controller since,
			 * in that case, tp must be the controlling terminal.
			 */
			*(int *)data = tp->t_pgrp ? tp->t_pgrp->pg_id : 0;
			goto out;

		case TIOCPKT:
			if (*(int *)data) {
			        if (pti->pt_flags & PF_UCNTL) {
					error = EINVAL;
					goto out;
				}
				pti->pt_flags |= PF_PKT;
			} else
				pti->pt_flags &= ~PF_PKT;
			goto out;

		case TIOCUCNTL:
			if (*(int *)data) {
			        if (pti->pt_flags & PF_PKT) {
					error = EINVAL;
					goto out;
				}
				pti->pt_flags |= PF_UCNTL;
			} else
				pti->pt_flags &= ~PF_UCNTL;
			goto out;

		case TIOCREMOTE:
			if (*(int *)data)
				pti->pt_flags |= PF_REMOTE;
			else
				pti->pt_flags &= ~PF_REMOTE;
			ttyflush(tp, FREAD|FWRITE);
			goto out;

		case TIOCSETP:
		case TIOCSETN:
		case TIOCSETD:
		case TIOCSETA_32:
		case TIOCSETAW_32:
		case TIOCSETAF_32:
		case TIOCSETA_64:
		case TIOCSETAW_64:
		case TIOCSETAF_64:
			ndflush(&tp->t_outq, tp->t_outq.c_cc);
			break;

		case TIOCSIG:
			if (*(unsigned int *)data >= NSIG ||
			    *(unsigned int *)data == 0) {
				error = EINVAL;
				goto out;
			}
			if ((tp->t_lflag&NOFLSH) == 0)
				ttyflush(tp, FREAD|FWRITE);
			if ((*(unsigned int *)data == SIGINFO) &&
			    ((tp->t_lflag&NOKERNINFO) == 0))
				ttyinfo_locked(tp);
			/*
			 * SAFE: All callers drop the lock on return and
			 * SAFE: the linesw[] will short circut this call
			 * SAFE: if the ioctl() is eaten before the lower
			 * SAFE: level code gets to see it.
			 */
			tty_unlock(tp);
			tty_pgsignal(tp, *(unsigned int *)data, 1);
			tty_lock(tp);
			goto out;

		case TIOCPTYGRANT:	/* grantpt(3) */
			/*
			 * Change the uid of the slave to that of the calling
			 * thread, change the gid of the slave to GID_TTY,
			 * change the mode to 0620 (rw--w----).
			 */
			{
				error = _devfs_setattr(pti->pt_devhandle, 0620, kauth_getuid(), GID_TTY);
				goto out;
			}

		case TIOCPTYGNAME:	/* ptsname(3) */
			/*
			 * Report the name of the slave device in *data
			 * (128 bytes max.).  Use the same template string
			 * used for calling devfs_make_node() to create it.
			 */
			snprintf(data, 128, "/dev/" PTSD_TEMPLATE, minor(dev));
			error = 0;
			goto out;
		
		case TIOCPTYUNLK:	/* unlockpt(3) */
			/*
			 * Unlock the slave device so that it can be opened.
			 */
			pti->pt_flags |= PF_UNLOCKED;
			error = 0;
			goto out;
		}
	error = (*linesw[tp->t_line].l_ioctl)(tp, cmd, data, flag, p);
	if (error == ENOTTY) {
		error = ttioctl_locked(tp, cmd, data, flag, p);
		if (error == ENOTTY) {
			if (pti->pt_flags & PF_UCNTL && (cmd & ~0xff) == UIOCCMD(0)) {
				/* Process the UIOCMD ioctl group */
				if (cmd & 0xff) {
					pti->pt_ucntl = (u_char)cmd;
					ptmx_wakeup(tp, FREAD);
				}
				error = 0;
				goto out;
			} else if (cmd == TIOCSBRK || cmd == TIOCCBRK) {
				/*
				 * POSIX conformance; rdar://3936338
				 *
				 * Clear ENOTTY in the case of setting or
				 * clearing a break failing because pty's
				 * don't support break like real serial
				 * ports.
				 */
				error = 0;
				goto out;
			}
		}
	}

	/*
	 * If external processing and packet mode send ioctl packet.
	 */
	if ((tp->t_lflag&EXTPROC) && (pti->pt_flags & PF_PKT)) {
		switch(cmd) {
		case TIOCSETA_32:
		case TIOCSETAW_32:
		case TIOCSETAF_32:
		case TIOCSETA_64:
		case TIOCSETAW_64:
		case TIOCSETAF_64:
		case TIOCSETP:
		case TIOCSETN:
		case TIOCSETC:
		case TIOCSLTC:
		case TIOCLBIS:
		case TIOCLBIC:
		case TIOCLSET:
			pti->pt_send |= TIOCPKT_IOCTL;
			ptmx_wakeup(tp, FREAD);
		default:
			break;
		}
	}
	stop = (tp->t_iflag & IXON) && CCEQ(cc[VSTOP], CTRL('s'))
		&& CCEQ(cc[VSTART], CTRL('q'));
	if (pti->pt_flags & PF_NOSTOP) {
		if (stop) {
			pti->pt_send &= ~TIOCPKT_NOSTOP;
			pti->pt_send |= TIOCPKT_DOSTOP;
			pti->pt_flags &= ~PF_NOSTOP;
			ptmx_wakeup(tp, FREAD);
		}
	} else {
		if (!stop) {
			pti->pt_send &= ~TIOCPKT_DOSTOP;
			pti->pt_send |= TIOCPKT_NOSTOP;
			pti->pt_flags |= PF_NOSTOP;
			ptmx_wakeup(tp, FREAD);
		}
	}
out:
	tty_unlock(tp);
	return (error);
}

/*
 * kqueue support.
 */
int ptsd_kqfilter(dev_t, struct knote *); 
static void ptsd_kqops_read_detach(struct knote *);
static int ptsd_kqops_read_event(struct knote *, long);
static void ptsd_kqops_write_detach(struct knote *);
static int ptsd_kqops_write_event(struct knote *, long);

static struct filterops ptsd_kqops_read = {
	.f_isfd = 1,
	.f_detach = ptsd_kqops_read_detach,
	.f_event = ptsd_kqops_read_event,
};                                    
static struct filterops ptsd_kqops_write = {
	.f_isfd = 1,
	.f_detach = ptsd_kqops_write_detach,
	.f_event = ptsd_kqops_write_event,
};                                  

static void
ptsd_kqops_read_detach(struct knote *kn)
{
	struct ptmx_ioctl *pti;
	struct tty *tp;
	dev_t dev = (dev_t) kn->kn_hookid;

	pti = ptmx_get_ioctl(minor(dev), 0);
	tp = pti->pt_tty;

	if (tp == NULL)
		return;

	tty_lock(tp);
	KNOTE_DETACH(&tp->t_rsel.si_note, kn);
	tty_unlock(tp);

	kn->kn_hookid = 0;
}

static int
ptsd_kqops_read_event(struct knote *kn, long hint)
{
	struct ptmx_ioctl *pti;
	struct tty *tp;
	dev_t dev = (dev_t) kn->kn_hookid;
	int retval = 0;

	pti = ptmx_get_ioctl(minor(dev), 0);
	tp = pti->pt_tty;

	if (tp == NULL)
		return (ENXIO);

	if (hint == 0)
		tty_lock(tp);

	kn->kn_data = ttnread(tp);
	if (kn->kn_data > 0) {
		retval = 1;
	}

	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		kn->kn_flags |= EV_EOF;
		retval = 1;
	}

	if (hint == 0)
		tty_unlock(tp);
	return (retval);
}                                                                                                
static void 
ptsd_kqops_write_detach(struct knote *kn)
{
	struct ptmx_ioctl *pti;
	struct tty *tp;
	dev_t dev = (dev_t) kn->kn_hookid;

	pti = ptmx_get_ioctl(minor(dev), 0);
	tp = pti->pt_tty;

	if (tp == NULL)
		return;

	tty_lock(tp);
	KNOTE_DETACH(&tp->t_wsel.si_note, kn);
	tty_unlock(tp);

	kn->kn_hookid = 0;
}

static int
ptsd_kqops_write_event(struct knote *kn, long hint)
{
	struct ptmx_ioctl *pti;
	struct tty *tp;
	dev_t dev = (dev_t) kn->kn_hookid;
	int retval = 0;

	pti = ptmx_get_ioctl(minor(dev), 0);
	tp = pti->pt_tty;

	if (tp == NULL)
		return (ENXIO);

	if (hint == 0)
		tty_lock(tp);

	if ((tp->t_outq.c_cc <= tp->t_lowat) &&
			ISSET(tp->t_state, TS_CONNECTED)) {
		kn->kn_data = tp->t_outq.c_cn - tp->t_outq.c_cc;
		retval = 1;
	}

	if (ISSET(tp->t_state, TS_ZOMBIE)) {
		kn->kn_flags |= EV_EOF;
		retval = 1;
	}

	if (hint == 0)
		tty_unlock(tp);
	return (retval);

}

int
ptsd_kqfilter(dev_t dev, struct knote *kn)
{
	struct tty *tp = NULL; 
	struct ptmx_ioctl *pti = NULL;
	int retval = 0;

	/* make sure we're talking about the right device type */
	if (cdevsw[major(dev)].d_open != ptsd_open) {
		return (EINVAL);
	}

	if ((pti = ptmx_get_ioctl(minor(dev), 0)) == NULL) {
	        return (ENXIO);
	}

	tp = pti->pt_tty;
	tty_lock(tp);

	kn->kn_hookid = dev;

        switch (kn->kn_filter) {
        case EVFILT_READ:
                kn->kn_fop = &ptsd_kqops_read;
		SLIST_INIT(&tp->t_rsel.si_note);
                KNOTE_ATTACH(&tp->t_rsel.si_note, kn);
                break;
        case EVFILT_WRITE:
                kn->kn_fop = &ptsd_kqops_write;
		SLIST_INIT(&tp->t_wsel.si_note);
                KNOTE_ATTACH(&tp->t_wsel.si_note, kn);
                break;
        default:
                retval = EINVAL;
                break;
        }

        tty_unlock(tp);
        return (retval);
}

