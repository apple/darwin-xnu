/*
 * Copyright (c) 1997-2013 Apple Inc. All rights reserved.
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
#include <sys/user.h>
#include <sys/signalvar.h>
#include <sys/sysctl.h>
#include <miscfs/devfs/devfs.h>
#include <miscfs/devfs/devfsdefs.h>	/* DEVFS_LOCK()/DEVFS_UNLOCK() */

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

#include "tty_dev.h"

/*
 * Forward declarations
 */
int ptmx_init(int n_ptys);
static struct ptmx_ioctl *ptmx_get_ioctl(int minor, int open_flag);
static int ptmx_free_ioctl(int minor, int open_flag);
static int ptmx_get_name(int minor, char *buffer, size_t size);
static void ptsd_revoke_knotes(int minor, struct tty *tp);

extern	d_open_t	ptsopen;
extern	d_close_t	ptsclose;
extern	d_read_t	ptsread;
extern	d_write_t	ptswrite;
extern	d_ioctl_t	ptyioctl;
extern	d_stop_t	ptsstop;
extern	d_reset_t	ptsreset;
extern	d_select_t	ptsselect;

extern	d_open_t	ptcopen;
extern	d_close_t	ptcclose;
extern	d_read_t	ptcread;
extern	d_write_t	ptcwrite;
extern	d_stop_t	ptcstop;
extern	d_reset_t	ptcreset;
extern	d_select_t	ptcselect;

static int ptmx_major;		/* dynamically assigned major number */
static struct cdevsw ptmx_cdev = {
	ptcopen,	ptcclose,	ptcread,	ptcwrite,
	ptyioctl,	ptcstop,	ptcreset,	0,
	ptcselect,	eno_mmap,	eno_strat,	eno_getc,
	eno_putc,	D_TTY
};

static int ptsd_major;		/* dynamically assigned major number */
static struct cdevsw ptsd_cdev = {
	ptsopen,	ptsclose,	ptsread,	ptswrite,
	ptyioctl,	ptsstop,	ptsreset,	0,
	ptsselect,	eno_mmap,	eno_strat,	eno_getc,
	eno_putc,	D_TTY
};

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
		CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
		&ptmx_max, 0, &sysctl_ptmx_max, "I", "ptmx_max");

static int	ptmx_clone(dev_t dev, int minor);

/*
 * Set of locks to keep the interaction between kevents and revoke
 * from causing havoc.
 */

#define	LOG2_PTSD_KE_NLCK	2
#define	PTSD_KE_NLCK		(1l << LOG2_PTSD_KE_NLCK)
#define	PTSD_KE_LOCK_INDEX(x)	((x) & (PTSD_KE_NLCK - 1))

static lck_mtx_t ptsd_kevent_lock[PTSD_KE_NLCK];

static void
ptsd_kevent_lock_init(void)
{
	int i;
	lck_grp_t *lgrp = lck_grp_alloc_init("ptsd kevent", LCK_GRP_ATTR_NULL);

	for (i = 0; i < PTSD_KE_NLCK; i++)
		lck_mtx_init(&ptsd_kevent_lock[i], lgrp, LCK_ATTR_NULL);
}

static void
ptsd_kevent_mtx_lock(int minor)
{
	lck_mtx_lock(&ptsd_kevent_lock[PTSD_KE_LOCK_INDEX(minor)]);
}

static void
ptsd_kevent_mtx_unlock(int minor)
{
	lck_mtx_unlock(&ptsd_kevent_lock[PTSD_KE_LOCK_INDEX(minor)]);
}

static struct tty_dev_t _ptmx_driver;

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

	if (cdevsw_setkqueueok(ptmx_major, &ptmx_cdev, 0) == -1) {
		panic("Failed to set flags on ptmx cdevsw entry.");
	}

	/* Get a major number for /dev/pts/nnn */
	if ((ptsd_major = cdevsw_add(-15, &ptsd_cdev)) == -1) {
		(void)cdevsw_remove(ptmx_major, &ptmx_cdev);
		printf("ptmx_init: failed to obtain /dev/ptmx major number\n");
		return (ENOENT);
	}
	
	if (cdevsw_setkqueueok(ptsd_major, &ptsd_cdev, 0) == -1) {
		panic("Failed to set flags on ptmx cdevsw entry.");
	}

	/*
	 * Locks to guard against races between revoke and kevents
	 */
	ptsd_kevent_lock_init();

	/* Create the /dev/ptmx device {<major>,0} */
	(void)devfs_make_node_clone(makedev(ptmx_major, 0),
				DEVFS_CHAR, UID_ROOT, GID_TTY, 0666,
				ptmx_clone, PTMX_TEMPLATE);

	_ptmx_driver.master = ptmx_major;
	_ptmx_driver.slave = ptsd_major;
	_ptmx_driver.fix_7828447 = 1;
	_ptmx_driver.fix_7070978 = 1;
#if CONFIG_MACF
	_ptmx_driver.mac_notify = 1;
#endif
	_ptmx_driver.open = &ptmx_get_ioctl;
	_ptmx_driver.free = &ptmx_free_ioctl;
	_ptmx_driver.name = &ptmx_get_name;
	_ptmx_driver.revoke = &ptsd_revoke_knotes;
	tty_dev_register(&_ptmx_driver);

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
		
		/* is minor in range now? */
		if (minor < 0 || minor >= _state.pis_total) {
			ttyfree(new_ptmx_ioctl->pt_tty);
			DEVFS_UNLOCK();
			FREE(new_ptmx_ioctl, M_TTYS);
			return (NULL);
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
	}
	
	if (minor < 0 || minor >= _state.pis_total) {
		return (NULL);
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
	
	if (minor < 0 || minor >= _state.pis_total) {
		DEVFS_UNLOCK();
		return (-1);
	}

	_state.pis_ioctl_list[minor]->pt_flags &= ~(open_flag);

	/*
	 * Was this the last close?  We will recognize it because we only get
	 * a notification on the last close of a device, and we will have
	 * cleared both the master and the slave open bits in the flags.
	 */
	if (!(_state.pis_ioctl_list[minor]->pt_flags & (PF_OPEN_M|PF_OPEN_S))) {
		/* Mark as free so it can be reallocated later */
		old_ptmx_ioctl = _state.pis_ioctl_list[ minor];
		_state.pis_ioctl_list[minor] = NULL;
		_state.pis_free++;
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
	}

	return (0);	/* Success */
}

static int
ptmx_get_name(int minor, char *buffer, size_t size)
{
	return snprintf(buffer, size, "/dev/" PTSD_TEMPLATE, minor);
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


/*
 * kqueue support.
 */
int ptsd_kqfilter(dev_t, struct knote *); 
static void ptsd_kqops_detach(struct knote *);
static int ptsd_kqops_event(struct knote *, long);
static int ptsd_kqops_touch(struct knote *kn, struct kevent_internal_s *kev);
static int ptsd_kqops_process(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev);

struct filterops ptsd_kqops = {
	.f_isfd = 1,
	.f_detach = ptsd_kqops_detach,
	.f_event = ptsd_kqops_event,
	.f_touch = ptsd_kqops_touch,
	.f_process = ptsd_kqops_process,
};                                    

#define	PTSD_KNOTE_VALID	NULL
#define	PTSD_KNOTE_REVOKED	((void *)-911l)

/*
 * In the normal case, by the time the driver_close() routine is called
 * on the slave, all knotes have been detached.  However in the revoke(2)
 * case, the driver's close routine is called while there are knotes active
 * that reference the handlers below.  And we have no obvious means to
 * reach from the driver out to the kqueue's that reference them to get
 * them to stop.
 */

static void
ptsd_kqops_detach(struct knote *kn)
{
	struct ptmx_ioctl *pti;
	struct tty *tp;
	dev_t dev, lockdev = (dev_t)kn->kn_hookid;

	ptsd_kevent_mtx_lock(minor(lockdev));

	if ((dev = (dev_t)kn->kn_hookid) != 0) {
		pti = ptmx_get_ioctl(minor(dev), 0);
		if (pti != NULL && (tp = pti->pt_tty) != NULL) {
			tty_lock(tp);
			if (kn->kn_filter == EVFILT_READ)
				KNOTE_DETACH(&tp->t_rsel.si_note, kn);
			else
				KNOTE_DETACH(&tp->t_wsel.si_note, kn);
			tty_unlock(tp);
			kn->kn_hookid = 0;
		}
	}

	ptsd_kevent_mtx_unlock(minor(lockdev));
}

static int
ptsd_kqops_common(struct knote *kn, dev_t dev, long hint)
{
	struct ptmx_ioctl *pti;
	struct tty *tp;
	int retval = 0;

	do {
		if (kn->kn_hook != PTSD_KNOTE_VALID ) {
			/* We were revoked */
			kn->kn_data = 0;
			kn->kn_flags |= EV_EOF;
			retval = 1;
			break;
		}

		pti = ptmx_get_ioctl(minor(dev), 0);
		if (pti == NULL || (tp = pti->pt_tty) == NULL) {
			kn->kn_data = ENXIO;
			kn->kn_flags |= EV_ERROR;
			retval = 1;
			break;
		}

		if (hint == 0)
			tty_lock(tp);

		if (kn->kn_filter == EVFILT_READ) {
			kn->kn_data = ttnread(tp);
			if (kn->kn_data > 0)
				retval = 1;
			if (ISSET(tp->t_state, TS_ZOMBIE)) {
				kn->kn_flags |= EV_EOF;
				retval = 1;
			}
		} else {	/* EVFILT_WRITE */
			if ((tp->t_outq.c_cc <= tp->t_lowat) &&
			    ISSET(tp->t_state, TS_CONNECTED)) {
				kn->kn_data = tp->t_outq.c_cn - tp->t_outq.c_cc;
				retval = 1;
			}
			if (ISSET(tp->t_state, TS_ZOMBIE)) {
				kn->kn_flags |= EV_EOF;
				retval = 1;
			}
		}

		if (hint == 0)
			tty_unlock(tp);

	} while (0);

	return (retval);
}                                                                                                

static int
ptsd_kqops_event(struct knote *kn, long hint)
{
	dev_t dev = (dev_t)kn->kn_hookid;
	int res;

	ptsd_kevent_mtx_lock(minor(dev));
	res = ptsd_kqops_common(kn, dev, hint);
	ptsd_kevent_mtx_unlock(minor(dev));
	return res;
}
	

static int
ptsd_kqops_touch(struct knote *kn, struct kevent_internal_s *kev)
{
	dev_t dev = (dev_t)kn->kn_hookid;
	int res;

	ptsd_kevent_mtx_lock(minor(dev));

	/* accept new kevent state */
	kn->kn_sfflags = kev->fflags;
	kn->kn_sdata = kev->data;
	if ((kn->kn_status & KN_UDATA_SPECIFIC) == 0)
		kn->kn_udata = kev->udata;

	/* recapture fired state of knote */
	res = ptsd_kqops_common(kn, dev, 0);

	ptsd_kevent_mtx_unlock(minor(dev));

	return res;
}

static int
ptsd_kqops_process(struct knote *kn, struct filt_process_s *data, struct kevent_internal_s *kev)
{
#pragma unused(data)
	dev_t dev = (dev_t)kn->kn_hookid;
	int res;

	ptsd_kevent_mtx_lock(minor(dev));
	res = ptsd_kqops_common(kn, dev, 0);
	if (res) {
		*kev = kn->kn_kevent;
		if (kn->kn_flags & EV_CLEAR) {
			kn->kn_fflags = 0;
			kn->kn_data = 0;
		}
	}
	ptsd_kevent_mtx_unlock(minor(dev));
	return res;
}

int
ptsd_kqfilter(dev_t dev, struct knote *kn)
{
	struct tty *tp = NULL; 
	struct ptmx_ioctl *pti = NULL;
	int retval = 0;

	/* make sure we're talking about the right device type */
	if (cdevsw[major(dev)].d_open != ptsopen) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = EINVAL;
		return 0;
	}

	if ((pti = ptmx_get_ioctl(minor(dev), 0)) == NULL) {
		kn->kn_flags = EV_ERROR;
		kn->kn_data = ENXIO;
	        return 0;
	}

	tp = pti->pt_tty;
	tty_lock(tp);

	kn->kn_hookid = dev;
	kn->kn_hook = PTSD_KNOTE_VALID;
	kn->kn_filtid = EVFILTID_PTSD;

        switch (kn->kn_filter) {
        case EVFILT_READ:
                KNOTE_ATTACH(&tp->t_rsel.si_note, kn);
                break;
        case EVFILT_WRITE:
                KNOTE_ATTACH(&tp->t_wsel.si_note, kn);
                break;
        default:
		kn->kn_flags = EV_ERROR;
		kn->kn_data = EINVAL;
                break;
        }

        tty_unlock(tp);

	ptsd_kevent_mtx_lock(minor(dev));

	/* capture current event state */
	retval = ptsd_kqops_common(kn, dev, 0);

	ptsd_kevent_mtx_unlock(minor(dev));

        return (retval);
}

/*
 * Support for revoke(2).
 *
 * Mark all the kn_hook fields so that future invocations of the
 * f_event op will just say "EOF" *without* looking at the
 * ptmx_ioctl structure (which may disappear or be recycled at
 * the end of ptsd_close).  Issue wakeups to post that EOF to
 * anyone listening.  And finally remove the knotes from the
 * tty's klists to keep ttyclose() happy, and set the hookid to
 * zero to make the final detach passively successful.
 */
static void
ptsd_revoke_knotes(int minor, struct tty *tp)
{
	struct klist *list;
	struct knote *kn, *tkn;

	/* (Hold and drop the right locks in the right order.) */

	ptsd_kevent_mtx_lock(minor);
	tty_lock(tp);

	list = &tp->t_rsel.si_note;
	SLIST_FOREACH(kn, list, kn_selnext)
		kn->kn_hook = PTSD_KNOTE_REVOKED;

	list = &tp->t_wsel.si_note;
	SLIST_FOREACH(kn, list, kn_selnext)
		kn->kn_hook = PTSD_KNOTE_REVOKED;

	tty_unlock(tp);
	ptsd_kevent_mtx_unlock(minor);

	tty_lock(tp);
	ttwakeup(tp);
	ttwwakeup(tp);
	tty_unlock(tp);

	ptsd_kevent_mtx_lock(minor);
	tty_lock(tp);

	list = &tp->t_rsel.si_note;
	SLIST_FOREACH_SAFE(kn, list, kn_selnext, tkn) {
		(void) KNOTE_DETACH(list, kn);
		kn->kn_hookid = 0;
	}

	list = &tp->t_wsel.si_note;
	SLIST_FOREACH_SAFE(kn, list, kn_selnext, tkn) {
		(void) KNOTE_DETACH(list, kn);
		kn->kn_hookid = 0;
	}

	tty_unlock(tp);
	ptsd_kevent_mtx_unlock(minor);
}
