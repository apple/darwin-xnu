/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/*
 *	Copyright (c) 1995 Apple Computer, Inc. 
 *
 *  Change Log:
 *    Created, March 17, 1997 by Tuyen Nguyen for MacOSX.
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
#include <sys/ioctl.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/ioccom.h>

#include <sys/sysctl.h>

#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/ddp.h>
#include <netat/at_pcb.h>
#include <netat/at_var.h>
#include <netat/routing_tables.h>
#include <netat/debug.h>

extern struct atpcb ddp_head;

extern void 
  ddp_putmsg(gref_t *gref, gbuf_t *m),
  elap_wput(gref_t *gref, gbuf_t *m),
  atp_wput(gref_t *gref, gbuf_t *m),
  asp_wput(gref_t *gref, gbuf_t *m),
#ifdef AURP_SUPPORT
  aurp_wput(gref_t *gref, gbuf_t *m),
#endif
  adsp_wput(gref_t *gref, gbuf_t *m);
  
int atp_free_cluster_timeout_set = 0;


void atalk_putnext(gref_t *gref, gbuf_t *m);
/* bms:  make gref_close non static so its callable from kernel */
int gref_close(gref_t *gref);

SYSCTL_DECL(_net_appletalk);
dbgBits_t dbgBits;
SYSCTL_STRUCT(_net_appletalk, OID_AUTO, debug, CTLFLAG_WR, 
	      &dbgBits, dbgBits, "AppleTalk Debug Flags");
volatile int RouterMix = RT_MIX_DEFAULT; /* default for nbr of ppsec */
SYSCTL_INT(_net_appletalk, OID_AUTO, routermix, CTLFLAG_WR, 
	   (int *)&RouterMix, 0, "Appletalk RouterMix");
at_ddp_stats_t at_ddp_stats;		/* DDP statistics */
SYSCTL_STRUCT(_net_appletalk, OID_AUTO, ddpstats, CTLFLAG_RD,
	      &at_ddp_stats, at_ddp_stats, "AppleTalk DDP Stats");

atlock_t refall_lock;

caddr_t	atp_free_cluster_list = 0;

void gref_wput(gref, m)
	gref_t *gref;
	gbuf_t *m;
{
	switch (gref->proto) {
	case ATPROTO_DDP:
		ddp_putmsg(gref, m); break;
	case ATPROTO_LAP:
		elap_wput(gref, m); break;
	case ATPROTO_ATP:
		atp_wput(gref, m); break;
	case ATPROTO_ASP:
		asp_wput(gref, m); break;
#ifdef AURP_SUPPORT
	case ATPROTO_AURP:
		aurp_wput(gref, m); break;
#endif
	case ATPROTO_ADSP:
		adsp_wput(gref, m); break;
	case ATPROTO_NONE:
		if (gbuf_type(m) == MSG_IOCTL) {
			gbuf_freem(gbuf_cont(m));
			gbuf_cont(m) = 0;
			((ioc_t *)gbuf_rptr(m))->ioc_rval = -1;
			((ioc_t *)gbuf_rptr(m))->ioc_error = EPROTO;
			gbuf_set_type(m, MSG_IOCNAK);
			atalk_putnext(gref, m);
		} else
			gbuf_freem(m);
		break;
	default:
		gbuf_freem(m);
		break;
	}
}

int _ATsocket(proto, err, proc)
	int proto;
	int *err;
	void *proc;
{
	int fd;
	gref_t *gref;

	/* make sure the specified protocol id is valid */
	switch (proto) {

	/* ATPROTO_DDP and ATPROTO_LAP have been replaced with 
	   BSD-style socket interface. */

	case ATPROTO_ATP:
	case ATPROTO_ASP:
	case ATPROTO_AURP:
	case ATPROTO_ADSP:
		break;
	default:
		*err = EPROTOTYPE;
#ifdef APPLETALK_DEBUG
		kprintf("_ATsocket: error EPROTOTYPE =%d\n", *err);
#endif
		return -1;
	}

	/* allocate a protocol channel */
	if ((*err = gref_alloc(&gref)) != 0) {
#ifdef APPLETALK_DEBUG
		kprintf("_ATsocket: error gref_open =%d\n", *err);
#endif
		return -1;
	}
	gref->proto = proto;
	gref->pid = ((struct proc *)proc)->p_pid;

	/* open the specified protocol */
	switch (gref->proto) {

	/* ATPROTO_DDP and ATPROTO_LAP have been replaced with 
	   BSD-style socket interface. */

	case ATPROTO_ATP:
		*err = atp_open(gref, 1); break;
	case ATPROTO_ASP:
		*err = asp_open(gref); break;
#ifdef AURP_SUPPORT
	case ATPROTO_AURP:
		*err = aurp_open(gref); break;
#endif
	case ATPROTO_ADSP:
		*err = adsp_open(gref); break;
	}

	/* create the descriptor for the channel */
	if (*err) {
#ifdef APPLETALK_DEBUG
		kprintf("_ATsocket: open failed for %d proto; err = %d\n", 
			gref->proto, *err);
#endif
		gref->proto = ATPROTO_NONE;
	}
	if (*err || (*err = atalk_openref(gref, &fd, proc))) {
#ifdef APPLETALK_DEBUG
		kprintf("_ATsocket: error atalk_openref =%d\n", *err);
#endif
		(void)gref_close(gref);
		return -1;
	}
/*
	kprintf("_ATsocket: proto=%d return=%d fd=%d\n", proto, *err, fd);
*/
	return fd;
} /* _ATsocket */

int _ATgetmsg(fd, ctlptr, datptr, flags, err, proc)
	int fd;
	strbuf_t *ctlptr;
	strbuf_t *datptr;
	int *flags;
	int *err;
	void *proc;
{
	int rc = -1;
	gref_t *gref;

	if ((*err = atalk_getref(0, fd, &gref, proc)) == 0) {
		switch (gref->proto) {
		case ATPROTO_ASP:
			rc = ASPgetmsg(gref, ctlptr, datptr, NULL, flags, err); 
			break;
		case ATPROTO_AURP:
#ifdef AURP_SUPPORT
			rc = AURPgetmsg(err); 
			break;
#endif
		default:
			*err = EPROTONOSUPPORT; 
			break;
		}
	}

/*	kprintf("_ATgetmsg: return=%d\n", *err);*/
	return rc;
}

int _ATputmsg(fd, ctlptr, datptr, flags, err, proc)
	int fd;
	strbuf_t *ctlptr;
	strbuf_t *datptr;
	int flags;
	int *err;
	void *proc;
{
	int rc = -1;
	gref_t *gref;

	if ((*err = atalk_getref(0, fd, &gref, proc)) == 0) {
		switch (gref->proto) {
		case ATPROTO_ASP:
			rc = ASPputmsg(gref, ctlptr, datptr, NULL, flags, err); break;
		default:
			*err = EPROTONOSUPPORT; break;
		}
	}

/*	kprintf("_ATputmsg: return=%d\n", *err); */
	return rc;
}

int _ATclose(fp, proc)
	struct file *fp;
	struct proc *proc;
{
	int err;
	gref_t *gref;

	if ((err = atalk_closeref(fp, &gref)) == 0) {
	     thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	     (void)gref_close(gref);
	     thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	}

	return err;
}

int _ATrw(fp, rw, uio, ext)
     void *fp;
     enum uio_rw rw;
     struct uio *uio;
     int ext;
{
    int s, err, len, clen = 0, res;
    gref_t *gref;
    gbuf_t *m, *mhead, *mprev;

    if ((err = atalk_getref(fp, 0, &gref, 0)) != 0)
    	return err;

    if ((len = uio->uio_resid) == 0)
    	return 0;

    ATDISABLE(s, gref->lock);

    if (rw == UIO_READ) {
	KERNEL_DEBUG(DBG_ADSP_ATRW, 0, gref, len, gref->rdhead, 0);
	while ((gref->errno == 0) && ((mhead = gref->rdhead) == 0)) {
		gref->sevents |= POLLMSG;
		err = tsleep(&gref->event, PSOCK | PCATCH, "AT read", 0);
		gref->sevents &= ~POLLMSG;
		if (err != 0) {
			ATENABLE(s, gref->lock);
			return err;
		}
		KERNEL_DEBUG(DBG_ADSP_ATRW, 1, gref, gref->rdhead, mhead, gbuf_next(mhead));
	}

	if (gref->errno) {
		ATENABLE(s, gref->lock);
		return EPIPE;
	}
	if ((gref->rdhead = gbuf_next(mhead)) == 0)
		gref->rdtail = 0;

	KERNEL_DEBUG(DBG_ADSP_ATRW, 2, gref, gref->rdhead, mhead, gbuf_next(mhead));

	ATENABLE(s, gref->lock);

//##### LD TEST 08/05
//	simple_lock(&gref->lock);

	gbuf_next(mhead) = 0;

	for (mprev=0, m=mhead; m && len; len-=clen) {
		if ((clen = gbuf_len(m)) > 0) {
			if (clen > len)
				clen = len;
			uio->uio_rw = UIO_READ;
			if ((res = uiomove((caddr_t)gbuf_rptr(m), 
					   clen, uio))) {
				KERNEL_DEBUG(DBG_ADSP_ATRW, 3, m, clen, 
					     len, gbuf_cont(m));
				break;
			}
			if (gbuf_len(m) > len) {
				gbuf_rinc(m,clen);
				break;
			}
		}
		mprev = m;
		m = gbuf_cont(m);
	}
	if (m) {
		KERNEL_DEBUG(DBG_ADSP_ATRW, 4, m, gbuf_len(m), mprev, gref->rdhead);
		if (mprev)
			gbuf_cont(mprev) = 0;
		else
			mhead = 0;
		ATDISABLE(s, gref->lock);
		if (gref->rdhead == 0)
			gref->rdtail = m;
		gbuf_next(m) = gref->rdhead;
		gref->rdhead = m;
		ATENABLE(s, gref->lock);
	}
	if (mhead)
		gbuf_freem(mhead);
//### LD TEST
//	simple_unlock(&gref->lock);
    } else {
  	if (gref->writeable) {
		while (!(*gref->writeable)(gref)) {
			/* flow control on, wait to be enabled to write */ 
			gref->sevents |= POLLSYNC;
			err = tsleep(&gref->event, PSOCK | PCATCH, "AT write", 0);
			gref->sevents &= ~POLLSYNC;
			if (err != 0) {
				ATENABLE(s, gref->lock);
				return err;
			}
		}
	}

	ATENABLE(s, gref->lock);

	/* allocate a buffer to copy in the write data */
	if ((m = gbuf_alloc(AT_WR_OFFSET+len, PRI_MED)) == 0)
		return ENOBUFS;
	gbuf_rinc(m,AT_WR_OFFSET);
	gbuf_wset(m,len);

	/* copy in the write data */
	uio->uio_rw = UIO_WRITE;
	if ((res = uiomove((caddr_t)gbuf_rptr(m), len, uio))) {
#ifdef APPLETALK_DEBUG
		kprintf("_ATrw: UIO_WRITE: res=%d\n", res);
#endif
		gbuf_freeb(m);
		return EIO;
	}

	/* forward the write data to the appropriate protocol module */
	gref_wput(gref, m);
  }

  return 0;
} /* _ATrw */

int _ATread(fp, uio, cred, flags, p)
	void *fp;
	struct uio *uio;
	void *cred;
	int flags;
	struct proc *p;
{
     int stat;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	stat = _ATrw(fp, UIO_READ, uio, 0);
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	return stat;
}

int _ATwrite(fp, uio, cred, flags, p)
	void *fp;
	struct uio *uio;
	void *cred;
	int flags;
	struct proc *p;
{
     int stat;


	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	stat = _ATrw(fp, UIO_WRITE, uio, 0);
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

	return stat;
}

/* Most of the processing from _ATioctl, so that it can be called
   from the new ioctl code */
/* bms:  update to be callable from kernel */
int at_ioctl(gref_t *gref, u_long cmd, caddr_t arg, int fromKernel)
{
    int s, err = 0, len;
    gbuf_t *m, *mdata;
    ioc_t *ioc;
    ioccmd_t ioccmd;

    /* error if not for us */
    if ((cmd  & 0xffff) != 0xff99)
        return EOPNOTSUPP;

    /* copy in ioc command info */
/*
    kprintf("at_ioctl: arg ioccmd.ic_cmd=%x ic_len=%x gref->lock=%x, gref->event=%x\n",
        ((ioccmd_t *)arg)->ic_cmd, ((ioccmd_t *)arg)->ic_len, 
        gref->lock, gref->event);
*/
    if (fromKernel)
        bcopy (arg, &ioccmd, sizeof (ioccmd_t));
    else {
    	if ((err = copyin((caddr_t)arg, (caddr_t)&ioccmd, sizeof(ioccmd_t))) != 0) { 
#ifdef APPLETALK_DEBUG
			kprintf("at_ioctl: err = %d, copyin(%x, %x, %d)\n", err, 
              		(caddr_t)arg, (caddr_t)&ioccmd, sizeof(ioccmd_t));
#endif
            return err;
        } 
    }

    /* allocate a buffer to create an ioc command
       first mbuf contains ioc command */
    if ((m = gbuf_alloc(sizeof(ioc_t), PRI_HI)) == 0)
        return ENOBUFS;
    gbuf_wset(m, sizeof(ioc_t));    /* mbuf->m_len */
    gbuf_set_type(m, MSG_IOCTL);    /* mbuf->m_type */

    /* create the ioc command 
       second mbuf contains the actual ASP command */
    if (ioccmd.ic_len) {
        if ((gbuf_cont(m) = gbuf_alloc(ioccmd.ic_len, PRI_HI)) == 0) {
            gbuf_freem(m);
#ifdef APPLETALK_DEBUG
			kprintf("at_ioctl: gbuf_alloc err=%d\n",ENOBUFS);
#endif
            return ENOBUFS;
        }
        gbuf_wset(gbuf_cont(m), ioccmd.ic_len);     /* mbuf->m_len */
        if (fromKernel)
            bcopy (ioccmd.ic_dp, gbuf_rptr(gbuf_cont(m)), ioccmd.ic_len);
        else {
            if ((err = copyin((caddr_t)ioccmd.ic_dp, (caddr_t)gbuf_rptr(gbuf_cont(m)), ioccmd.ic_len)) != 0) { 
                gbuf_freem(m);
                return err;
            }
        }
    }
    ioc = (ioc_t *) gbuf_rptr(m);
    ioc->ioc_cmd = ioccmd.ic_cmd;
    ioc->ioc_count = ioccmd.ic_len;
    ioc->ioc_error = 0;
    ioc->ioc_rval = 0;

    /* send the ioc command to the appropriate recipient */
	gref_wput(gref, m);

    /* wait for the ioc ack */
    ATDISABLE(s, gref->lock);
    while ((m = gref->ichead) == 0) {
        gref->sevents |= POLLPRI;
#ifdef APPLETALK_DEBUG
		kprintf("sleep gref = 0x%x\n", (unsigned)gref);
#endif
		err = tsleep(&gref->iocevent, PSOCK | PCATCH, "AT ioctl", 0);
		gref->sevents &= ~POLLPRI;
		if (err != 0) {
			ATENABLE(s, gref->lock);
#ifdef APPLETALK_DEBUG
			kprintf("at_ioctl: EINTR\n");
#endif
			return err;
		}
	}

	/* PR-2224797 */
 	if (gbuf_next(m) == m)		/* error case */
		gbuf_next(m) = 0; 

	gref->ichead = gbuf_next(m);

	ATENABLE(s, gref->lock);

#ifdef APPLETALK_DEBUG
	kprintf("at_ioctl: woke up from ioc sleep gref = 0x%x\n", 
		(unsigned)gref);
#endif

    /* process the ioc response */
    ioc = (ioc_t *) gbuf_rptr(m);
    if ((err = ioc->ioc_error) == 0) {
        ioccmd.ic_timout = ioc->ioc_rval;
        ioccmd.ic_len = 0;
        mdata = gbuf_cont(m);
        if (mdata && ioccmd.ic_dp) {
            ioccmd.ic_len = gbuf_msgsize(mdata);
            for (len = 0; mdata; mdata = gbuf_cont(mdata)) {
                if (fromKernel)
                    bcopy (gbuf_rptr(mdata), &ioccmd.ic_dp[len], gbuf_len(mdata));
                else {
                    if ((err = copyout((caddr_t)gbuf_rptr(mdata), (caddr_t)&ioccmd.ic_dp[len], gbuf_len(mdata))) < 0) {
#ifdef APPLETALK_DEBUG
						kprintf("at_ioctl: len=%d error copyout=%d from=%x to=%x gbuf_len=%x\n",
					 			len, err, (caddr_t)gbuf_rptr(mdata), (caddr_t)&ioccmd.ic_dp[len], gbuf_len(mdata));
#endif
                        goto l_done;
                    }
                }
                len += gbuf_len(mdata);
            }
        }
        
        if (fromKernel)
            bcopy (&ioccmd, arg, sizeof(ioccmd_t));
        else {
            if ((err = copyout((caddr_t)&ioccmd, (caddr_t)arg, sizeof(ioccmd_t))) != 0) {
#ifdef APPLETALK_DEBUG
                kprintf("at_ioctl: error copyout2=%d from=%x to=%x len=%d\n",
                         err, &ioccmd, arg, sizeof(ioccmd_t));
#endif
                goto l_done;
            }
        }
    }

l_done:
	gbuf_freem(m);
	/*kprintf("at_ioctl: I_done=%d\n", err);*/
	return err;
} /* at_ioctl */

int _ATioctl(fp, cmd, arg, proc)
	void *fp;
	u_long cmd;
	register caddr_t arg;
	void *proc;
{
	int err;
	gref_t *gref;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	if ((err = atalk_getref(fp, 0, &gref, 0)) != 0) {
#ifdef APPLETALK_DEBUG
		kprintf("_ATioctl: atalk_getref err = %d\n", err);
#endif
	}
	else
	     err = at_ioctl(gref, cmd, arg, 0);

	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

	return err;
}

int _ATselect(fp, which, wql, proc)
	struct file *fp;
	int which;
	void * wql;
	struct proc *proc;
{
	int s, err, rc = 0;
	gref_t *gref;

	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	err = atalk_getref(fp, 0, &gref, 0);
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);

	if (err != 0)
		rc = 1;
	else {
	     ATDISABLE(s, gref->lock);
	     if (which == FREAD) {
		  if (gref->rdhead || (gref->readable && (*gref->readable)(gref)))
		       rc = 1;
		  else {
		       gref->sevents |= POLLIN;
		       selrecord(proc, &gref->si, wql);
		  }
	     }
	     else if (which == POLLOUT) {
		  if (gref->writeable) {
		       if ((*gref->writeable)(gref))
			    rc = 1;
		       else {
			    gref->sevents |= POLLOUT;
			    selrecord(proc, &gref->si, wql);
		       }
		  } else
		       rc = 1;
	     }
	     ATENABLE(s, gref->lock);
	}

	return rc;
}

int _ATkqfilter(fp, kn, p)
	struct file *fp;
	struct knote *kn;
	struct proc *p;
{
	return (EOPNOTSUPP);
}

void atalk_putnext(gref, m)
	gref_t *gref;
	gbuf_t *m;
{
	int s;

	ATDISABLE(s, gref->lock);

	/* *** potential leak? *** */
	gbuf_next(m) = 0;

	switch (gbuf_type(m)) {
	case MSG_IOCACK:
	case MSG_IOCNAK:
		if (gref->ichead)
			gbuf_next(gref->ichead) = m;
		else {
			gref->ichead = m;
			if (gref->sevents & POLLPRI) {
#ifdef APPLETALK_DEBUG
				kprintf("wakeup gref = 0x%x\n", (unsigned)gref);
#endif
				wakeup(&gref->iocevent);
			}
		}
		break;
	case MSG_ERROR:
		/* *** this processing was moved to atalk_notify *** */
		panic("atalk_putnext receved MSG_ERROR");
		break;
	default:
		if (gref->errno)
		   gbuf_freem(m);
		else 
		   if (gref->rdhead) {
			gbuf_next(gref->rdtail) = m;
			gref->rdtail = m;
		    } else {
			gref->rdhead = m;
			if (gref->sevents & POLLMSG) {
				gref->sevents &= ~POLLMSG;
				wakeup(&gref->event);
			}
			if (gref->sevents & POLLIN) {
				gref->sevents &= ~POLLIN;
				selwakeup(&gref->si);
			}
			gref->rdtail = m;
		    }
	} /* switch gbuf_type(m) */

	ATENABLE(s, gref->lock);
} /* atalk_putnext */

void atalk_enablew(gref)
	gref_t *gref;
{
	if (gref->sevents & POLLSYNC)
		wakeup(&gref->event);
}

void atalk_flush(gref)
	gref_t *gref;
{
	int s;

	ATDISABLE(s, gref->lock);
	if (gref->rdhead) {
		gbuf_freel(gref->rdhead);
		gref->rdhead = 0;
	}
	if (gref->ichead) {
		gbuf_freel(gref->ichead);
		gref->ichead = 0;
	}
	ATENABLE(s, gref->lock);
}

/*
 * Notify an appletalk user of an asynchronous error;
 * just wake up so that he can collect error status.
 */
void atalk_notify(gref, errno)
	register gref_t *gref;
	int errno;
{
	int s;
	ATDISABLE(s, gref->lock);

	if (gref->atpcb_socket) {
	    /* For DDP --
	       This section is patterned after udp_notify() in 
	       netinet/udp_usrreq.c 
	    */
	    gref->atpcb_socket->so_error = errno;
	    sorwakeup(gref->atpcb_socket);
	    sowwakeup(gref->atpcb_socket);
	} else {
	    /* for ATP, ASP, and ADSP */
	    if (gref->errno == 0) {
		gref->errno = errno;
		/* clear out data waiting to be read */
		if (gref->rdhead) {
			gbuf_freel(gref->rdhead);
			gref->rdhead = 0;
		}
		/* blocked read */
		if (gref->sevents & POLLMSG) {
			gref->sevents &= ~POLLMSG;
			wakeup(&gref->event);
		}
		/* select */
		if (gref->sevents & POLLIN) {
			gref->sevents &= ~POLLIN;
			selwakeup(&gref->si);
		}
	    }
	}
	ATENABLE(s, gref->lock);
} /* atalk_notify */

void atalk_notify_sel(gref)
	gref_t *gref;
{
	int s;

	ATDISABLE(s, gref->lock);
	if (gref->sevents & POLLIN) {
		gref->sevents &= ~POLLIN;
		selwakeup(&gref->si);
	}
	ATENABLE(s, gref->lock);
}

int atalk_peek(gref, event)
	gref_t *gref;
	unsigned char *event;
{
	int s, rc;

	ATDISABLE(s, gref->lock);
	if (gref->rdhead) {
		*event = *gbuf_rptr(gref->rdhead);
		rc = 0;
	} else
		rc = -1;
	ATENABLE(s, gref->lock);

	return rc;
}

static gbuf_t *trace_msg;

void atalk_settrace(str, p1, p2, p3, p4, p5)
	char *str;
{
	int len;
	gbuf_t *m, *nextm;
	char trace_buf[256];

	sprintf(trace_buf, str, p1, p2, p3, p4, p5);
	len = strlen(trace_buf);
#ifdef APPLETALK_DEBUG
	kprintf("atalk_settrace: gbufalloc size=%d\n", len+1);
#endif
	if ((m = gbuf_alloc(len+1, PRI_MED)) == 0)
		return;
	gbuf_wset(m,len);
	strcpy(gbuf_rptr(m), trace_buf);
	if (trace_msg) {
		for (nextm=trace_msg; gbuf_cont(nextm); nextm=gbuf_cont(nextm)) ;
		gbuf_cont(nextm) = m;
	} else
		trace_msg = m;
}

void atalk_gettrace(m)
	gbuf_t *m;
{
	if (trace_msg) {
		gbuf_cont(m) = trace_msg;
		trace_msg = 0;
	}
}

#define GREF_PER_BLK 32
static gref_t *gref_free_list = 0;

int gref_alloc(grefp)
	gref_t **grefp;
{
	extern gbuf_t *atp_resource_m;
	int i, s;
	gbuf_t *m;
	gref_t *gref, *gref_array;

	*grefp = (gref_t *)NULL;

	ATDISABLE(s, refall_lock);
	if (gref_free_list == 0) {
		ATENABLE(s, refall_lock);
#ifdef APPLETALK_DEBUG
		kprintf("gref_alloc: gbufalloc size=%d\n", GREF_PER_BLK*sizeof(gref_t));
#endif
		if ((m = gbuf_alloc(GREF_PER_BLK*sizeof(gref_t),PRI_HI)) == 0)
			return ENOBUFS;
		bzero(gbuf_rptr(m), GREF_PER_BLK*sizeof(gref_t));
		gref_array = (gref_t *)gbuf_rptr(m);
		for (i=0; i < GREF_PER_BLK-1; i++)
			gref_array[i].atpcb_next = (gref_t *)&gref_array[i+1];
		ATDISABLE(s, refall_lock);
		gbuf_cont(m) = atp_resource_m;
		atp_resource_m = m;
		gref_array[i].atpcb_next = gref_free_list;
		gref_free_list = (gref_t *)&gref_array[0];
	}

	gref = gref_free_list;
	gref_free_list = gref->atpcb_next;
	ATENABLE(s, refall_lock);
	ATLOCKINIT(gref->lock);
//### LD Test 08/05/98
//	simple_lock_init(&gref->lock);
	ATEVENTINIT(gref->event);
	ATEVENTINIT(gref->iocevent);

	/* *** just for now *** */
	gref->atpcb_socket = (struct socket *)NULL;

	*grefp = gref;
	return 0;
} /* gref_alloc */

/* bms:  make gref_close callable from kernel */
int gref_close(gref_t *gref)
{
	int s, rc;

	switch (gref->proto) {

	/* ATPROTO_DDP and ATPROTO_LAP have been replaced with 
	   BSD-style socket interface. */

	case ATPROTO_ATP:
		rc = atp_close(gref, 1); break;
	case ATPROTO_ASP:
	  	rc = asp_close(gref); break;
#ifdef AURP_SUPPORT
	case ATPROTO_AURP:
		rc = aurp_close(gref); break;
		break;
#endif
	case ATPROTO_ADSP:
		rc = adsp_close(gref); break;
	default:
		rc = 0;
		break;
	}

	if (rc == 0) {
		atalk_flush(gref);
		selthreadclear(&gref->si);

		/* from original gref_free() */
		ATDISABLE(s, refall_lock);
		bzero((char *)gref, sizeof(gref_t));
		gref->atpcb_next = gref_free_list;
		gref_free_list = gref;
		ATENABLE(s, refall_lock);
	}

	return rc;
}

/* 
   Buffer Routines

   *** Some to be replaced with mbuf routines, some to be re-written
       as mbuf routines (and moved to kern/uicp_mbuf.c or sys/mbuf.h?).
   ***

*/

/*
 * LD 5/12/97 Added for MacOSX, defines a m_clattach function that:
 * "Allocates an mbuf structure and attaches an external cluster."
 */

struct mbuf *m_clattach(extbuf, extfree, extsize, extarg, wait)
	caddr_t extbuf;	
	void (*extfree)(caddr_t , u_int, caddr_t);
	u_int extsize;
	caddr_t extarg;
	int wait;
{
        struct mbuf *m;

        if ((m = m_gethdr(wait, MSG_DATA)) == NULL)
                return (NULL);

        m->m_ext.ext_buf = extbuf;
        m->m_ext.ext_free = extfree;
        m->m_ext.ext_size = extsize;
        m->m_ext.ext_arg = extarg;
        m->m_ext.ext_refs.forward = 
	  m->m_ext.ext_refs.backward = &m->m_ext.ext_refs;
        m->m_data = extbuf;
        m->m_flags |= M_EXT;

        return (m);
}



/*
	temp fix for bug 2731148  - until this code is re-written to use standard clusters
	Deletes any free clusters on the free list.
*/
void atp_delete_free_clusters()
{
	caddr_t cluster;
	caddr_t cluster_list;
	
	
	/* check for free clusters on the free_cluster_list to be deleted */
	MBUF_LOCK();	/* lock used by mbuf routines */

		untimeout(&atp_delete_free_clusters, NULL);
		atp_free_cluster_timeout_set = 0;

		cluster_list = atp_free_cluster_list;
		atp_free_cluster_list = 0;
		
	MBUF_UNLOCK();
	
	while (cluster = cluster_list)
	{
		cluster_list = *((caddr_t*)cluster);
		FREE(cluster, M_MCLUST);
	}
	
}


/* 
   Used as the "free" routine for over-size clusters allocated using
   m_lgbuf_alloc(). Called by m_free while under MBUF_LOCK.
*/

void m_lgbuf_free(buf, size, arg)
     caddr_t buf;
     u_int size;
     caddr_t arg; /* not needed, but they're in m_free() */
{
	/* FREE(buf, M_MCLUST); - can't free here - called from m_free while under lock */
	
	/* move to free_cluster_list to be deleted later */
	caddr_t cluster = (caddr_t)buf;
	
	/* don't need a lock because this is only called called from m_free which */
	/* is under MBUF_LOCK */
	*((caddr_t*)cluster) = atp_free_cluster_list;
	atp_free_cluster_list = cluster;
	
	if (atp_free_cluster_timeout_set == 0)
	{
		atp_free_cluster_timeout_set = 1;
		timeout(&atp_delete_free_clusters, NULL, (1 * HZ));
	}
}

/*
  Used to allocate an mbuf when there is the possibility that it may
  need to be larger than the size of a standard cluster.
*/

struct mbuf *m_lgbuf_alloc(size, wait)
	int size, wait;
{
	struct mbuf *m;

	if (atp_free_cluster_list)
		atp_delete_free_clusters();	/* delete any free clusters on the free list */
	
	/* If size is too large, allocate a cluster, otherwise, use the
	   standard mbuf allocation routines.*/
	if (size > MCLBYTES) {
		void *buf;
		if (NULL == 
		    (buf = (void *)_MALLOC(size, M_MCLUST, 
					   (wait)? M_WAITOK: M_NOWAIT))) {
			return(NULL);
		}
		if (NULL == 
		    (m = m_clattach(buf, m_lgbuf_free, size, 0, 
				    (wait)? M_WAIT: M_DONTWAIT))) {
			m_lgbuf_free(buf, 0, 0);
			return(NULL);
		}
	} else {
		m = m_gethdr(((wait)? M_WAIT: M_DONTWAIT), MSG_DATA);
		if (m && (size > MHLEN)) {
			MCLGET(m, ((wait)? M_WAIT: M_DONTWAIT));
			if (!(m->m_flags & M_EXT)) {
				(void)m_free(m);
				return(NULL);
			}
		}
	}

	return(m);
} /* m_lgbuf_alloc */

/*
   gbuf_alloc() is a wrapper for m_lgbuf_alloc(), which is used to 
   allocate an mbuf when there is the possibility that it may need 
   to be larger than the size of a standard cluster.

   gbuf_alloc() sets the mbuf lengths, unlike the standard mbuf routines.
*/     

gbuf_t *gbuf_alloc_wait(size, wait)
     int size, wait;
{
	gbuf_t *m = (gbuf_t *)m_lgbuf_alloc(size, wait);

	/* Standard mbuf allocation routines assume that the caller
	   will set the size. */
	if (m) {
		(struct mbuf *)m->m_pkthdr.len = size;
		(struct mbuf *)m->m_len = size;
	}

	return(m);
}

int gbuf_msgsize(m)
	gbuf_t *m;
{
	int size;

	for (size=0; m; m=gbuf_cont(m))
		size += gbuf_len(m);
	return size;
}

int append_copy(m1, m2, wait)
     struct mbuf *m1, *m2;
     int wait;
{
	if ((!(m1->m_flags & M_EXT)) && (!(m2->m_flags & M_EXT)) && 
	    (m_trailingspace(m1) >= m2->m_len)) {
		/* splat the data from one into the other */
		bcopy(mtod(m2, caddr_t), mtod(m1, caddr_t) + m1->m_len,
		      (u_int)m2->m_len);
		m1->m_len += m2->m_len;
		if (m1->m_flags & M_PKTHDR)
		    m1->m_pkthdr.len += m2->m_len;
		return 1;
	}
	if ((m1->m_next = m_copym(m2, 0, m2->m_len, 
				  (wait)? M_WAIT: M_DONTWAIT)) == NULL)
		return 0;
	return 1;
} /* append_copy */

/* 
   Copy an mbuf chain, referencing existing external storage, if any.
   Leave space for a header in the new chain, if the space has been 
   left in the origin chain.
*/ 
struct mbuf *copy_pkt(mlist, pad) 
     struct mbuf *mlist; /* the mbuf chain to be copied */ 
     int pad;		 /* hint as to how long the header might be
			    If pad is < 0, leave the same amount of space
			    as there was in the original. */ 
{ 
	struct mbuf *new_m; 
	int len;

	if (pad < 0)
		len = m_leadingspace(mlist);
	else
		len = min(pad, m_leadingspace(mlist));

	/* preserve space for the header at the beginning of the mbuf */
	if (len) {
		mlist->m_data -= (len);
		mlist->m_len += (len);
		if (mlist->m_flags & M_PKTHDR)
		    mlist->m_pkthdr.len += (len);
		new_m = m_copym(mlist, 0, M_COPYALL, M_DONTWAIT);
		m_adj(mlist, len);
		m_adj(new_m, len);
	} else 
		new_m = m_copym(mlist, 0, M_COPYALL, M_DONTWAIT);

	return(new_m);
}

void gbuf_linkb(m1, m2)
	gbuf_t *m1;
	gbuf_t *m2;
{
	while (gbuf_cont(m1) != 0)
		m1 = gbuf_cont(m1);
	gbuf_cont(m1) = m2;
}

void gbuf_linkpkt(m1, m2)
	gbuf_t *m1;
	gbuf_t *m2;
{
	while (gbuf_next(m1) != 0)
		m1 = gbuf_next(m1);
	gbuf_next(m1) = m2;
}

int gbuf_freel(m)
	gbuf_t *m;
{
	gbuf_t *tmp_m;

	while ((tmp_m = m) != 0) {
		m = gbuf_next(m);
		gbuf_next(tmp_m) = 0;
		gbuf_freem(tmp_m);
	}
	return (0);
}

/* free empty mbufs at the front of the chain */
gbuf_t *gbuf_strip(m)
     gbuf_t *m;
{
	gbuf_t *tmp_m;

	while (m && gbuf_len(m) == 0) {
		tmp_m = m;
		m = gbuf_cont(m);
		gbuf_freeb(tmp_m);
	}
	return(m);
}

/**************************************/

int ddp_adjmsg(m, len)
	gbuf_t 		*m;
	int 	len;
{
	int buf_len;
	gbuf_t *curr_m, *prev_m;

	if (m == (gbuf_t *)0)
		return 0;

	if (len > 0) {
		for (curr_m=m; curr_m;) {
			buf_len = gbuf_len(curr_m);
			if (len < buf_len) {
				gbuf_rinc(curr_m,len);
				return 1;
			}
			len -= buf_len;
			gbuf_rinc(curr_m,buf_len);
			if ((curr_m = gbuf_cont(curr_m)) == 0) {
				gbuf_freem(m);
				return 0;
			}
		}

	} else if (len < 0) {
		len = -len;
l_cont:	prev_m = 0;
		for (curr_m=m; gbuf_cont(curr_m);
			prev_m=curr_m, curr_m=gbuf_cont(curr_m)) ;
		buf_len = gbuf_len(curr_m);
		if (len < buf_len) {
			gbuf_wdec(curr_m,len);
			return 1;
		}
		if (prev_m == 0)
			return 0;
		gbuf_cont(prev_m) = 0;
		gbuf_freeb(curr_m);
		len -= buf_len;
		goto l_cont;

	} else
		return 1;
}

/*
 * The message chain, m is grown in size by len contiguous bytes.
 * If len is non-negative, len bytes are added to the
 * end of the gbuf_t chain.  If len is negative, the
 * bytes are added to the front. ddp_growmsg only adds bytes to 
 * message blocks of the same type.
 * It returns a pointer to the new gbuf_t on sucess, 0 on failure.
 */

gbuf_t *ddp_growmsg(mp, len)
	gbuf_t 	*mp;
	int 	len;
{
	gbuf_t	*m, *d;

	if ((m = mp) == (gbuf_t *) 0)
		return ((gbuf_t *) 0);

	if (len <= 0) {
		len = -len;
		if ((d = gbuf_alloc(len, PRI_MED)) == 0)
			return ((gbuf_t *) 0);
		gbuf_set_type(d, gbuf_type(m));
		gbuf_wset(d,len);
		/* link in new gbuf_t */
		gbuf_cont(d) = m;
		return (d);

	} else {
	        register int	count;
		/*
		 * Add to tail.
		 */
		if ((count = gbuf_msgsize(m)) < 0)
			return ((gbuf_t *) 0);
		/* find end of chain */
		for ( ; m; m = gbuf_cont(m)) {
			if (gbuf_len(m) >= count) 
				break;
			count -= gbuf_len(m);
		}
		/* m now points to gbuf_t to add to */
		if ((d = gbuf_alloc(len, PRI_MED)) == 0)
			return ((gbuf_t *) 0);
		gbuf_set_type(d, gbuf_type(m));
		/* link in new gbuf_t */
		gbuf_cont(d) = gbuf_cont(m);
		gbuf_cont(m) = d;
		gbuf_wset(d,len);
		return (d);
	}
}

/*
 *	return the MSG_IOCACK/MSG_IOCNAK. Note that the same message
 *	block is used as the vehicle, and that if there is an error return,
 *	then linked blocks are lopped off. BEWARE of multiple references.
 *	Used by other appletalk modules, so it is not static!
 */

void ioc_ack(errno, m, gref)
     int		errno;
     register gbuf_t	*m;
     register gref_t	*gref;
{
	ioc_t *iocbp = (ioc_t *)gbuf_rptr(m);
	
	/*kprintf("ioc_ack: m=%x gref=%x errno=%d\n", m, gref, errno);*/
	if ((iocbp->ioc_error = errno) != 0)
	{	/* errno != 0, then there is an error, get rid of linked blocks! */

		if (gbuf_cont(m)) {
		        gbuf_freem(gbuf_cont(m));
		        gbuf_cont(m) = 0;
		}
	        gbuf_set_type(m, MSG_IOCNAK);
		iocbp->ioc_count = 0;	/* only make zero length if error */
		iocbp->ioc_rval = -1;
	} else
	        gbuf_set_type(m, MSG_IOCACK);

	atalk_putnext(gref, m);
}

