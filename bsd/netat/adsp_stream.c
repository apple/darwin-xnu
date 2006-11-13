/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 *	Copyright (c) 1995-1998 Apple Computer, Inc.
 *	All Rights Reserved.
 */

/*
 * 09/07/95 - Modified for performance (Tuyen Nguyen)
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
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
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <sys/malloc.h>

#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/ddp.h>
#include <netat/at_snmp.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/at_var.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

void SndMsgUp();
void adsp_rput();
static void adsp_iocack();
static void adsp_iocnak();
void adsp_dequeue_ccb();
unsigned char adspAssignSocket();
int adspallocate(), adsprelease();
int adspInited = 0;

atlock_t adspall_lock;
atlock_t adspgen_lock;
GLOBAL adspGlobal;

/**********/

int adsp_pidM[256];
char adsp_inputC[256];
CCB *adsp_inputQ[256];

extern at_ifaddr_t *ifID_home;

CCB *ccb_used_list;

void adsp_input(mp)
	gbuf_t *mp;
{
	gref_t *gref;
	CCBPtr sp;
	at_ddp_t *p;
	int s, l;
	gbuf_t *mb;

	switch (gbuf_type(mp)) {
	case MSG_DATA:
		p = (at_ddp_t *)gbuf_rptr(mp);
		ATDISABLE(s, adspall_lock);
		sp = adsp_inputQ[p->dst_socket];
		if ((sp == 0) || (sp->gref==0) || (sp->state==sClosed))
		{
			ATENABLE(s, adspall_lock);
			gbuf_freem(mp);
			return;
		}
		else if (sp->otccbLink != 0) {
			do {
				if ((sp->remoteAddress.a.node == p->src_node)
					&& (sp->remoteAddress.a.socket == p->src_socket)
				&& (sp->remoteAddress.a.net == NET_VALUE(p->src_net)))
					break;
			} while ((sp = sp->otccbLink) != 0);
			if (sp == 0)
			{
				ATENABLE(s, adspall_lock);
				gbuf_freem(mp);
				return;
			}
		}
		if (sp->lockFlag) {
			gbuf_next(mp) = 0;
			if (sp->deferred_mb) {
				for (mb=sp->deferred_mb; gbuf_next(mb); mb=gbuf_next(mb)) ; 
				gbuf_next(mb) = mp;
			} else
				sp->deferred_mb = mp;
			ATENABLE(s, adspall_lock);
			return;
		}
		ATDISABLE(l, sp->lockRemove);
		sp->lockFlag = 1;
		ATENABLE(l, adspall_lock);
		while (mp) {
			adsp_rput(sp->gref, mp);
			if ((mp = sp->deferred_mb) != 0) {
				sp->deferred_mb = gbuf_next(mp);
				gbuf_next(mp) = 0;
			}
		}
		sp->lockFlag = 0;
		ATENABLE(s, sp->lockRemove);
		return;

	case MSG_IOCACK:
	case MSG_IOCNAK:
		gref = (gref_t *)((ioc_t *)gbuf_rptr(mp))->ioc_private;
		break;

	case MSG_IOCTL:
#ifdef APPLETALK_DEBUG
		kprintf("unexpected MSG_IOCTL in adsp_input()");
#endif
		/* fall through */

	default:
		gbuf_freem(mp);
		return;
	}

	adsp_rput(gref, mp);
}

/**********/
int adsp_readable(gref)
	gref_t *gref;
{
	int rc;
	CCBPtr sp;

	if (gref->info == 0)
	        /*
		 * we don't have the structure we need to determine
		 * if there's data available... we return readable in
		 * this case to keep from hanging up in the select
		 * a subsequent read will run into the same missing data
		 * structure and return an error... the ATselect code does
		 * this if it can't retrieve the 'gref' structure from the 
		 * file table for the fd specified
		 */
	        return(1);

	sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	rc = sp->rData;

	return rc;
}

int adsp_writeable(gref)
	gref_t *gref;
{
	int s, rc;
	CCBPtr sp;

	if (gref->info == 0)
	        /*
		 * we don't have the structure we need to determine
		 * if there's room available... we return writeable in
		 * this case to keep from hanging up in the select
		 * a subsequent write will run into the same missing data
		 * structure and return an error... the ATselect code does
		 * this if it can't retrieve the 'gref' structure from the 
		 * file table for the fd specified
		 */
	        return(1);

	sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	ATDISABLE(s, sp->lock);
	rc = CalcSendQFree(sp);
	ATENABLE(s, sp->lock);

	return rc;
}

static void adsp_init()
{
	adspInited++;
	InitGlobals();
	ccb_used_list = 0;
	bzero(adsp_pidM, sizeof(adsp_pidM));
	bzero(adsp_inputC, sizeof(adsp_inputC));
	bzero(adsp_inputQ, sizeof(adsp_inputQ));
}

/*
 * Description:
 *	ADSP open and close routines.  These routines
 *	initalize and release the ADSP structures.  They do not
 *	have anything to do with "connections"
 */

int adsp_open(gref)
	gref_t *gref;
{
    register CCBPtr sp;
    int s;
    
    if (!adspInited)
		adsp_init();

    if (!adspAllocateCCB(gref))
	return(ENOBUFS);	/* can't get buffers */
 
	sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	gref->readable = adsp_readable;
	gref->writeable = adsp_writeable;
	ATDISABLE(s, adspall_lock);
	if ((sp->otccbLink = ccb_used_list) != 0)
		sp->otccbLink->ccbLink = sp;
	ccb_used_list = sp;
	ATENABLE(s, adspall_lock);
	return 0;
}

int adsp_close(gref)
	gref_t *gref;
{
  int s, l;
  unsigned char localSocket;

  /* make sure we've not yet removed the CCB (e.g., due to TrashSession) */
  ATDISABLE(l, adspgen_lock);
  if (gref->info) {
	CCBPtr sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	ATDISABLE(s, sp->lock);
	ATENABLE(s, adspgen_lock);
	localSocket = sp->localSocket;
	ATENABLE(l, sp->lock);
	if (localSocket)
		adspRelease(gref);
	else
	{
		adsp_dequeue_ccb(sp);
		gbuf_freeb((gbuf_t *)gref->info);
	}
  } else
	ATENABLE(l, adspgen_lock);
    return 0;
}


/*
 * Name:
 * 	adsp_rput
 *
 * Description:
 *	ADSP streams read put and service routines.
 */

void adsp_rput(gref, mp)
    gref_t *gref;			/* READ queue */
    gbuf_t *mp;
{
  switch (gbuf_type(mp)) {
  case MSG_HANGUP:
  case MSG_IOCACK:
  case MSG_IOCNAK:
	switch (adspReadHandler(gref, mp)) {
	case STR_PUTNEXT:	
	    atalk_putnext(gref, mp); 
	    break;
	case STR_IGNORE:
	    break;
        }
	break;
  case MSG_ERROR:
#ifdef APPLETALK_DEBUG
	kprintf("adsp_rput received MSG_ERROR");
#endif
	/* fall through */
  default:
	CheckReadQueue(gbuf_rptr(((gbuf_t *)gref->info)));
	CheckSend(gbuf_rptr(((gbuf_t *)gref->info)));

    	switch (gbuf_type(mp)) {
	case MSG_IOCTL:
	case MSG_DATA:
	case MSG_PROTO:
	    if (adspReadHandler(gref, mp) == STR_PUTNEXT)
		atalk_putnext(gref, mp);
	    break;
	default:
	    atalk_putnext(gref, mp);
	    break;
	}
  }
}

/*
 * Name:
 * 	adsp_wput
 *
 * Description:
 *	ADSP streams write put and service routines.
 *
 */

int adsp_wput(gref, mp)
    gref_t *gref;			/* WRITE queue */
    gbuf_t *mp;
{
	int rc;
	int s;
	gbuf_t *xm;
	ioc_t *iocbp;
	CCBPtr sp;
	
	if (gref->info)
		sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	else
		sp = 0;

	if (gbuf_type(mp) == MSG_IOCTL) {
		iocbp = (ioc_t *)gbuf_rptr(mp);
		switch (iocbp->ioc_cmd) {
		case ADSPBINDREQ: 
			{
			unsigned char v;

			if (gbuf_cont(mp) == NULL) {
				iocbp->ioc_rval = -1;
				adsp_iocnak(gref, mp, EINVAL);
			}
			v = *(unsigned char *)gbuf_rptr(gbuf_cont(mp));
			ATDISABLE(s, adspall_lock);
			if ( (v != 0)
			     && ((v > DDP_SOCKET_LAST) || (v < 2)
				 || ddp_socket_inuse(v, DDP_ADSP))) {
				ATENABLE(s, adspall_lock);
				iocbp->ioc_rval = -1;
				adsp_iocnak(gref, mp, EINVAL);
			}
			else {
				if (v == 0) {
					ATENABLE(s, adspall_lock);
					if ((v = adspAssignSocket(gref, 0)) == 0) {
						iocbp->ioc_rval = -1;
						adsp_iocnak(gref, mp, EINVAL);
						return 0;
					}
				} else {
					adsp_inputC[v] = 1;
					adsp_inputQ[v] = sp;
					adsp_pidM[v] = sp->pid;
					ATENABLE(s, adspall_lock);
					adsp_dequeue_ccb(sp);
				}
				*(unsigned char *)gbuf_rptr(gbuf_cont(mp)) = v;
				sp->localSocket = v;
				iocbp->ioc_rval = 0;
				adsp_iocack(gref, mp);
			}
			return 0;
			}

		case ADSPGETSOCK:
		case ADSPGETPEER:
			{
			at_inet_t *addr;

			if (((xm = gbuf_cont(mp)) == NULL)
			    && ((xm = gbuf_alloc(sizeof(at_inet_t), PRI_MED)) == NULL)) {
				iocbp->ioc_rval = -1;
				adsp_iocnak(gref, mp, ENOBUFS);
				return 0;
			}
			gbuf_cont(mp) = xm;
			gbuf_wset(xm,sizeof(at_inet_t));
			addr = (at_inet_t *)gbuf_rptr(xm);
			if (iocbp->ioc_cmd == ADSPGETSOCK) {
				/* Obtain Network and Node Id's from DDP */
				/* *** was ddp_get_cfg() *** */
				addr->net = ifID_home->ifThisNode.s_net;
				addr->node = ifID_home->ifThisNode.s_node;
				addr->socket = (sp)? sp->localSocket: 0;
			} else
				if (sp)
					*addr = sp->remoteAddress.a;
				else {
					addr->net = 0;
					addr->node = 0;
					addr->socket = 0;
				}
			iocbp->ioc_rval = 0;
			adsp_iocack(gref, mp);
			return 0;
			}
		case DDP_IOC_GET_CFG:
			/* respond to an DDP_IOC_GET_CFG sent on an adsp fd */
			if (((xm = gbuf_cont(mp)) == NULL) &&
			    (xm = gbuf_alloc(sizeof(ddp_addr_t), PRI_MED)) == NULL) {
			    iocbp->ioc_rval = -1;
			    adsp_iocnak(gref, mp, ENOBUFS);
			    return 0;
			}
			gbuf_cont(mp) = xm;
			gbuf_wset(xm, sizeof(ddp_addr_t));
			/* Obtain Network and Node Id's from DDP */
			{
			/* *** was ddp_get_cfg() *** */
			  ddp_addr_t *cfgp = 
			    (ddp_addr_t *)gbuf_rptr(gbuf_cont(mp));
			  cfgp->inet.net = ifID_home->ifThisNode.s_net;
			  cfgp->inet.node = ifID_home->ifThisNode.s_node;
			  cfgp->inet.socket = (sp)? sp->localSocket: 0;
			  cfgp->ddptype = DDP_ADSP;
			}
			iocbp->ioc_rval = 0;
			adsp_iocack(gref, mp);
			return 0;
		} /* switch */
	}

	if (!gref->info)
	    gbuf_freem(mp);
	else {
	    ATDISABLE(s, sp->lockClose);
	    rc = adspWriteHandler(gref, mp);
	    ATENABLE(s, sp->lockClose);

	    switch (rc) {
	    case STR_PUTNEXT:
		if (gbuf_type(mp) == MSG_IOCTL) {
		    iocbp = (ioc_t *)gbuf_rptr(mp);
		    iocbp->ioc_private = (void *)gref;
		}
		DDP_OUTPUT(mp);
		break;
	    case STR_IGNORE:
	    case STR_IGNORE+99:
		break;
	    default:
		gbuf_freem(mp);
		break;
	    }
	}

	return 0;
} /* adsp_wput */

void adspioc_ack(errno, m, gref)
    int errno;
    gbuf_t *m;
    gref_t *gref;
{
    ioc_t *iocbp;

    if (m == NULL)
	return;
    iocbp = (ioc_t *) gbuf_rptr(m);

    iocbp->ioc_error = errno;	/* set the errno */
    iocbp->ioc_count = gbuf_msgsize(gbuf_cont(m));
    if (gbuf_type(m) == MSG_IOCTL)	/* if an ioctl, this is an ack */
	gbuf_set_type(m, MSG_IOCACK);	/* and ALWAYS update the user */
    					/* ioctl structure */
    trace_mbufs(D_M_ADSP,"A ", m);
    SndMsgUp(gref, m);
}

static void adsp_iocack(gref, m)
     gref_t *gref;
     register gbuf_t *m;
{
	if (gbuf_type(m) == MSG_IOCTL)
		gbuf_set_type(m, MSG_IOCACK);

	if (gbuf_cont(m))
		((ioc_t *)gbuf_rptr(m))->ioc_count = gbuf_msgsize(gbuf_cont(m));
	else
		((ioc_t *)gbuf_rptr(m))->ioc_count = 0;

	SndMsgUp(gref, m);
}


static void adsp_iocnak(gref, m, err)
     gref_t *gref;
     register gbuf_t *m;
     register int err;
{
	if (gbuf_type(m) == MSG_IOCTL)
		gbuf_set_type(m, MSG_IOCNAK);
	((ioc_t *)gbuf_rptr(m))->ioc_count = 0;

	if (err == 0)
		err = ENXIO;
	((ioc_t *)gbuf_rptr(m))->ioc_error = err;

	if (gbuf_cont(m)) {
		gbuf_freem(gbuf_cont(m));
		gbuf_cont(m) = NULL;
	}
	SndMsgUp(gref, m);
}

unsigned char
adspAssignSocket(gref, flag)
	gref_t *gref;
	int flag;
{
	unsigned char sVal, sMax, sMin, sSav, inputC;
	CCBPtr sp;
	int s;

	sMax = flag ? DDP_SOCKET_LAST-46 : DDP_SOCKET_LAST-6;
	sMin = DDP_SOCKET_1st_DYNAMIC;

	ATDISABLE(s, adspall_lock);
	for (inputC=255, sVal=sMax; sVal >= sMin; sVal--) {
		if (!ddp_socket_inuse(sVal, DDP_ADSP))
			break;
		else if (flag) {
			if (adsp_inputC[sVal] && 
			        /* meaning that raw DDP doesn't have it */
			    (adsp_inputC[sVal] < inputC)
			    && (adsp_inputQ[sVal]->state == sOpen)) {
				inputC = adsp_inputC[sVal];
				sSav = sVal;
			}
		}
	}
	if (sVal < sMin) {
		if (!flag || (inputC == 255)) {
			ATENABLE(s, adspall_lock);
			return 0;
		}
		sVal = sSav;
	}
	sp = (CCBPtr)gbuf_rptr(((gbuf_t *)gref->info));
	ATENABLE(s, adspall_lock);
	adsp_dequeue_ccb(sp);
	ATDISABLE(s, adspall_lock);
	adsp_inputC[sVal]++;
	sp->otccbLink = adsp_inputQ[sVal];
	adsp_inputQ[sVal] = sp;
	if (!flag)
		adsp_pidM[sVal] = sp->pid;
	ATENABLE(s, adspall_lock);
	return sVal;
}

int
adspDeassignSocket(sp)
	CCBPtr sp;
{
	unsigned char sVal;
	CCBPtr curr_sp;
	CCBPtr prev_sp;
	int pid = 0;
	int s, l;

	dPrintf(D_M_ADSP, D_L_TRACE, ("adspDeassignSocket: pid=%d,s=%d\n",
		sp->pid, sp->localSocket));
	ATDISABLE(s, adspall_lock);
	sVal = sp->localSocket;
	if ((curr_sp = adsp_inputQ[sVal]) != 0) {
		prev_sp = 0;
		while (curr_sp != sp) {
			prev_sp = curr_sp;
			curr_sp = curr_sp->otccbLink;
		}
		if (curr_sp) {
			ATDISABLE(l, sp->lockRemove);
			if (prev_sp)
				prev_sp->otccbLink = sp->otccbLink;
			else
				adsp_inputQ[sVal] = sp->otccbLink;
			ATENABLE(l, sp->lockRemove);
			if (adsp_inputQ[sVal])
				adsp_inputC[sVal]--;
			else {
				pid = adsp_pidM[sVal];
				adsp_inputC[sVal] = 0;
				adsp_pidM[sVal] = 0;
			}
			sp->ccbLink = 0;
			sp->otccbLink = 0;
			sp->localSocket = 0;
			ATENABLE(s, adspall_lock);
		    return pid ? 0 : 1;
		}
	}
	ATENABLE(s, adspall_lock);

	dPrintf(D_M_ADSP, D_L_ERROR, 
		("adspDeassignSocket: closing, no CCB block, trouble ahead\n"));
	return -1;
} /* adspDeassignSocket */

/*
 * remove CCB from the use list
 */
void
adsp_dequeue_ccb(sp)
	CCB *sp;
{
	int s;

	ATDISABLE(s, adspall_lock);
	if (sp == ccb_used_list) {
		if ((ccb_used_list = sp->otccbLink) != 0)
			sp->otccbLink->ccbLink = 0;
	} else if (sp->ccbLink) {
		if ((sp->ccbLink->otccbLink = sp->otccbLink) != 0)
			sp->otccbLink->ccbLink = sp->ccbLink;
	}

	sp->otccbLink = 0;
	sp->ccbLink = 0;
	ATENABLE(s, adspall_lock);
}

void SndMsgUp(gref, mp)
    gref_t *gref;			/* WRITE queue */
	gbuf_t *mp;
{
/*
    dPrintf(D_M_ADSP, D_L_TRACE, 
	  ("SndMsgUp: gref=0x%x, mbuf=0x%x\n",	(unsigned)gref, (unsigned)mp));
    trace_mbufs(D_M_ADSP, "        m", mp);
*/
    atalk_putnext(gref, mp);
}
