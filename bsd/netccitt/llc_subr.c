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
 * Copyright (C) Dirk Husemann, Computer Science Department IV, 
 * 		 University of Erlangen-Nuremberg, Germany, 1990, 1991, 1992
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 * 
 * This code is derived from software contributed to Berkeley by
 * Dirk Husemann and the Computer Science Department (IV) of
 * the University of Erlangen-Nuremberg, Germany.
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
 *	@(#)llc_subr.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>
#include <sys/domain.h>
#include <sys/socket.h>
#include <sys/protosw.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/malloc.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_llc.h>
#include <net/route.h>

#include <netccitt/dll.h>
#include <netccitt/llc_var.h>

/*
 * Frame names for diagnostic messages
 */
char *frame_names[] = { "INFO", "RR", "RNR", "REJ", "DM", "SABME", "DISC",
	"UA", "FRMR", "UI", "XID", "TEST", "ILLEGAL", "TIMER", "N2xT1"};


/*
 * Trace level
 */
int llc_tracelevel = LLCTR_URGENT;

/*
 * Values for accessing various bitfields
 */
struct bitslice llc_bitslice[] = {
/*	  mask, shift value */
	{ 0x1,  0x0 },
	{ 0xfe, 0x1 },
	{ 0x3,  0x0 },
	{ 0xc,  0x2 },
	{ 0x10, 0x4 },
	{ 0xe0, 0x5 },
	{ 0x1f, 0x0 }
};

/*
 * We keep the link control blocks on a doubly linked list - 
 * primarily for checking in llc_time() 
 */

struct llccb_q llccb_q = { &llccb_q, &llccb_q };

/*
 * Flag for signalling wether route tree for AF_LINK has been
 * initialized yet.
 */

int af_link_rts_init_done = 0; 


/*
 * Functions dealing with struct sockaddr_dl */

/* Compare sdl_a w/ sdl_b */

sdl_cmp(struct sockaddr_dl *sdl_a, struct sockaddr_dl *sdl_b)
{
	if (LLADDRLEN(sdl_a) != LLADDRLEN(sdl_b))
		return(1);
	return(bcmp((caddr_t) sdl_a->sdl_data, (caddr_t) sdl_b->sdl_data,
		    LLADDRLEN(sdl_a)));
}

/* Copy sdl_f to sdl_t */

sdl_copy(struct sockaddr_dl *sdl_f, struct sockaddr_dl *sdl_t)
{
	bcopy((caddr_t) sdl_f, (caddr_t) sdl_t, sdl_f->sdl_len);
}

/* Swap sdl_a w/ sdl_b */

sdl_swapaddr(struct sockaddr_dl *sdl_a, struct sockaddr_dl *sdl_b)
{
	struct sockaddr_dl sdl_tmp;

	sdl_copy(sdl_a, &sdl_tmp); 
	sdl_copy(sdl_b, sdl_a); 
	sdl_copy(&sdl_tmp, sdl_b);
}

/* Fetch the sdl of the associated if */

struct sockaddr_dl * 
sdl_getaddrif(struct ifnet *ifp)
{
	register struct ifaddr *ifa;

	for(ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) 	
		if (ifa->ifa_addr->sa_family == AF_LINK ) 		
			return((struct sockaddr_dl *)(ifa->ifa_addr));

	return((struct sockaddr_dl *)0);
}

/* Check addr of interface with the one given */

sdl_checkaddrif(struct ifnet *ifp, struct sockaddr_dl *sdl_c)
{
	register struct ifaddr *ifa;

	for(ifa = ifp->if_addrlist; ifa; ifa = ifa->ifa_next) 	
		if ((ifa->ifa_addr->sa_family == AF_LINK ) && 	 
		    !sdl_cmp((struct sockaddr_dl *)(ifa->ifa_addr), sdl_c))
			return(1);
	
	return(0);
}

/* Build an sdl from MAC addr, DLSAP addr, and interface */

sdl_setaddrif(struct ifnet *ifp, u_char *mac_addr, u_char dlsap_addr, 
	      u_char mac_len, struct sockaddr_dl *sdl_to)
{
	register struct sockaddr_dl *sdl_tmp;

	if ((sdl_tmp = sdl_getaddrif(ifp)) ) { 	
		sdl_copy(sdl_tmp, sdl_to); 	
		bcopy((caddr_t) mac_addr, (caddr_t) LLADDR(sdl_to), mac_len);
		*(LLADDR(sdl_to)+mac_len) = dlsap_addr;
		sdl_to->sdl_alen = mac_len+1; 	
		return(1); 
	} else return(0);
}

/* Fill out the sdl header aggregate */

sdl_sethdrif(struct ifnet *ifp, u_char *mac_src, u_char dlsap_src, u_char *mac_dst,
	     u_char dlsap_dst, u_char mac_len, struct sdl_hdr *sdlhdr_to)
{
	if ( !sdl_setaddrif(ifp, mac_src, dlsap_src, mac_len,
			     &sdlhdr_to->sdlhdr_src) ||
	     !sdl_setaddrif(ifp, mac_dst, dlsap_dst, mac_len,
			     &sdlhdr_to->sdlhdr_dst) )
		return(0);
	else return(1);
}

static struct sockaddr_dl sap_saddr; 
static struct sockaddr_dl sap_sgate = {
	sizeof(struct sockaddr_dl), /* _len */ 
	AF_LINK                     /* _af */
};

/*
 * Set sapinfo for SAP address, llcconfig, af, and interface
 */
struct npaidbentry *
llc_setsapinfo(struct ifnet *ifp, u_char af, u_char sap, struct dllconfig *llconf)
{
	struct protosw *pp; 
	struct sockaddr_dl *ifdl_addr; 
	struct rtentry *sirt = (struct rtentry *)0; 
	struct npaidbentry *sapinfo; 
	u_char saploc; 
	int size = sizeof(struct npaidbentry);

	USES_AF_LINK_RTS;

	/* 
	 * We rely/assume that only STREAM protocols will make use of 
	 * connection oriented LLC2. If this will one day not be the 
	 * case this will obviously fail. 
	 */ 
	pp = pffindtype (af, SOCK_STREAM); 
	if (pp == 0 || pp->pr_input == 0 || pp->pr_ctlinput == 0) { 	
		printf("network	level protosw error"); 	
		return 0; 
	}

	/*
	 * We need a way to jot down the LLC2 configuration for
	 * a certain LSAP address. To do this we enter 
	 * a "route" for the SAP.
	 */
	ifdl_addr = sdl_getaddrif(ifp);
	sdl_copy(ifdl_addr, &sap_saddr); 
	sdl_copy(ifdl_addr, &sap_sgate);
	saploc = LLSAPLOC(&sap_saddr, ifp); 
	sap_saddr.sdl_data[saploc] = sap;
	sap_saddr.sdl_alen++;

	/* now enter it */ 
	rtrequest(RTM_ADD, (struct sockaddr *)&sap_saddr,
			(struct sockaddr *)&sap_sgate, 0, 0, &sirt); 
	if (sirt == 0) 	
		return 0;

	/* Plug in config information in rt->rt_llinfo */

//	sirt->rt_llinfo = malloc(size , M_PCB, M_WAITOK); 
	MALLOC(sirt->rt_llinfo, caddr_t, size, M_PCB, M_WAITOK);
	sapinfo = (struct npaidbentry *) sirt->rt_llinfo; 
	if (sapinfo) { 	
		bzero ((caddr_t)sapinfo, size); 	
		/* 	 
		 * For the time being we support LLC CLASS II here 	 
		 * only 	 
		 */ 	
		sapinfo->si_class = LLC_CLASS_II; 	
		sapinfo->si_window = llconf->dllcfg_window;
		sapinfo->si_trace = llconf->dllcfg_trace; 	
		if (sapinfo->si_trace)
			llc_tracelevel--;
		else llc_tracelevel++;
		sapinfo->si_input = pp->pr_input; 	
		sapinfo->si_ctlinput = (caddr_t (*)())pp->pr_ctlinput;

		return (sapinfo);
	}

	return 0;
}

/*
 * Get sapinfo for SAP address and interface 
 */
struct npaidbentry *
llc_getsapinfo(u_char sap, struct ifnet *ifp)
{
	struct sockaddr_dl *ifdl_addr; 
	struct sockaddr_dl si_addr; 
	struct rtentry *sirt; 
	u_char saploc;

	USES_AF_LINK_RTS;

	ifdl_addr = sdl_getaddrif(ifp); 
	sdl_copy(ifdl_addr, &si_addr); 
	saploc = LLSAPLOC(&si_addr, ifp); 
	si_addr.sdl_data[saploc] = sap;
	si_addr.sdl_alen++;

	if ((sirt = rtalloc1((struct sockaddr *)&si_addr, 0))) 	
		sirt->rt_refcnt--; 
	else return(0);

	return((struct npaidbentry *)sirt->rt_llinfo);
}

/*
 * llc_seq2slot() --- We only allocate enough memory to hold the window. This
 * introduces the necessity to keep track of two ``pointers''
 *
 *        o llcl_freeslot     the next free slot to be used
 *                            this one advances modulo llcl_window
 *        o llcl_projvs       the V(S) associated with the next frame
 *                            to be set via llcl_freeslot
 *                            this one advances modulo LLC_MAX_SEQUENCE
 *
 * A new frame is inserted at llcl_output_buffers[llcl_freeslot], after
 * which both llcl_freeslot and llcl_projvs are incremented.
 *
 * The slot sl(sn) for any given sequence number sn is given by
 *
 *        sl(sn) = (llcl_freeslot + llcl_window - 1 - (llcl_projvs +
 *                  LLC_MAX_SEQUENCE- sn) % LLC_MAX_SEQUENCE) % 
 *                  llcl_window 
 *
 * i.e. we first calculate the number of frames we need to ``go back''
 * from the current one (really the next one, but that doesn't matter as
 * llcl_projvs is likewise of by plus one) and subtract that from the
 * pointer to the most recently taken frame (llcl_freeslot - 1).
 */

short
llc_seq2slot(struct llc_linkcb *linkp, short seqn)
{
	register sn = 0;

	sn = (linkp->llcl_freeslot + linkp->llcl_window - 
	      (linkp->llcl_projvs + LLC_MAX_SEQUENCE - seqn) % 
	      LLC_MAX_SEQUENCE) % linkp->llcl_window;

	return sn;
}

/*
 * LLC2 link state handler
 *
 * There is in most cases one function per LLC2 state. The LLC2 standard
 * ISO 8802-2 allows in some cases for ambiguities, i.e. we have the choice
 * to do one thing or the other. Right now I have just chosen one but have also 
 * indicated the spot by "multiple possibilities". One could make the behavior 
 * in those cases configurable, allowing the superuser to enter a profile word
 * (32/64 bits, whatever is needed) that would suit her needs [I quite like 
 * that idea, perhaps I'll get around to it].
 *
 * [Preceeding each state handler function is the description as taken from
 * ISO 8802-2, section 7.9.2.1]
 */

/*
 * ADM --- The connection component is in the asynchronous disconnected mode.
 *         It can accept an SABME PDU from a remote LLC SSAP or, at the request
 *         of the service access point user, can initiate an SABME PDU
 *         transmission to a remote LLC DSAP, to establish a data link
 *         connection. It also responds to a DISC command PDU and to any
 *         command PDU with the P bit set to ``1''.
 */
int
llc_state_ADM(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
	      int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case NL_CONNECT_REQUEST:
		llc_send(linkp, LLCFT_SABME, LLC_CMD, pollfinal);
		LLC_SETFLAG(linkp, P, pollfinal);
		LLC_SETFLAG(linkp, S, 0);
		linkp->llcl_retry = 0;
		LLC_NEWSTATE(linkp, SETUP);
		break;
	case LLCFT_SABME + LLC_CMD:
		/* 
		 * ISO 8802-2, table 7-1, ADM state says to set
		 * the P flag, yet this will cause an SABME [P] to be
		 * answered with an UA only, not an UA [F], all
		 * other `disconnected' states set the F flag, so ...
		 */
		LLC_SETFLAG(linkp, F, pollfinal);
		LLC_NEWSTATE(linkp, CONN);
		action = LLC_CONNECT_INDICATION;
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_DM, LLC_RSP, pollfinal);
		break;
	default:
		if (cmdrsp == LLC_CMD && pollfinal == 1) 
			llc_send(linkp, LLCFT_DM, LLC_RSP, 1);
		/* remain in ADM state */
	}

	return action;
}

/*
 * CONN --- The local connection component has received an SABME PDU from a
 *          remote LLC SSAP, and it is waiting for the local user to accept or
 *          refuse the connection.
 */
int
llc_state_CONN(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
	       int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case NL_CONNECT_RESPONSE:
		llc_send(linkp, LLCFT_UA, LLC_RSP, LLC_GETFLAG(linkp, F));
		LLC_RESETCOUNTER(linkp);
		LLC_SETFLAG(linkp, P, 0);
		LLC_SETFLAG(linkp, REMOTE_BUSY, 0);
		LLC_NEWSTATE(linkp, NORMAL);
		break;
	case NL_DISCONNECT_REQUEST:
		llc_send(linkp, LLCFT_DM, LLC_RSP, LLC_GETFLAG(linkp, F));
		LLC_NEWSTATE(linkp, ADM);
		break;
	case LLCFT_SABME + LLC_CMD:
		LLC_SETFLAG(linkp, F, pollfinal);
		break;
	case LLCFT_DM + LLC_RSP:
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	/* all other frames effect nothing here */
	}

	return action;
}

/*
 * RESET_WAIT --- The local connection component is waiting for the local user
 *                 to indicate a RESET_REQUEST or a DISCONNECT_REQUEST.  
 */
int
llc_state_RESET_WAIT(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		     int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case NL_RESET_REQUEST:
		if (LLC_GETFLAG(linkp, S) == 0) {
			llc_send(linkp, LLCFT_SABME, LLC_CMD, pollfinal);
			LLC_SETFLAG(linkp, P, pollfinal);
			LLC_START_ACK_TIMER(linkp);
			linkp->llcl_retry = 0;
			LLC_NEWSTATE(linkp, RESET);
		} else {
			llc_send(linkp, LLCFT_UA, LLC_RSP, 
				      LLC_GETFLAG(linkp, F));
			LLC_RESETCOUNTER(linkp);
			LLC_SETFLAG(linkp, P, 0);
			LLC_SETFLAG(linkp, REMOTE_BUSY, 0);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_RESET_CONFIRM;
		}
		break;
	case NL_DISCONNECT_REQUEST:
		if (LLC_GETFLAG(linkp, S) == 0) {
			llc_send(linkp, LLCFT_DISC, LLC_CMD, pollfinal);
			LLC_SETFLAG(linkp, P, pollfinal);
			LLC_START_ACK_TIMER(linkp);
			linkp->llcl_retry = 0;
			LLC_NEWSTATE(linkp, D_CONN);
		} else {
			llc_send(linkp, LLCFT_DM, LLC_RSP, 
				      LLC_GETFLAG(linkp, F));
			LLC_NEWSTATE(linkp, ADM);
		}
		break;
	case LLCFT_DM + LLC_RSP:
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLCFT_SABME + LLC_CMD:
		LLC_SETFLAG(linkp, S, 1);
		LLC_SETFLAG(linkp, F, pollfinal);
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_DM, LLC_RSP, pollfinal);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	}

	return action;
}

/*
 * RESET_CHECK --- The local connection component is waiting for the local user
 *                 to accept or refuse a remote reset request.
 */
int
llc_state_RESET_CHECK(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		      int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case NL_RESET_RESPONSE:
		llc_send(linkp, LLCFT_UA, LLC_RSP, LLC_GETFLAG(linkp, F));
		LLC_RESETCOUNTER(linkp);
		LLC_SETFLAG(linkp, P, 0);
		LLC_SETFLAG(linkp, REMOTE_BUSY, 0);
		LLC_NEWSTATE(linkp, NORMAL);
		break;
	case NL_DISCONNECT_REQUEST:
		llc_send(linkp, LLCFT_DM, LLC_RSP, LLC_GETFLAG(linkp, F));
		LLC_NEWSTATE(linkp, ADM);
		break;
	case LLCFT_DM + LLC_RSP:
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLCFT_SABME + LLC_CMD:
		LLC_SETFLAG(linkp, F, pollfinal);
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_DM, LLC_RSP, pollfinal);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	}

	return action;
}

/*
 * SETUP --- The connection component has transmitted an SABME command PDU to a
 *           remote LLC DSAP and is waiting for a reply.
 */
int
llc_state_SETUP(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case LLCFT_SABME + LLC_CMD:
		LLC_RESETCOUNTER(linkp);
		llc_send(linkp, LLCFT_UA, LLC_RSP, pollfinal);
		LLC_SETFLAG(linkp, S, 1);
		break;
	case LLCFT_UA + LLC_RSP:
		if (LLC_GETFLAG(linkp, P) == pollfinal) {
			LLC_STOP_ACK_TIMER(linkp);
			LLC_RESETCOUNTER(linkp);
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_SETFLAG(linkp, REMOTE_BUSY, 0);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_CONNECT_CONFIRM;
		}
		break;
	case LLC_ACK_TIMER_EXPIRED:
		if (LLC_GETFLAG(linkp, S) == 1) {
			LLC_SETFLAG(linkp, P, 0);
			LLC_SETFLAG(linkp, REMOTE_BUSY, 0),
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_CONNECT_CONFIRM;
		} else if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_SABME, LLC_CMD, pollfinal);
			LLC_SETFLAG(linkp, P, pollfinal);
			LLC_START_ACK_TIMER(linkp);
			linkp->llcl_retry++;
		} else {
			LLC_NEWSTATE(linkp, ADM);
			action = LLC_DISCONNECT_INDICATION;
		}
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_DM, LLC_RSP, pollfinal);
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLCFT_DM + LLC_RSP:
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	}

	return action;
}

/*
 * RESET --- As a result of a service access point user request or the receipt
 *           of a FRMR response PDU, the local connection component has sent an
 *           SABME command PDU to the remote LLC DSAP to reset the data link
 *           connection and is waiting for a reply.
 */
int
llc_state_RESET(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case LLCFT_SABME + LLC_CMD:
		LLC_RESETCOUNTER(linkp);
		LLC_SETFLAG(linkp, S, 1);
		llc_send(linkp, LLCFT_UA, LLC_RSP, pollfinal);
		break;
	case LLCFT_UA + LLC_RSP:
		if (LLC_GETFLAG(linkp, P) == pollfinal) {
			LLC_STOP_ACK_TIMER(linkp);
			LLC_RESETCOUNTER(linkp);
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_SETFLAG(linkp, REMOTE_BUSY, 0);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_RESET_CONFIRM;
		}
		break;
	case LLC_ACK_TIMER_EXPIRED:
		if (LLC_GETFLAG(linkp, S) == 1) {
			LLC_SETFLAG(linkp, P, 0);
			LLC_SETFLAG(linkp, REMOTE_BUSY, 0);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_RESET_CONFIRM;
		} else if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_SABME, LLC_CMD, pollfinal);
			LLC_SETFLAG(linkp, P, pollfinal);
			LLC_START_ACK_TIMER(linkp);
			linkp->llcl_retry++;
		} else {
			LLC_NEWSTATE(linkp, ADM);
			action = LLC_DISCONNECT_INDICATION;
		}
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_DM, LLC_RSP, pollfinal);
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLCFT_DM + LLC_RSP:
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	}

	return action;
}

/*
 * D_CONN --- At the request of the service access point user, the local LLC
 *            has sent a DISC command PDU to the remote LLC DSAP and is waiting
 *            for a reply.
 */
int
llc_state_D_CONN(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		 int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case LLCFT_SABME + LLC_CMD:
		llc_send(linkp, LLCFT_DM, LLC_RSP, pollfinal);
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		break;
	case LLCFT_UA + LLC_RSP:
		if (LLC_GETFLAG(linkp, P) == pollfinal) {
			LLC_STOP_ACK_TIMER(linkp);
			LLC_NEWSTATE(linkp, ADM);
		}
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_UA, LLC_RSP, pollfinal);
		break;
	case LLCFT_DM + LLC_RSP:
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		break;
	case LLC_ACK_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_DISC, LLC_CMD, pollfinal);
			LLC_SETFLAG(linkp, P, pollfinal);
			LLC_START_ACK_TIMER(linkp);
			linkp->llcl_retry++;
		} else LLC_NEWSTATE(linkp, ADM);
		break;
	}

	return action;
}

/*
 * ERROR --- The local connection component has detected an error in a received
 *           PDU and has sent a FRMR response PDU. It is waiting for a reply from 
 *           the remote connection component.
 */
int
llc_state_ERROR(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case LLCFT_SABME + LLC_CMD:
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, RESET_CHECK);
		action = LLC_RESET_INDICATION_REMOTE;
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_UA, LLC_RSP, pollfinal);
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLCFT_DM + LLC_RSP:
		LLC_STOP_ACK_TIMER(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLCFT_FRMR + LLC_RSP:
		LLC_STOP_ACK_TIMER(linkp);
		LLC_SETFLAG(linkp, S, 0);
		LLC_NEWSTATE(linkp, RESET_WAIT);
		action = LLC_FRMR_RECEIVED;
		break;
	case LLC_ACK_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_FRMR, LLC_RSP, 0);
			LLC_START_ACK_TIMER(linkp);
			linkp->llcl_retry++;
		} else {
			LLC_SETFLAG(linkp, S, 0);
			LLC_NEWSTATE(linkp, RESET_WAIT);
			action = LLC_RESET_INDICATION_LOCAL;
		}
		break;
	default:
		if (cmdrsp == LLC_CMD){
			llc_send(linkp, LLCFT_FRMR, LLC_RSP, pollfinal);
			LLC_START_ACK_TIMER(linkp);
		}
		break;

	}

	return action;
}

/*
 * NORMAL, BUSY, REJECT, AWAIT, AWAIT_BUSY, and AWAIT_REJECT all share
 * a common core state handler.
 */
int
llc_state_NBRAcore(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		   int cmdrsp, int pollfinal)
{
	int action = 0;

	switch(frame_kind + cmdrsp) {
	case NL_DISCONNECT_REQUEST:
		llc_send(linkp, LLCFT_DISC, LLC_CMD, pollfinal);
		LLC_SETFLAG(linkp, P, pollfinal);
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_START_ACK_TIMER(linkp);
		linkp->llcl_retry = 0;
		LLC_NEWSTATE(linkp, D_CONN);
		break;
	case NL_RESET_REQUEST:
		llc_send(linkp, LLCFT_SABME, LLC_CMD, pollfinal);
		LLC_SETFLAG(linkp, P, pollfinal);
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_START_ACK_TIMER(linkp);
		linkp->llcl_retry = 0;
		LLC_SETFLAG(linkp, S, 0);
		LLC_NEWSTATE(linkp, RESET);
		break;
	case LLCFT_SABME + LLC_CMD:
		LLC_SETFLAG(linkp, F, pollfinal);
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_NEWSTATE(linkp, RESET_CHECK);
		action = LLC_RESET_INDICATION_REMOTE;
		break;
	case LLCFT_DISC + LLC_CMD:
		llc_send(linkp, LLCFT_UA, LLC_RSP, pollfinal);
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLCFT_FRMR + LLC_RSP:
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_SETFLAG(linkp, S, 0);
		LLC_NEWSTATE(linkp, RESET_WAIT);
		action =  LLC_FRMR_RECEIVED;
		break;
	case LLCFT_DM + LLC_RSP:
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_NEWSTATE(linkp, ADM);
		action = LLC_DISCONNECT_INDICATION;
		break;
	case LLC_INVALID_NR + LLC_CMD:
	case LLC_INVALID_NS + LLC_CMD:
		LLC_SETFRMR(linkp, frame, cmdrsp, 
			 (frame_kind == LLC_INVALID_NR ? LLC_FRMR_Z :
			  (LLC_FRMR_V | LLC_FRMR_W)));
		llc_send(linkp, LLCFT_FRMR, LLC_RSP, pollfinal);
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_START_ACK_TIMER(linkp);
		linkp->llcl_retry = 0;
		LLC_NEWSTATE(linkp, ERROR);
		action = LLC_FRMR_SENT;
		break;
	case LLC_INVALID_NR + LLC_RSP:
	case LLC_INVALID_NS + LLC_RSP:
	case LLCFT_UA + LLC_RSP:
	case LLC_BAD_PDU: {
		char frmrcause = 0;

		switch (frame_kind) {
		case LLC_INVALID_NR: frmrcause = LLC_FRMR_Z; break;
		case LLC_INVALID_NS: frmrcause = LLC_FRMR_V | LLC_FRMR_W; break;
		default: frmrcause = LLC_FRMR_W;
		}
		LLC_SETFRMR(linkp, frame, cmdrsp, frmrcause);
		llc_send(linkp, LLCFT_FRMR, LLC_RSP, 0);
		LLC_STOP_ALL_TIMERS(linkp);
		LLC_START_ACK_TIMER(linkp);
		linkp->llcl_retry = 0;
		LLC_NEWSTATE(linkp, ERROR);
		action = LLC_FRMR_SENT;
		break;
	}
	default:
		if (cmdrsp == LLC_RSP && pollfinal == 1 && 
		    LLC_GETFLAG(linkp, P) == 0) {
			LLC_SETFRMR(linkp, frame, cmdrsp, LLC_FRMR_W);
			LLC_STOP_ALL_TIMERS(linkp);
			LLC_START_ACK_TIMER(linkp);
			linkp->llcl_retry = 0;
			LLC_NEWSTATE(linkp, ERROR);
			action = LLC_FRMR_SENT;
		}
		break;
	case LLC_P_TIMER_EXPIRED:
	case LLC_ACK_TIMER_EXPIRED:
	case LLC_REJ_TIMER_EXPIRED:
	case LLC_BUSY_TIMER_EXPIRED:
		if (linkp->llcl_retry >= llc_n2) {
			LLC_STOP_ALL_TIMERS(linkp);
			LLC_SETFLAG(linkp, S, 0);
			LLC_NEWSTATE(linkp, RESET_WAIT);
			action = LLC_RESET_INDICATION_LOCAL;
		}
		break;
	}

	return action;
}

/*
 * NORMAL --- A data link connection exists between the local LLC service access
 *            point and the remote LLC service access point. Sending and
 *            reception of information and supervisory PDUs can be performed.
 */
int
llc_state_NORMAL(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		 int cmdrsp, int pollfinal)
{
	int action = LLC_PASSITON;

	switch(frame_kind + cmdrsp) {
	case NL_DATA_REQUEST:
		if (LLC_GETFLAG(linkp, REMOTE_BUSY) == 0) {
#ifdef not_now
			if (LLC_GETFLAG(linkp, P) == 0) {
				/* multiple possibilities */
				llc_send(linkp, LLCFT_INFO, LLC_CMD, 1);
				LLC_START_P_TIMER(linkp);
				if (LLC_TIMERXPIRED(linkp, ACK) != LLC_TIMER_RUNNING)
					LLC_START_ACK_TIMER(linkp);
			} else {
#endif 
				/* multiple possibilities */
				llc_send(linkp, LLCFT_INFO, LLC_CMD, 0);
				if (LLC_TIMERXPIRED(linkp, ACK) != LLC_TIMER_RUNNING)
					LLC_START_ACK_TIMER(linkp);
#ifdef not_now
			}
#endif
			action = 0;
		}
		break;
	case LLC_LOCAL_BUSY_DETECTED:
		if (LLC_GETFLAG(linkp, P) == 0) {
			/* multiple possibilities --- action-wise */
			/* multiple possibilities --- CMD/RSP-wise */
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_START_P_TIMER(linkp);
			LLC_SETFLAG(linkp, DATA, 0);
			LLC_NEWSTATE(linkp, BUSY);
			action = 0;
		} else { 
			/* multiple possibilities --- CMD/RSP-wise */
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_SETFLAG(linkp, DATA, 0);
			LLC_NEWSTATE(linkp, BUSY);
			action = 0;			
		}
		break;
	case LLC_INVALID_NS + LLC_CMD:
	case LLC_INVALID_NS + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_REJ, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_START_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, REJECT);
			action = 0;
		} else if (pollfinal == 0 && p == 1) {
			llc_send(linkp, LLCFT_REJ, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_START_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, REJECT);
			action = 0;
		} else if ((pollfinal == 0 && p == 0) || 
			   (pollfinal == 1 && p == 1 && cmdrsp == LLC_RSP)) {
			llc_send(linkp, LLCFT_REJ, LLC_CMD, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_START_P_TIMER(linkp);
			LLC_START_REJ_TIMER(linkp);
			if (cmdrsp == LLC_RSP && pollfinal == 1) {
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			} else action = 0;
			LLC_NEWSTATE(linkp, REJECT);
		}
		break;
	} 
	case LLCFT_INFO + LLC_CMD:
	case LLCFT_INFO + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			LLC_INC(linkp->llcl_vr);
			LLC_SENDACKNOWLEDGE(linkp, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = LLC_DATA_INDICATION;
		} else if (pollfinal == 0 && p == 1) {
			LLC_INC(linkp->llcl_vr);
			LLC_SENDACKNOWLEDGE(linkp, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = LLC_DATA_INDICATION;
		} else if ((pollfinal == 0 && p == 0 && cmdrsp == LLC_CMD) ||
			   (pollfinal == p && cmdrsp == LLC_RSP)) {
			LLC_INC(linkp->llcl_vr);
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_SENDACKNOWLEDGE(linkp, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (cmdrsp == LLC_RSP && pollfinal == 1) 
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			action = LLC_DATA_INDICATION;
		}
		break;
	}
	case LLCFT_RR + LLC_CMD:
	case LLCFT_RR + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			LLC_SENDACKNOWLEDGE(linkp, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if ((pollfinal == 0) || 
			   (cmdrsp == LLC_RSP && pollfinal == 1 && p == 1)) {
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} 
		break;
	}
	case LLCFT_RNR + LLC_CMD:
	case LLCFT_RNR + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		} else if ((pollfinal == 0) || 
			   (cmdrsp == LLC_RSP && pollfinal == 1 && p == 1)) {
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case LLCFT_REJ + LLC_CMD:
	case LLCFT_REJ + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			llc_resend(linkp, LLC_RSP, 1);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if (pollfinal == 0 && p == 1) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if ((pollfinal == 0 && p == 0 && cmdrsp == LLC_CMD) ||
			   (pollfinal == p && cmdrsp == LLC_RSP)) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_START_P_TIMER(linkp);
			llc_resend(linkp, LLC_CMD, 1);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case NL_INITIATE_PF_CYCLE:
		if (LLC_GETFLAG(linkp, P) == 0) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			action = 0;
		}
		break;
	case LLC_P_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			linkp->llcl_retry++;
			LLC_NEWSTATE(linkp, AWAIT);
			action = 0;
		}
		break;
	case LLC_ACK_TIMER_EXPIRED:
	case LLC_BUSY_TIMER_EXPIRED:
		if ((LLC_GETFLAG(linkp, P) == 0) 
		    && (linkp->llcl_retry < llc_n2)) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			linkp->llcl_retry++;
			LLC_NEWSTATE(linkp, AWAIT);
			action = 0;
		}
		break;
	}
	if (action == LLC_PASSITON)
		action = llc_state_NBRAcore(linkp, frame, frame_kind, 
					    cmdrsp, pollfinal);

	return action;
}

/*
 * BUSY --- A data link connection exists between the local LLC service access
 *          point and the remote LLC service access point. I PDUs may be sent.
 *          Local conditions make it likely that the information feld of
 *          received I PDUs will be ignored. Supervisory PDUs may be both sent
 *          and received.
 */
int
llc_state_BUSY(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
	       int cmdrsp, int pollfinal)
{
	int action = LLC_PASSITON;

	switch(frame_kind + cmdrsp) {
	case NL_DATA_REQUEST:
		if (LLC_GETFLAG(linkp, REMOTE_BUSY) == 0)
			if (LLC_GETFLAG(linkp, P) == 0) {
				llc_send(linkp, LLCFT_INFO, LLC_CMD, 1);
				LLC_START_P_TIMER(linkp);
				if (LLC_TIMERXPIRED(linkp, ACK) != LLC_TIMER_RUNNING)
					LLC_START_ACK_TIMER(linkp);
				action = 0;
			} else {
				llc_send(linkp, LLCFT_INFO, LLC_CMD, 0);
				if (LLC_TIMERXPIRED(linkp, ACK) != LLC_TIMER_RUNNING)
					LLC_START_ACK_TIMER(linkp);
				action = 0;
			}
		break;
	case LLC_LOCAL_BUSY_CLEARED: {
		register int p = LLC_GETFLAG(linkp, P);
		register int df = LLC_GETFLAG(linkp, DATA);

		switch (df) {
		case 1: 
			if (p == 0) {
				/* multiple possibilities */
				llc_send(linkp, LLCFT_REJ, LLC_CMD, 1);
				LLC_START_REJ_TIMER(linkp);
				LLC_START_P_TIMER(linkp);
				LLC_NEWSTATE(linkp, REJECT);
				action = 0;
			} else {
				llc_send(linkp, LLCFT_REJ, LLC_CMD, 0);
				LLC_START_REJ_TIMER(linkp);
				LLC_NEWSTATE(linkp, REJECT);
				action = 0;
			}
			break;
		case 0:
			if (p == 0) {
				/* multiple possibilities */
				llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
				LLC_START_P_TIMER(linkp);
				LLC_NEWSTATE(linkp, NORMAL);
				action = 0;
			} else {
				llc_send(linkp, LLCFT_RR, LLC_CMD, 0);
				LLC_NEWSTATE(linkp, NORMAL);
				action = 0;
			}
			break;
		case 2:
			if (p == 0) {
				/* multiple possibilities */
				llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
				LLC_START_P_TIMER(linkp);
				LLC_NEWSTATE(linkp, REJECT);
				action = 0;
			} else {
				llc_send(linkp, LLCFT_RR, LLC_CMD, 0);
				LLC_NEWSTATE(linkp, REJECT);
				action =0;
			}
			break;
		}
		break;
	}
	case LLC_INVALID_NS + LLC_CMD:
	case LLC_INVALID_NS + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (LLC_GETFLAG(linkp, DATA) == 0)
				LLC_SETFLAG(linkp, DATA, 1);
			action = 0;
		} else if ((cmdrsp == LLC_CMD && pollfinal == 0 && p == 0) ||
			   (cmdrsp == LLC_RSP && pollfinal == p)) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (LLC_GETFLAG(linkp, DATA) == 0) 
				LLC_SETFLAG(linkp, DATA, 1);
			if (cmdrsp == LLC_RSP && pollfinal == 1) {
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			} else action = 0;
		} else if (pollfinal == 0 && p == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (LLC_GETFLAG(linkp, DATA) == 0)
				LLC_SETFLAG(linkp, DATA, 1);
			action = 0;
		}
		break;
	}
	case LLCFT_INFO + LLC_CMD:
	case LLCFT_INFO + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			LLC_INC(linkp->llcl_vr);
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (LLC_GETFLAG(linkp, DATA) == 2)
				LLC_STOP_REJ_TIMER(linkp);
			LLC_SETFLAG(linkp, DATA, 0);
			action = LLC_DATA_INDICATION;			
		} else if ((cmdrsp == LLC_CMD && pollfinal == 0 && p == 0) ||
			   (cmdrsp == LLC_RSP && pollfinal == p)) {
			LLC_INC(linkp->llcl_vr);
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (LLC_GETFLAG(linkp, DATA) == 2)
				LLC_STOP_REJ_TIMER(linkp);
			if (cmdrsp == LLC_RSP && pollfinal == 1)
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			action = LLC_DATA_INDICATION;
		} else if (pollfinal == 0 && p == 1) {
			LLC_INC(linkp->llcl_vr);
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (LLC_GETFLAG(linkp, DATA) == 2)
				LLC_STOP_REJ_TIMER(linkp);
			LLC_SETFLAG(linkp, DATA, 0);
			action = LLC_DATA_INDICATION;
		}
		break;
	}
	case LLCFT_RR + LLC_CMD:
	case LLCFT_RR + LLC_RSP: 
	case LLCFT_RNR + LLC_CMD:
	case LLCFT_RNR + LLC_RSP: { 
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (frame_kind == LLCFT_RR) {
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			} else {
				LLC_SET_REMOTE_BUSY(linkp, action);
			}
		} else if (pollfinal = 0 || 
			   (cmdrsp == LLC_RSP && pollfinal == 1)) {
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (frame_kind == LLCFT_RR) {
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			} else  {
				LLC_SET_REMOTE_BUSY(linkp, action);
			}
		}
		break;
	}
	case LLCFT_REJ + LLC_CMD:
	case LLCFT_REJ + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if ((cmdrsp == LLC_CMD && pollfinal == 0 && p == 0) ||
			   (cmdrsp == LLC_RSP && pollfinal == p)) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if (pollfinal == 0 && p == 1) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case NL_INITIATE_PF_CYCLE:
		if (LLC_GETFLAG(linkp, P) == 0) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			action = 0;
		}
		break;
	case LLC_P_TIMER_EXPIRED:
		/* multiple possibilities */
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			linkp->llcl_retry++;
			LLC_NEWSTATE(linkp, AWAIT_BUSY);
			action = 0;
		}
		break;
	case LLC_ACK_TIMER_EXPIRED:
	case LLC_BUSY_TIMER_EXPIRED:
		if (LLC_GETFLAG(linkp, P) == 0 && linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			linkp->llcl_retry++;
			LLC_NEWSTATE(linkp, AWAIT_BUSY);
			action = 0;
		}
		break;
	case LLC_REJ_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) 
			if (LLC_GETFLAG(linkp, P) == 0) {
				/* multiple possibilities */
				llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
				LLC_START_P_TIMER(linkp);
				linkp->llcl_retry++;
				LLC_SETFLAG(linkp, DATA, 1);
				LLC_NEWSTATE(linkp, AWAIT_BUSY);
				action = 0;
			} else{
				LLC_SETFLAG(linkp, DATA, 1);
				LLC_NEWSTATE(linkp, BUSY);
				action = 0;
			}
		
		break;
	}
	if (action == LLC_PASSITON)
		action = llc_state_NBRAcore(linkp, frame, frame_kind, 
					    cmdrsp, pollfinal);

	return action;
}

/*
 * REJECT --- A data link connection exists between the local LLC service
 *            access point and the remote LLC service access point. The local
 *            connection component has requested that the remote connection
 *            component resend a specific I PDU that the local connection
 *            componnent has detected as being out of sequence. Both I PDUs and
 *            supervisory PDUs may be sent and received.
 */ 
int
llc_state_REJECT(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		 int cmdrsp, int pollfinal)
{
	int action = LLC_PASSITON;

	switch(frame_kind + cmdrsp) {
	case NL_DATA_REQUEST:
		if (LLC_GETFLAG(linkp, P) == 0) {
			llc_send(linkp, LLCFT_INFO, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			if (LLC_TIMERXPIRED(linkp, ACK) != LLC_TIMER_RUNNING)
				LLC_START_ACK_TIMER(linkp);
			LLC_NEWSTATE(linkp, REJECT);
			action = 0;
		} else { 
			llc_send(linkp, LLCFT_INFO, LLC_CMD, 0);
			if (LLC_TIMERXPIRED(linkp, ACK) != LLC_TIMER_RUNNING)
				LLC_START_ACK_TIMER(linkp);
			LLC_NEWSTATE(linkp, REJECT);
			action = 0;
		}
		break;
	case NL_LOCAL_BUSY_DETECTED:
		if (LLC_GETFLAG(linkp, P) == 0) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_SETFLAG(linkp, DATA, 2);
			LLC_NEWSTATE(linkp, BUSY);
			action = 0;
		} else {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_SETFLAG(linkp, DATA, 2);
			LLC_NEWSTATE(linkp, BUSY);
			action = 0;
		}
		break;
	case LLC_INVALID_NS + LLC_CMD:
	case LLC_INVALID_NS + LLC_RSP: { 
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = 0;
		} else if (pollfinal == 0 || 
			   (cmdrsp == LLC_RSP && pollfinal == 1 && p == 1)) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			if (cmdrsp == LLC_RSP && pollfinal == 1) {
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			} else action = 0;
		}
		break;
	}
	case LLCFT_INFO + LLC_CMD:
	case LLCFT_INFO + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			LLC_INC(linkp->llcl_vr);
			LLC_SENDACKNOWLEDGE(linkp, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_STOP_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_DATA_INDICATION;
		} else if ((cmdrsp = LLC_RSP && pollfinal == p) ||
			   (cmdrsp == LLC_CMD && pollfinal == 0 && p == 0)) {
			LLC_INC(linkp->llcl_vr);
			LLC_SENDACKNOWLEDGE(linkp, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			if (cmdrsp == LLC_RSP && pollfinal == 1)
				LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_STOP_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_DATA_INDICATION;
		} else if (pollfinal == 0 && p == 1) {
			LLC_INC(linkp->llcl_vr);
			LLC_SENDACKNOWLEDGE(linkp, LLC_CMD, 0);
			LLC_STOP_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_DATA_INDICATION;
		}
		break;
	}
	case LLCFT_RR + LLC_CMD:
	case LLCFT_RR + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			LLC_SENDACKNOWLEDGE(linkp, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if (pollfinal == 0 || 
			   (cmdrsp == LLC_RSP && pollfinal == 1 && p == 1)) {
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case LLCFT_RNR + LLC_CMD:
	case LLCFT_RNR + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		} else if (pollfinal == 0 ||
			   (cmdrsp == LLC_RSP && pollfinal == 1 && p == 1)) {
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = 0;
		}
		break;
	}
	case LLCFT_REJ + LLC_CMD:
	case LLCFT_REJ + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			llc_resend(linkp, LLC_RSP, 1);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if ((cmdrsp == LLC_CMD && pollfinal == 0 && p == 0) ||
			   (cmdrsp == LLC_RSP && pollfinal == p)) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_UPDATE_P_FLAG(linkp, cmdrsp, pollfinal);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if (pollfinal == 0 && p == 1) {
			linkp->llcl_vs = nr;
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case NL_INITIATE_PF_CYCLE:
		if (LLC_GETFLAG(linkp, P) == 0) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			action = 0;
		}
		break;
	case LLC_REJ_TIMER_EXPIRED:
		if (LLC_GETFLAG(linkp, P) == 0 && linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_REJ, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_START_REJ_TIMER(linkp);
			linkp->llcl_retry++;
			action = 0;
		}
	case LLC_P_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_START_REJ_TIMER(linkp);
			linkp->llcl_retry++;
			LLC_NEWSTATE(linkp, AWAIT_REJECT);
			action = 0;
		}
		break;
	case LLC_ACK_TIMER_EXPIRED:
	case LLC_BUSY_TIMER_EXPIRED:
		if (LLC_GETFLAG(linkp, P) == 0 && linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_START_REJ_TIMER(linkp);
			linkp->llcl_retry++;
			/* 
			 * I cannot locate the description of RESET_V(S)
			 * in ISO 8802-2, table 7-1, state REJECT, last event,
			 * and  assume they meant to set V(S) to 0 ...
			 */
			linkp->llcl_vs = 0; /* XXX */
			LLC_NEWSTATE(linkp, AWAIT_REJECT);
			action = 0;
		}

		break;
	}
	if (action == LLC_PASSITON)
		action = llc_state_NBRAcore(linkp, frame, frame_kind, 
					    cmdrsp, pollfinal);

	return action;
}

/*
 * AWAIT --- A data link connection exists between the local LLC service access
 *           point and the remote LLC service access point. The local LLC is
 *           performing a timer recovery operation and has sent a command PDU
 *           with the P bit set to ``1'', and is awaiting an acknowledgement
 *           from the remote LLC. I PDUs may be received but not sent.
 *           Supervisory PDUs may be both sent and received.
 */
int
llc_state_AWAIT(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		int cmdrsp, int pollfinal)
{
	int action = LLC_PASSITON;

	switch(frame_kind + cmdrsp) {
	case LLC_LOCAL_BUSY_DETECTED:
		llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
		LLC_SETFLAG(linkp, DATA, 0);
		LLC_NEWSTATE(linkp, AWAIT_BUSY);
		action = 0;
		break;
	case LLC_INVALID_NS + LLC_CMD:
	case LLC_INVALID_NS + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_REJ, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_START_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, AWAIT_REJECT);
			action = 0;
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			llc_send(linkp, LLCFT_REJ, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_START_REJ_TIMER(linkp);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, REJECT);
		} else if (pollfinal == 0) {
			llc_send(linkp, LLCFT_REJ, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_START_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, AWAIT_REJECT);
			action = 0;
		}
		break;
	}
	case LLCFT_INFO + LLC_RSP:
	case LLCFT_INFO + LLC_CMD: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		LLC_INC(linkp->llcl_vr);
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = LLC_DATA_INDICATION;
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			llc_resend(linkp, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_DATA_INDICATION;
		} else if (pollfinal == 0) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = LLC_DATA_INDICATION;
		}
		break;
	}
	case LLCFT_RR + LLC_CMD:
	case LLCFT_RR + LLC_RSP:
	case LLCFT_REJ + LLC_CMD:
	case LLCFT_REJ + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, NORMAL);
		} else if (pollfinal == 0) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		}	
		break;
	}
	case LLCFT_RNR + LLC_CMD:
	case LLCFT_RNR + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (pollfinal == 1 && cmdrsp == LLC_CMD) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		} else if (pollfinal == 1 && cmdrsp == LLC_RSP) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			LLC_SET_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, NORMAL);
		} else if (pollfinal == 0) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case LLC_P_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_RR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			linkp->llcl_retry++;
			action = 0;
		}
		break;
	}
	if (action == LLC_PASSITON)
		action = llc_state_NBRAcore(linkp, frame, frame_kind, 
					    cmdrsp, pollfinal);

	return action;
}

/*
 * AWAIT_BUSY --- A data link connection exists between the local LLC service
 *                access point and the remote LLC service access point. The
 *                local LLC is performing a timer recovery operation and has
 *                sent a command PDU with the P bit set to ``1'', and is
 *                awaiting an acknowledgement from the remote LLC. I PDUs may
 *                not be sent. Local conditions make it likely that the
 *                information feld of receoved I PDUs will be ignored.
 *                Supervisory PDUs may be both sent and received.
 */
int
llc_state_AWAIT_BUSY(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		     int cmdrsp, int pollfinal)
{
	int action = LLC_PASSITON;

	switch(frame_kind + cmdrsp) {
	case LLC_LOCAL_BUSY_CLEARED:
		switch (LLC_GETFLAG(linkp, DATA)) {
		case 1:
			llc_send(linkp, LLCFT_REJ, LLC_CMD, 0);
			LLC_START_REJ_TIMER(linkp);
			LLC_NEWSTATE(linkp, AWAIT_REJECT);
			action = 0;
			break;
		case 0:
			llc_send(linkp, LLCFT_RR, LLC_CMD, 0);
			LLC_NEWSTATE(linkp, AWAIT);
			action = 0;
			break;
		case 2:
			llc_send(linkp, LLCFT_RR, LLC_CMD, 0);
			LLC_NEWSTATE(linkp, AWAIT_REJECT);
			action = 0;
			break;
		}
		break;
	case LLC_INVALID_NS + LLC_CMD:
	case LLC_INVALID_NS + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SETFLAG(linkp, DATA, 1);
			action = 0;
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			/* optionally */
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			LLC_SETFLAG(linkp, DATA, 1);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_NEWSTATE(linkp, BUSY);
		} else if (pollfinal == 0) {
			/* optionally */
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SETFLAG(linkp, DATA, 1);
			action = 0;
		}
	}
	case LLCFT_INFO + LLC_CMD:
	case LLCFT_INFO + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_INC(linkp->llcl_vr);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SETFLAG(linkp, DATA, 0);
			action = LLC_DATA_INDICATION;
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
			LLC_INC(linkp->llcl_vr);
			LLC_START_P_TIMER(linkp);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_SETFLAG(linkp, DATA, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_NEWSTATE(linkp, BUSY);
			action = LLC_DATA_INDICATION;
		} else if (pollfinal == 0) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
			LLC_INC(linkp->llcl_vr);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SETFLAG(linkp, DATA, 0);
			action = LLC_DATA_INDICATION;
		}
		break;
	}
	case LLCFT_RR + LLC_CMD:
	case LLCFT_REJ + LLC_CMD:
	case LLCFT_RR + LLC_RSP:
	case LLCFT_REJ + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, BUSY);
		} else if (pollfinal == 0) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case LLCFT_RNR + LLC_CMD:
	case LLCFT_RNR + LLC_RSP: {
		register int p = LLC_GETFLAG(linkp, P);
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RNR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			LLC_SET_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, BUSY);
		} else if (pollfinal == 0) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case LLC_P_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_RNR, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			linkp->llcl_retry++;
			action = 0;
		}
		break;
	}
	if (action == LLC_PASSITON)
		action = llc_state_NBRAcore(linkp, frame, frame_kind, 
					    cmdrsp, pollfinal);

	return action;
}

/*
 * AWAIT_REJECT --- A data link connection exists between the local LLC service
 *                  access point and the remote LLC service access point. The
 *                  local connection component has requested that the remote
 *                  connection component re-transmit a specific I PDU that the
 *                  local connection component has detected as being out of
 *                  sequence. Before the local LLC entered this state it was
 *                  performing a timer recovery operation and had sent a
 *                  command PDU with the P bit set to ``1'', and is still
 *                  awaiting an acknowledgment from the remote LLC. I PDUs may
 *                  be received but not transmitted. Supervisory PDUs may be
 *                  both transmitted and received.
 */
int
llc_state_AWAIT_REJECT(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		       int cmdrsp, int pollfinal)
{
	int action = LLC_PASSITON;

	switch(frame_kind + cmdrsp) {
	case LLC_LOCAL_BUSY_DETECTED:
		llc_send(linkp, LLCFT_RNR, LLC_CMD, 0);
		LLC_SETFLAG(linkp, DATA, 2);
		LLC_NEWSTATE(linkp, AWAIT_BUSY);
		action = 0;
		break;
	case LLC_INVALID_NS + LLC_CMD:
	case LLC_INVALID_NS + LLC_RSP: {
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = 0;
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			llc_resend(linkp, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, REJECT);
		} else if (pollfinal == 0) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			action = 0;	
		}
		break;
	}
	case LLCFT_INFO + LLC_CMD:
	case LLCFT_INFO + LLC_RSP: {
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			LLC_INC(linkp->llcl_vr);
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_STOP_REJ_TIMER(linkp);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_NEWSTATE(linkp, AWAIT);
			action = LLC_DATA_INDICATION;
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_INC(linkp->llcl_vr);
			LLC_STOP_P_TIMER(linkp);
			LLC_STOP_REJ_TIMER(linkp);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			llc_resend(linkp, LLC_CMD, 0);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, NORMAL);
			action = LLC_DATA_INDICATION;
		} else if (pollfinal == 0) {
			LLC_INC(linkp->llcl_vr);
			llc_send(linkp, LLCFT_RR, LLC_CMD, 0);
			LLC_STOP_REJ_TIMER(linkp);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_NEWSTATE(linkp, AWAIT);
			action = LLC_DATA_INDICATION;
		}
		break;
	}
	case LLCFT_RR + LLC_CMD:
	case LLCFT_REJ + LLC_CMD:
	case LLCFT_RR + LLC_RSP:
	case LLCFT_REJ + LLC_RSP: {
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);
		
		if (cmdrsp == LLC_CMD && pollfinal ==  1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			llc_resend(linkp, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, REJECT);
		} else if (pollfinal == 0) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_CLEAR_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case LLCFT_RNR + LLC_CMD:
	case LLCFT_RNR + LLC_RSP: {
		register int nr = LLCGBITS(frame->llc_control_ext, s_nr);

		if (cmdrsp == LLC_CMD && pollfinal == 1) {
			llc_send(linkp, LLCFT_RR, LLC_RSP, 1);
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		} else if (cmdrsp == LLC_RSP && pollfinal == 1) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			linkp->llcl_vs = nr;
			LLC_STOP_P_TIMER(linkp);
			LLC_SET_REMOTE_BUSY(linkp, action);
			LLC_NEWSTATE(linkp, REJECT);
		} else if (pollfinal == 0) {
			LLC_UPDATE_NR_RECEIVED(linkp, nr);
			LLC_SET_REMOTE_BUSY(linkp, action);
		}
		break;
	}
	case LLC_P_TIMER_EXPIRED:
		if (linkp->llcl_retry < llc_n2) {
			llc_send(linkp, LLCFT_REJ, LLC_CMD, 1);
			LLC_START_P_TIMER(linkp);
			linkp->llcl_retry++;
			action = 0;
		}
		break;
	}
	if (action == LLC_PASSITON)
		action = llc_state_NBRAcore(linkp, frame, frame_kind, 
					    cmdrsp, pollfinal);

	return action;
}


/*
 * llc_statehandler() --- Wrapper for llc_state_*() functions.
 *                         Deals with action codes and checks for
 *                         ``stuck'' links.
 */

int
llc_statehandler(struct llc_linkcb *linkp, struct llc *frame, int frame_kind,
		 int cmdrsp, int pollfinal)
{
	register int action = 0;

	/*
	 * To check for ``zombie'' links each time llc_statehandler() gets called
	 * the AGE timer of linkp is reset. If it expires llc_timer() will
	 * take care of the link --- i.e. kill it 8=)
	 */
	LLC_STARTTIMER(linkp, AGE);

	/*
	 * Now call the current statehandler function.
	 */
	action = (*linkp->llcl_statehandler)(linkp, frame, frame_kind, 
					     cmdrsp, pollfinal);
once_more_and_again:
	switch (action) {
	case LLC_CONNECT_INDICATION: {
		int naction;

		LLC_TRACE(linkp, LLCTR_INTERESTING, "CONNECT INDICATION");
		linkp->llcl_nlnext = 
		     (*linkp->llcl_sapinfo->si_ctlinput)
		      (PRC_CONNECT_INDICATION,
		       (struct sockaddr *) &linkp->llcl_addr, (caddr_t) linkp);
		if (linkp->llcl_nlnext == 0)
			naction = NL_DISCONNECT_REQUEST;
		else naction = NL_CONNECT_RESPONSE;
		action = (*linkp->llcl_statehandler)(linkp, frame, naction, 0, 0);
		goto once_more_and_again;
	}
	case LLC_CONNECT_CONFIRM:
		/* llc_resend(linkp, LLC_CMD, 0); */
		llc_start(linkp);
		break;
	case LLC_DISCONNECT_INDICATION:
		LLC_TRACE(linkp, LLCTR_INTERESTING, "DISCONNECT INDICATION");
		(*linkp->llcl_sapinfo->si_ctlinput)
		  (PRC_DISCONNECT_INDICATION, 
		   (struct sockaddr *) &linkp->llcl_addr, linkp->llcl_nlnext);
		break;
        /* internally visible only */
	case LLC_RESET_CONFIRM:
	case LLC_RESET_INDICATION_LOCAL:
		/*
		 * not much we can do here, the state machine either makes it or
		 * brakes it ...
		 */
		break;
	case LLC_RESET_INDICATION_REMOTE:
		LLC_TRACE(linkp, LLCTR_SHOULDKNOW, "RESET INDICATION (REMOTE)");
		action = (*linkp->llcl_statehandler)(linkp, frame, 
						     NL_RESET_RESPONSE, 0, 0);
		goto once_more_and_again;
	case LLC_FRMR_SENT:
		LLC_TRACE(linkp, LLCTR_URGENT, "FRMR SENT");
		break;
	case LLC_FRMR_RECEIVED:
		LLC_TRACE(linkp, LLCTR_URGEN, "FRMR RECEIVED");
		action = (*linkp->llcl_statehandler)(linkp, frame,
						     NL_RESET_REQUEST, 0, 0);
		
		goto once_more_and_again;
	case LLC_REMOTE_BUSY:
		LLC_TRACE(linkp, LLCTR_SHOULDKNOW, "REMOTE BUSY");
		break;
	case LLC_REMOTE_NOT_BUSY:
		LLC_TRACE(linkp, LLCTR_SHOULDKNOW, "REMOTE BUSY CLEARED");
		/*
		 * try to get queued frames out
		 */
		llc_start(linkp);
		break;
	}		

	/*
         * Only LLC_DATA_INDICATION is for the time being
	 * passed up to the network layer entity.
	 * The remaining action codes are for the time 
	 * being visible internally only.
         * However, this can/may be changed if necessary.
	 */

	return action;
}


/*
 * Core LLC2 routines
 */ 

/*
 * The INIT call. This routine is called once after the system is booted.
 */

llc_init()
{
	llcintrq.ifq_maxlen = IFQ_MAXLEN;
}


/*
 * In case of a link reset we need to shuffle the frames queued inside the
 * LLC2 window.
 */

void
llc_resetwindow(struct llc_linkcb *linkp)
{
	register struct mbuf *mptr = (struct mbuf *) 0;
	register struct mbuf *anchor = (struct mbuf *)0;
	register short i;

	/* Pick up all queued frames and collect them in a linked mbuf list */
	if (linkp->llcl_slotsfree != linkp->llcl_window) {
		i = llc_seq2slot(linkp, linkp->llcl_nr_received);
		anchor = mptr = linkp->llcl_output_buffers[i]; 
		for (; i != linkp->llcl_freeslot; 
		     i = llc_seq2slot(linkp, i+1)) {
			if (linkp->llcl_output_buffers[i]) {
				mptr->m_nextpkt = linkp->llcl_output_buffers[i];
				mptr = mptr->m_nextpkt;
			} else panic("LLC2 window broken");
		}
	}
	/* clean closure */
	if (mptr)
		mptr->m_nextpkt = (struct mbuf *) 0;

	/* Now --- plug 'em in again */
	if (anchor != (struct mbuf *)0) {
		for (i = 0, mptr = anchor; mptr != (struct mbuf *) 0; i++) {
			linkp->llcl_output_buffers[i] = mptr;
			mptr = mptr->m_nextpkt;
			linkp->llcl_output_buffers[i]->m_nextpkt = (struct mbuf *)0;
		}
		linkp->llcl_freeslot = i;
	} else linkp->llcl_freeslot = 0;
	
	/* We're resetting the link, the next frame to be acknowledged is 0 */
	linkp->llcl_nr_received = 0;

	/* set distance between LLC2 sequence number and the top of window to 0 */
	linkp->llcl_projvs = linkp->llcl_freeslot;

	return;
}
			
/*
 * llc_newlink() --- We allocate enough memory to contain a link control block
 *                   and initialize it properly. We don't intiate the actual
 *					 setup of the LLC2 link here.
 */
struct llc_linkcb *
llc_newlink(struct sockaddr_dl *dst, struct ifnet *ifp, struct rtentry *nlrt, 
	    caddr_t nlnext, struct rtentry *llrt)
{
	struct llc_linkcb *nlinkp;
	u_char sap = LLSAPADDR(dst);
	short llcwindow;


	/* allocate memory for link control block */
	MALLOC(nlinkp, struct llc_linkcb *, sizeof(struct llc_linkcb),
	       M_PCB, M_NOWAIT);
	if (nlinkp == 0)
		return (NULL);
	bzero((caddr_t)nlinkp, sizeof(struct llc_linkcb));
	
	/* copy link address */
	sdl_copy(dst, &nlinkp->llcl_addr);

	/* hold on to the network layer route entry */
	nlinkp->llcl_nlrt = nlrt;

	/* likewise the network layer control block */
	nlinkp->llcl_nlnext = nlnext;

	/* jot down the link layer route entry */
	nlinkp->llcl_llrt = llrt;

	/* reset writeq */
	nlinkp->llcl_writeqh = nlinkp->llcl_writeqt = NULL;

	/* setup initial state handler function */
	nlinkp->llcl_statehandler = llc_state_ADM;
	
	/* hold on to interface pointer */
	nlinkp->llcl_if = ifp;

	/* get service access point information */
	nlinkp->llcl_sapinfo = llc_getsapinfo(sap, ifp);

	/* get window size from SAP info block */
	if ((llcwindow = nlinkp->llcl_sapinfo->si_window) == 0)
		llcwindow = LLC_MAX_WINDOW;

	/* allocate memory for window buffer */
	MALLOC(nlinkp->llcl_output_buffers, struct mbuf **, 
	       llcwindow*sizeof(struct mbuf *), M_PCB, M_NOWAIT);
	if (nlinkp->llcl_output_buffers == 0) {
		FREE(nlinkp, M_PCB);
		return(NULL);
	}
	bzero((caddr_t)nlinkp->llcl_output_buffers, 
	      llcwindow*sizeof(struct mbuf *));

	/* set window size & slotsfree */
	nlinkp->llcl_slotsfree = nlinkp->llcl_window = llcwindow;

	/* enter into linked listed of link control blocks */
	insque(nlinkp, &llccb_q);

	return(nlinkp);
}

/*
 * llc_dellink() --- farewell to link control block
 */
llc_dellink(struct llc_linkcb *linkp)
{
	register struct mbuf *m;
	register struct mbuf *n;
	register struct npaidbentry *sapinfo = linkp->llcl_sapinfo;
	register i;

	/* notify upper layer of imminent death */
	if (linkp->llcl_nlnext && sapinfo->si_ctlinput)
		(*sapinfo->si_ctlinput)
		   (PRC_DISCONNECT_INDICATION, 
		    (struct sockaddr *)&linkp->llcl_addr, linkp->llcl_nlnext);

	/* pull the plug */
	if (linkp->llcl_llrt)
		((struct npaidbentry *)(linkp->llcl_llrt->rt_llinfo))->np_link 
			= (struct llc_linkcb *) 0;

	/* leave link control block queue */
	remque(linkp);

	/* drop queued packets */
	for (m = linkp->llcl_writeqh; m;) {
		n = m->m_act;
		m_freem(m);
		m = n;
	}

	/* drop packets in the window */
	for(i = 0; i < linkp->llcl_window; i++)
		if (linkp->llcl_output_buffers[i])
			m_freem(linkp->llcl_output_buffers[i]);

	/* return the window space */
	FREE((caddr_t)linkp->llcl_output_buffers, M_PCB);

	/* return the control block space --- now it's gone ... */
	FREE((caddr_t)linkp, M_PCB);
}

llc_decode(struct llc* frame, struct llc_linkcb * linkp)
{
	register int ft = LLC_BAD_PDU;

	if ((frame->llc_control & 01) == 0) {
		ft = LLCFT_INFO;
	/* S or U frame ? */
	} else switch (frame->llc_control) {

	/* U frames */
	case LLC_UI:
	case LLC_UI_P:     ft = LLC_UI; break;
	case LLC_DM:
	case LLC_DM_P:     ft =LLCFT_DM; break;
	case LLC_DISC:
	case LLC_DISC_P:   ft = LLCFT_DISC; break;
	case LLC_UA:
	case LLC_UA_P:     ft = LLCFT_UA; break;
	case LLC_SABME:
	case LLC_SABME_P:  ft = LLCFT_SABME; break;
	case LLC_FRMR:
	case LLC_FRMR_P:   ft = LLCFT_FRMR; break;
	case LLC_XID:
	case LLC_XID_P:    ft = LLCFT_XID; break;
	case LLC_TEST:
	case LLC_TEST_P:   ft = LLCFT_TEST; break;

	/* S frames */
	case LLC_RR:       ft = LLCFT_RR; break;
	case LLC_RNR:      ft = LLCFT_RNR; break;
	case LLC_REJ:      ft = LLCFT_REJ; break;
	} /* switch */

	if (linkp) {
		switch (ft) {
		case LLCFT_INFO:
			if (LLCGBITS(frame->llc_control, i_ns) != linkp->llcl_vr) {
				ft = LLC_INVALID_NS;
				break;
			}
			/* fall thru --- yeeeeeee */
		case LLCFT_RR:
		case LLCFT_RNR:
		case LLCFT_REJ:
			/* splash! */
			if (LLC_NR_VALID(linkp, LLCGBITS(frame->llc_control_ext, 
							 s_nr)) == 0)
				ft = LLC_INVALID_NR;
			break;
		}
	}

	return ft;
}

/*
 * llc_anytimersup() --- Checks if at least one timer is still up and running.
 */
int
llc_anytimersup(struct llc_linkcb * linkp)
{
	register int i;
	
	FOR_ALL_LLC_TIMERS(i)
		if (linkp->llcl_timers[i] > 0)
			break;
	if (i == LLC_AGE_SHIFT)
		return 0;
	else return 1;
}

/*
 * llc_link_dump() - dump link info
 */

#define SAL(s) ((struct sockaddr_dl *)&(s)->llcl_addr)
#define CHECK(l, s) if (LLC_STATEEQ(l, s)) return #s

char *timer_names[] = {"ACK", "P", "BUSY", "REJ", "AGE"};

char *
llc_getstatename(struct llc_linkcb *linkp)
{
	CHECK(linkp, ADM);
	CHECK(linkp, CONN);
	CHECK(linkp, RESET_WAIT);
	CHECK(linkp, RESET_CHECK);
	CHECK(linkp, SETUP);
	CHECK(linkp, RESET);
	CHECK(linkp, D_CONN);
	CHECK(linkp, ERROR);
	CHECK(linkp, NORMAL);
	CHECK(linkp, BUSY);
	CHECK(linkp, REJECT);
	CHECK(linkp, AWAIT);
	CHECK(linkp, AWAIT_BUSY);
	CHECK(linkp, AWAIT_REJECT);

	return "UNKNOWN - eh?";
}

void
llc_link_dump(struct llc_linkcb* linkp, const char *message)
{
	register int i;
	register char *state;

	/* print interface */
	printf("if %s%d\n", linkp->llcl_if->if_name, linkp->llcl_if->if_unit);
	
	/* print message */
	printf(">> %s <<\n", message);

	/* print MAC and LSAP */
	printf("llc addr ");
	for (i = 0; i < (SAL(linkp)->sdl_alen)-2; i++)
		printf("%x:", (char)*(LLADDR(SAL(linkp))+i) & 0xff);
	printf("%x,", (char)*(LLADDR(SAL(linkp))+i) & 0xff);
	printf("%x\n", (char)*(LLADDR(SAL(linkp))+i+1) & 0xff);

	/* print state we're in and timers */
        printf("state %s, ", llc_getstatename(linkp));
        for (i = LLC_ACK_SHIFT; i < LLC_AGE_SHIFT; i++)
		printf("%s-%c %d/", timer_names[i], 
		       (linkp->llcl_timerflags & (1<<i) ? 'R' : 'S'),
		       linkp->llcl_timers[i]);
	printf("%s-%c %d\n", timer_names[i], (linkp->llcl_timerflags & (1<<i) ? 
					     'R' : 'S'), linkp->llcl_timers[i]);

	/* print flag values */
	printf("flags P %d/F %d/S %d/DATA %d/REMOTE_BUSY %d\n",
	       LLC_GETFLAG(linkp, P), LLC_GETFLAG(linkp, S), 
	       LLC_GETFLAG(linkp, DATA), LLC_GETFLAG(linkp, REMOTE_BUSY));

	/* print send and receive state variables, ack, and window */
	printf("V(R) %d/V(S) %d/N(R) received %d/window %d/freeslot %d\n",
	       linkp->llcl_vs, linkp->llcl_vr, linkp->llcl_nr_received,
	       linkp->llcl_window, linkp->llcl_freeslot);

	/* further expansions can follow here */

}

void
llc_trace(struct llc_linkcb *linkp, int level, const char *message)
{
	if (linkp->llcl_sapinfo->si_trace && level > llc_tracelevel)
		llc_link_dump(linkp, message);

	return;
}
