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
/*-
 * Copyright (c) 1991, 1993
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
 *	@(#)tp_iso.c	8.1 (Berkeley) 6/10/93
 */

/***********************************************************
		Copyright IBM Corporation 1987

                      All Rights Reserved

Permission to use, copy, modify, and distribute this software and its 
documentation for any purpose and without fee is hereby granted, 
provided that the above copyright notice appear in all copies and that
both that copyright notice and this permission notice appear in 
supporting documentation, and that the name of IBM not be
used in advertising or publicity pertaining to distribution of the
software without specific, written prior permission.  

IBM DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
IBM BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
SOFTWARE.

******************************************************************/

/*
 * ARGO Project, Computer Sciences Dept., University of Wisconsin - Madison
 */
/* 
 * ARGO TP
 *
 * Here is where you find the iso-dependent code.  We've tried
 * keep all net-level and (primarily) address-family-dependent stuff
 * out of the tp source, and everthing here is reached indirectly
 * through a switch table (struct nl_protosw *) tpcb->tp_nlproto 
 * (see tp_pcb.c). 
 * The routines here are:
 * 		iso_getsufx: gets transport suffix out of an isopcb structure.
 * 		iso_putsufx: put transport suffix into an isopcb structure.
 *		iso_putnetaddr: put a whole net addr into an isopcb.
 *		iso_getnetaddr: get a whole net addr from an isopcb.
 *		iso_cmpnetaddr: compare a whole net addr from an isopcb.
 *		iso_recycle_suffix: clear suffix for reuse in isopcb
 * 		tpclnp_ctlinput: handle ER CNLPdu : icmp-like stuff
 * 		tpclnp_mtu: figure out what size tpdu to use
 *		tpclnp_input: take a pkt from clnp, strip off its clnp header, 
 *				give to tp
 *		tpclnp_output_dg: package a pkt for clnp given 2 addresses & some data
 *		tpclnp_output: package a pkt for clnp given an isopcb & some data
 */

#if ISO

#include <sys/param.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/protosw.h>

#include <net/if.h>
#include <net/route.h>

#include <netiso/argo_debug.h>
#include <netiso/tp_param.h>
#include <netiso/tp_stat.h>
#include <netiso/tp_pcb.h>
#include <netiso/tp_trace.h>
#include <netiso/tp_stat.h>
#include <netiso/tp_tpdu.h>
#include <netiso/tp_clnp.h>
#include <netiso/cltp_var.h>

/*
 * CALLED FROM:
 * 	pr_usrreq() on PRU_BIND, PRU_CONNECT, PRU_ACCEPT, and PRU_PEERADDR
 * FUNCTION, ARGUMENTS:
 * 	The argument (which) takes the value TP_LOCAL or TP_FOREIGN.
 */

iso_getsufx(isop, lenp, data_out, which)
	struct isopcb *isop;
	u_short *lenp;
	caddr_t data_out;
	int which;
{
	register struct sockaddr_iso *addr = 0;

	switch (which) {
	case TP_LOCAL:
		addr = isop->isop_laddr;
		break;

	case TP_FOREIGN:
		addr = isop->isop_faddr;
	}
	if (addr)
		bcopy(TSEL(addr), data_out, (*lenp = addr->siso_tlen));
}

/* CALLED FROM:
 * 	tp_newsocket(); i.e., when a connection is being established by an
 * 	incoming CR_TPDU.
 *
 * FUNCTION, ARGUMENTS:
 * 	Put a transport suffix (found in name) into an isopcb structure (isop).
 * 	The argument (which) takes the value TP_LOCAL or TP_FOREIGN.
 */
void
iso_putsufx(isop, sufxloc, sufxlen, which)
	struct isopcb *isop;
	caddr_t sufxloc;
	int sufxlen, which;
{
	struct sockaddr_iso **dst, *backup;
	register struct sockaddr_iso *addr;
	struct mbuf *m;
	int len;

	switch (which) {
	default:
		return;

	case TP_LOCAL:
		dst = &isop->isop_laddr;
		backup = &isop->isop_sladdr;
		break;

	case TP_FOREIGN:
		dst = &isop->isop_faddr;
		backup = &isop->isop_sfaddr;
	}
	if ((addr = *dst) == 0) {
		addr = *dst = backup;
		addr->siso_nlen = 0;
		addr->siso_slen = 0;
		addr->siso_plen = 0;
		printf("iso_putsufx on un-initialized isopcb\n");
	}
	len = sufxlen + addr->siso_nlen +
			(sizeof(*addr) - sizeof(addr->siso_data));
	if (addr == backup) {
		if (len > sizeof(*addr)) {
				m = m_getclr(M_DONTWAIT, MT_SONAME);
				if (m == 0)
					return;
				addr = *dst = mtod(m, struct sockaddr_iso *);
				*addr = *backup;
				m->m_len = len;
		}
	}
	bcopy(sufxloc, TSEL(addr), sufxlen);
	addr->siso_tlen = sufxlen;
	addr->siso_len = len;
}

/*
 * CALLED FROM:
 * 	tp.trans whenever we go into REFWAIT state.
 * FUNCTION and ARGUMENT:
 *	 Called when a ref is frozen, to allow the suffix to be reused. 
 * 	(isop) is the net level pcb.  This really shouldn't have to be
 * 	done in a NET level pcb but... for the internet world that just
 * 	the way it is done in BSD...
 * 	The alternative is to have the port unusable until the reference
 * 	timer goes off.
 */
void
iso_recycle_tsuffix(isop)
	struct isopcb	*isop;
{
	isop->isop_laddr->siso_tlen = isop->isop_faddr->siso_tlen = 0;
}

/*
 * CALLED FROM:
 * 	tp_newsocket(); i.e., when a connection is being established by an
 * 	incoming CR_TPDU.
 *
 * FUNCTION and ARGUMENTS:
 * 	Copy a whole net addr from a struct sockaddr (name).
 * 	into an isopcb (isop).
 * 	The argument (which) takes values TP_LOCAL or TP_FOREIGN
 */ 
void
iso_putnetaddr(isop, name, which)
	register struct isopcb	*isop;
	struct sockaddr_iso	*name;
	int which;
{
	struct sockaddr_iso **sisop, *backup;
	register struct sockaddr_iso *siso;

	switch (which) {
	default:
		printf("iso_putnetaddr: should panic\n");
		return;
	case TP_LOCAL:
		sisop = &isop->isop_laddr;
		backup = &isop->isop_sladdr;
		break;
	case TP_FOREIGN:
		sisop = &isop->isop_faddr;
		backup = &isop->isop_sfaddr;
	}
	siso = ((*sisop == 0) ? (*sisop = backup) : *sisop);
	IFDEBUG(D_TPISO)
		printf("ISO_PUTNETADDR\n");
		dump_isoaddr(isop->isop_faddr);
	ENDDEBUG
	siso->siso_addr = name->siso_addr;
}

/*
 * CALLED FROM:
 * 	tp_input() when a connection is being established by an
 * 	incoming CR_TPDU, and considered for interception.
 *
 * FUNCTION and ARGUMENTS:
 * 	compare a whole net addr from a struct sockaddr (name),
 * 	with that implicitly stored in an isopcb (isop).
 * 	The argument (which) takes values TP_LOCAL or TP_FOREIGN.
 */ 
iso_cmpnetaddr(isop, name, which)
	register struct isopcb	*isop;
	register struct sockaddr_iso	*name;
	int which;
{
	struct sockaddr_iso **sisop, *backup;
	register struct sockaddr_iso *siso;

	switch (which) {
	default:
		printf("iso_cmpnetaddr: should panic\n");
		return 0;
	case TP_LOCAL:
		sisop = &isop->isop_laddr;
		backup = &isop->isop_sladdr;
		break;
	case TP_FOREIGN:
		sisop = &isop->isop_faddr;
		backup = &isop->isop_sfaddr;
	}
	siso = ((*sisop == 0) ? (*sisop = backup) : *sisop);
	IFDEBUG(D_TPISO)
		printf("ISO_CMPNETADDR\n");
		dump_isoaddr(siso);
	ENDDEBUG
	if (name->siso_tlen && bcmp(TSEL(name), TSEL(siso), name->siso_tlen))
		return (0);
	return (bcmp((caddr_t)name->siso_data,
			 (caddr_t)siso->siso_data, name->siso_nlen) == 0);
}

/*
 * CALLED FROM:
 *  pr_usrreq() PRU_SOCKADDR, PRU_ACCEPT, PRU_PEERADDR
 * FUNCTION and ARGUMENTS:
 * 	Copy a whole net addr from an isopcb (isop) into
 * 	a struct sockaddr (name).
 * 	The argument (which) takes values TP_LOCAL or TP_FOREIGN.
 */ 

void
iso_getnetaddr( isop, name, which)
	struct isopcb *isop;
	struct mbuf *name;
	int which;
{
	struct sockaddr_iso *siso =
		(which == TP_LOCAL ? isop->isop_laddr : isop->isop_faddr);
	if (siso)
		bcopy((caddr_t)siso, mtod(name, caddr_t),
				(unsigned)(name->m_len = siso->siso_len));
	else
		name->m_len = 0;
}
/*
 * NAME: 	tpclnp_mtu()
 *
 * CALLED FROM:
 *  tp_route_to() on incoming CR, CC, and pr_usrreq() for PRU_CONNECT
 *
 * FUNCTION, ARGUMENTS, and RETURN VALUE:
 *
 * Perform subnetwork dependent part of determining MTU information.
 * It appears that setting a double pointer to the rtentry associated with
 * the destination, and returning the header size for the network protocol
 * suffices.
 * 
 * SIDE EFFECTS:
 * Sets tp_routep pointer in pcb.
 *
 * NOTES:
 */
tpclnp_mtu(tpcb)
register struct tp_pcb *tpcb;
{
	struct isopcb			*isop = (struct isopcb *)tpcb->tp_npcb;

	IFDEBUG(D_CONN)
		printf("tpclnp_mtu(tpcb)\n", tpcb);
	ENDDEBUG
	tpcb->tp_routep = &(isop->isop_route.ro_rt);
	if (tpcb->tp_netservice == ISO_CONS)
		return 0;
	else
		return (sizeof(struct clnp_fixed) + sizeof(struct clnp_segment) +
			2 * sizeof(struct iso_addr));

}

/*
 * CALLED FROM:
 *  tp_emit()
 * FUNCTION and ARGUMENTS:
 *  Take a packet(m0) from tp and package it so that clnp will accept it.
 *  This means prepending space for the clnp header and filling in a few
 *  of the fields.
 *  isop is the isopcb structure; datalen is the length of the data in the
 *  mbuf string m0.
 * RETURN VALUE:
 *  whatever (E*) is returned form the net layer output routine.
 */

int
tpclnp_output(isop, m0, datalen, nochksum)
	struct isopcb		*isop;
	struct mbuf 		*m0;
	int 				datalen;
	int					nochksum;
{
	register struct mbuf *m = m0;
	IncStat(ts_tpdu_sent);

	IFDEBUG(D_TPISO)
		struct tpdu *hdr = mtod(m0, struct tpdu *);

		printf(
"abt to call clnp_output: datalen 0x%x, hdr.li 0x%x, hdr.dutype 0x%x nocsum x%x dst addr:\n",
			datalen,
			(int)hdr->tpdu_li, (int)hdr->tpdu_type, nochksum);
		dump_isoaddr(isop->isop_faddr);
		printf("\nsrc addr:\n");
		dump_isoaddr(isop->isop_laddr);
		dump_mbuf(m0, "at tpclnp_output");
	ENDDEBUG

	return 
		clnp_output(m0, isop, datalen,  /* flags */nochksum ? CLNP_NO_CKSUM : 0);
}

/*
 * CALLED FROM:
 *  tp_error_emit()
 * FUNCTION and ARGUMENTS:
 *  This is a copy of tpclnp_output that takes the addresses
 *  instead of a pcb.  It's used by the tp_error_emit, when we
 *  don't have an iso_pcb with which to call the normal output rtn.
 * RETURN VALUE:
 *  ENOBUFS or
 *  whatever (E*) is returned form the net layer output routine.
 */

int
tpclnp_output_dg(laddr, faddr, m0, datalen, ro, nochksum)
	struct iso_addr		*laddr, *faddr;
	struct mbuf 		*m0;
	int 				datalen;
	struct route 		*ro;
	int					nochksum;
{
	struct isopcb		tmppcb;
	int					err;
	int					flags;
	register struct mbuf *m = m0;

	IFDEBUG(D_TPISO)
		printf("tpclnp_output_dg  datalen 0x%x m0 0x%x\n", datalen, m0);
	ENDDEBUG

	/*
	 *	Fill in minimal portion of isopcb so that clnp can send the
	 *	packet.
	 */
	bzero((caddr_t)&tmppcb, sizeof(tmppcb));
	tmppcb.isop_laddr = &tmppcb.isop_sladdr;
	tmppcb.isop_laddr->siso_addr = *laddr;
	tmppcb.isop_faddr = &tmppcb.isop_sfaddr;
	tmppcb.isop_faddr->siso_addr = *faddr;

	IFDEBUG(D_TPISO)
		printf("tpclnp_output_dg  faddr: \n");
		dump_isoaddr(&tmppcb.isop_sfaddr);
		printf("\ntpclnp_output_dg  laddr: \n");
		dump_isoaddr(&tmppcb.isop_sladdr);
		printf("\n");
	ENDDEBUG

	/*
	 *	Do not use packet cache since this is a one shot error packet
	 */
	flags = (CLNP_NOCACHE|(nochksum?CLNP_NO_CKSUM:0));

	IncStat(ts_tpdu_sent);

	err = clnp_output(m0, &tmppcb, datalen,  flags);
	
	/*
	 *	Free route allocated by clnp (if the route was indeed allocated)
	 */
	if (tmppcb.isop_route.ro_rt)
		RTFREE(tmppcb.isop_route.ro_rt);
	
	return(err);
}
/*
 * CALLED FROM:
 * 	clnp's input routine, indirectly through the protosw.
 * FUNCTION and ARGUMENTS:
 * Take a packet (m) from clnp, strip off the clnp header and give it to tp
 * No return value.  
 */
ProtoHook
tpclnp_input(m, src, dst, clnp_len, ce_bit)
	register struct mbuf *m;
	struct sockaddr_iso *src, *dst;
	int clnp_len, ce_bit;
{
	struct mbuf *tp_inputprep();
	int tp_input(), cltp_input(), (*input)() = tp_input;

	IncStat(ts_pkt_rcvd);

	IFDEBUG(D_TPINPUT)
		printf("tpclnp_input: m 0x%x clnp_len 0x%x\n", m, clnp_len);
		dump_mbuf(m, "at tpclnp_input");
	ENDDEBUG
	/*
	 * CLNP gives us an mbuf chain WITH the clnp header pulled up,
	 * and the length of the clnp header.
	 * First, strip off the Clnp header. leave the mbuf there for the
	 * pullup that follows.
	 */
	m->m_len -= clnp_len;
	m->m_data += clnp_len;
	m->m_pkthdr.len -= clnp_len;
	/* XXXX: should probably be in clnp_input */
	switch (dst->siso_data[dst->siso_nlen - 1]) {
#if TUBA
	case ISOPROTO_TCP:
		return (tuba_tcpinput(m, src, dst));
#endif
	case 0:
		if (m->m_len == 0 && (m = m_pullup(m, 1)) == 0)
			return 0;
		if (*(mtod(m, u_char *)) == ISO10747_IDRP)
			return (idrp_input(m, src, dst));
	}
	m = tp_inputprep(m);
	if (m == 0)
		return 0;
	if (mtod(m, u_char *)[1] == UD_TPDU_type)
		input = cltp_input;

	IFDEBUG(D_TPINPUT)
		dump_mbuf(m, "after tpclnp_input both pullups");
	ENDDEBUG

	IFDEBUG(D_TPISO)
		printf("calling %sinput : src 0x%x, dst 0x%x, src addr:\n", 
			(input == tp_input ? "tp_" : "clts_"), src, dst);
		dump_isoaddr(src);
		printf(" dst addr:\n");
		dump_isoaddr(dst);
	ENDDEBUG

	(void) (*input)(m, (struct sockaddr *)src, (struct sockaddr *)dst,
				0, tpclnp_output_dg, ce_bit);

	IFDEBUG(D_QUENCH)
		{ 
			if(time.tv_usec & 0x4 && time.tv_usec & 0x40) {
				printf("tpclnp_input: FAKING %s\n", 
					tp_stat.ts_pkt_rcvd & 0x1?"QUENCH":"QUENCH2");
				if(tp_stat.ts_pkt_rcvd & 0x1) {
					tpclnp_ctlinput(PRC_QUENCH, &src);
				} else {
					tpclnp_ctlinput(PRC_QUENCH2, &src);
				}
			}
		}
	ENDDEBUG

	return 0;
}

ProtoHook
iso_rtchange()
{
	return 0;
}

/*
 * CALLED FROM:
 *  tpclnp_ctlinput()
 * FUNCTION and ARGUMENTS:
 *  find the tpcb pointer and pass it to tp_quench
 */
void
tpiso_decbit(isop)
	struct isopcb *isop;
{
	tp_quench((struct tp_pcb *)isop->isop_socket->so_pcb, PRC_QUENCH2);
}
/*
 * CALLED FROM:
 *  tpclnp_ctlinput()
 * FUNCTION and ARGUMENTS:
 *  find the tpcb pointer and pass it to tp_quench
 */
void
tpiso_quench(isop)
	struct isopcb *isop;
{
	tp_quench((struct tp_pcb *)isop->isop_socket->so_pcb, PRC_QUENCH);
}

/*
 * CALLED FROM:
 *  The network layer through the protosw table.
 * FUNCTION and ARGUMENTS:
 *	When clnp an ICMP-like msg this gets called.
 *	It either returns an error status to the user or
 *	it causes all connections on this address to be aborted
 *	by calling the appropriate xx_notify() routine.
 *	(cmd) is the type of ICMP error.   
 * 	(siso) is the address of the guy who sent the ER CLNPDU
 */
ProtoHook
tpclnp_ctlinput(cmd, siso)
	int cmd;
	struct sockaddr_iso *siso;
{
	extern u_char inetctlerrmap[];
	extern ProtoHook tpiso_abort();
	extern ProtoHook iso_rtchange();
	extern ProtoHook tpiso_reset();
	void iso_pcbnotify();

	IFDEBUG(D_TPINPUT)
		printf("tpclnp_ctlinput1: cmd 0x%x addr: \n", cmd);
		dump_isoaddr(siso);
	ENDDEBUG

	if (cmd < 0 || cmd > PRC_NCMDS)
		return 0;
	if (siso->siso_family != AF_ISO)
		return 0;
	switch (cmd) {

		case	PRC_QUENCH2:
			iso_pcbnotify(&tp_isopcb, siso, 0, (int (*)())tpiso_decbit);
			break;

		case	PRC_QUENCH:
			iso_pcbnotify(&tp_isopcb, siso, 0, (int (*)())tpiso_quench);
			break;

		case	PRC_TIMXCEED_REASS:
		case	PRC_ROUTEDEAD:
			iso_pcbnotify(&tp_isopcb, siso, 0, tpiso_reset);
			break;

		case	PRC_HOSTUNREACH:
		case	PRC_UNREACH_NET:
		case	PRC_IFDOWN:
		case	PRC_HOSTDEAD:
			iso_pcbnotify(&tp_isopcb, siso,
					(int)inetctlerrmap[cmd], iso_rtchange);
			break;

		default:
		/*
		case	PRC_MSGSIZE:
		case	PRC_UNREACH_HOST:
		case	PRC_UNREACH_PROTOCOL:
		case	PRC_UNREACH_PORT:
		case	PRC_UNREACH_NEEDFRAG:
		case	PRC_UNREACH_SRCFAIL:
		case	PRC_REDIRECT_NET:
		case	PRC_REDIRECT_HOST:
		case	PRC_REDIRECT_TOSNET:
		case	PRC_REDIRECT_TOSHOST:
		case	PRC_TIMXCEED_INTRANS:
		case	PRC_PARAMPROB:
		*/
		iso_pcbnotify(&tp_isopcb, siso, (int)inetctlerrmap[cmd], tpiso_abort);
		break;
	}
	return 0;
}
/*
 * XXX - Variant which is called by clnp_er.c with an isoaddr rather
 * than a sockaddr_iso.
 */

static struct sockaddr_iso siso = {sizeof(siso), AF_ISO};
tpclnp_ctlinput1(cmd, isoa)
	int cmd;
	struct iso_addr *isoa;
{
	bzero((caddr_t)&siso.siso_addr, sizeof(siso.siso_addr));
	bcopy((caddr_t)isoa, (caddr_t)&siso.siso_addr, isoa->isoa_len);
	tpclnp_ctlinput(cmd, &siso);
}

/*
 * These next 2 routines are
 * CALLED FROM:
 *	xxx_notify() from tp_ctlinput() when
 *  net level gets some ICMP-equiv. type event.
 * FUNCTION and ARGUMENTS:
 *  Cause the connection to be aborted with some sort of error
 *  reason indicating that the network layer caused the abort.
 *  Fakes an ER TPDU so we can go through the driver.
 *  abort always aborts the TP connection.
 *  reset may or may not, depending on the TP class that's in use.
 */
ProtoHook
tpiso_abort(isop)
	struct isopcb *isop;
{
	struct tp_event e;

	IFDEBUG(D_CONN)
		printf("tpiso_abort 0x%x\n", isop);
	ENDDEBUG
	e.ev_number = ER_TPDU;
	e.ATTR(ER_TPDU).e_reason = ECONNABORTED;
	return  tp_driver((struct tp_pcb *)isop->isop_socket->so_pcb, &e);
}

ProtoHook
tpiso_reset(isop)
	struct isopcb *isop;
{
	struct tp_event e;

	e.ev_number = T_NETRESET;
	return tp_driver((struct tp_pcb *)isop->isop_socket->so_pcb, &e);

}

#endif /* ISO */
