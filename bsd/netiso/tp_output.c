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
 *	@(#)tp_output.c	8.1 (Berkeley) 6/10/93
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
 * In here is tp_ctloutput(), the guy called by [sg]etsockopt(),
 */

#include <sys/param.h>
#include <sys/mbuf.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/errno.h>
#include <sys/time.h>
#include <sys/kernel.h>

#include <netiso/tp_param.h>
#include <netiso/tp_user.h>
#include <netiso/tp_stat.h>
#include <netiso/tp_ip.h>
#include <netiso/tp_clnp.h>
#include <netiso/tp_timer.h>
#include <netiso/argo_debug.h>
#include <netiso/tp_pcb.h>
#include <netiso/tp_trace.h>

#define TPDUSIZESHIFT 24
#define CLASSHIFT 16

/*
 * NAME: 	tp_consistency()
 *
 * CALLED FROM:
 * 	tp_ctloutput(), tp_input()
 *
 * FUNCTION and ARGUMENTS:
 * 	Checks the consistency of options and tpdusize with class,
 *	using the parameters passed in via (param).
 *	(cmd) may be TP_STRICT or TP_FORCE or both.
 *  Force means it will set all the values in (tpcb) to those in
 *  the input arguements iff no errors were encountered.
 *  Strict means that no inconsistency will be tolerated.  If it's
 *  not used, checksum and tpdusize inconsistencies will be tolerated.
 *  The reason for this is that in some cases, when we're negotiating down 
 *	from class  4, these options should be changed but should not 
 *  cause negotiation to fail.
 *
 * RETURNS
 *  E* or EOK
 *  E* if the various parms aren't ok for a given class
 *  EOK if they are ok for a given class
 */

int
tp_consistency( tpcb, cmd, param )
	u_int cmd;
	struct tp_conn_param *param;
	struct tp_pcb *tpcb;
{
	register int	error = EOK;
	int 			class_to_use  = tp_mask_to_num(param->p_class);

	IFTRACE(D_SETPARAMS)
		tptrace(TPPTmisc, 
		"tp_consist enter class_to_use dontchange param.class cmd", 
		class_to_use, param->p_dont_change_params, param->p_class, cmd);
	ENDTRACE
	IFDEBUG(D_SETPARAMS)
		printf("tp_consistency %s %s\n", 
			cmd& TP_FORCE?	"TP_FORCE":	"",
			cmd& TP_STRICT?	"TP_STRICT":"");
	ENDDEBUG
	if ((cmd & TP_FORCE) && (param->p_dont_change_params)) {
		cmd &= ~TP_FORCE;
	}
	/* can switch net services within a domain, but
	 * cannot switch domains 
	 */
	switch( param->p_netservice) {
	case ISO_CONS:
	case ISO_CLNS:
	case ISO_COSNS:
		/* param->p_netservice in ISO DOMAIN */
		if(tpcb->tp_domain != AF_ISO ) {
			error = EINVAL; goto done;
		}
		break;
	case IN_CLNS:
		/* param->p_netservice in INET DOMAIN */
		if( tpcb->tp_domain != AF_INET ) {
			error = EINVAL; goto done;
		}
		break;
		/* no others not possible-> netservice is a 2-bit field! */
	}

	IFDEBUG(D_SETPARAMS)
		printf("p_class 0x%x, class_to_use 0x%x\n",  param->p_class,
			class_to_use);
	ENDDEBUG
	if((param->p_netservice < 0) || (param->p_netservice > TP_MAX_NETSERVICES)){
		error = EINVAL; goto done;
	}
	if( (param->p_class & TP_CLASSES_IMPLEMENTED) == 0 ) {
		error = EINVAL; goto done;
	} 
	IFDEBUG(D_SETPARAMS)
		printf("Nretrans 0x%x\n",  param->p_Nretrans );
	ENDDEBUG
	if( ( param->p_Nretrans < 1 ) ||
		  (param->p_cr_ticks < 1) || (param->p_cc_ticks < 1) ) {
			/* bad for any class because negot has to be done a la class 4 */
			error = EINVAL; goto done;
	}
	IFDEBUG(D_SETPARAMS)
		printf("use_csum 0x%x\n",  param->p_use_checksum );
		printf("xtd_format 0x%x\n",  param->p_xtd_format );
		printf("xpd_service 0x%x\n",  param->p_xpd_service );
		printf("tpdusize 0x%x\n",  param->p_tpdusize );
		printf("tpcb->flags 0x%x\n",  tpcb->tp_flags );
	ENDDEBUG
	switch( class_to_use ) {

	case 0:
		/* do not use checksums, xtd format, or XPD */

		if( param->p_use_checksum | param->p_xtd_format | param->p_xpd_service ) {
			if(cmd & TP_STRICT) {
				error = EINVAL;
			} else {
				param->p_use_checksum = 0;
				param->p_xtd_format = 0;
				param->p_xpd_service = 0;
			}
			break;
		}

		if (param->p_tpdusize < TP_MIN_TPDUSIZE) {
			if(cmd & TP_STRICT) {
				error = EINVAL;
			} else {
				param->p_tpdusize = TP_MIN_TPDUSIZE;
			}
			break;
		}
		if (param->p_tpdusize > TP0_TPDUSIZE)  {
			if (cmd & TP_STRICT) {
				error = EINVAL; 
			} else {
				param->p_tpdusize = TP0_TPDUSIZE;
			}
			break;
		} 

		/* connect/disc data not allowed for class 0 */
		if (tpcb->tp_ucddata) {
			if(cmd & TP_STRICT) {
				error = EINVAL;
			} else if(cmd & TP_FORCE) {
				m_freem(tpcb->tp_ucddata);
				tpcb->tp_ucddata = 0;
			}
		}
		break;
		
	case 4:
		IFDEBUG(D_SETPARAMS)
			printf("dt_ticks 0x%x\n",  param->p_dt_ticks );
			printf("x_ticks 0x%x\n",  param->p_x_ticks );
			printf("dr_ticks 0x%x\n",  param->p_dr_ticks );
			printf("keepalive 0x%x\n",  param->p_keepalive_ticks );
			printf("sendack 0x%x\n",  param->p_sendack_ticks );
			printf("inact 0x%x\n",  param->p_inact_ticks );
			printf("ref 0x%x\n",  param->p_ref_ticks );
		ENDDEBUG
		if( (param->p_class & TP_CLASS_4 ) && (
			  (param->p_dt_ticks < 1) || (param->p_dr_ticks < 1) || 
			  (param->p_x_ticks < 1)	|| (param->p_keepalive_ticks < 1) ||
			  (param->p_sendack_ticks < 1) || (param->p_ref_ticks < 1) ||
			  (param->p_inact_ticks < 1) ) ) {
				error = EINVAL;
				break;
		}
		IFDEBUG(D_SETPARAMS)
			printf("rx_strat 0x%x\n",  param->p_rx_strat );
		ENDDEBUG
		if(param->p_rx_strat > 
			( TPRX_USE_CW | TPRX_EACH | TPRX_FASTSTART) ) {
				if(cmd & TP_STRICT) {
					error = EINVAL;
				} else {
					param->p_rx_strat = TPRX_USE_CW;
				}
				break;
		}
		IFDEBUG(D_SETPARAMS)
			printf("ack_strat 0x%x\n",  param->p_ack_strat );
		ENDDEBUG
		if((param->p_ack_strat != 0) && (param->p_ack_strat != 1)) {
			if(cmd & TP_STRICT) {
				error = EINVAL;
			} else {
				param->p_ack_strat = TPACK_WINDOW;
			}
			break;
		}
		if (param->p_tpdusize < TP_MIN_TPDUSIZE) {
			if(cmd & TP_STRICT) {
				error = EINVAL;
			} else {
				param->p_tpdusize = TP_MIN_TPDUSIZE;
			}
			break;
		}
		if (param->p_tpdusize > TP_TPDUSIZE)  {
			if(cmd & TP_STRICT) {
				error = EINVAL; 
			} else {
				param->p_tpdusize = TP_TPDUSIZE;
			}
			break;
		} 
		break;
	}

	if ((error==0) && (cmd & TP_FORCE)) {
		long dusize = ((long)param->p_ptpdusize) << 7;
		/* Enforce Negotation rules below */
		tpcb->tp_class = param->p_class;
		if (tpcb->tp_use_checksum || param->p_use_checksum)
			tpcb->tp_use_checksum = 1;
		if (!tpcb->tp_xpd_service || !param->p_xpd_service)
			tpcb->tp_xpd_service = 0;
		if (!tpcb->tp_xtd_format || !param->p_xtd_format)
			tpcb->tp_xtd_format = 0;
		if (dusize) {
			if (tpcb->tp_l_tpdusize > dusize)
				tpcb->tp_l_tpdusize = dusize;
			if (tpcb->tp_ptpdusize == 0 ||
				tpcb->tp_ptpdusize > param->p_ptpdusize)
				tpcb->tp_ptpdusize = param->p_ptpdusize;
		} else {
			if (param->p_tpdusize != 0 &&
				tpcb->tp_tpdusize > param->p_tpdusize)
				tpcb->tp_tpdusize = param->p_tpdusize;
			tpcb->tp_l_tpdusize = 1 << tpcb->tp_tpdusize;
		}
	}
done:

	IFTRACE(D_CONN)
		tptrace(TPPTmisc, "tp_consist returns class xtdfmt cmd", 
			error, tpcb->tp_class, tpcb->tp_xtd_format, cmd);
	ENDTRACE
	IFDEBUG(D_CONN)
		printf(
		"tp_consist rtns 0x%x class 0x%x xtd_fmt 0x%x cmd 0x%x\n",
			error, tpcb->tp_class, tpcb->tp_xtd_format, cmd);
	ENDDEBUG
	return error;
}

/*
 * NAME: 	tp_ctloutput()
 *
 * CALLED FROM:
 * 	[sg]etsockopt(), via so[sg]etopt(). 
 *
 * FUNCTION and ARGUMENTS:
 * 	Implements the socket options at transport level.
 * 	(cmd) is either PRCO_SETOPT or PRCO_GETOPT (see ../sys/protosw.h).
 * 	(so) is the socket.
 * 	(level) is SOL_TRANSPORT (see ../sys/socket.h)
 * 	(optname) is the particular command or option to be set.
 * 	(**mp) is an mbuf structure.  
 *
 * RETURN VALUE:
 * 	ENOTSOCK if the socket hasn't got an associated tpcb
 *  EINVAL if 
 * 		trying to set window too big
 * 		trying to set illegal max tpdu size 
 * 		trying to set illegal credit fraction
 * 		trying to use unknown or unimplemented class of TP
 *		structure passed to set timer values is wrong size
 *  	illegal combination of command/GET-SET option, 
 *			e.g., GET w/ TPOPT_CDDATA_CLEAR: 
 *  EOPNOTSUPP if the level isn't transport, or command is neither GET nor SET
 *   or if the transport-specific command is not implemented
 *  EISCONN if trying a command that isn't allowed after a connection
 *   is established
 *  ENOTCONN if trying a command that is allowed only if a connection is
 *   established
 *  EMSGSIZE if trying to give too much data on connect/disconnect
 *
 * SIDE EFFECTS:
 *
 * NOTES:
 */
ProtoHook 
tp_ctloutput(cmd, so, level, optname, mp)
	int 			cmd, level, optname;
	struct socket	*so;
	struct mbuf 	**mp;
{
	struct		tp_pcb	*tpcb = sototpcb(so);
	int 		s = splnet();
	caddr_t		value;
	unsigned	val_len;
	int			error = 0;

	IFTRACE(D_REQUEST)
		tptrace(TPPTmisc, "tp_ctloutput cmd so optname mp", 
			cmd, so, optname, mp);
	ENDTRACE
	IFDEBUG(D_REQUEST)
		printf(
	"tp_ctloutput so 0x%x cmd 0x%x optname 0x%x, mp 0x%x *mp 0x%x tpcb 0x%x\n", 
			so, cmd, optname, mp, mp?*mp:0, tpcb);
	ENDDEBUG
	if( tpcb == (struct tp_pcb *)0 ) {
		error = ENOTSOCK; goto done;
	}
	if(*mp == MNULL) {
		register struct mbuf *m;

		MGET(m, M_DONTWAIT, TPMT_SONAME); /* does off, type, next */
		if (m == NULL) {
			splx(s);
			return ENOBUFS;
		}
		m->m_len = 0;
		m->m_act = 0;
		*mp = m;
	}

	/*
	 *	Hook so one can set network options via a tp socket.
	 */
	if ( level == SOL_NETWORK ) {
		if ((tpcb->tp_nlproto == NULL) || (tpcb->tp_npcb == NULL))
			error = ENOTSOCK;
		else if (tpcb->tp_nlproto->nlp_ctloutput == NULL)
			error = EOPNOTSUPP;
		else
			return ((tpcb->tp_nlproto->nlp_ctloutput)(cmd, optname, 
				tpcb->tp_npcb, *mp));
		goto done;
	} else if ( level == SOL_SOCKET) {
		if (optname == SO_RCVBUF && cmd == PRCO_SETOPT) {
			u_long old_credit = tpcb->tp_maxlcredit;
			tp_rsyset(tpcb);
			if (tpcb->tp_rhiwat != so->so_rcv.sb_hiwat &&
			    tpcb->tp_state == TP_OPEN &&
			    (old_credit < tpcb->tp_maxlcredit))
				tp_emit(AK_TPDU_type, tpcb,
					tpcb->tp_rcvnxt, 0, MNULL);
			tpcb->tp_rhiwat = so->so_rcv.sb_hiwat;
		}
		goto done;
	} else if ( level !=  SOL_TRANSPORT ) {
		error = EOPNOTSUPP; goto done;
	} 
	if (cmd != PRCO_GETOPT && cmd != PRCO_SETOPT) {
		error = EOPNOTSUPP; goto done;
	} 
	if ( so->so_error ) {
		error = so->so_error; goto done;
	}

	/* The only options allowed after connection is established
	 * are GET (anything) and SET DISC DATA and SET PERF MEAS
	 */
	if ( ((so->so_state & SS_ISCONNECTING)||(so->so_state & SS_ISCONNECTED))
		&&
		(cmd == PRCO_SETOPT  && 
			optname != TPOPT_DISC_DATA && 
			optname != TPOPT_CFRM_DATA && 
			optname != TPOPT_PERF_MEAS &&
			optname != TPOPT_CDDATA_CLEAR ) ) {
		error = EISCONN; goto done;
	} 
	/* The only options allowed after disconnection are GET DISC DATA,
	 * and TPOPT_PSTATISTICS
	 * and they're not allowed if the ref timer has gone off, because
	 * the tpcb is gone 
	 */
	if ((so->so_state & (SS_ISCONNECTED | SS_ISCONFIRMING)) ==  0) {
		if ( so->so_pcb == (caddr_t)0 ) {
			error = ENOTCONN; goto done;
		}
		if ( (tpcb->tp_state == TP_REFWAIT || tpcb->tp_state == TP_CLOSING) &&
				(optname != TPOPT_DISC_DATA && optname != TPOPT_PSTATISTICS)) {
			error = ENOTCONN; goto done;
		}
	}

	value = mtod(*mp, caddr_t);  /* it's aligned, don't worry,
								  * but lint complains about it 
								  */
	val_len = (*mp)->m_len;

	switch (optname) {

	case TPOPT_INTERCEPT:
#define INA(t) (((struct inpcb *)(t->tp_npcb))->inp_laddr.s_addr)
#define ISOA(t) (((struct isopcb *)(t->tp_npcb))->isop_laddr->siso_addr)

		if ((so->so_state & SS_PRIV) == 0) {
			error = EPERM;
		} else if (cmd != PRCO_SETOPT || tpcb->tp_state != TP_CLOSED ||
					(tpcb->tp_flags & TPF_GENERAL_ADDR) ||
					tpcb->tp_next == 0)
			error = EINVAL;
		else {
			register struct tp_pcb *t;
			error = EADDRINUSE;
			for (t = tp_listeners; t; t = t->tp_nextlisten)
				if ((t->tp_flags & TPF_GENERAL_ADDR) == 0 &&
						t->tp_domain == tpcb->tp_domain)
					switch (tpcb->tp_domain) {
					default:
						goto done;
#if	INET
					case AF_INET:
						if (INA(t) == INA(tpcb))
							goto done;
						continue;
#endif
#if ISO
					case AF_ISO:
						if (bcmp(ISOA(t).isoa_genaddr, ISOA(tpcb).isoa_genaddr,
										ISOA(t).isoa_len) == 0)
							goto done;
						continue;
#endif
					}
			tpcb->tp_lsuffixlen = 0;
			tpcb->tp_state = TP_LISTENING;
			error = 0;
			remque(tpcb);
			tpcb->tp_next = tpcb->tp_prev = tpcb;
			tpcb->tp_nextlisten = tp_listeners;
			tp_listeners = tpcb;
		}
		break;

	case TPOPT_MY_TSEL:
		if ( cmd == PRCO_GETOPT ) {
			ASSERT( tpcb->tp_lsuffixlen <= MAX_TSAP_SEL_LEN );
			bcopy((caddr_t)tpcb->tp_lsuffix, value, tpcb->tp_lsuffixlen);
			(*mp)->m_len = tpcb->tp_lsuffixlen;
		} else /* cmd == PRCO_SETOPT  */ {
			if( (val_len > MAX_TSAP_SEL_LEN) || (val_len <= 0 )) {
				printf("val_len 0x%x (*mp)->m_len 0x%x\n", val_len, (*mp));
				error = EINVAL;
			} else {
				bcopy(value, (caddr_t)tpcb->tp_lsuffix, val_len);
				tpcb->tp_lsuffixlen = val_len;
			}
		}
		break;

	case TPOPT_PEER_TSEL:
		if ( cmd == PRCO_GETOPT ) {
			ASSERT( tpcb->tp_fsuffixlen <= MAX_TSAP_SEL_LEN );
			bcopy((caddr_t)tpcb->tp_fsuffix, value, tpcb->tp_fsuffixlen);
			(*mp)->m_len = tpcb->tp_fsuffixlen;
		} else /* cmd == PRCO_SETOPT  */ {
			if( (val_len > MAX_TSAP_SEL_LEN) || (val_len <= 0 )) {
				printf("val_len 0x%x (*mp)->m_len 0x%x\n", val_len, (*mp));
				error = EINVAL; 
			} else {
				bcopy(value, (caddr_t)tpcb->tp_fsuffix, val_len);
				tpcb->tp_fsuffixlen = val_len;
			}
		}
		break;

	case TPOPT_FLAGS:
		IFDEBUG(D_REQUEST)
			printf("%s TPOPT_FLAGS value 0x%x *value 0x%x, flags 0x%x \n", 
				cmd==PRCO_GETOPT?"GET":"SET", 
				value,
				*value, 
				tpcb->tp_flags);
		ENDDEBUG

		if ( cmd == PRCO_GETOPT ) {
			*(int *)value = (int)tpcb->tp_flags;
			(*mp)->m_len = sizeof(u_int);
		} else /* cmd == PRCO_SETOPT  */ {
			error = EINVAL; goto done;
		}
		break;

	case TPOPT_PARAMS:
		/* This handles:
		 * timer values,
		 * class, use of transport expedited data,
		 * max tpdu size, checksum, xtd format and
		 * disconnect indications, and may get rid of connect/disc data
		 */
		IFDEBUG(D_SETPARAMS)
			printf("TPOPT_PARAMS value 0x%x, cmd %s \n", value,
				cmd==PRCO_GETOPT?"GET":"SET");
		ENDDEBUG
		IFDEBUG(D_REQUEST)
			printf("TPOPT_PARAMS value 0x%x, cmd %s \n", value,
				cmd==PRCO_GETOPT?"GET":"SET");
		ENDDEBUG

		if ( cmd == PRCO_GETOPT ) {
			*(struct tp_conn_param *)value = tpcb->_tp_param;
			(*mp)->m_len = sizeof(tpcb->_tp_param);
		} else /* cmd == PRCO_SETOPT  */ {
			if( (error = 
				tp_consistency(tpcb, TP_STRICT | TP_FORCE, 
								(struct tp_conn_param *)value))==0) {
				/* 
				 * tp_consistency doesn't copy the whole set of params 
				 */
				tpcb->_tp_param = *(struct tp_conn_param *)value;
				(*mp)->m_len = sizeof(tpcb->_tp_param);
			}
		}
		break;

	case TPOPT_PSTATISTICS: 
#ifdef TP_PERF_MEAS
		if (cmd == PRCO_SETOPT) {
			error = EINVAL; goto done;
		} 
		IFPERF(tpcb)
			if (*mp) {
				struct mbuf * n;
				do {
					MFREE(*mp, n);
					*mp = n;
				} while (n);
			}
			*mp = m_copym(tpcb->tp_p_mbuf, (int)M_COPYALL, M_WAITOK);
		ENDPERF 
		else {
			error = EINVAL; goto done;
		} 
		break;
#else
		error = EOPNOTSUPP;
		goto done;
#endif /* TP_PERF_MEAS */
		
	case TPOPT_CDDATA_CLEAR: 
		if (cmd == PRCO_GETOPT) {
			error = EINVAL;
		} else {
			if (tpcb->tp_ucddata) {
				m_freem(tpcb->tp_ucddata);
				tpcb->tp_ucddata = 0;
			}
		}
		break;

	case TPOPT_CFRM_DATA:
	case TPOPT_DISC_DATA: 
	case TPOPT_CONN_DATA: 
		if( tpcb->tp_class == TP_CLASS_0 ) {
			error = EOPNOTSUPP;
			break;
		}
		IFDEBUG(D_REQUEST)
			printf("%s\n", optname==TPOPT_DISC_DATA?"DISC data":"CONN data");
			printf("m_len 0x%x, vallen 0x%x so_snd.cc 0x%x\n", 
				(*mp)->m_len, val_len, so->so_snd.sb_cc);
			dump_mbuf(so->so_snd.sb_mb, "tp_ctloutput: sosnd ");
		ENDDEBUG
		if (cmd == PRCO_SETOPT) {
			int len = tpcb->tp_ucddata ?  tpcb->tp_ucddata->m_len : 0;
			/* can append connect data in several calls */
			if (len + val_len > 
				(optname==TPOPT_CONN_DATA?TP_MAX_CR_DATA:TP_MAX_DR_DATA) ) {
				error = EMSGSIZE; goto done;
			} 
			(*mp)->m_next = MNULL;
			(*mp)->m_act = 0;
			if (tpcb->tp_ucddata)
				m_cat(tpcb->tp_ucddata, *mp);
			else
				tpcb->tp_ucddata = *mp;
			IFDEBUG(D_REQUEST)
				dump_mbuf(tpcb->tp_ucddata, "tp_ctloutput after CONN_DATA");
			ENDDEBUG
			IFTRACE(D_REQUEST)
				tptrace(TPPTmisc,"C/D DATA: flags snd.sbcc val_len",
					tpcb->tp_flags, so->so_snd.sb_cc,val_len,0);
			ENDTRACE
			*mp = MNULL;
			if (optname == TPOPT_CFRM_DATA && (so->so_state & SS_ISCONFIRMING))
				(void) tp_confirm(tpcb);
		}
		break;

	case TPOPT_PERF_MEAS: 
#ifdef TP_PERF_MEAS
		if (cmd == PRCO_GETOPT) {
			*value = (u_int)tpcb->tp_perf_on;
			(*mp)->m_len = sizeof(u_int);
		} else if (cmd == PRCO_SETOPT) {
			(*mp)->m_len = 0;
			if ((*value) != 0 && (*value) != 1 )
				error = EINVAL;
			else  tpcb->tp_perf_on = (*value);
		}
		if( tpcb->tp_perf_on ) 
			error = tp_setup_perf(tpcb);
#else  /* TP_PERF_MEAS */
		error = EOPNOTSUPP;
#endif /* TP_PERF_MEAS */
		break;

	default:
		error = EOPNOTSUPP;
	}
	
done:
	IFDEBUG(D_REQUEST)
		dump_mbuf(so->so_snd.sb_mb, "tp_ctloutput sosnd at end");
		dump_mbuf(*mp, "tp_ctloutput *mp");
	ENDDEBUG
	/* 
	 * sigh: getsockopt looks only at m_len : all output data must 
	 * reside in the first mbuf 
	 */
	if (*mp) {
		if (cmd == PRCO_SETOPT) {
			m_freem(*mp);
			*mp = MNULL;
		} else {
			ASSERT ( m_compress(*mp, mp) <= MLEN );
			if (error)
				(*mp)->m_len = 0;
			IFDEBUG(D_REQUEST)
				dump_mbuf(*mp, "tp_ctloutput *mp after compress");
			ENDDEBUG
		}
	}
	splx(s);
	return error;
}
