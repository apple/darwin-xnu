/*	$KAME: natpt_log.h,v 1.5 2000/03/25 07:23:55 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _NATPT_LOG_H
#define	_NATPT_LOG_H


#if (defined(KERNEL)) || (defined(_KERNEL))

/*  Header at beginning of logged packet.				*/

struct	l_pkt
{
    char	ifName[IFNAMSIZ];
    char	__buf[4];
};


/*  Header at beginning of active Transration Table			*/

struct	l_att
{
    u_int		_stub;
#define	ATT_ALLOC	(0)
#define	ATT_REMOVE	(1)
#define	ATT_FASTEN	(2)
#define	ATT_UNFASTEN	(3)
#define	ATT_REGIST	(4)
    caddr_t		_addr;
#if	0
    struct  _aTT	_att;
    struct  _tcpstate	_state;
#endif
};
#endif	/* defined(KERNEL)	*/


/*  Header at beginning of each lbuf.					*/

#ifndef IN6ADDRSZ
#define	IN6ADDRSZ		16	/* IPv6 T_AAAA */
#define	INT16SZ			2	/* for systems without 16-bit ints	*/
#endif	/* !defined(IN6ADDRSZ)	*/

#define	LBFSZ	(MHLEN - sizeof(struct l_hdr))	/* LBUF payload within MBUF	*/
#define	MSGSZ	(LBFSZ	- IN6ADDRSZ)		/* max message size	*/


enum
{
    LOG_MSG,
    LOG_MBUF,
    LOG_IP4,
    LOG_IP6,
    LOG_IN4ADDR,
    LOG_IN6ADDR,
    LOG_CSLOT,
    LOG_TSLOT,
    LOG_RULE
};


struct	l_hdr
{
    u_short	 lh_type;	/* Type of data in this lbuf		*/
    u_short	 lh_pri;	/* Priorities of thie message		*/
    size_t	 lh_size;	/* Amount of data in this lbuf		*/
    u_long	 lh_sec;	/* Timestamp in second			*/
    u_long	 lh_usec;	/* Timestamp in microsecond		*/
};


struct	l_addr
{
    char	in6addr[IN6ADDRSZ];
    char	__msg[MSGSZ];
};


/*  Definition of whole lbuf						*/

struct	lbuf
{
    struct	l_hdr	l_hdr;
    union
    {
#ifdef _KERNEL
	struct	l_pkt	l_pkt;
	struct	l_att	l_att;
#endif	/* defined(_KERNEL)	*/
	struct	l_addr	__laddr;
	char		__buf[LBFSZ];
    }		l_dat;
};


#define	l_addr		l_dat.__laddr
#define	l_msg		l_dat.__laddr.__msg


#endif	/* !_NATPT_LOG_H	*/
