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
 * Simple FTP transparent proxy for in-kernel use.  For use with the NAT
 * code.
 */


#define	isdigit(x)	((x) >= '0' && (x) <= '9')

#define	IPF_FTP_PROXY

#define	IPF_MINPORTLEN	18
#define	IPF_MAXPORTLEN	30


int ippr_ftp_init __P((fr_info_t *, ip_t *, tcphdr_t *,
		       ap_session_t *, nat_t *));
int ippr_ftp_in __P((fr_info_t *, ip_t *, tcphdr_t *,
		       ap_session_t *, nat_t *));
int ippr_ftp_out __P((fr_info_t *, ip_t *, tcphdr_t *,
		       ap_session_t *, nat_t *));
u_short ipf_ftp_atoi __P((char **));


/*
 * FTP application proxy initialization.
 */
int ippr_ftp_init(fin, ip, tcp, aps, nat)
fr_info_t *fin;
ip_t *ip;
tcphdr_t *tcp;
ap_session_t *aps;
nat_t *nat;
{
	aps->aps_sport = tcp->th_sport;
	aps->aps_dport = tcp->th_dport;
	return 0;
}


int ippr_ftp_in(fin, ip, tcp, aps, nat)
fr_info_t *fin;
ip_t *ip;
tcphdr_t *tcp;
ap_session_t *aps;
nat_t *nat;
{
	u_32_t	sum1, sum2;
	short sel;

	if (tcp->th_sport == aps->aps_dport) {
		sum2 = (u_32_t)ntohl(tcp->th_ack);
		sel = aps->aps_sel;
		if ((aps->aps_after[!sel] > aps->aps_after[sel]) &&
			(sum2 > aps->aps_after[!sel])) {
			sel = aps->aps_sel = !sel; /* switch to other set */
		}
		if (aps->aps_seqoff[sel] && (sum2 > aps->aps_after[sel])) {
			sum1 = (u_32_t)aps->aps_seqoff[sel];
			tcp->th_ack = htonl(sum2 - sum1);
			return 2;
		}
	}
	return 0;
}


/*
 * ipf_ftp_atoi - implement a version of atoi which processes numbers in
 * pairs separated by commas (which are expected to be in the range 0 - 255),
 * returning a 16 bit number combining either side of the , as the MSB and
 * LSB.
 */
u_short ipf_ftp_atoi(ptr)
char **ptr;
{
	register char *s = *ptr, c;
	register u_char i = 0, j = 0;

	while ((c = *s++) && isdigit(c)) {
		i *= 10;
		i += c - '0';
	}
	if (c != ',') {
		*ptr = NULL;
		return 0;
	}
	while ((c = *s++) && isdigit(c)) {
		j *= 10;
		j += c - '0';
	}
	*ptr = s;
	return (i << 8) | j;
}


int ippr_ftp_out(fin, ip, tcp, aps, nat)
fr_info_t *fin;
ip_t *ip;
tcphdr_t *tcp;
ap_session_t *aps;
nat_t *nat;
{
	register u_32_t	sum1, sum2;
	char	newbuf[IPF_MAXPORTLEN+1];
	char	portbuf[IPF_MAXPORTLEN+1], *s;
	int	ch = 0, off = (ip->ip_hl << 2) + (tcp->th_off << 2);
	u_int	a1, a2, a3, a4;
	u_short	a5, a6;
	int	olen, dlen, nlen = 0, inc = 0;
	tcphdr_t tcph, *tcp2 = &tcph;
	void	*savep;
	nat_t	*ipn;
	struct	in_addr	swip;
	mb_t *m = *(mb_t **)fin->fin_mp;

#if	SOLARIS
	mb_t *m1;

	/* skip any leading M_PROTOs */
	while(m && (MTYPE(m) != M_DATA))
		m = m->b_cont;
	PANIC((!m),("ippr_ftp_out: no M_DATA"));

	dlen = msgdsize(m) - off;
	bzero(portbuf, sizeof(portbuf));
	copyout_mblk(m, off, MIN(sizeof(portbuf), dlen), portbuf);
#else
	dlen = mbufchainlen(m) - off;
	bzero(portbuf, sizeof(portbuf));
	m_copydata(m, off, MIN(sizeof(portbuf), dlen), portbuf);
#endif
	portbuf[IPF_MAXPORTLEN] = '\0';

	if ((dlen < IPF_MINPORTLEN) || strncmp(portbuf, "PORT ", 5))
		goto adjust_seqack;

	/*
	 * Skip the PORT command + space
	 */
	s = portbuf + 5;
	/*
	 * Pick out the address components, two at a time.
	 */
	(void) ipf_ftp_atoi(&s);
	if (!s)
		goto adjust_seqack;
	(void) ipf_ftp_atoi(&s);
	if (!s)
		goto adjust_seqack;
	a5 = ipf_ftp_atoi(&s);
	if (!s)
		goto adjust_seqack;
	/*
	 * check for CR-LF at the end.
	 */
	if (*s != '\n' || *(s - 1) != '\r')
		goto adjust_seqack;
	a6 = a5 & 0xff;
	a5 >>= 8;
	/*
	 * Calculate new address parts for PORT command
	 */
	a1 = ntohl(ip->ip_src.s_addr);
	a2 = (a1 >> 16) & 0xff;
	a3 = (a1 >> 8) & 0xff;
	a4 = a1 & 0xff;
	a1 >>= 24;
	olen = s - portbuf + 1;
	(void) snprintf(newbuf, sizeof(newbuf), "PORT %d,%d,%d,%d,%d,%d\r\n",
		a1, a2, a3, a4, a5, a6);
	nlen = strlen(newbuf);
	inc = nlen - olen;
#if SOLARIS
	for (m1 = m; m1->b_cont; m1 = m1->b_cont)
		;
	if (inc > 0) {
		mblk_t *nm;

		/* alloc enough to keep same trailer space for lower driver */
		nm = allocb(nlen + m1->b_datap->db_lim - m1->b_wptr, BPRI_MED);
		PANIC((!nm),("ippr_ftp_out: allocb failed"));

		nm->b_band = m1->b_band;
		nm->b_wptr += nlen;

		m1->b_wptr -= olen;
		PANIC((m1->b_wptr < m1->b_rptr),("ippr_ftp_out: cannot handle fragmented data block"));

		linkb(m1, nm);
	} else {
		m1->b_wptr += inc;
	}
	copyin_mblk(m, off, nlen, newbuf);
#else
	if (inc < 0)
		m_adj(m, inc);
	/* the mbuf chain will be extended if necessary by m_copyback() */
	m_copyback(m, off, nlen, newbuf);
#endif
	if (inc) {
#if SOLARIS || defined(__sgi)
		sum1 = ip->ip_len;
		sum2 = ip->ip_len + inc;

		/* Because ~1 == -2, We really need ~1 == -1 */
		if (sum1 > sum2)
			sum2--;
		sum2 -= sum1;
		sum2 = (sum2 & 0xffff) + (sum2 >> 16);

		fix_outcksum(&ip->ip_sum, sum2);
#endif
		ip->ip_len += inc;
	}
	ch = 1;

	/*
	 * Add skeleton NAT entry for connection which will come back the
	 * other way.
	 */
	savep = fin->fin_dp;
	fin->fin_dp = (char *)tcp2;
	bzero((char *)tcp2, sizeof(*tcp2));
	tcp2->th_sport = htons(a5 << 8 | a6);
	tcp2->th_dport = htons(20);
	swip = ip->ip_src;
	ip->ip_src = nat->nat_inip;
	if ((ipn = nat_new(nat->nat_ptr, ip, fin, IPN_TCP, NAT_OUTBOUND)))
		ipn->nat_age = fr_defnatage;
	(void) fr_addstate(ip, fin, FR_INQUE|FR_PASS|FR_QUICK|FR_KEEPSTATE);
	ip->ip_src = swip;
	fin->fin_dp = (char *)savep;

adjust_seqack:
	if (tcp->th_dport == aps->aps_dport) {
		sum2 = (u_32_t)ntohl(tcp->th_seq);
		off = aps->aps_sel;
		if ((aps->aps_after[!off] > aps->aps_after[off]) &&
			(sum2 > aps->aps_after[!off])) {
			off = aps->aps_sel = !off; /* switch to other set */
		}
		if (aps->aps_seqoff[off]) {
			sum1 = (u_32_t)aps->aps_after[off] -
			       aps->aps_seqoff[off];
			if (sum2 > sum1) {
				sum1 = (u_32_t)aps->aps_seqoff[off];
				sum2 += sum1;
				tcp->th_seq = htonl(sum2);
				ch = 1;
			}
		}

		if (inc && (sum2 > aps->aps_after[!off])) {
			aps->aps_after[!off] = sum2 + nlen - 1;
			aps->aps_seqoff[!off] = aps->aps_seqoff[off] + inc;
		}
	}
	return ch ? 2 : 0;
}
