/*-
 * Copyright (c) 2003 Sam Leffler, Errno Consulting
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer,
 *    without modification.
 * 2. Redistributions in binary form must reproduce at minimum a disclaimer
 *    similar to the "NO WARRANTY" disclaimer below ("Disclaimer") and any
 *    redistribution must be conditioned upon including a substantially
 *    similar Disclaimer requirement for further binary redistribution.
 * 3. Neither the names of the above-listed copyright holders nor the names
 *    of any contributors may be used to endorse or promote products derived
 *    from this software without specific prior written permission.
 *
 * NO WARRANTY
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF NONINFRINGEMENT, MERCHANTIBILITY
 * AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS OR CONTRIBUTORS BE LIABLE FOR SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
 * IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGES.
 *
 * $FreeBSD: src/sys/netinet/ip_divert.h,v 1.3 2004/02/25 19:55:28 mlaier Exp $
 */

#ifndef _NETINET_IP_DIVERT_H_
#define	_NETINET_IP_DIVERT_H_

#if IPDIVERT
/*
 * Divert socket definitions.
 */

/* 32-bit unique unsigned value used to identify a module */

struct divert_tag {
	u_int32_t	info;		/* port & flags */
	u_int16_t	cookie;		/* ipfw rule number */
};

/*
 * Return the divert cookie associated with the mbuf; if any.
 */
static __inline u_int16_t
divert_cookie(struct m_tag *mtag)
{
	return ((struct divert_tag *)(mtag+1))->cookie;
}
static __inline u_int16_t
divert_find_cookie(struct mbuf *m)
{
	struct m_tag *mtag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
									  KERNEL_TAG_TYPE_DIVERT, NULL);
	return mtag ? divert_cookie(mtag) : 0;
}

/*
 * Return the divert info associated with the mbuf; if any.
 */
static __inline u_int32_t
divert_info(struct m_tag *mtag)
{
	return ((struct divert_tag *)(mtag+1))->info;
}
static __inline u_int32_t
divert_find_info(struct mbuf *m)
{
	struct m_tag *mtag = m_tag_locate(m, KERNEL_MODULE_TAG_ID,
									  KERNEL_TAG_TYPE_DIVERT, NULL);
	return mtag ? divert_info(mtag) : 0;
}

extern	void div_init(void) __attribute__((section("__TEXT, initcode")));
extern	void div_input(struct mbuf *, int);
lck_mtx_t * 
        div_getlock(struct socket *,  int );
int	div_unlock(struct socket *, int, int);
int     div_lock(struct socket *, int , int );
extern	void divert_packet(struct mbuf *m, int incoming, int port, int rule);
extern struct pr_usrreqs div_usrreqs;

#endif /* IPDIVERT */
#endif /* _NETINET_IP_DIVERT_H_ */
