/*	$KAME: pim6_var.h,v 1.5 2000/03/25 07:23:59 sumikawa Exp $	*/

/*
 * Copyright (C) 1998 WIDE Project.
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

#ifndef _NETINET6_PIM6_VAR_H_
#define _NETINET6_PIM6_VAR_H_

/*
 * Protocol Independent Multicast (PIM),
 * implementation-specific definitions.
 *
 * Written by George Edmond Eddy (Rusty), ISI, February 1998
 * Modified by Pavlin Ivanov Radoslavov, USC/ISI, May 1998
 */

struct pim6stat {
	u_quad_t pim6s_rcv_total;	/* total PIM messages received	*/
	u_quad_t pim6s_rcv_tooshort;	/* received with too few bytes	*/
	u_quad_t pim6s_rcv_badsum;	/* received with bad checksum	*/
	u_quad_t pim6s_rcv_badversion;	/* received bad PIM version	*/
	u_quad_t pim6s_rcv_registers;	/* received registers		*/
	u_quad_t pim6s_rcv_badregisters; /* received invalid registers	*/
	u_quad_t pim6s_snd_registers;	/* sent registers		*/
};

#if (defined(KERNEL)) || (defined(_KERNEL))
extern struct pim6stat pim6stat;

int pim6_input __P((struct mbuf **, int*, int));
#endif /* KERNEL */

/*
 * Names for PIM sysctl objects
 */
#define PIMCTL_STATS		1	/* statistics (read-only) */
#define PIMCTL_MAXID		2

#define PIMCTL_NAMES { \
	{ 0, 0 }, \
	{ 0, 0 }, \
}

#endif /* _NETINET6_PIM6_VAR_H_ */
