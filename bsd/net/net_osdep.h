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
/*
 * glue for kernel code programming differences.
 */

/*
 * OS dependencies:
 *
 * - privileged process
 *	NetBSD, FreeBSD 3
 *		struct proc *p;
 *		if (p && !suser(p->p_ucred, &p->p_acflag))
 *			privileged;
 *	OpenBSD, BSDI [34], FreeBSD 2
 *		struct socket *so;
 *		if (so->so_state & SS_PRIV)
 *			privileged;
 * - foo_control
 *	NetBSD, FreeBSD 3
 *		needs to give struct proc * as argument
 *	OpenBSD, BSDI [34], FreeBSD 2
 *		do not need struct proc *
 * - bpf:
 *	OpenBSD, NetBSD, BSDI [34]
 *		need caddr_t * (= if_bpf **) and struct ifnet *
 *	FreeBSD 2, FreeBSD 3
 *		need only struct ifnet * as argument
 * - struct ifnet
 *			use queue.h?	member names	if name
 *			---		---		---
 *	FreeBSD 2	no		old standard	if_name+unit
 *	FreeBSD 3	yes		strange		if_name+unit
 *	OpenBSD		yes		standard	if_xname
 *	NetBSD		yes		standard	if_xname
 *	BSDI [34]	no		old standard	if_name+unit
 * - usrreq
 *	NetBSD, OpenBSD, BSDI [34], FreeBSD 2
 *		single function with PRU_xx, arguments are mbuf 
 *	FreeBSD 3
 *		separates functions, non-mbuf arguments
 * - {set,get}sockopt
 *	NetBSD, OpenBSD, BSDI [34], FreeBSD 2
 *		manipulation based on mbuf
 *	FreeBSD 3
 *		non-mbuf manipulation using sooptcopy{in,out}()
 * - timeout() and untimeout()
 *	NetBSD, OpenBSD, BSDI [34], FreeBSD 2
 *		timeout() is a void function
 *	FreeBSD 3
 *		timeout() is non-void, must keep returned value for untimeuot()
 * - sysctl
 *	NetBSD, OpenBSD
 *		foo_sysctl()
 *	BSDI [34]
 *		foo_sysctl() but with different style
 *	FreeBSD 2, FreeBSD 3
 *		linker hack
 *
 * - if_ioctl
 *	NetBSD, FreeBSD 3, BSDI [34]
 *		2nd argument is u_long cmd
 *	FreeBSD 2
 *		2nd argument is int cmd
 * - if attach routines
 *	NetBSD
 *		void xxattach(int);
 *	FreeBSD 2, FreeBSD 3
 *		void xxattach(void *);
 *		PSEUDO_SET(xxattach, if_xx);
 *
 * - ovbcopy()
 *	in NetBSD 1.4 or later, ovbcopy() is not supplied in the kernel.
 *	bcopy() is safe against overwrites.
 * - splnet()
 *	NetBSD 1.4 or later requires splsoftnet().
 *	other operating systems use splnet().
 *
 * - dtom()
 *	NEVER USE IT!
 *
 * - struct ifnet for loopback interface
 *	BSDI3: struct ifnet loif;
 *	BSDI4: struct ifnet *loifp;
 *	NetBSD, OpenBSD, FreeBSD2: struct ifnet loif[NLOOP];
 *
 *	odd thing is that many of them refers loif as ifnet *loif,
 *	not loif[NLOOP], from outside of if_loop.c.
 */

#ifndef __NET_NET_OSDEP_H_DEFINED_
#define __NET_NET_OSDEP_H_DEFINED_
#ifdef KERNEL

#if defined(__NetBSD__) || defined(__OpenBSD__)
#define if_name(ifp)	((ifp)->if_xname)
#else
struct ifnet;
extern char *if_name __P((struct ifnet *));
#endif

#if defined (__APPLE__)
#define HAVE_OLD_BPF
#endif

//#if defined(__FreeBSD__) && __FreeBSD__ >= 3
#if defined (__APPLE__)
#define ifa_list	ifa_link
#define if_addrlist	if_addrhead
#define if_list		if_link
#endif

#if defined(__NetBSD__) && __NetBSD_Version__ >= 104000000
#define ovbcopy		bcopy
#endif

#if defined(__OpenBSD__) || (defined(__bsdi__) && _BSDI_VERSION >= 199802)
#define HAVE_NRL_INPCB
#endif

#endif /*_KERNEL*/
#endif /*__NET_NET_OSDEP_H_DEFINED_ */
