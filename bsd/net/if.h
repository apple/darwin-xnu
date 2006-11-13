/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 1982, 1986, 1989, 1993
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
 *	@(#)if.h	8.1 (Berkeley) 6/10/93
 * $FreeBSD: src/sys/net/if.h,v 1.58.2.2 2001/07/24 19:10:18 brooks Exp $
 */

#ifndef _NET_IF_H_
#define	_NET_IF_H_

#define	IF_NAMESIZE	16

#ifndef _POSIX_C_SOURCE
#include <sys/appleapiopts.h>
#ifdef __APPLE__
/*
 * Define Data-Link event subclass, and associated
 * events.
 */

#define KEV_DL_SUBCLASS 2

#define KEV_DL_SIFFLAGS	    1
#define KEV_DL_SIFMETRICS   2
#define KEV_DL_SIFMTU	    3
#define KEV_DL_SIFPHYS	    4
#define KEV_DL_SIFMEDIA	    5
#define KEV_DL_SIFGENERIC   6
#define KEV_DL_ADDMULTI	    7
#define KEV_DL_DELMULTI	    8
#define KEV_DL_IF_ATTACHED  9
#define KEV_DL_IF_DETACHING 10
#define KEV_DL_IF_DETACHED  11
#define KEV_DL_LINK_OFF	    12
#define KEV_DL_LINK_ON	    13
#define KEV_DL_PROTO_ATTACHED	14
#define KEV_DL_PROTO_DETACHED	15
#define KEV_DL_LINK_ADDRESS_CHANGED	16

#include <net/if_var.h>
#include <sys/types.h>
#endif

#ifdef KERNEL_PRIVATE
struct if_clonereq {
	int	ifcr_total;		/* total cloners (out) */
	int	ifcr_count;		/* room for this many in user buffer */
	char	*ifcr_buffer;		/* buffer for cloner names */
};

/* in-kernel, LP64-aware version of if_clonereq.  all pointers 
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with if_clonereq
 */
struct if_clonereq64 {
	int	ifcr_total;		/* total cloners (out) */
	int	ifcr_count;		/* room for this many in user buffer */
	union {
	    u_int64_t	ifcru_buffer64;
	    char *	ifcru_buffer32;
	} ifcr_ifcru;
};
#endif KERNEL_PRIVATE

#define	IFF_UP		0x1		/* interface is up */
#define	IFF_BROADCAST	0x2		/* broadcast address valid */
#define	IFF_DEBUG	0x4		/* turn on debugging */
#define	IFF_LOOPBACK	0x8		/* is a loopback net */
#define	IFF_POINTOPOINT	0x10		/* interface is point-to-point link */
#define IFF_NOTRAILERS 0x20		/* obsolete: avoid use of trailers */
#define	IFF_RUNNING	0x40		/* resources allocated */
#define	IFF_NOARP	0x80		/* no address resolution protocol */
#define	IFF_PROMISC	0x100		/* receive all packets */
#define	IFF_ALLMULTI	0x200		/* receive all multicast packets */
#define	IFF_OACTIVE	0x400		/* transmission in progress */
#define	IFF_SIMPLEX	0x800		/* can't hear own transmissions */
#define	IFF_LINK0	0x1000		/* per link layer defined bit */
#define	IFF_LINK1	0x2000		/* per link layer defined bit */
#define	IFF_LINK2	0x4000		/* per link layer defined bit */
#define	IFF_ALTPHYS	IFF_LINK2	/* use alternate physical connection */
#define	IFF_MULTICAST	0x8000		/* supports multicast */

#ifdef KERNEL_PRIVATE
/* extended flags definitions:  (all bits are reserved for internal/future use) */
#define IFEF_AUTOCONFIGURING	0x1
#define IFEF_DVR_REENTRY_OK	0x20	/* When set, driver may be reentered from its own thread */
#define IFEF_ACCEPT_RTADVD	0x40	/* set to accept IPv6 router advertisement on the interface */
#define IFEF_DETACHING		0x80	/* Set when interface is detaching */
#define IFEF_USEKPI			0x100	/* Set when interface is created through the KPIs */
#define IFEF_VLAN		0x200	/* interface has one or more vlans */
#define IFEF_BOND		0x400	/* interface is part of bond */
#define	IFEF_ARPLL		0x800	/* ARP for IPv4LL addresses on this port */
#define IFEF_REUSE	0x20000000 /* DLIL ifnet recycler, ifnet is not new */
#define IFEF_INUSE	0x40000000 /* DLIL ifnet recycler, ifnet in use */
#define IFEF_UPDOWNCHANGE	0x80000000 /* Interface's up/down state is changing */

/* flags set internally only: */
#define	IFF_CANTCHANGE \
	(IFF_BROADCAST|IFF_POINTOPOINT|IFF_RUNNING|IFF_OACTIVE|\
	    IFF_SIMPLEX|IFF_MULTICAST|IFF_ALLMULTI)

#endif /* KERNEL_PRIVATE */

#define	IFQ_MAXLEN	50
#define	IFNET_SLOWHZ	1		/* granularity is 1 second */

/*
 * Message format for use in obtaining information about interfaces
 * from sysctl and the routing socket
 */
struct if_msghdr {
	unsigned short	ifm_msglen;	/* to skip over non-understood messages */
	unsigned char	ifm_version;	/* future binary compatability */
	unsigned char	ifm_type;	/* message type */
	int		ifm_addrs;	/* like rtm_addrs */
	int		ifm_flags;	/* value of if_flags */
	unsigned short	ifm_index;	/* index for associated ifp */
	struct	if_data ifm_data;	/* statistics and other data about if */
};

/*
 * Message format for use in obtaining information about interface addresses
 * from sysctl and the routing socket
 */
struct ifa_msghdr {
	unsigned short	ifam_msglen;	/* to skip over non-understood messages */
	unsigned char	ifam_version;	/* future binary compatability */
	unsigned char	ifam_type;	/* message type */
	int		ifam_addrs;	/* like rtm_addrs */
	int		ifam_flags;	/* value of ifa_flags */
	unsigned short	ifam_index;	/* index for associated ifp */
	int		ifam_metric;	/* value of ifa_metric */
};

/*
 * Message format for use in obtaining information about multicast addresses
 * from the routing socket
 */
struct ifma_msghdr {
	unsigned short	ifmam_msglen;	/* to skip over non-understood messages */
	unsigned char	ifmam_version;	/* future binary compatability */
	unsigned char	ifmam_type;	/* message type */
	int		ifmam_addrs;	/* like rtm_addrs */
	int		ifmam_flags;	/* value of ifa_flags */
	unsigned short	ifmam_index;	/* index for associated ifp */
};

/*
 * Message format for use in obtaining information about interfaces
 * from sysctl 
 */
struct if_msghdr2 {
	u_short	ifm_msglen;	/* to skip over non-understood messages */
	u_char	ifm_version;	/* future binary compatability */
	u_char	ifm_type;	/* message type */
	int	ifm_addrs;	/* like rtm_addrs */
	int	ifm_flags;	/* value of if_flags */
	u_short	ifm_index;	/* index for associated ifp */
	int	ifm_snd_len;	/* instantaneous length of send queue */
	int	ifm_snd_maxlen;	/* maximum length of send queue */
	int	ifm_snd_drops;	/* number of drops in send queue */
	int	ifm_timer;	/* time until if_watchdog called */
	struct if_data64	ifm_data;	/* statistics and other data about if */
};

/*
 * Message format for use in obtaining information about multicast addresses
 * from sysctl
 */
struct ifma_msghdr2 {
	u_short	ifmam_msglen;	/* to skip over non-understood messages */
	u_char	ifmam_version;	/* future binary compatability */
	u_char	ifmam_type;	/* message type */
	int	ifmam_addrs;	/* like rtm_addrs */
	int	ifmam_flags;	/* value of ifa_flags */
	u_short	ifmam_index;	/* index for associated ifp */
	int32_t ifmam_refcount;
};

/*
 * ifdevmtu: interface device mtu
 *    Used with SIOCGIFDEVMTU to get the current mtu in use by the device,
 *    as well as the minimum and maximum mtu allowed by the device.
 */
struct ifdevmtu {
	int	ifdm_current;
	int	ifdm_min;
	int	ifdm_max;
};

/*
 * Interface request structure used for socket
 * ioctl's.  All interface ioctl's must have parameter
 * definitions which begin with ifr_name.  The
 * remainder may be interface specific.
 */
struct	ifreq {
#ifndef IFNAMSIZ
#define	IFNAMSIZ	IF_NAMESIZE
#endif
	char	ifr_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	union {
		struct	sockaddr ifru_addr;
		struct	sockaddr ifru_dstaddr;
		struct	sockaddr ifru_broadaddr;
		short	ifru_flags;
		int	ifru_metric;
		int	ifru_mtu;
		int	ifru_phys;
		int	ifru_media;
		int 	ifru_intval;
		caddr_t	ifru_data;
#ifdef KERNEL_PRIVATE
		u_int64_t ifru_data64;	/* 64-bit ifru_data */
#endif KERNEL_PRIVATE
		struct	ifdevmtu ifru_devmtu;
	} ifr_ifru;
#define	ifr_addr	ifr_ifru.ifru_addr	/* address */
#define	ifr_dstaddr	ifr_ifru.ifru_dstaddr	/* other end of p-to-p link */
#define	ifr_broadaddr	ifr_ifru.ifru_broadaddr	/* broadcast address */
#ifdef __APPLE__
#define	ifr_flags	ifr_ifru.ifru_flags	/* flags */
#else
#define	ifr_flags	ifr_ifru.ifru_flags[0]	/* flags */
#define	ifr_prevflags	ifr_ifru.ifru_flags[1]	/* flags */
#endif /* __APPLE__ */
#define	ifr_metric	ifr_ifru.ifru_metric	/* metric */
#define	ifr_mtu		ifr_ifru.ifru_mtu	/* mtu */
#define ifr_phys	ifr_ifru.ifru_phys	/* physical wire */
#define ifr_media	ifr_ifru.ifru_media	/* physical media */
#define	ifr_data	ifr_ifru.ifru_data	/* for use by interface */
#define ifr_devmtu	ifr_ifru.ifru_devmtu	
#define ifr_intval	ifr_ifru.ifru_intval	/* integer value */
#ifdef KERNEL_PRIVATE
#define ifr_data64	ifr_ifru.ifru_data64	/* 64-bit pointer */
#endif KERNEL_PRIVATE
};

#define	_SIZEOF_ADDR_IFREQ(ifr) \
	((ifr).ifr_addr.sa_len > sizeof(struct sockaddr) ? \
	 (sizeof(struct ifreq) - sizeof(struct sockaddr) + \
	  (ifr).ifr_addr.sa_len) : sizeof(struct ifreq))

struct ifaliasreq {
	char	ifra_name[IFNAMSIZ];		/* if name, e.g. "en0" */
	struct	sockaddr ifra_addr;
	struct	sockaddr ifra_broadaddr;
	struct	sockaddr ifra_mask;
};

struct rslvmulti_req {
     struct sockaddr *sa;
     struct sockaddr **llsa;
};

struct ifmediareq {
	char	ifm_name[IFNAMSIZ];	/* if name, e.g. "en0" */
	int	ifm_current;		/* current media options */
	int	ifm_mask;		/* don't care mask */
	int	ifm_status;		/* media status */
	int	ifm_active;		/* active options */
	int	ifm_count;		/* # entries in ifm_ulist array */
	int	*ifm_ulist;		/* media words */
};

#ifdef KERNEL_PRIVATE
/* LP64 version of ifmediareq.  all pointers 
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with ifmediareq
 */
struct ifmediareq64 {
	char	ifm_name[IFNAMSIZ];	/* if name, e.g. "en0" */
	int	ifm_current;		/* current media options */
	int	ifm_mask;		/* don't care mask */
	int	ifm_status;		/* media status */
	int	ifm_active;		/* active options */
	int	ifm_count;		/* # entries in ifm_ulist array */
	union {				/* media words */
	    int * 	ifmu_ulist32;	/* 32-bit pointer */
	    u_int64_t	ifmu_ulist64;	/* 64-bit pointer */
	} ifm_ifmu;
};
#endif // KERNEL_PRIVATE

/* 
 * Structure used to retrieve aux status data from interfaces.
 * Kernel suppliers to this interface should respect the formatting
 * needed by ifconfig(8): each line starts with a TAB and ends with
 * a newline.  The canonical example to copy and paste is in if_tun.c.
 */

#define	IFSTATMAX	800		/* 10 lines of text */
struct ifstat {
	char	ifs_name[IFNAMSIZ];	/* if name, e.g. "en0" */
	char	ascii[IFSTATMAX + 1];
};

/*
 * Structure used in SIOCGIFCONF request.
 * Used to retrieve interface configuration
 * for machine (useful for programs which
 * must know all networks accessible).
 */
struct	ifconf {
	int	ifc_len;		/* size of associated buffer */
	union {
		caddr_t	ifcu_buf;
		struct	ifreq *ifcu_req;
	} ifc_ifcu;
#define	ifc_buf	ifc_ifcu.ifcu_buf	/* buffer address */
#define	ifc_req	ifc_ifcu.ifcu_req	/* array of structures returned */
};

#ifdef KERNEL_PRIVATE
/* LP64 version of ifconf.  all pointers 
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with ifconf
 */
struct ifconf64 {
	int     ifc_len;		/* size of associated buffer */
	union {
		struct ifreq *	ifcu_req;
	    	u_int64_t	ifcu_req64;
	} ifc_ifcu;
};
#define	ifc_req64	ifc_ifcu.ifcu_req64
#endif // KERNEL_PRIVATE

/*
 * DLIL KEV_DL_PROTO_ATTACHED/DETACHED structure
 */
struct kev_dl_proto_data {
     struct net_event_data   	link_data;
     unsigned long		proto_family;
     unsigned long		proto_remaining_count;
};

/*
 * Structure for SIOC[AGD]LIFADDR
 */
struct if_laddrreq {
	char			iflr_name[IFNAMSIZ];
	unsigned int		flags;
#define	IFLR_PREFIX	0x8000  /* in: prefix given  out: kernel fills id */
	unsigned int		prefixlen;         /* in/out */
	struct sockaddr_storage	addr;   /* in/out */
	struct sockaddr_storage	dstaddr; /* out */
};

#ifdef KERNEL
#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_IFADDR);
MALLOC_DECLARE(M_IFMADDR);
#endif
#endif
#endif /* _POSIX_C_SOURCE */

#ifndef KERNEL
struct if_nameindex {
	unsigned int	 if_index;	/* 1, 2, ... */
	char		*if_name;	/* null terminated name: "le0", ... */
};

__BEGIN_DECLS
unsigned int	 if_nametoindex(const char *);
char		*if_indextoname(unsigned int, char *);
struct		 if_nameindex *if_nameindex(void);
void		 if_freenameindex(struct if_nameindex *);
__END_DECLS
#endif

#ifdef KERNEL
#include <net/kpi_interface.h>
#endif

#endif /* !_NET_IF_H_ */
