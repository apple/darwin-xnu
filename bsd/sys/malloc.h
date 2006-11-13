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
/* Copyright (c) 1998, 1999 Apple Computer, Inc. All Rights Reserved */
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1987, 1993
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
 *	@(#)malloc.h	8.5 (Berkeley) 5/3/95
 */

#ifndef _SYS_MALLOC_H_
#define	_SYS_MALLOC_H_

#include <sys/appleapiopts.h>


#ifdef KERNEL
/*
 * flags to malloc
 */
#define	M_WAITOK	0x0000
#define	M_NOWAIT	0x0001
#define M_ZERO          0x0004          /* bzero the allocation */


#ifdef BSD_KERNEL_PRIVATE

#define KMEMSTATS

/*
 * Types of memory to be allocated (not all are used by us)
 */
#define	M_FREE		0	/* should be on free list */
#define	M_MBUF		1	/* mbuf */
#define	M_DEVBUF	2	/* device driver memory */
#define	M_SOCKET	3	/* socket structure */
#define	M_PCB		4	/* protocol control block */
#define	M_RTABLE	5	/* routing tables */
#define	M_HTABLE	6	/* IMP host tables */
#define	M_FTABLE	7	/* fragment reassembly header */
#define	M_ZOMBIE	8	/* zombie proc status */
#define	M_IFADDR	9	/* interface address */
#define	M_SOOPTS	10	/* socket options */
#define	M_SONAME	11	/* socket name */
#define	M_NAMEI		12	/* namei path name buffer */
#define	M_GPROF		13	/* kernel profiling buffer */
#define	M_IOCTLOPS	14	/* ioctl data buffer */
#define	M_MAPMEM	15	/* mapped memory descriptors */
#define	M_CRED		16	/* credentials */
#define	M_PGRP		17	/* process group header */
#define	M_SESSION	18	/* session header */
#define	M_IOV32		19	/* large iov's for 32 bit process */
#define	M_MOUNT		20	/* vfs mount struct */
#define	M_FHANDLE	21	/* network file handle */
#define	M_NFSREQ	22	/* NFS request header */
#define	M_NFSMNT	23	/* NFS mount structure */
#define	M_NFSNODE	24	/* NFS vnode private part */
#define	M_VNODE		25	/* Dynamically allocated vnodes */
#define	M_CACHE		26	/* Dynamically allocated cache entries */
#define	M_DQUOT		27	/* UFS quota entries */
#define	M_UFSMNT	28	/* UFS mount structure */
#define	M_SHM		29	/* SVID compatible shared memory segments */
#define	M_VMMAP		30	/* VM map structures */
#define	M_VMMAPENT	31	/* VM map entry structures */
#define	M_VMOBJ		32	/* VM object structure */
#define	M_VMOBJHASH	33	/* VM object hash structure */
#define	M_VMPMAP	34	/* VM pmap */
#define	M_VMPVENT	35	/* VM phys-virt mapping entry */
#define	M_VMPAGER	36	/* XXX: VM pager struct */
#define	M_VMPGDATA	37	/* XXX: VM pager private data */
#define	M_FILEPROC	38	/* Open file structure */
#define	M_FILEDESC	39	/* Open file descriptor table */
#define	M_LOCKF		40	/* Byte-range locking structures */
#define	M_PROC		41	/* Proc structures */
#define	M_SUBPROC	42	/* Proc sub-structures */
#define	M_SEGMENT	43	/* Segment for LFS */
#define	M_LFSNODE	44	/* LFS vnode private part */
#define	M_FFSNODE	45	/* FFS vnode private part */
#define	M_MFSNODE	46	/* MFS vnode private part */
#define	M_NQLEASE	47	/* XXX: Nqnfs lease */
#define	M_NQMHOST	48	/* XXX: Nqnfs host address table */
#define	M_NETADDR	49	/* Export host address structure */
#define	M_NFSSVC	50	/* Nfs server structure */
#define	M_NFSUID	51	/* Nfs uid mapping structure */
#define	M_NFSD		52	/* Nfs server daemon structure */
#define	M_IPMOPTS	53	/* internet multicast options */
#define	M_IPMADDR	54	/* internet multicast address */
#define	M_IFMADDR	55	/* link-level multicast address */
#define	M_MRTABLE	56	/* multicast routing tables */
#define	M_ISOFSMNT	57	/* ISOFS mount structure */
#define	M_ISOFSNODE	58	/* ISOFS vnode private part */
#define	M_NFSRVDESC	59	/* NFS server socket descriptor */
#define	M_NFSDIROFF	60	/* NFS directory offset data */
#define	M_NFSBIGFH	61	/* NFS version 3 file handle */
#define	M_MSDOSFSMNT	62	/* MSDOS FS mount structure */
#define	M_MSDOSFSFAT	63	/* MSDOS FS fat table */
#define	M_MSDOSFSNODE	64	/* MSDOS FS vnode private part */
#define	M_TTYS		65	/* allocated tty structures */
#define	M_EXEC		66	/* argument lists & other mem used by exec */
#define	M_MISCFSMNT	67	/* miscfs mount structures */
#define	M_MISCFSNODE	68	/* miscfs vnode private part */
#define	M_ADOSFSMNT	69	/* adosfs mount structures */
#define	M_ADOSFSNODE	70	/* adosfs vnode private part */
#define	M_ANODE		71	/* adosfs anode structures and tables. */
#define	M_BUFHDR	72	/* File buffer cache headers */
#define	M_OFILETABL	73	/* Open file descriptor table */
#define	M_MCLUST	74	/* mbuf cluster buffers */
#define	M_HFSMNT	75	/* HFS mount structure */
#define	M_HFSNODE	76	/* HFS catalog node */
#define	M_HFSFORK	77	/* HFS file fork */
#define M_VOLFSMNT	78  /* VOLFS mount structure */
#define	M_VOLFSNODE	79	/* VOLFS private node part */
#define	M_TEMP		80	/* misc temporary data buffers */
#define	M_KTRACE	M_TEMP	/* ktrace buffers */
#define	M_SECA		81	/* security associations, key management */
#define M_DEVFS		82
#define M_IPFW		83	/* IP Forwarding/NAT */
#define M_UDFNODE	84	/* UDF inodes */
#define M_UDFMNT	85	/* UDF mount structures */
#define M_IP6NDP	86	/* IPv6 Neighbour Discovery*/
#define M_IP6OPT	87	/* IPv6 options management */
#define M_IP6MISC	88	/* IPv6 misc. memory */
#define M_TSEGQ		89	/* TCP segment queue entry */
#define M_IGMP		90
#define M_JNL_JNL   91  /* Journaling: "struct journal" */
#define M_JNL_TR    92  /* Journaling: "struct transaction" */ 
#define	M_SPECINFO	93	/* special file node */
#define M_KQUEUE	94	/* kqueue */
#define	M_HFSDIRHINT	95	/* HFS directory hint */
#define M_CLRDAHEAD	96	/* storage for cluster read-ahead state */
#define M_CLWRBEHIND	97	/* storage for cluster write-behind state */
#define	M_IOV64		98	/* large iov's for 64 bit process */
#define M_FILEGLOB	99	/* fileglobal */
#define M_KAUTH		100	/* kauth subsystem */
#define M_DUMMYNET	101	/* dummynet */
#define M_UNSAFEFS	102	/* storage for vnode lock state for unsafe FS */

#else /* BSD_KERNEL_PRIVATE */

#define	M_RTABLE	5	/* routing tables */
#define	M_IFADDR	9	/* interface address (IOFireWireIP)*/
#define	M_LOCKF		40	/* Byte-range locking structures (msdos) */ 
#define	M_TEMP		80	/* misc temporary data buffers */
#define	M_HFSMNT	75	/* HFS mount structure (afpfs) */
#define M_KAUTH		100	/* kauth subsystem (smb) */
#define	M_SONAME	11	/* socket name (smb) */
#define	M_PCB		4	/* protocol control block (smb) */
#define M_UDFNODE	84	/* UDF inodes (udf)*/
#define M_UDFMNT	85	/* UDF mount structures (udf)*/

#endif /* BSD_KERNEL_PRIVATE */

#ifdef BSD_KERNEL_PRIVATE


#define	M_LAST		103	/* Must be last type + 1 */

/* Strings corresponding to types of memory */
/* Must be in synch with the #defines above */
#define	INITKMEMNAMES { \
	"free",		/* 0 M_FREE */ \
	"mbuf",		/* 1 M_MBUF */ \
	"devbuf",	/* 2 M_DEVBUF */ \
	"socket",	/* 3 M_SOCKET */ \
	"pcb",		/* 4 M_PCB */ \
	"routetbl",	/* 5 M_RTABLE */ \
	"hosttbl",	/* 6 M_HTABLE */ \
	"fragtbl",	/* 7 M_FTABLE */ \
	"zombie",	/* 8 M_ZOMBIE */ \
	"ifaddr",	/* 9 M_IFADDR */ \
	"soopts",	/* 10 M_SOOPTS */ \
	"soname",	/* 11 M_SONAME */ \
	"namei",	/* 12 M_NAMEI */ \
	"gprof",	/* 13 M_GPROF */ \
	"ioctlops",	/* 14 M_IOCTLOPS */ \
	"mapmem",	/* 15 M_MAPMEM */ \
	"cred",		/* 16 M_CRED */ \
	"pgrp",		/* 17 M_PGRP */ \
	"session",	/* 18 M_SESSION */ \
	"iov32",	/* 19 M_IOV32 */ \
	"mount",	/* 20 M_MOUNT */ \
	"fhandle",	/* 21 M_FHANDLE */ \
	"NFS req",	/* 22 M_NFSREQ */ \
	"NFS mount",	/* 23 M_NFSMNT */ \
	"NFS node",	/* 24 M_NFSNODE */ \
	"vnodes",	/* 25 M_VNODE */ \
	"namecache",	/* 26 M_CACHE */ \
	"UFS quota",	/* 27 M_DQUOT */ \
	"UFS mount",	/* 28 M_UFSMNT */ \
	"shm",		/* 29 M_SHM */ \
	"VM map",	/* 30 M_VMMAP */ \
	"VM mapent",	/* 31 M_VMMAPENT */ \
	"VM object",	/* 32 M_VMOBJ */ \
	"VM objhash",	/* 33 M_VMOBJHASH */ \
	"VM pmap",	/* 34 M_VMPMAP */ \
	"VM pvmap",	/* 35 M_VMPVENT */ \
	"VM pager",	/* 36 M_VMPAGER */ \
	"VM pgdata",	/* 37 M_VMPGDATA */ \
	"fileproc",	/* 38 M_FILEPROC */ \
	"file desc",	/* 39 M_FILEDESC */ \
	"lockf",	/* 40 M_LOCKF */ \
	"proc",		/* 41 M_PROC */ \
	"subproc",	/* 42 M_SUBPROC */ \
	"LFS segment",	/* 43 M_SEGMENT */ \
	"LFS node",	/* 44 M_LFSNODE */ \
	"FFS node",	/* 45 M_FFSNODE */ \
	"MFS node",	/* 46 M_MFSNODE */ \
	"NQNFS Lease",	/* 47 M_NQLEASE */ \
	"NQNFS Host",	/* 48 M_NQMHOST */ \
	"Export Host",	/* 49 M_NETADDR */ \
	"NFS srvsock",	/* 50 M_NFSSVC */ \
	"NFS uid",	/* 51 M_NFSUID */ \
	"NFS daemon",	/* 52 M_NFSD */ \
	"ip_moptions",	/* 53 M_IPMOPTS */ \
	"in_multi",	/* 54 M_IPMADDR */ \
	"ether_multi",	/* 55 M_IFMADDR */ \
	"mrt",		/* 56 M_MRTABLE */ \
	"ISOFS mount",	/* 57 M_ISOFSMNT */ \
	"ISOFS node",	/* 58 M_ISOFSNODE */ \
	"NFSV3 srvdesc",/* 59 M_NFSRVDESC */ \
	"NFSV3 diroff",	/* 60 M_NFSDIROFF */ \
	"NFSV3 bigfh",	/* 61 M_NFSBIGFH */ \
	"MSDOSFS mount",/* 62 M_MSDOSFSMNT */ \
	"MSDOSFS fat",	/* 63 M_MSDOSFSFAT */ \
	"MSDOSFS node",	/* 64 M_MSDOSFSNODE */ \
	"ttys",		/* 65 M_TTYS */ \
	"exec",		/* 66 M_EXEC */ \
	"miscfs mount",	/* 67 M_MISCFSMNT */ \
	"miscfs node",	/* 68 M_MISCFSNODE */ \
	"adosfs mount",	/* 69 M_ADOSFSMNT */ \
	"adosfs node",	/* 70 M_ADOSFSNODE */ \
	"adosfs anode",	/* 71 M_ANODE */ \
	"buf hdrs",	/* 72 M_BUFHDR */ \
	"ofile tabl",	/* 73 M_OFILETABL */ \
	"mbuf clust",	/* 74 M_MCLUST */ \
	"HFS mount",	/* 75 M_HFSMNT */ \
	"HFS node",	/* 76 M_HFSNODE */ \
	"HFS fork",	/* 77 M_HFSFORK */ \
	"VOLFS mount", 	/* 78 M_VOLFSMNT */ \
	"VOLFS node", 	/* 79 M_VOLFSNODE */ \
	"temp",		/* 80 M_TEMP */ \
	"key mgmt",	/* 81 M_SECA */ \
	"DEVFS",	/* 82 M_DEVFS */ \
	"IpFw/IpAcct",	/* 83 M_IPFW */ \
	"UDF node",	/* 84 M_UDFNODE */ \
	"UDF mount",	/* 85 M_UDFMNT */ \
	"IPv6 NDP",	/* 86 M_IP6NDP */ \
	"IPv6 options",	/* 87 M_IP6OPT */ \
	"IPv6 Misc",	/* 88 M_IP6MISC */\
	"TCP Segment Q",/* 89 M_TSEGQ */\
	"IGMP state",	/* 90 M_IGMP */\
	"Journal",    /* 91 M_JNL_JNL */\
	"Transaction",    /* 92 M_JNL_TR */\
	"specinfo",		/* 93 M_SPECINFO */\
	"kqueue",	/* 94 M_KQUEUE */\
	"HFS dirhint",	/* 95 M_HFSDIRHINT */ \
        "cluster_read",	/* 96 M_CLRDAHEAD */ \
        "cluster_write",/* 97 M_CLWRBEHIND */ \
	"iov64",	/* 98 M_IOV64 */ \
	"fileglob",	/* 99 M_FILEGLOB */ \
	"kauth",		/* 100 M_KAUTH */ \
	"dummynet",		/* 101 M_DUMMYNET */ \
        "unsafe_fsnode"	/* 102 M_UNSAFEFS */ \
}

struct kmemstats {
	long	ks_inuse;	/* # of packets of this type currently
				 * in use */
	long	ks_calls;	/* total packets of this type ever allocated */
	long 	ks_memuse;	/* total memory held in bytes */
	u_short	ks_limblocks;	/* number of times blocked for hitting limit */
	u_short	ks_mapblocks;	/* number of times blocked for kernel map */
	long	ks_maxused;	/* maximum number ever used */
	long	ks_limit;	/* most that are allowed to exist */
	long	ks_size;	/* sizes of this thing that are allocated */
	long	ks_spare;
};

extern struct kmemstats kmemstats[];

#endif /* BSD_KERNEL_PRIVATE */

/*
 * The malloc/free primatives used
 * by the BSD kernel code.
 */
#define	MALLOC(space, cast, size, type, flags) \
	(space) = (cast)_MALLOC(size, type, flags)

#define FREE(addr, type) \
	_FREE((void *)addr, type)

#define MALLOC_ZONE(space, cast, size, type, flags) \
	(space) = (cast)_MALLOC_ZONE(size, type, flags)

#define FREE_ZONE(addr, size, type) \
	_FREE_ZONE((void *)addr, size, type)

extern void	*_MALLOC(
			size_t		size,
			int		type,
			int		flags);

extern void	_FREE(
			void		*addr,
			int		type);

extern void	*_MALLOC_ZONE(
			size_t		size,
			int		type,
			int		flags);

extern void	_FREE_ZONE(
			void		*elem,
			size_t		size,
			int		type);

#endif	/* KERNEL */

#endif	/* _SYS_MALLOC_H_ */
