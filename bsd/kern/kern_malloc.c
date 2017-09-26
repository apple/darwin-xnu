/*
 * Copyright (c) 2000-2013 Apple Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
/* Copyright (c) 1995, 1997 Apple Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1987, 1991, 1993
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
 *	@(#)kern_malloc.c	8.4 (Berkeley) 5/20/95
 */
/*
 * NOTICE: This file was modified by SPARTA, Inc. in 2005 to introduce
 * support for mandatory and extensible security protections.  This notice
 * is included in support of clause 2.2 (b) of the Apple Public License,
 * Version 2.0.
 */

#include <sys/param.h>
#include <sys/malloc.h>

#include <sys/socket.h>
#include <sys/socketvar.h>

#include <net/route.h>
#include <net/necp.h>

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>
#include <netinet/flow_divert.h>

#include <sys/event.h>
#include <sys/eventvar.h>

#include <sys/proc_internal.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/ubc_internal.h>
#include <sys/namei.h>
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/tty.h>
#include <sys/quota.h>
#include <sys/uio_internal.h>
#include <sys/resourcevar.h>
#include <sys/signalvar.h>
#include <sys/decmpfs.h>

#include <miscfs/specfs/specdev.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>

#include <mach/mach_types.h>

#include <kern/zalloc.h>
#include <kern/kalloc.h>

void kmeminit(void);

/* Strings corresponding to types of memory.
 * Must be in synch with the #defines is sys/malloc.h 
 * NOTE - the reason we pass null strings in some cases is to reduce of foot
 * print as much as possible for systems where a tiny kernel is needed.
 * todo - We should probably redesign this and use enums for our types and only
 * include types needed for that configuration of the kernel.  This can't be
 * done without some kind of kpi since several types are hardwired and exported
 * (for example see types M_UDFMNT, M_TEMP, etc in sys/malloc.h)
 */
const char *memname[] = {
	"free",		/* 0 M_FREE */
	"mbuf",		/* 1 M_MBUF */
	"devbuf",	/* 2 M_DEVBUF */ 
	"socket",	/* 3 M_SOCKET */ 
	"pcb",		/* 4 M_PCB */ 
	"routetbl",	/* 5 M_RTABLE */ 
	"hosttbl",	/* 6 M_HTABLE */ 
	"fragtbl",	/* 7 M_FTABLE */ 
	"zombie",	/* 8 M_ZOMBIE */ 
	"ifaddr",	/* 9 M_IFADDR */ 
	"soopts",	/* 10 M_SOOPTS */ 
	"soname",	/* 11 M_SONAME */ 
	"namei",	/* 12 M_NAMEI */ 
	"gprof",	/* 13 M_GPROF */ 
	"ioctlops",	/* 14 M_IOCTLOPS */ 
	"mapmem",	/* 15 M_MAPMEM */ 
	"cred",		/* 16 M_CRED */ 
	"pgrp",		/* 17 M_PGRP */ 
	"session",	/* 18 M_SESSION */ 
	"iov32",	/* 19 M_IOV32 */ 
	"mount",	/* 20 M_MOUNT */ 
	"fhandle",		/* 21 M_FHANDLE */ 
#if (NFSCLIENT || NFSSERVER)
	"NFS req",		/* 22 M_NFSREQ */ 
	"NFS mount",	/* 23 M_NFSMNT */ 
	"NFS node",		/* 24 M_NFSNODE */ 
#else
	"",				/* 22 M_NFSREQ */ 
	"",				/* 23 M_NFSMNT */ 
	"",				/* 24 M_NFSNODE */ 
#endif
	"vnodes",		/* 25 M_VNODE */ 
	"namecache",	/* 26 M_CACHE */ 
#if QUOTA
	"UFS quota",	/* 27 M_DQUOT */ 
#else
	"",				/* 27 M_DQUOT */ 
#endif
	"proc uuid policy",		/* 28 M_PROC_UUID_POLICY */ 
#if (SYSV_SEM || SYSV_MSG || SYSV_SHM)
	"shm",			/* 29 M_SHM */ 
#else
	"",				/* 29 M_SHM */ 
#endif
	"plimit",		/* 30 M_VMMAP */ 
	"sigacts",	/* 31 M_VMMAPENT */ 
	"VM object",	/* 32 M_VMOBJ */ 
	"VM objhash",	/* 33 M_VMOBJHASH */ 
	"VM pmap",		/* 34 M_VMPMAP */ 
	"VM pvmap",		/* 35 M_VMPVENT */ 
	"VM pager",		/* 36 M_VMPAGER */ 
	"VM pgdata",	/* 37 M_VMPGDATA */ 
	"fileproc",		/* 38 M_FILEPROC */ 
	"file desc",	/* 39 M_FILEDESC */ 
	"lockf",		/* 40 M_LOCKF */ 
	"proc",			/* 41 M_PROC */ 
	"pstats",		/* 42 M_SUBPROC */ 
	"LFS segment",	/* 43 M_SEGMENT */ 
	"LFS node",		/* 44 M_LFSNODE */ 
	"",				/* 45 M_FFSNODE */ 
	"MFS node",		/* 46 M_MFSNODE */ 
	"NQNFS Lease",	/* 47 M_NQLEASE */ 
	"NQNFS Host",	/* 48 M_NQMHOST */ 
	"Export Host",	/* 49 M_NETADDR */ 
#if (NFSCLIENT || NFSSERVER)
	"NFS srvsock",	/* 50 M_NFSSVC */ 
	"NFS uid",		/* 51 M_NFSUID */ 
	"NFS daemon",	/* 52 M_NFSD */ 
#else
	"",				/* 50 M_NFSSVC */ 
	"",				/* 51 M_NFSUID */ 
	"",				/* 52 M_NFSD */ 
#endif
	"ip_moptions",	/* 53 M_IPMOPTS */ 
	"in_multi",		/* 54 M_IPMADDR */ 
	"ether_multi",	/* 55 M_IFMADDR */ 
	"mrt",			/* 56 M_MRTABLE */ 
	"",		/* 57 unused entry */ 
	"",		/* 58 unused entry */ 
#if (NFSCLIENT || NFSSERVER)
	"NFSV3 srvdesc",/* 59 M_NFSRVDESC */ 
	"NFSV3 diroff",	/* 60 M_NFSDIROFF */ 
	"NFSV3 bigfh",	/* 61 M_NFSBIGFH */ 
#else
	"",				/* 59 M_NFSRVDESC */ 
	"",				/* 60 M_NFSDIROFF */ 
	"",				/* 61 M_NFSBIGFH */ 
#endif
	"MSDOSFS mount",/* 62 M_MSDOSFSMNT */ 
	"MSDOSFS fat",	/* 63 M_MSDOSFSFAT */ 
	"MSDOSFS node",	/* 64 M_MSDOSFSNODE */ 
	"ttys",			/* 65 M_TTYS */ 
	"exec",			/* 66 M_EXEC */ 
	"miscfs mount",	/* 67 M_MISCFSMNT */ 
	"miscfs node",	/* 68 M_MISCFSNODE */ 
	"adosfs mount",	/* 69 M_ADOSFSMNT */ 
	"adosfs node",	/* 70 M_ADOSFSNODE */ 
	"adosfs anode",	/* 71 M_ANODE */ 
	"buf hdrs",		/* 72 M_BUFHDR */ 
	"ofile tabl",	/* 73 M_OFILETABL */ 
	"mbuf clust",	/* 74 M_MCLUST */ 
	"",				/* 75 unused */
	"",				/* 76 unused */
	"",				/* 77 unused */
	"", 			/* 78 unused */
	"", 			/* 79 unused */
	"temp",			/* 80 M_TEMP */ 
	"key mgmt",		/* 81 M_SECA */ 
	"DEVFS",		/* 82 M_DEVFS */ 
	"IpFw/IpAcct",	/* 83 M_IPFW */ 
	"UDF node",		/* 84 M_UDFNODE */ 
	"UDF mount",	/* 85 M_UDFMNT */ 
#if INET6
	"IPv6 NDP",		/* 86 M_IP6NDP */ 
	"IPv6 options",	/* 87 M_IP6OPT */ 
	"IPv6 Misc",	/* 88 M_IP6MISC */
#else
	"",				/* 86 M_IP6NDP */ 
	"",				/* 87 M_IP6OPT */ 
	"",				/* 88 M_IP6MISC */
#endif
	"TCP Segment Q",/* 89 M_TSEGQ */
	"IGMP state",	/* 90 M_IGMP */
	"",    			/* 91 unused */
	"",    			/* 92 unused */
	"specinfo",		/* 93 M_SPECINFO */
	"kqueue",		/* 94 M_KQUEUE */
	"",				/* 95 unused */
	"cluster_read",	/* 96 M_CLRDAHEAD */
	"cluster_write",/* 97 M_CLWRBEHIND */ 
	"iov64",		/* 98 M_IOV64 */ 
	"fileglob",		/* 99 M_FILEGLOB */ 
	"kauth",		/* 100 M_KAUTH */ 
	"dummynet",		/* 101 M_DUMMYNET */ 
	"",			/* 102 M_UNSAFEFS */ 
	"macpipelabel", /* 103 M_MACPIPELABEL */
	"mactemp",      /* 104 M_MACTEMP */
	"sbuf",         /* 105 M_SBUF */
	"extattr",      /* 106 M_EXTATTR */
	"select",       /* 107 M_SELECT */
#if TRAFFIC_MGT
	"traffic_mgt",   /* 108 M_TRAFFIC_MGT */
#else
	"", /* 108 M_TRAFFIC_MGT */
#endif
#if FS_COMPRESSION
	"decmpfs_cnode",/* 109 M_DECMPFS_CNODE */
#else
	"",             /* 109 M_DECMPFS_CNODE */
#endif /* FS_COMPRESSION */
	"ipmfilter",	/* 110 M_INMFILTER */
	"ipmsource",	/* 111 M_IPMSOURCE */
	"in6mfilter", 	/* 112 M_IN6MFILTER */
	"ip6mopts",	/* 113 M_IP6MOPTS */
	"ip6msource",	/* 114 M_IP6MSOURCE */
#if FLOW_DIVERT
	"flow_divert_pcb",	/* 115 M_FLOW_DIVERT_PCB */
	"flow_divert_group",	/* 116 M_FLOW_DIVERT_GROUP */
#else
	"",					/* 115 M_FLOW_DIVERT_PCB */
	"",					/* 116 M_FLOW_DIVERT_GROUP */
#endif
	"ip6cga",	/* 117 M_IP6CGA */
#if NECP
	"necp",					/* 118 M_NECP */
	"necp_session_policy",	/* 119 M_NECP_SESSION_POLICY */
	"necp_socket_policy",	/* 120 M_NECP_SOCKET_POLICY */
	"necp_ip_policy",		/* 121 M_NECP_IP_POLICY */
#else
	"",						/* 118 M_NECP */
	"",						/* 119 M_NECP_SESSION_POLICY */
	"",						/* 120 M_NECP_SOCKET_POLICY */
	"",						/* 121 M_NECP_IP_POLICY */
#endif
	"fdvnodedata"	/* 122 M_FD_VN_DATA */
	"fddirbuf",	/* 123 M_FD_DIRBUF */
	"netagent",	/* 124 M_NETAGENT */
	"Event Handler",/* 125 M_EVENTHANDLER */
	"Link Layer Table",	/* 126 M_LLTABLE */
	"Network Work Queue",	/* 127 M_NWKWQ */
	""
};

/* for use with kmzones.kz_zalloczone */
#define KMZ_CREATEZONE_ACCT	((void *)-3)
#define	KMZ_CREATEZONE		((void *)-2)
#define KMZ_LOOKUPZONE		((void *)-1)
#define KMZ_MALLOC			((void *)0)
#define	KMZ_SHAREZONE		((void *)1)

struct kmzones {
	size_t		kz_elemsize;
	void		*kz_zalloczone;
	boolean_t	kz_noencrypt;
} kmzones[M_LAST] = {
#define	SOS(sname)	sizeof (struct sname)
#define SOX(sname)	-1
	{ -1,		0, FALSE },			/* 0 M_FREE */
	{ MSIZE,	KMZ_CREATEZONE, FALSE },	/* 1 M_MBUF */
	{ 0,		KMZ_MALLOC, FALSE },		/* 2 M_DEVBUF */
	{ SOS(socket),	KMZ_CREATEZONE, TRUE },		/* 3 M_SOCKET */
	{ SOS(inpcb),	KMZ_LOOKUPZONE, TRUE },		/* 4 M_PCB */
	{ M_MBUF,	KMZ_SHAREZONE, FALSE },		/* 5 M_RTABLE */
	{ M_MBUF,	KMZ_SHAREZONE, FALSE },		/* 6 M_HTABLE */
	{ M_MBUF,	KMZ_SHAREZONE, FALSE },		/* 7 M_FTABLE */
	{ SOS(rusage),	KMZ_CREATEZONE, TRUE },		/* 8 M_ZOMBIE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 9 M_IFADDR */
	{ M_MBUF,	KMZ_SHAREZONE, FALSE },		/* 10 M_SOOPTS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 11 M_SONAME */
	{ MAXPATHLEN,	KMZ_CREATEZONE, FALSE },	/* 12 M_NAMEI */
	{ 0,		KMZ_MALLOC, FALSE },		/* 13 M_GPROF */
	{ 0,		KMZ_MALLOC, FALSE },		/* 14 M_IOCTLOPS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 15 M_MAPMEM */
	{ SOS(ucred),	KMZ_CREATEZONE, FALSE },	/* 16 M_CRED */
	{ SOS(pgrp),	KMZ_CREATEZONE, FALSE },	/* 17 M_PGRP */
	{ SOS(session),	KMZ_CREATEZONE, FALSE },	/* 18 M_SESSION */
	{ SOS(user32_iovec),	KMZ_LOOKUPZONE, FALSE },/* 19 M_IOV32 */
	{ SOS(mount),	KMZ_CREATEZONE, FALSE },	/* 20 M_MOUNT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 21 M_FHANDLE */
#if (NFSCLIENT || NFSSERVER)
	{ SOS(nfsreq),	KMZ_CREATEZONE, FALSE },	/* 22 M_NFSREQ */
	{ SOS(nfsmount),KMZ_CREATEZONE, FALSE },	/* 23 M_NFSMNT */
	{ SOS(nfsnode),	KMZ_CREATEZONE, FALSE },	/* 24 M_NFSNODE */
#else
	{ 0,		KMZ_MALLOC, FALSE },		/* 22 M_NFSREQ */
	{ 0,		KMZ_MALLOC, FALSE },		/* 23 M_NFSMNT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 24 M_NFSNODE */
#endif
	{ SOS(vnode),	KMZ_CREATEZONE, TRUE },		/* 25 M_VNODE */
	{ SOS(namecache), KMZ_CREATEZONE, FALSE },	/* 26 M_CACHE */
#if QUOTA
	{ SOX(dquot),	KMZ_LOOKUPZONE, FALSE },	/* 27 M_DQUOT */
#else
	{ 0,		KMZ_MALLOC, FALSE },		/* 27 M_DQUOT */
#endif
	{ 0,		KMZ_MALLOC, FALSE },		/* 28 M_PROC_UUID_POLICY */
	{ 0,		KMZ_MALLOC, FALSE },		/* 29 M_SHM */
	{ SOS(plimit),	KMZ_CREATEZONE, TRUE },		/* 30 M_PLIMIT */
	{ SOS(sigacts),	KMZ_CREATEZONE_ACCT, TRUE },	/* 31 M_SIGACTS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 32 M_VMOBJ */
	{ 0,		KMZ_MALLOC, FALSE },		/* 33 M_VMOBJHASH */
	{ 0,		KMZ_MALLOC, FALSE },		/* 34 M_VMPMAP */
	{ 0,		KMZ_MALLOC, FALSE },		/* 35 M_VMPVENT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 36 M_VMPAGER */
	{ 0,		KMZ_MALLOC, FALSE },		/* 37 M_VMPGDATA */
	{ SOS(fileproc),KMZ_CREATEZONE_ACCT, TRUE },	/* 38 M_FILEPROC */
	{ SOS(filedesc),KMZ_CREATEZONE_ACCT, TRUE },	/* 39 M_FILEDESC */
	{ SOX(lockf),	KMZ_CREATEZONE_ACCT, TRUE },	/* 40 M_LOCKF */
	{ SOS(proc),	KMZ_CREATEZONE, FALSE },	/* 41 M_PROC */
	{ SOS(pstats),	KMZ_CREATEZONE, TRUE },		/* 42 M_PSTATS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 43 M_SEGMENT */
	{ M_FFSNODE,	KMZ_SHAREZONE, FALSE },		/* 44 M_LFSNODE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 45 M_FFSNODE */
	{ M_FFSNODE,	KMZ_SHAREZONE, FALSE },		/* 46 M_MFSNODE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 47 M_NQLEASE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 48 M_NQMHOST */
	{ 0,		KMZ_MALLOC, FALSE },		/* 49 M_NETADDR */
#if (NFSCLIENT || NFSSERVER)
	{ SOX(nfsrv_sock),
	                KMZ_CREATEZONE_ACCT, FALSE },	/* 50 M_NFSSVC */
	{ 0,		KMZ_MALLOC, FALSE },		/* 51 M_NFSUID */
	{ SOX(nfsrvcache),
	                KMZ_CREATEZONE_ACCT, FALSE },	/* 52 M_NFSD */
#else
	{ 0,		KMZ_MALLOC, FALSE },		/* 50 M_NFSSVC */
	{ 0,		KMZ_MALLOC, FALSE },		/* 51 M_NFSUID */
	{ 0,		KMZ_MALLOC, FALSE },		/* 52 M_NFSD */
#endif
	{ SOX(ip_moptions),
	                KMZ_LOOKUPZONE, FALSE },	/* 53 M_IPMOPTS */
	{ SOX(in_multi),KMZ_LOOKUPZONE, FALSE },	/* 54 M_IPMADDR */
	{ SOX(ether_multi),
	                KMZ_LOOKUPZONE, FALSE },	/* 55 M_IFMADDR */
	{ SOX(mrt),	KMZ_CREATEZONE, TRUE },		/* 56 M_MRTABLE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 57 unused entry */
	{ 0,		KMZ_MALLOC, FALSE },		/* 58 unused entry */
#if (NFSCLIENT || NFSSERVER)
	{ SOS(nfsrv_descript),
	                KMZ_CREATEZONE_ACCT, FALSE },	/* 59 M_NFSRVDESC */
	{ SOS(nfsdmap),	KMZ_CREATEZONE, FALSE },	/* 60 M_NFSDIROFF */
	{ SOS(fhandle),	KMZ_LOOKUPZONE, FALSE },	/* 61 M_NFSBIGFH */
#else
	{ 0,		KMZ_MALLOC, FALSE },		/* 59 M_NFSRVDESC */
	{ 0,		KMZ_MALLOC, FALSE },		/* 60 M_NFSDIROFF */
	{ 0,		KMZ_MALLOC, FALSE },		/* 61 M_NFSBIGFH */
#endif
	{ 0,		KMZ_MALLOC, FALSE },		/* 62 M_MSDOSFSMNT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 63 M_MSDOSFSFAT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 64 M_MSDOSFSNODE */
	{ SOS(tty),	KMZ_CREATEZONE, FALSE },	/* 65 M_TTYS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 66 M_EXEC */
	{ 0,		KMZ_MALLOC, FALSE },		/* 67 M_MISCFSMNT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 68 M_MISCFSNODE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 69 M_ADOSFSMNT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 70 M_ADOSFSNODE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 71 M_ANODE */
	{ 0,		KMZ_MALLOC, TRUE },		/* 72 M_BUFHDR */
	{ (NDFILE * OFILESIZE),
	                KMZ_CREATEZONE_ACCT, FALSE },	/* 73 M_OFILETABL */
	{ MCLBYTES,	KMZ_CREATEZONE, FALSE },	/* 74 M_MCLUST */
	{ 0,		KMZ_MALLOC, FALSE },		/* 75 unused */
	{ 0,		KMZ_MALLOC, FALSE },		/* 76 unused */
	{ 0,		KMZ_MALLOC, FALSE },		/* 77 unused */
	{ 0,		KMZ_MALLOC, FALSE },		/* 78 unused */
	{ 0,		KMZ_MALLOC, FALSE },		/* 79 unused */
	{ 0,		KMZ_MALLOC, FALSE },		/* 80 M_TEMP */
	{ 0,		KMZ_MALLOC, FALSE },		/* 81 M_SECA */
	{ 0,		KMZ_MALLOC, FALSE },		/* 82 M_DEVFS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 83 M_IPFW */
	{ 0,		KMZ_MALLOC, FALSE },		/* 84 M_UDFNODE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 85 M_UDFMOUNT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 86 M_IP6NDP */
	{ 0,		KMZ_MALLOC, FALSE },		/* 87 M_IP6OPT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 88 M_IP6MISC */
	{ 0,		KMZ_MALLOC, FALSE },		/* 89 M_TSEGQ */
	{ 0,		KMZ_MALLOC, FALSE },		/* 90 M_IGMP */
	{ 0,	 	KMZ_MALLOC, FALSE },		/* 91 unused */
	{ 0,	 	KMZ_MALLOC, FALSE },		/* 92 unused */
	{ SOS(specinfo),KMZ_CREATEZONE, TRUE },		/* 93 M_SPECINFO */
	{ SOS(kqueue),	KMZ_CREATEZONE, FALSE },	/* 94 M_KQUEUE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 95 unused */
	{ SOS(cl_readahead),  KMZ_CREATEZONE, TRUE },	/* 96 M_CLRDAHEAD */
	{ SOS(cl_writebehind),KMZ_CREATEZONE, TRUE },	/* 97 M_CLWRBEHIND */
	{ SOS(user64_iovec),	KMZ_LOOKUPZONE, FALSE },/* 98 M_IOV64 */
	{ SOS(fileglob),	KMZ_CREATEZONE, TRUE },	/* 99 M_FILEGLOB */
	{ 0,		KMZ_MALLOC, FALSE },		/* 100 M_KAUTH */
	{ 0,		KMZ_MALLOC, FALSE },		/* 101 M_DUMMYNET */
	{ 0,		KMZ_MALLOC, FALSE },		/* 102 M_UNSAFEFS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 103 M_MACPIPELABEL */
	{ 0,		KMZ_MALLOC, FALSE },		/* 104 M_MACTEMP */
	{ 0,		KMZ_MALLOC, FALSE },		/* 105 M_SBUF */
	{ 0,		KMZ_MALLOC, FALSE },		/* 106 M_HFS_EXTATTR */
	{ 0,		KMZ_MALLOC, FALSE },		/* 107 M_SELECT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 108 M_TRAFFIC_MGT */
#if FS_COMPRESSION
	{ SOS(decmpfs_cnode),KMZ_CREATEZONE , FALSE},	/* 109 M_DECMPFS_CNODE */
#else
	{ 0,		KMZ_MALLOC, FALSE },		/* 109 M_DECMPFS_CNODE */
#endif /* FS_COMPRESSION */
 	{ 0,		KMZ_MALLOC, FALSE },		/* 110 M_INMFILTER */
	{ 0,		KMZ_MALLOC, FALSE },		/* 111 M_IPMSOURCE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 112 M_IN6MFILTER */
	{ 0,		KMZ_MALLOC, FALSE },		/* 113 M_IP6MOPTS */
	{ 0,		KMZ_MALLOC, FALSE },		/* 114 M_IP6MSOURCE */
#if FLOW_DIVERT
	{ SOS(flow_divert_pcb),		KMZ_CREATEZONE, TRUE },	/* 115 M_FLOW_DIVERT_PCB */
	{ SOS(flow_divert_group),	KMZ_CREATEZONE, TRUE },	/* 116 M_FLOW_DIVERT_GROUP */
#else
	{ 0,		KMZ_MALLOC, FALSE },		/* 115 M_FLOW_DIVERT_PCB */
	{ 0,		KMZ_MALLOC, FALSE },		/* 116 M_FLOW_DIVERT_GROUP */
#endif	/* FLOW_DIVERT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 117 M_IP6CGA */
	{ 0,		KMZ_MALLOC, FALSE },		/* 118 M_NECP */
#if NECP
	{ SOS(necp_session_policy),	KMZ_CREATEZONE, TRUE },	/* 119 M_NECP_SESSION_POLICY */
	{ SOS(necp_kernel_socket_policy),	KMZ_CREATEZONE, TRUE },	/* 120 M_NECP_SOCKET_POLICY */
	{ SOS(necp_kernel_ip_output_policy),	KMZ_CREATEZONE, TRUE },	/* 121 M_NECP_IP_POLICY */
#else
	{ 0,		KMZ_MALLOC, FALSE },		/* 119 M_NECP_SESSION_POLICY */
	{ 0,		KMZ_MALLOC, FALSE },		/* 120 M_NECP_SOCKET_POLICY */
	{ 0,		KMZ_MALLOC, FALSE },		/* 121 M_NECP_IP_POLICY */
#endif /* NECP */
	{ 0,		KMZ_MALLOC, FALSE },		/* 122 M_FD_VN_DATA */
	{ 0,		KMZ_MALLOC, FALSE },		/* 123 M_FD_DIRBUF */
	{ 0,		KMZ_MALLOC, FALSE },		/* 124 M_NETAGENT */
	{ 0,		KMZ_MALLOC, FALSE },		/* 125 M_EVENTHANDLER */
	{ 0,		KMZ_MALLOC, FALSE },		/* 126 M_LLTABLE */
	{ 0,		KMZ_MALLOC, FALSE },		/* 127 M_NWKWQ */
#undef	SOS
#undef	SOX
};

extern zone_t kalloc_zone(vm_size_t);	/* XXX */

/*
 * Initialize the kernel memory allocator
 */
void
kmeminit(void)
{
	struct kmzones	*kmz;

	if ((sizeof(kmzones)/sizeof(kmzones[0])) != (sizeof(memname)/sizeof(memname[0]))) {
		panic("kmeminit: kmzones has %lu elements but memname has %lu\n",
			  (sizeof(kmzones)/sizeof(kmzones[0])), (sizeof(memname)/sizeof(memname[0])));
	}

	kmz = kmzones;
	while (kmz < &kmzones[M_LAST]) {
/* XXX */
		if (kmz->kz_elemsize == (size_t)(-1))
			;
		else
/* XXX */
		if (kmz->kz_zalloczone == KMZ_CREATEZONE ||
		    kmz->kz_zalloczone == KMZ_CREATEZONE_ACCT) {
			kmz->kz_zalloczone = zinit(kmz->kz_elemsize,
						1024 * 1024, PAGE_SIZE,
						memname[kmz - kmzones]);
			zone_change(kmz->kz_zalloczone, Z_CALLERACCT,
				    (kmz->kz_zalloczone == KMZ_CREATEZONE_ACCT));

			if (kmz->kz_noencrypt == TRUE)
				zone_change(kmz->kz_zalloczone, Z_NOENCRYPT, TRUE);
		}
		else if (kmz->kz_zalloczone == KMZ_LOOKUPZONE)
			kmz->kz_zalloczone = kalloc_zone(kmz->kz_elemsize);

		kmz++;
	}

	kmz = kmzones;
	while (kmz < &kmzones[M_LAST]) {
/* XXX */
		if (kmz->kz_elemsize == (size_t)(-1))
			;
		else
/* XXX */
		if (kmz->kz_zalloczone == KMZ_SHAREZONE) {
			kmz->kz_zalloczone =
				kmzones[kmz->kz_elemsize].kz_zalloczone;
			kmz->kz_elemsize =
				kmzones[kmz->kz_elemsize].kz_elemsize;
		}

		kmz++;
	}
}

void *
_MALLOC_external(
	size_t		size,
	int		type,
	int		flags);
void *
_MALLOC_external(
	size_t		size,
	int		type,
	int		flags)
{
    static vm_allocation_site_t site = { .tag = VM_KERN_MEMORY_KALLOC, .flags = VM_TAG_BT };
    return (__MALLOC(size, type, flags, &site));
}

void *
__MALLOC(
	size_t		size,
	int		type,
	int		flags,
	vm_allocation_site_t *site)
{
	void 	*addr = NULL;
	vm_size_t 	msize = size;

	if (type >= M_LAST)
		panic("_malloc TYPE");

	if (size == 0)
		return (NULL);

	if (msize != size) {
		panic("Requested size to __MALLOC is too large (%llx)!\n", (uint64_t)size);
	}

	if (flags & M_NOWAIT) {
		addr = (void *)kalloc_canblock(&msize, FALSE, site);
	} else {
		addr = (void *)kalloc_canblock(&msize, TRUE, site);
		if (addr == NULL) {
			/*
			 * We get here when the caller told us to block waiting for memory, but
			 * kalloc said there's no memory left to get.  Generally, this means there's a 
			 * leak or the caller asked for an impossibly large amount of memory. If the caller
			 * is expecting a NULL return code then it should explicitly set the flag M_NULL. 
			 * If the caller isn't expecting a NULL return code, we just panic. This is less 
			 * than ideal, but returning NULL when the caller isn't expecting it doesn't help 
			 * since the majority of callers don't check the return value and will just 
			 * dereference the pointer and trap anyway.  We may as well get a more 
			 * descriptive message out while we can.
			 */
			if (flags & M_NULL) {
				return NULL;
			}
			panic("_MALLOC: kalloc returned NULL (potential leak), size %llu", (uint64_t) size);
		}
	}
	if (!addr)
		return (0);

	if (flags & M_ZERO)
		bzero(addr, size);

	return  (addr);
}

void
_FREE(
	void		*addr,
	int		type)
{
	if (type >= M_LAST)
		panic("_free TYPE");

	if (!addr)
		return; /* correct (convenient bsd kernel legacy) */

	kfree_addr(addr);
}

void *
__REALLOC(
	void		*addr,
	size_t		size,
	int		type,
	int		flags,
	vm_allocation_site_t *site)
{
	void		*newaddr;
	size_t		alloc;

	/* realloc(NULL, ...) is equivalent to malloc(...) */
	if (addr == NULL)
		return (__MALLOC(size, type, flags, site));

	alloc = kalloc_size(addr);
	/* 
	 * Find out the size of the bucket in which the new sized allocation 
	 * would land. If it matches the bucket of the original allocation, 
	 * simply return the address.
	 */
	if (kalloc_bucket_size(size) == alloc) {
		if (flags & M_ZERO) { 
			if (alloc < size)
				bzero(addr + alloc, (size - alloc));
			else
				bzero(addr + size, (alloc - size));
		}
		return addr;
	}

	/* Allocate a new, bigger (or smaller) block */
	if ((newaddr = __MALLOC(size, type, flags, site)) == NULL)
		return (NULL);

	/* Copy over original contents */
	bcopy(addr, newaddr, MIN(size, alloc));
	_FREE(addr, type);

	return (newaddr);
}

void *
_MALLOC_ZONE_external(
	size_t		size,
	int		type,
	int		flags);
void *
_MALLOC_ZONE_external(
	size_t		size,
	int		type,
	int		flags)
{
    return (__MALLOC_ZONE(size, type, flags, NULL));
}

void *
__MALLOC_ZONE(
	size_t		size,
	int		type,
	int		flags,
	vm_allocation_site_t *site)
{
	struct kmzones	*kmz;
	void		*elem;

	if (type >= M_LAST)
		panic("_malloc_zone TYPE");

	kmz = &kmzones[type];
	if (kmz->kz_zalloczone == KMZ_MALLOC)
		panic("_malloc_zone ZONE: type = %d", type);

/* XXX */
	if (kmz->kz_elemsize == (size_t)(-1))
		panic("_malloc_zone XXX");
/* XXX */
	if (size == kmz->kz_elemsize)
		if (flags & M_NOWAIT) {
	  		elem = (void *)zalloc_noblock(kmz->kz_zalloczone);
		} else {
	  		elem = (void *)zalloc(kmz->kz_zalloczone);
		}
	else {
		vm_size_t kalloc_size = size;
		if (size > kalloc_size) {
			elem = NULL;
		} else if (flags & M_NOWAIT) {
			elem = (void *)kalloc_canblock(&kalloc_size, FALSE, site);
		} else {
			elem = (void *)kalloc_canblock(&kalloc_size, TRUE, site);
		}
	}

	if (elem && (flags & M_ZERO))
		bzero(elem, size);

	return (elem);
}

void
_FREE_ZONE(
	void		*elem,
	size_t		size,
	int		type)
{
	struct kmzones	*kmz;

	if (type >= M_LAST)
		panic("FREE_SIZE");

	kmz = &kmzones[type];
	if (kmz->kz_zalloczone == KMZ_MALLOC)
		panic("free_zone ZONE");

/* XXX */
	if (kmz->kz_elemsize == (size_t)(-1))
		panic("FREE_SIZE XXX");
/* XXX */
	if (size == kmz->kz_elemsize)
		zfree(kmz->kz_zalloczone, elem);
	else
		kfree(elem, size);
}

#if DEBUG || DEVELOPMENT

extern unsigned int zone_map_jetsam_limit;

static int
sysctl_zone_map_jetsam_limit SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int oldval = 0, val = 0, error = 0;

	oldval = zone_map_jetsam_limit;
	error = sysctl_io_number(req, oldval, sizeof(int), &val, NULL);
	if (error || !req->newptr) {
		return (error);
	}

	if (val <= 0 || val > 100) {
		printf("sysctl_zone_map_jetsam_limit: new jetsam limit value is invalid.\n");
		return EINVAL;
	}

	zone_map_jetsam_limit = val;
	return (0);
}

SYSCTL_PROC(_kern, OID_AUTO, zone_map_jetsam_limit, CTLTYPE_INT|CTLFLAG_RW, 0, 0,
		sysctl_zone_map_jetsam_limit, "I", "Zone map jetsam limit");

extern boolean_t run_zone_test(void);

static int
sysctl_run_zone_test SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	int ret_val = run_zone_test();

	return SYSCTL_OUT(req, &ret_val, sizeof(ret_val));
}

SYSCTL_PROC(_kern, OID_AUTO, run_zone_test,
	CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
	0, 0, &sysctl_run_zone_test, "I", "Test zone allocator KPI");

#endif /* DEBUG || DEVELOPMENT */

#if CONFIG_ZLEAKS

SYSCTL_DECL(_kern_zleak);
SYSCTL_NODE(_kern, OID_AUTO, zleak, CTLFLAG_RW | CTLFLAG_LOCKED, 0, "zleak");

/*
 * kern.zleak.active
 *
 * Show the status of the zleak subsystem (0 = enabled, 1 = active,
 * and -1 = failed), and if enabled, allow it to be activated immediately.
 */
static int
sysctl_zleak_active SYSCTL_HANDLER_ARGS
{
#pragma unused(arg1, arg2)
	int oldval, val, error;

	val = oldval = get_zleak_state();
	error = sysctl_handle_int(oidp, &val, 0, req);
	if (error || !req->newptr)
		return (error);
	/*
	 * Can only be activated if it's off (and not failed.)
	 * Cannot be deactivated once it's on.
	 */
	if (val == 1 && oldval == 0) {
		kern_return_t kr = zleak_activate();

		if (KERN_SUCCESS != kr)
			printf("zleak_active: failed to activate "
			    "live zone leak debugging (%d).\n", kr);
	} if (val == 0 && oldval == 1) {
		printf("zleak_active: active, cannot be disabled.\n");
		return (EINVAL);
	}
	return (0);
}

SYSCTL_PROC(_kern_zleak, OID_AUTO, active,
    CTLTYPE_INT | CTLFLAG_RW | CTLFLAG_LOCKED,
    0, 0, sysctl_zleak_active, "I", "zleak activity");

/*
 * kern.zleak.max_zonemap_size
 *
 * Read the value of the maximum zonemap size in bytes; useful
 * as the maximum size that zleak.global_threshold and
 * zleak.zone_threshold should be set to.
 */
static int
sysctl_zleak_max_zonemap_size SYSCTL_HANDLER_ARGS
{
	uint64_t zmap_max_size = *(vm_size_t *)arg1;

	return sysctl_handle_quad(oidp, &zmap_max_size, arg2, req);
}

SYSCTL_PROC(_kern_zleak, OID_AUTO, max_zonemap_size,
    CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_LOCKED,
    &zleak_max_zonemap_size, 0,
    sysctl_zleak_max_zonemap_size, "Q", "zleak max zonemap size");


static int
sysctl_zleak_threshold SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg2)
	int error;
	uint64_t value = *(vm_size_t *)arg1;

	error = sysctl_io_number(req, value, sizeof (value), &value, NULL);

	if (error || !req->newptr)
		return (error);

	if (value > (uint64_t)zleak_max_zonemap_size)
		return (ERANGE);

	*(vm_size_t *)arg1 = value;
	return (0);
}

/*
 * kern.zleak.global_threshold
 *
 * Set the global zleak threshold size (in bytes).  If the zone map
 * grows larger than this value, zleaks are automatically activated.
 *
 * The default value is set in zleak_init().
 */
SYSCTL_PROC(_kern_zleak, OID_AUTO, global_threshold,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    &zleak_global_tracking_threshold, 0,
    sysctl_zleak_threshold, "Q", "zleak global threshold");

/*
 * kern.zleak.zone_threshold
 *
 * Set the per-zone threshold size (in bytes) above which any
 * zone will automatically start zleak tracking.
 *
 * The default value is set in zleak_init().
 *
 * Setting this variable will have no effect until zleak tracking is
 * activated (See above.)
 */
SYSCTL_PROC(_kern_zleak, OID_AUTO, zone_threshold,
    CTLTYPE_QUAD | CTLFLAG_RW | CTLFLAG_LOCKED,
    &zleak_per_zone_tracking_threshold, 0,
    sysctl_zleak_threshold, "Q", "zleak per-zone threshold");

#endif	/* CONFIG_ZLEAKS */

extern uint64_t get_zones_collectable_bytes(void);

static int
sysctl_zones_collectable_bytes SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1, arg2)
	uint64_t zones_free_mem = get_zones_collectable_bytes();

	return SYSCTL_OUT(req, &zones_free_mem, sizeof(zones_free_mem));
}

SYSCTL_PROC(_kern, OID_AUTO, zones_collectable_bytes,
	CTLTYPE_QUAD | CTLFLAG_RD | CTLFLAG_MASKED | CTLFLAG_LOCKED,
	0, 0, &sysctl_zones_collectable_bytes, "Q", "Collectable memory in zones");
