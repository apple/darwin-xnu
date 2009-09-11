/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

#include <netinet/in.h>
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#include <netinet/in_pcb.h>

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

#include <hfs/hfs_cnode.h>

#include <miscfs/specfs/specdev.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>

#include <vfs/vfs_journal.h>

#include <mach/mach_types.h>

#include <kern/zalloc.h>
#include <kern/kalloc.h>

void kmeminit(void) __attribute__((section("__TEXT, initcode")));

/* Strings corresponding to types of memory.
 * Must be in synch with the #defines is sys/malloc.h 
 * NOTE - the reason we pass null strings in some cases is to reduce of foot
 * print as much as possible for systems where a tiny kernel is needed.
 * todo - We should probably redsign this and use enums for our types and only
 * include types needed for that configuration of the kernel.  This can't be
 * done without some kind of kpi since several types are hardwired and exported
 * (for example see types M_HFSMNT, M_UDFMNT, M_TEMP, etc in sys/malloc.h)
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
	"",				/* 28 M_UFSMNT */ 
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
#if HFS
	"HFS mount",	/* 75 M_HFSMNT */ 
	"HFS node",		/* 76 M_HFSNODE */ 
	"HFS fork",		/* 77 M_HFSFORK */ 
#else
	"",				/* 75 M_HFSMNT */ 
	"",				/* 76 M_HFSNODE */ 
	"",				/* 77 M_HFSFORK */ 
#endif
	"ZFS mount", 	/* 78 M_ZFSFSMNT */ 
	"ZFS node", 	/* 79 M_ZFSNODE */ 
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
#if JOURNALING
	"Journal",		/* 91 M_JNL_JNL */
	"Transaction",	/* 92 M_JNL_TR */
#else
	"",    			/* 91 M_JNL_JNL */
	"",    			/* 92 M_JNL_TR */
#endif
	"specinfo",		/* 93 M_SPECINFO */
	"kqueue",		/* 94 M_KQUEUE */
#if HFS
	"HFS dirhint",	/* 95 M_HFSDIRHINT */ 
#else
	"",				/* 95 M_HFSDIRHINT */ 
#endif
	"cluster_read",	/* 96 M_CLRDAHEAD */ 
	"cluster_write",/* 97 M_CLWRBEHIND */ 
	"iov64",		/* 98 M_IOV64 */ 
	"fileglob",		/* 99 M_FILEGLOB */ 
	"kauth",		/* 100 M_KAUTH */ 
	"dummynet",		/* 101 M_DUMMYNET */ 
#ifndef __LP64__
	"unsafe_fsnode",	/* 102 M_UNSAFEFS */ 
#else
	"",			/* 102 M_UNSAFEFS */ 
#endif /* __LP64__ */
	"macpipelabel", /* 103 M_MACPIPELABEL */
	"mactemp",      /* 104 M_MACTEMP */
	"sbuf",         /* 105 M_SBUF */
	"extattr",      /* 106 M_EXTATTR */
	"lctx",         /* 107 M_LCTX */
#if TRAFFIC_MGT
	"traffic_mgt",   /* 108 M_TRAFFIC_MGT */
#else
	"", /* 108 M_TRAFFIC_MGT */
#endif
#if HFS_COMPRESSION
	"decmpfs_cnode",/* 109 M_DECMPFS_CNODE */
#else
	"",             /* 109 M_DECMPFS_CNODE */
#endif /* HFS_COMPRESSION */
};

/* for use with kmzones.kz_zalloczone */
#define	KMZ_CREATEZONE		((void *)-2)
#define KMZ_LOOKUPZONE		((void *)-1)
#define KMZ_MALLOC			((void *)0)
#define	KMZ_SHAREZONE		((void *)1)

struct kmzones {
	size_t		kz_elemsize;
	void		*kz_zalloczone;
} kmzones[M_LAST] = {
#define	SOS(sname)	sizeof (struct sname)
#define SOX(sname)	-1
	{ -1,		0 },			/* 0 M_FREE */
	{ MSIZE,	KMZ_CREATEZONE },	/* 1 M_MBUF */
	{ 0,		KMZ_MALLOC },		/* 2 M_DEVBUF */
	{ SOS(socket),	KMZ_CREATEZONE },	/* 3 M_SOCKET */
	{ SOS(inpcb),	KMZ_LOOKUPZONE },	/* 4 M_PCB */
	{ M_MBUF,	KMZ_SHAREZONE },	/* 5 M_RTABLE */
	{ M_MBUF,	KMZ_SHAREZONE },	/* 6 M_HTABLE */
	{ M_MBUF,	KMZ_SHAREZONE },	/* 7 M_FTABLE */
	{ SOS(rusage),	KMZ_CREATEZONE },	/* 8 M_ZOMBIE */
	{ 0,		KMZ_MALLOC },		/* 9 M_IFADDR */
	{ M_MBUF,	KMZ_SHAREZONE },		/* 10 M_SOOPTS */
	{ 0,		KMZ_MALLOC },		/* 11 M_SONAME */
	{ MAXPATHLEN,	KMZ_CREATEZONE },		/* 12 M_NAMEI */
	{ 0,		KMZ_MALLOC },		/* 13 M_GPROF */
	{ 0,		KMZ_MALLOC },		/* 14 M_IOCTLOPS */
	{ 0,		KMZ_MALLOC },		/* 15 M_MAPMEM */
	{ SOS(ucred),	KMZ_CREATEZONE },	/* 16 M_CRED */
	{ SOS(pgrp),	KMZ_CREATEZONE },	/* 17 M_PGRP */
	{ SOS(session),	KMZ_CREATEZONE },	/* 18 M_SESSION */
	{ SOS(user32_iovec),	KMZ_LOOKUPZONE },	/* 19 M_IOV32 */
	{ SOS(mount),	KMZ_CREATEZONE },	/* 20 M_MOUNT */
	{ 0,		KMZ_MALLOC },		/* 21 M_FHANDLE */
#if (NFSCLIENT || NFSSERVER)
	{ SOS(nfsreq),	KMZ_CREATEZONE },	/* 22 M_NFSREQ */
	{ SOS(nfsmount),	KMZ_CREATEZONE },	/* 23 M_NFSMNT */
	{ SOS(nfsnode),	KMZ_CREATEZONE },	/* 24 M_NFSNODE */
#else
	{ 0,		KMZ_MALLOC },		/* 22 M_NFSREQ */
	{ 0,		KMZ_MALLOC },		/* 23 M_NFSMNT */
	{ 0,		KMZ_MALLOC },		/* 24 M_NFSNODE */
#endif
	{ SOS(vnode),	KMZ_CREATEZONE },	/* 25 M_VNODE */
	{ SOS(namecache),	KMZ_CREATEZONE },	/* 26 M_CACHE */
#if QUOTA
	{ SOX(dquot),	KMZ_LOOKUPZONE },	/* 27 M_DQUOT */
#else
	{ 0,		KMZ_MALLOC },		/* 27 M_DQUOT */
#endif
	{ 0,		KMZ_MALLOC },		/* 28 M_UFSMNT */
	{ 0,		KMZ_MALLOC },		/* 29 M_CGSUM */
	{ SOS(plimit),	KMZ_CREATEZONE },	/* 30 M_PLIMIT */
	{ SOS(sigacts),	KMZ_CREATEZONE },	/* 31 M_SIGACTS */
	{ 0,		KMZ_MALLOC },		/* 32 M_VMOBJ */
	{ 0,		KMZ_MALLOC },		/* 33 M_VMOBJHASH */
	{ 0,		KMZ_MALLOC },		/* 34 M_VMPMAP */
	{ 0,		KMZ_MALLOC },		/* 35 M_VMPVENT */
	{ 0,		KMZ_MALLOC },		/* 36 M_VMPAGER */
	{ 0,		KMZ_MALLOC },		/* 37 M_VMPGDATA */
	{ SOS(fileproc),	KMZ_CREATEZONE },	/* 38 M_FILEPROC */
	{ SOS(filedesc),	KMZ_CREATEZONE },	/* 39 M_FILEDESC */
	{ SOX(lockf),	KMZ_CREATEZONE },	/* 40 M_LOCKF */
	{ SOS(proc),	KMZ_CREATEZONE },	/* 41 M_PROC */
	{ SOS(pstats),	KMZ_CREATEZONE },	/* 42 M_PSTATS */
	{ 0,		KMZ_MALLOC },		/* 43 M_SEGMENT */
	{ M_FFSNODE,	KMZ_SHAREZONE },	/* 44 M_LFSNODE */
	{ 0,		KMZ_MALLOC },		/* 45 M_FFSNODE */
	{ M_FFSNODE,	KMZ_SHAREZONE },	/* 46 M_MFSNODE */
	{ 0,		KMZ_MALLOC },		/* 47 M_NQLEASE */
	{ 0,		KMZ_MALLOC },		/* 48 M_NQMHOST */
	{ 0,		KMZ_MALLOC },		/* 49 M_NETADDR */
#if (NFSCLIENT || NFSSERVER)
	{ SOX(nfsrv_sock),
			KMZ_CREATEZONE },	/* 50 M_NFSSVC */
	{ 0,		KMZ_MALLOC },		/* 51 M_NFSUID */
	{ SOX(nfsrvcache),
			KMZ_CREATEZONE },	/* 52 M_NFSD */
#else
	{ 0,		KMZ_MALLOC },		/* 50 M_NFSSVC */
	{ 0,		KMZ_MALLOC },		/* 51 M_NFSUID */
	{ 0,		KMZ_MALLOC },		/* 52 M_NFSD */
#endif
	{ SOX(ip_moptions),
			KMZ_LOOKUPZONE },	/* 53 M_IPMOPTS */
	{ SOX(in_multi),	KMZ_LOOKUPZONE },	/* 54 M_IPMADDR */
	{ SOX(ether_multi),
			KMZ_LOOKUPZONE },	/* 55 M_IFMADDR */
	{ SOX(mrt),	KMZ_CREATEZONE },	/* 56 M_MRTABLE */
	{ 0,		KMZ_MALLOC },		/* 57 unused entry */
	{ 0,		KMZ_MALLOC },		/* 58 unused entry */
#if (NFSCLIENT || NFSSERVER)
	{ SOS(nfsrv_descript),
			KMZ_CREATEZONE },	/* 59 M_NFSRVDESC */
	{ SOS(nfsdmap),	KMZ_CREATEZONE },	/* 60 M_NFSDIROFF */
	{ SOS(fhandle),	KMZ_LOOKUPZONE },	/* 61 M_NFSBIGFH */
#else
	{ 0,		KMZ_MALLOC },		/* 59 M_NFSRVDESC */
	{ 0,		KMZ_MALLOC },		/* 60 M_NFSDIROFF */
	{ 0,		KMZ_MALLOC },		/* 61 M_NFSBIGFH */
#endif
	{ 0,		KMZ_MALLOC },		/* 62 M_MSDOSFSMNT */
	{ 0,		KMZ_MALLOC },		/* 63 M_MSDOSFSFAT */
	{ 0,		KMZ_MALLOC },		/* 64 M_MSDOSFSNODE */
	{ SOS(tty),	KMZ_CREATEZONE },	/* 65 M_TTYS */
	{ 0,		KMZ_MALLOC },		/* 66 M_EXEC */
	{ 0,		KMZ_MALLOC },		/* 67 M_MISCFSMNT */
	{ 0,		KMZ_MALLOC },		/* 68 M_MISCFSNODE */
	{ 0,		KMZ_MALLOC },		/* 69 M_ADOSFSMNT */
	{ 0,		KMZ_MALLOC },		/* 70 M_ADOSFSNODE */
	{ 0,		KMZ_MALLOC },		/* 71 M_ANODE */
	{ SOX(buf),	KMZ_CREATEZONE },	/* 72 M_BUFHDR */
	{ (NDFILE * OFILESIZE),
			KMZ_CREATEZONE },	/* 73 M_OFILETABL */
	{ MCLBYTES,	KMZ_CREATEZONE },	/* 74 M_MCLUST */
#if HFS
	{ SOX(hfsmount),	KMZ_LOOKUPZONE },	/* 75 M_HFSMNT */
	{ SOS(cnode),	KMZ_CREATEZONE },	/* 76 M_HFSNODE */
	{ SOS(filefork),	KMZ_CREATEZONE },	/* 77 M_HFSFORK */
#else
	{ 0,		KMZ_MALLOC },		/* 75 M_HFSMNT */
	{ 0,		KMZ_MALLOC },		/* 76 M_HFSNODE */
	{ 0,		KMZ_MALLOC },		/* 77 M_HFSFORK */
#endif
	{ 0,		KMZ_MALLOC },		/* 78 M_ZFSMNT */
	{ 0,		KMZ_MALLOC },		/* 79 M_ZFSNODE */
	{ 0,		KMZ_MALLOC },		/* 80 M_TEMP */
	{ 0,		KMZ_MALLOC },		/* 81 M_SECA */
	{ 0,		KMZ_MALLOC },		/* 82 M_DEVFS */
	{ 0,		KMZ_MALLOC },		/* 83 M_IPFW */
	{ 0,		KMZ_MALLOC },		/* 84 M_UDFNODE */
	{ 0,		KMZ_MALLOC },		/* 85 M_UDFMOUNT */
	{ 0,		KMZ_MALLOC },		/* 86 M_IP6NDP */
	{ 0,		KMZ_MALLOC },		/* 87 M_IP6OPT */
	{ 0,		KMZ_MALLOC },		/* 88 M_IP6MISC */
	{ 0,		KMZ_MALLOC },		/* 89 M_TSEGQ */
	{ 0,		KMZ_MALLOC },		/* 90 M_IGMP */
#if JOURNALING
	{ SOS(journal), KMZ_CREATEZONE },	/* 91 M_JNL_JNL */
	{ SOS(transaction), KMZ_CREATEZONE },	/* 92 M_JNL_TR */
#else
	{ 0,	 KMZ_MALLOC },		/* 91 M_JNL_JNL */
	{ 0,	 KMZ_MALLOC },		/* 92 M_JNL_TR */
#endif
	{ SOS(specinfo), KMZ_CREATEZONE },	/* 93 M_SPECINFO */
	{ SOS(kqueue), KMZ_CREATEZONE },	/* 94 M_KQUEUE */
#if HFS
	{ SOS(directoryhint), KMZ_CREATEZONE },	/* 95 M_HFSDIRHINT */
#else
	{ 0,	KMZ_MALLOC },		/* 95 M_HFSDIRHINT */
#endif
	{ SOS(cl_readahead),  KMZ_CREATEZONE },	/* 96 M_CLRDAHEAD */
	{ SOS(cl_writebehind),KMZ_CREATEZONE },	/* 97 M_CLWRBEHIND */
	{ SOS(user64_iovec),	KMZ_LOOKUPZONE },	/* 98 M_IOV64 */
	{ SOS(fileglob),	KMZ_CREATEZONE },	/* 99 M_FILEGLOB */
	{ 0,		KMZ_MALLOC },		/* 100 M_KAUTH */
	{ 0,		KMZ_MALLOC },		/* 101 M_DUMMYNET */
#ifndef __LP64__
	{ SOS(unsafe_fsnode),KMZ_CREATEZONE },	/* 102 M_UNSAFEFS */
#else 
	{ 0,		KMZ_MALLOC },		/* 102 M_UNSAFEFS */
#endif /* __LP64__ */
	{ 0,		KMZ_MALLOC },		/* 103 M_MACPIPELABEL */
	{ 0,		KMZ_MALLOC },		/* 104 M_MACTEMP */
	{ 0,		KMZ_MALLOC },		/* 105 M_SBUF */
	{ 0,		KMZ_MALLOC },		/* 106 M_HFS_EXTATTR */
	{ 0,		KMZ_MALLOC },		/* 107 M_LCTX */
	{ 0,		KMZ_MALLOC },		/* 108 M_TRAFFIC_MGT */
#if HFS_COMPRESSION
	{ SOS(decmpfs_cnode),KMZ_CREATEZONE },	/* 109 M_DECMPFS_CNODE */
#else
	{ 0,		KMZ_MALLOC },		/* 109 M_DECMPFS_CNODE */
#endif /* HFS_COMPRESSION */
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
		if (kmz->kz_zalloczone == KMZ_CREATEZONE) {
			kmz->kz_zalloczone = zinit(kmz->kz_elemsize,
						1024 * 1024, PAGE_SIZE,
						memname[kmz - kmzones]);
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

#define	MDECL(reqlen)					\
union {							\
	struct	_mhead hdr;				\
	char	_m[(reqlen) + sizeof (struct _mhead)];	\
}

struct _mhead {
	size_t	mlen;
	char	dat[0];
};

void *
_MALLOC(
	size_t		size,
	int		type,
	int		flags)
{
	MDECL(size)	*mem;
	size_t		memsize = sizeof (*mem);

	if (type >= M_LAST)
		panic("_malloc TYPE");

	if (size == 0)
		return (NULL);

	if (flags & M_NOWAIT) {
		mem = (void *)kalloc_noblock(memsize);
	} else {
		mem = (void *)kalloc(memsize);

		if (mem == NULL) {

			/*
			 * We get here when the caller told us to block waiting for memory, but
			 * kalloc said there's no memory left to get.  Generally, this means there's a 
			 * leak or the caller asked for an impossibly large amount of memory.  Since there's
			 * nothing left to wait for and the caller isn't expecting a NULL return code, we
			 * just panic.  This is less than ideal, but returning NULL doesn't help since the
			 * majority of callers don't check the return value and will just dereference the pointer and
			 * trap anyway.  We may as well get a more descriptive message out while we can.
			 */

			panic("_MALLOC: kalloc returned NULL (potential leak), size %llu", (uint64_t) size);
		}
	}
	if (!mem)
		return (0);

	mem->hdr.mlen = memsize;

	if (flags & M_ZERO)
		bzero(mem->hdr.dat, size);

	return  (mem->hdr.dat);
}

void
_FREE(
	void		*addr,
	int		type)
{
	struct _mhead	*hdr;

	if (type >= M_LAST)
		panic("_free TYPE");

	if (!addr)
		return; /* correct (convenient bsd kernel legacy) */

	hdr = addr; hdr--;
	kfree(hdr, hdr->mlen);
}

void *
_MALLOC_ZONE(
	size_t		size,
	int		type,
	int		flags)
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
	else
		if (flags & M_NOWAIT) {
			elem = (void *)kalloc_noblock(size);
		} else {
			elem = (void *)kalloc(size);
		}

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
