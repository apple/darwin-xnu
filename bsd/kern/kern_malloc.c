/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

#include <ufs/ufs/inode.h>

#include <hfs/hfs_cnode.h>
#include <isofs/cd9660/cd9660_node.h>

#include <miscfs/volfs/volfs.h>
#include <miscfs/specfs/specdev.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfsnode.h>
#include <nfs/nfsmount.h>

#include <vfs/vfs_journal.h>

#include <mach/mach_types.h>

#include <kern/zalloc.h>
#include <kern/kalloc.h>

struct kmemstats kmemstats[M_LAST];
char *memname[] = INITKMEMNAMES;

struct kmzones {
	size_t		kz_elemsize;
	void		*kz_zalloczone;
#define	KMZ_CREATEZONE		((void *)-2)
#define KMZ_LOOKUPZONE		((void *)-1)
#define KMZ_MALLOC		((void *)0)
#define	KMZ_SHAREZONE		((void *)1)
} kmzones[M_LAST] = {
#define	SOS(sname)	sizeof (struct sname)
#define SOX(sname)	-1
	-1,		0,			/* 0 M_FREE */
	MSIZE,		KMZ_CREATEZONE,		/* 1 M_MBUF */
	0,		KMZ_MALLOC,		/* 2 M_DEVBUF */
	SOS(socket),	KMZ_CREATEZONE,		/* 3 M_SOCKET */
	SOS(inpcb),	KMZ_LOOKUPZONE,		/* 4 M_PCB */
	M_MBUF,		KMZ_SHAREZONE,		/* 5 M_RTABLE */
	M_MBUF,		KMZ_SHAREZONE,		/* 6 M_HTABLE */
	M_MBUF,		KMZ_SHAREZONE,		/* 7 M_FTABLE */
	SOS(rusage),	KMZ_CREATEZONE,		/* 8 M_ZOMBIE */
	0,		KMZ_MALLOC,		/* 9 M_IFADDR */
	M_MBUF,		KMZ_SHAREZONE,		/* 10 M_SOOPTS */
	0,		KMZ_MALLOC,		/* 11 M_SONAME */
	MAXPATHLEN,	KMZ_CREATEZONE,		/* 12 M_NAMEI */
	0,		KMZ_MALLOC,		/* 13 M_GPROF */
	0,		KMZ_MALLOC,		/* 14 M_IOCTLOPS */
	0,		KMZ_MALLOC,		/* 15 M_MAPMEM */
	SOS(ucred),	KMZ_CREATEZONE,		/* 16 M_CRED */
	SOS(pgrp),	KMZ_CREATEZONE,		/* 17 M_PGRP */
	SOS(session),	KMZ_CREATEZONE,		/* 18 M_SESSION */
	SOS(iovec_32),	KMZ_LOOKUPZONE,		/* 19 M_IOV32 */
	SOS(mount),	KMZ_CREATEZONE,		/* 20 M_MOUNT */
	0,		KMZ_MALLOC,		/* 21 M_FHANDLE */
	SOS(nfsreq),	KMZ_CREATEZONE,		/* 22 M_NFSREQ */
	SOS(nfsmount),	KMZ_CREATEZONE,		/* 23 M_NFSMNT */
	SOS(nfsnode),	KMZ_CREATEZONE,		/* 24 M_NFSNODE */
	SOS(vnode),	KMZ_CREATEZONE,		/* 25 M_VNODE */
	SOS(namecache),	KMZ_CREATEZONE,		/* 26 M_CACHE */
	SOX(dquot),	KMZ_LOOKUPZONE,		/* 27 M_DQUOT */
	SOX(ufsmount),	KMZ_LOOKUPZONE,		/* 28 M_UFSMNT */
	0,		KMZ_MALLOC,		/* 29 M_CGSUM */
	0,		KMZ_MALLOC,		/* 30 M_VMMAP */
	0,		KMZ_MALLOC,		/* 31 M_VMMAPENT */
	0,		KMZ_MALLOC,		/* 32 M_VMOBJ */
	0,		KMZ_MALLOC,		/* 33 M_VMOBJHASH */
	0,		KMZ_MALLOC,		/* 34 M_VMPMAP */
	0,		KMZ_MALLOC,		/* 35 M_VMPVENT */
	0,		KMZ_MALLOC,		/* 36 M_VMPAGER */
	0,		KMZ_MALLOC,		/* 37 M_VMPGDATA */
	SOS(fileproc),	KMZ_CREATEZONE,		/* 38 M_FILEPROC */
	SOS(filedesc),	KMZ_CREATEZONE,		/* 39 M_FILEDESC */
	SOX(lockf),	KMZ_CREATEZONE,		/* 40 M_LOCKF */
	SOS(proc),	KMZ_CREATEZONE,		/* 41 M_PROC */
	SOS(pstats),	KMZ_CREATEZONE,		/* 42 M_SUBPROC */
	0,		KMZ_MALLOC,		/* 43 M_SEGMENT */
	M_FFSNODE,	KMZ_SHAREZONE,		/* 44 M_LFSNODE */
	SOS(inode),	KMZ_CREATEZONE,		/* 45 M_FFSNODE */
	M_FFSNODE,	KMZ_SHAREZONE,		/* 46 M_MFSNODE */
	0,		KMZ_MALLOC,		/* 47 M_NQLEASE */
	0,		KMZ_MALLOC,		/* 48 M_NQMHOST */
	0,		KMZ_MALLOC,		/* 49 M_NETADDR */
	SOX(nfssvc_sock),
			KMZ_CREATEZONE,		/* 50 M_NFSSVC */
	SOS(nfsuid),	KMZ_CREATEZONE,		/* 51 M_NFSUID */
	SOX(nfsrvcache),
			KMZ_CREATEZONE,		/* 52 M_NFSD */
	SOX(ip_moptions),
			KMZ_LOOKUPZONE,		/* 53 M_IPMOPTS */
	SOX(in_multi),	KMZ_LOOKUPZONE,		/* 54 M_IPMADDR */
	SOX(ether_multi),
			KMZ_LOOKUPZONE,		/* 55 M_IFMADDR */
	SOX(mrt),	KMZ_CREATEZONE,		/* 56 M_MRTABLE */
	SOX(iso_mnt),	KMZ_LOOKUPZONE,		/* 57 M_ISOFSMNT */
	SOS(iso_node),	KMZ_CREATEZONE,		/* 58 M_ISOFSNODE */
	SOS(nfsrv_descript),
			KMZ_CREATEZONE,		/* 59 M_NFSRVDESC */
	SOS(nfsdmap),	KMZ_CREATEZONE,		/* 60 M_NFSDIROFF */
	SOS(fhandle),	KMZ_LOOKUPZONE,		/* 61 M_NFSBIGFH */
	0,		KMZ_MALLOC,		/* 62 M_MSDOSFSMNT */
	0,		KMZ_MALLOC,		/* 63 M_MSDOSFSFAT */
	0,		KMZ_MALLOC,		/* 64 M_MSDOSFSNODE */
	SOS(tty),	KMZ_CREATEZONE,		/* 65 M_TTYS */
	0,		KMZ_MALLOC,		/* 66 M_EXEC */
	0,		KMZ_MALLOC,		/* 67 M_MISCFSMNT */
	0,		KMZ_MALLOC,		/* 68 M_MISCFSNODE */
	0,		KMZ_MALLOC,		/* 69 M_ADOSFSMNT */
	0,		KMZ_MALLOC,		/* 70 M_ADOSFSNODE */
	0,		KMZ_MALLOC,		/* 71 M_ANODE */
	SOX(buf),	KMZ_CREATEZONE,		/* 72 M_BUFHDR */
	(NDFILE * OFILESIZE),
			KMZ_CREATEZONE,		/* 73 M_OFILETABL */
	MCLBYTES,	KMZ_CREATEZONE,		/* 74 M_MCLUST */
	SOX(hfsmount),	KMZ_LOOKUPZONE,		/* 75 M_HFSMNT */
	SOS(cnode),	KMZ_CREATEZONE,		/* 76 M_HFSNODE */
	SOS(filefork),	KMZ_CREATEZONE,		/* 77 M_HFSFORK */
	SOX(volfs_mntdata),	KMZ_LOOKUPZONE,		/* 78 M_VOLFSMNT */
	SOS(volfs_vndata),	KMZ_CREATEZONE,		/* 79 M_VOLFSNODE */
	0,		KMZ_MALLOC,		/* 80 M_TEMP */
	0,		KMZ_MALLOC,		/* 81 M_SECA */
	0,		KMZ_MALLOC,		/* 82 M_DEVFS */
	0,		KMZ_MALLOC,		/* 83 M_IPFW */
	0,		KMZ_MALLOC,		/* 84 M_UDFNODE */
	0,		KMZ_MALLOC,		/* 85 M_UDFMOUNT */
	0,		KMZ_MALLOC,		/* 86 M_IP6NDP */
	0,		KMZ_MALLOC,		/* 87 M_IP6OPT */
	0,		KMZ_MALLOC,		/* 88 M_IP6MISC */
	0,		KMZ_MALLOC,		/* 89 M_TSEGQ */
	0,		KMZ_MALLOC,		/* 90 M_IGMP */
	SOS(journal), KMZ_CREATEZONE,     /* 91 M_JNL_JNL */
	SOS(transaction), KMZ_CREATEZONE,     /* 92 M_JNL_TR */
	SOS(specinfo), KMZ_CREATEZONE,		/* 93 M_SPECINFO */
	SOS(kqueue), KMZ_CREATEZONE,		/* 94 M_KQUEUE */
	SOS(directoryhint), KMZ_CREATEZONE,	/* 95 M_HFSDIRHINT */
	SOS(cl_readahead),  KMZ_CREATEZONE,	/* 96 M_CLRDAHEAD */
	SOS(cl_writebehind),KMZ_CREATEZONE,	/* 97 M_CLWRBEHIND */
	SOS(iovec_64),	KMZ_LOOKUPZONE,		/* 98 M_IOV64 */
	SOS(fileglob),	KMZ_CREATEZONE,		/* 99 M_FILEGLOB */
	0,		KMZ_MALLOC,		/* 100 M_KAUTH */
	0,		KMZ_MALLOC,		/* 101 M_DUMMYNET */
	SOS(unsafe_fsnode),KMZ_CREATEZONE,	/* 102 M_UNSAFEFS */
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
		panic("kmeminit: kmzones has %d elements but memname has %d\n",
			  (sizeof(kmzones)/sizeof(kmzones[0])), (sizeof(memname)/sizeof(memname[0])));
	}

	kmz = kmzones;
	while (kmz < &kmzones[M_LAST]) {
/* XXX */
		if (kmz->kz_elemsize == -1)
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
		if (kmz->kz_elemsize == -1)
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

#define ZEROSIZETOKEN (void *)0xFADEDFAD

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

	/*
	 * On zero request we do not return zero as that
	 * could be mistaken for ENOMEM.
	 */
	if (size == 0)
		return (ZEROSIZETOKEN);

	if (flags & M_NOWAIT) {
		mem = (void *)kalloc_noblock(memsize);
	} else {
		mem = (void *)kalloc(memsize);
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

	if (addr == (void *)ZEROSIZETOKEN)
		return;
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
	if (kmz->kz_elemsize == -1)
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
	if (kmz->kz_elemsize == -1)
		panic("FREE_SIZE XXX");
/* XXX */
	if (size == kmz->kz_elemsize)
		zfree(kmz->kz_zalloczone, elem);
	else
		kfree(elem, size);
}
