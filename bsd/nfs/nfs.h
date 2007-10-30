/*
 * Copyright (c) 2000-2007 Apple Inc.  All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfs.h	8.4 (Berkeley) 5/1/95
 * FreeBSD-Id: nfs.h,v 1.32 1997/10/12 20:25:38 phk Exp $
 */

#ifndef _NFS_NFS_H_
#define _NFS_NFS_H_

#include <sys/appleapiopts.h>
#include <sys/cdefs.h>

#ifdef __APPLE_API_PRIVATE
/*
 * Tunable constants for nfs
 */

#define NFS_TICKINTVL	5		/* Desired time for a tick (msec) */
#define NFS_HZ		(hz / nfs_ticks) /* Ticks/sec */
__private_extern__ int nfs_ticks;
#define	NFS_TIMEO	(1 * NFS_HZ)	/* Default timeout = 1 second */
#define	NFS_MINTIMEO	(1 * NFS_HZ)	/* Min timeout to use */
#define	NFS_MAXTIMEO	(60 * NFS_HZ)	/* Max timeout to backoff to */
#define	NFS_MINIDEMTIMEO (5 * NFS_HZ)	/* Min timeout for non-idempotent ops*/
#define	NFS_MAXREXMIT	100		/* Stop counting after this many */
#define	NFS_RETRANS	10		/* Num of retrans for soft mounts */
#define	NFS_TRYLATERDEL	4		/* Initial try later delay (sec) */
#define	NFS_MAXGRPS	16		/* Max. size of groups list */
#define	NFS_MINATTRTIMO 5		/* Attribute cache timeout in sec */
#define	NFS_MAXATTRTIMO 60
#define	NFS_MINDIRATTRTIMO 5		/* directory attribute cache timeout in sec */
#define	NFS_MAXDIRATTRTIMO 60
#define	NFS_IOSIZE	(1024 * 1024)	/* suggested I/O size */
#define	NFS_RWSIZE	32768		/* Def. read/write data size <= 32K */
#define	NFS_WSIZE	NFS_RWSIZE	/* Def. write data size <= 32K */
#define	NFS_RSIZE	NFS_RWSIZE	/* Def. read data size <= 32K */
#define	NFS_DGRAM_WSIZE	8192		/* UDP Def. write data size <= 8K */
#define	NFS_DGRAM_RSIZE	8192		/* UDP Def. read data size <= 8K */
#define NFS_READDIRSIZE	8192		/* Def. readdir size */
#define	NFS_DEFRAHEAD	16		/* Def. read ahead # blocks */
#define	NFS_MAXRAHEAD	128		/* Max. read ahead # blocks */
#define	NFS_DEFMAXASYNCWRITES 	128	/* Def. max # concurrent async write RPCs */
#define	NFS_DEFASYNCTHREAD 	16	/* Def. # nfsiod threads */
#define	NFS_MAXASYNCTHREAD 	64	/* max # nfsiod threads */
#define	NFS_ASYNCTHREADMAXIDLE	60	/* Seconds before idle nfsiods are reaped */
#define	NFS_DEFSTATFSRATELIMIT 	10	/* Def. max # statfs RPCs per second */
#define NFS_REQUESTDELAY	10	/* ms interval to check request queue */
#define NFSRV_DEADSOCKDELAY	5	/* Seconds before dead sockets are reaped */
#define NFSRV_MAXWGATHERDELAY	100	/* Max. write gather delay (msec) */
#ifndef NFSRV_WGATHERDELAY
#define NFSRV_WGATHERDELAY	1	/* Default write gather delay (msec) */
#endif
#define	NFS_DIRBLKSIZ	4096		/* Must be a multiple of DIRBLKSIZ */
#if defined(KERNEL) && !defined(DIRBLKSIZ)
#define	DIRBLKSIZ	512		/* XXX we used to use ufs's DIRBLKSIZ */
 					/* can't be larger than NFS_FABLKSIZE */
#endif

/* default values for unresponsive mount timeouts */
#define NFS_TPRINTF_INITIAL_DELAY	12
#define NFS_TPRINTF_DELAY		30

/*
 * Oddballs
 */
#define NFS_CMPFH(n, f, s) \
	((n)->n_fhsize == (s) && !bcmp((caddr_t)(n)->n_fhp, (caddr_t)(f), (s)))
#define NFS_SRVMAXDATA(n) \
		(((n)->nd_vers == NFS_VER3) ? (((n)->nd_nam2) ? \
		 NFS_MAXDGRAMDATA : NFS_MAXDATA) : NFS_V2MAXDATA)

/*
 * The IO_METASYNC flag should be implemented for local file systems.
 * (Until then, it is nothin at all.)
 */
#ifndef IO_METASYNC
#define IO_METASYNC	0
#endif

/*
 * Expected allocation sizes for major data structures. If the actual size
 * of the structure exceeds these sizes, then malloc() will be allocating
 * almost twice the memory required. This is used in nfs_init() to warn
 * the sysadmin that the size of a structure should be reduced.
 * (These sizes are always a power of 2. If the kernel malloc() changes
 *  to one that does not allocate space in powers of 2 size, then this all
 *  becomes bunk!).
 * Note that some of these structures come out of there own nfs zones.
*/
#define NFS_NODEALLOC	512
#define NFS_MNTALLOC	512
#define NFS_SVCALLOC	256

/*
 * Arguments to mount NFS
 */
#define NFS_ARGSVERSION	5		/* change when nfs_args changes */
struct nfs_args {
	int		version;	/* args structure version number */
	struct sockaddr	*addr;		/* file server address */
	int		addrlen;	/* length of address */
	int		sotype;		/* Socket type */
	int		proto;		/* and Protocol */
	u_char		*fh;		/* File handle to be mounted */
	int		fhsize;		/* Size, in bytes, of fh */
	int		flags;		/* flags */
	int		wsize;		/* write size in bytes */
	int		rsize;		/* read size in bytes */
	int		readdirsize;	/* readdir size in bytes */
	int		timeo;		/* initial timeout in .1 secs */
	int		retrans;	/* times to retry send */
	int		maxgrouplist;	/* Max. size of group list */
	int		readahead;	/* # of blocks to readahead */
	int		leaseterm;	/* obsolete: Term (sec) of lease */
	int		deadthresh;	/* obsolete: Retrans threshold */
	char		*hostname;	/* server's name */
	/* NFS_ARGSVERSION 3 ends here */
	int		acregmin;	/* reg file min attr cache timeout */
	int		acregmax;	/* reg file max attr cache timeout */
	int		acdirmin;	/* dir min attr cache timeout */
	int		acdirmax;	/* dir max attr cache timeout */
	/* NFS_ARGSVERSION 4 ends here */
	uint32_t	auth;		/* security mechanism flavor */
};
struct nfs_args4 {
	int		version;	/* args structure version number */
	struct sockaddr	*addr;		/* file server address */
	int		addrlen;	/* length of address */
	int		sotype;		/* Socket type */
	int		proto;		/* and Protocol */
	u_char		*fh;		/* File handle to be mounted */
	int		fhsize;		/* Size, in bytes, of fh */
	int		flags;		/* flags */
	int		wsize;		/* write size in bytes */
	int		rsize;		/* read size in bytes */
	int		readdirsize;	/* readdir size in bytes */
	int		timeo;		/* initial timeout in .1 secs */
	int		retrans;	/* times to retry send */
	int		maxgrouplist;	/* Max. size of group list */
	int		readahead;	/* # of blocks to readahead */
	int		leaseterm;	/* obsolete: Term (sec) of lease */
	int		deadthresh;	/* obsolete: Retrans threshold */
	char		*hostname;	/* server's name */
	/* NFS_ARGSVERSION 3 ends here */
	int		acregmin;	/* reg file min attr cache timeout */
	int		acregmax;	/* reg file max attr cache timeout */
	int		acdirmin;	/* dir min attr cache timeout */
	int		acdirmax;	/* dir max attr cache timeout */
};

struct nfs_args3 {
	int		version;	/* args structure version number */
	struct sockaddr	*addr;		/* file server address */
	int		addrlen;	/* length of address */
	int		sotype;		/* Socket type */
	int		proto;		/* and Protocol */
	u_char		*fh;		/* File handle to be mounted */
	int		fhsize;		/* Size, in bytes, of fh */
	int		flags;		/* flags */
	int		wsize;		/* write size in bytes */
	int		rsize;		/* read size in bytes */
	int		readdirsize;	/* readdir size in bytes */
	int		timeo;		/* initial timeout in .1 secs */
	int		retrans;	/* times to retry send */
	int		maxgrouplist;	/* Max. size of group list */
	int		readahead;	/* # of blocks to readahead */
	int		leaseterm;	/* obsolete: Term (sec) of lease */
	int		deadthresh;	/* obsolete: Retrans threshold */
	char		*hostname;	/* server's name */
};

#ifdef KERNEL
/* LP64 version of nfs_args.  all pointers and longs
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with nfs_args
 */
struct user_nfs_args {
	int		version;	/* args structure version number */
	user_addr_t	addr __attribute((aligned(8)));		/* file server address */
	int		addrlen;	/* length of address */
	int		sotype;		/* Socket type */
	int		proto;		/* and Protocol */
	user_addr_t	fh __attribute((aligned(8)));		/* File handle to be mounted */
	int		fhsize;		/* Size, in bytes, of fh */
	int		flags;		/* flags */
	int		wsize;		/* write size in bytes */
	int		rsize;		/* read size in bytes */
	int		readdirsize;	/* readdir size in bytes */
	int		timeo;		/* initial timeout in .1 secs */
	int		retrans;	/* times to retry send */
	int		maxgrouplist;	/* Max. size of group list */
	int		readahead;	/* # of blocks to readahead */
	int		leaseterm;	/* obsolete: Term (sec) of lease */
	int		deadthresh;	/* obsolete: Retrans threshold */
	user_addr_t	hostname __attribute((aligned(8)));	/* server's name */
	/* NFS_ARGSVERSION 3 ends here */
	int		acregmin;	/* reg file min attr cache timeout */
	int		acregmax;	/* reg file max attr cache timeout */
	int		acdirmin;	/* dir min attr cache timeout */
	int		acdirmax;	/* dir max attr cache timeout */
	/* NFS_ARGSVERSION 4 ends here */
	uint32_t	auth;		/* security mechanism flavor */
};
struct user_nfs_args4 {
	int		version;	/* args structure version number */
	user_addr_t	addr __attribute((aligned(8)));		/* file server address */
	int		addrlen;	/* length of address */
	int		sotype;		/* Socket type */
	int		proto;		/* and Protocol */
	user_addr_t	fh __attribute((aligned(8)));		/* File handle to be mounted */
	int		fhsize;		/* Size, in bytes, of fh */
	int		flags;		/* flags */
	int		wsize;		/* write size in bytes */
	int		rsize;		/* read size in bytes */
	int		readdirsize;	/* readdir size in bytes */
	int		timeo;		/* initial timeout in .1 secs */
	int		retrans;	/* times to retry send */
	int		maxgrouplist;	/* Max. size of group list */
	int		readahead;	/* # of blocks to readahead */
	int		leaseterm;	/* obsolete: Term (sec) of lease */
	int		deadthresh;	/* obsolete: Retrans threshold */
	user_addr_t	hostname __attribute((aligned(8)));	/* server's name */
	/* NFS_ARGSVERSION 3 ends here */
	int		acregmin;	/* reg file min attr cache timeout */
	int		acregmax;	/* reg file max attr cache timeout */
	int		acdirmin;	/* dir min attr cache timeout */
	int		acdirmax;	/* dir max attr cache timeout */
};
struct user_nfs_args3 {
	int		version;	/* args structure version number */
	user_addr_t	addr __attribute((aligned(8)));		/* file server address */
	int		addrlen;	/* length of address */
	int		sotype;		/* Socket type */
	int		proto;		/* and Protocol */
	user_addr_t	fh __attribute((aligned(8)));		/* File handle to be mounted */
	int		fhsize;		/* Size, in bytes, of fh */
	int		flags;		/* flags */
	int		wsize;		/* write size in bytes */
	int		rsize;		/* read size in bytes */
	int		readdirsize;	/* readdir size in bytes */
	int		timeo;		/* initial timeout in .1 secs */
	int		retrans;	/* times to retry send */
	int		maxgrouplist;	/* Max. size of group list */
	int		readahead;	/* # of blocks to readahead */
	int		leaseterm;	/* obsolete: Term (sec) of lease */
	int		deadthresh;	/* obsolete: Retrans threshold */
	user_addr_t	hostname __attribute((aligned(8)));	/* server's name */
};

#endif // KERNEL

/*
 * NFS mount option flags
 */
#define	NFSMNT_SOFT		0x00000001  /* soft mount (hard is default) */
#define	NFSMNT_WSIZE		0x00000002  /* set write size */
#define	NFSMNT_RSIZE		0x00000004  /* set read size */
#define	NFSMNT_TIMEO		0x00000008  /* set initial timeout */
#define	NFSMNT_RETRANS		0x00000010  /* set number of request retries */
#define	NFSMNT_MAXGRPS		0x00000020  /* set maximum grouplist size */
#define	NFSMNT_INT		0x00000040  /* allow interrupts on hard mount */
#define	NFSMNT_NOCONN		0x00000080  /* Don't Connect the socket */
#define	NFSMNT_NONEGNAMECACHE	0x00000100  /* Don't do negative name caching */
#define	NFSMNT_NFSV3		0x00000200  /* Use NFS Version 3 protocol */
#define	NFSMNT_NFSV4		0x00000400  /* Use NFS Version 4 protocol */
#define	NFSMNT_DUMBTIMR		0x00000800  /* Don't estimate rtt dynamically */
// #define	NFSMNT_UNUSED	0x00001000  /* unused */
#define	NFSMNT_READAHEAD	0x00002000  /* set read ahead */
// #define	NFSMNT_UNUSED	0x00004000  /* unused */
#define	NFSMNT_RESVPORT		0x00008000  /* Allocate a reserved port */
#define	NFSMNT_RDIRPLUS		0x00010000  /* Use Readdirplus for V3 */
#define	NFSMNT_READDIRSIZE	0x00020000  /* Set readdir size */
#define	NFSMNT_NOLOCKS		0x00040000  /* don't support file locking */
#define	NFSMNT_LOCALLOCKS	0x00080000  /* do file locking locally on client */
#define	NFSMNT_ACREGMIN		0x00100000  /* reg min attr cache timeout */
#define	NFSMNT_ACREGMAX		0x00200000  /* reg max attr cache timeout */
#define	NFSMNT_ACDIRMIN		0x00400000  /* dir min attr cache timeout */
#define	NFSMNT_ACDIRMAX		0x00800000  /* dir max attr cache timeout */
#define	NFSMNT_SECFLAVOR	0x01000000  /* Use security flavor */
#define	NFSMNT_SECGIVEN		0x02000000  /* A sec= mount option was given */

/*
 * Structures for the nfssvc(2) syscall. Not that anyone but nfsd
 * should ever try and use it.
 */
struct nfsd_args {
	int	sock;		/* Socket to serve */
	caddr_t	name;		/* Client addr for connection based sockets */
	int	namelen;	/* Length of name */
};

#ifdef KERNEL
/* LP64 version of nfsd_args.  all pointers and longs
 * grow when we're dealing with a 64-bit process.
 * WARNING - keep in sync with nfsd_args
 */
struct user_nfsd_args {
	int	        sock;		/* Socket to serve */
	user_addr_t	name __attribute((aligned(8)));		/* Client addr for connection based sockets */
	int	        namelen;	/* Length of name */
};

#endif // KERNEL

/*
 * NFS Server File Handle structures
 */

/* NFS export handle identifies which NFS export */
#define	NFS_FH_VERSION	0x4e580000		/* 'NX00' */
struct nfs_exphandle {
	uint32_t	nxh_version;		/* data structure version */
	uint32_t	nxh_fsid;		/* File System Export ID */
	uint32_t	nxh_expid;		/* Export ID */
	uint16_t	nxh_flags;		/* export handle flags */
	uint8_t		nxh_reserved;		/* future use */
	uint8_t		nxh_fidlen;		/* length of File ID */
};

/* nxh_flags */
#define NXHF_INVALIDFH		0x0001		/* file handle is invalid */

#define	NFS_MAX_FID_SIZE	(NFS_MAX_FH_SIZE - sizeof(struct nfs_exphandle))
#define	NFSV4_MAX_FID_SIZE	(NFSV4_MAX_FH_SIZE - sizeof(struct nfs_exphandle))
#define	NFSV3_MAX_FID_SIZE	(NFSV3_MAX_FH_SIZE - sizeof(struct nfs_exphandle))
#define	NFSV2_MAX_FID_SIZE	(NFSV2_MAX_FH_SIZE - sizeof(struct nfs_exphandle))

/* NFS server internal view of fhandle_t */
/* The first sizeof(fhandle_t) bytes must match what goes into fhandle_t. */
/* (fhp is used to allow use of an external buffer) */
struct nfs_filehandle {
	uint32_t		nfh_len;	/* total length of file handle */
	struct nfs_exphandle	nfh_xh;		/* export handle */
	unsigned char		nfh_fid[NFS_MAX_FID_SIZE]; /* File ID */
	unsigned char		*nfh_fhp;	/* pointer to file handle */
};

/*
 * NFS export data structures
 */

/* Structure to hold an array of security flavors */
#define NX_MAX_SEC_FLAVORS 5
struct nfs_sec {
	int count;
	uint32_t flavors[NX_MAX_SEC_FLAVORS];
}; 

struct nfs_export_net_args {
	uint32_t		nxna_flags;	/* export flags */
	struct xucred		nxna_cred;	/* mapped credential for root/all user */
	struct sockaddr_storage	nxna_addr;	/* net address to which exported */
	struct sockaddr_storage	nxna_mask;	/* mask for net address */
	struct nfs_sec		nxna_sec;	/* security mechanism flavors */
};

struct nfs_export_args {
	uint32_t		nxa_fsid;	/* export FS ID */
	uint32_t		nxa_expid;	/* export ID */
	char			*nxa_fspath;	/* export FS path */
	char			*nxa_exppath;	/* export sub-path */
	uint32_t		nxa_flags;	/* export arg flags */
	uint32_t		nxa_netcount;	/* #entries in ex_nets array */
	struct nfs_export_net_args *nxa_nets;	/* array of net args */
};

#ifdef KERNEL
/* LP64 version of export_args */

struct user_nfs_export_args {
	uint32_t		nxa_fsid;	/* export FS ID */
	uint32_t		nxa_expid;	/* export ID */
	user_addr_t		nxa_fspath;	/* export FS path */
	user_addr_t		nxa_exppath;	/* export sub-path */
	uint32_t		nxa_flags;	/* export arg flags */
	uint32_t		nxa_netcount;	/* #entries in ex_nets array */
	user_addr_t		nxa_nets;	/* array of net args */
};

#endif /* KERNEL */

/* nfs export arg flags */
#define NXA_DELETE		0x0001	/* delete the specified export(s) */
#define NXA_ADD			0x0002	/* add the specified export(s) */
#define NXA_REPLACE		0x0003	/* delete and add the specified export(s) */
#define NXA_DELETE_ALL		0x0004	/* delete all exports */
#define NXA_OFFLINE		0x0008	/* export is offline */

/* export option flags */
#define NX_READONLY		0x0001	/* exported read-only */
#define NX_DEFAULTEXPORT	0x0002	/* exported to the world */
#define NX_MAPROOT		0x0004	/* map root access to anon credential */
#define NX_MAPALL		0x0008	/* map all access to anon credential */
#define NX_32BITCLIENTS		0x0020	/* restrict directory cookies to 32 bits */
#define NX_OFFLINE		0x0040	/* export is offline */

/*
 * fs.nfs sysctl(3) export stats record structures
 */
#define NFS_EXPORT_STAT_REC_VERSION 1	/* export stat record version */
#define NFS_USER_STAT_REC_VERSION 1     /* active user list record version */

/* descriptor describing following records */
struct nfs_export_stat_desc
{
	uint32_t rec_vers;		/* version of export stat records */
	uint32_t rec_count;		/* total record count */
}__attribute__((__packed__));

/* export stat record containing path and stat counters */
struct nfs_export_stat_rec {
	char     path[RPCMNT_PATHLEN + 1];
	uint64_t ops;		/* Count of NFS Requests received for this export */
	uint64_t bytes_read;	/* Count of bytes read from this export */
	uint64_t bytes_written;	/* Count of bytes written to this export */
}__attribute__((__packed__));

/* Active user list stat buffer descriptor */
struct nfs_user_stat_desc
{
	uint32_t rec_vers;	/* version of active user stat records */
	uint32_t rec_count;	/* total record count */
}__attribute__((__packed__));

/* Active user list user stat record format */
struct nfs_user_stat_user_rec {
	u_char			rec_type;
	uid_t			uid;
	struct sockaddr_storage	sock;
	uint64_t		ops;
	uint64_t		bytes_read;
	uint64_t		bytes_written;
	uint32_t		tm_start;
	uint32_t		tm_last;
}__attribute__((__packed__));

/* Active user list path record format */
struct nfs_user_stat_path_rec {
	u_char	rec_type;
	char	path[RPCMNT_PATHLEN + 1];
}__attribute__((__packed__));

/* Defines for rec_type field of
 * nfs_user_stat_rec & nfs_user_stat_rec
 * data structures
 */
#define NFS_USER_STAT_USER_REC  0
#define NFS_USER_STAT_PATH_REC  1


#ifdef KERNEL
struct nfs_exportfs;

struct nfs_export_options {
	uint32_t		nxo_flags;	/* export options */
	kauth_cred_t		nxo_cred;	/* mapped credential */
	struct nfs_sec		nxo_sec;	/* security mechanism flavors */
};

/* Network address lookup element and individual export options */
struct nfs_netopt {
	struct radix_node		no_rnodes[2];	/* radix tree glue */
	struct nfs_export_options	no_opt;		/* export options */
};

/* statistic counters for each exported directory
 *
 * Since 64-bit atomic operations are not available on 32-bit platforms,
 * 64-bit counters are implemented using 32-bit integers and 32-bit
 * atomic operations
 */
typedef struct nfsstatcount64 {
	uint32_t	hi;
	uint32_t	lo;
} nfsstatcount64;

struct nfs_export_stat_counters {
	struct nfsstatcount64 ops;		/* Count of NFS Requests received for this export  */
	struct nfsstatcount64 bytes_read;	/* Count of bytes read from this export */
	struct nfsstatcount64 bytes_written;	/* Count of bytes written to his export */
}__attribute__((__packed__));

/* Macro for updating nfs export stat counters */
#define NFSStatAdd64(PTR, VAL) \
	do { \
		uint32_t NFSSA_OldValue = \
		OSAddAtomic((VAL), (SInt32*)&(PTR)->lo); \
		if ((NFSSA_OldValue + (VAL)) < NFSSA_OldValue) \
			OSAddAtomic(1, (SInt32*)&(PTR)->hi); \
	} while (0)

/* Some defines for dealing with active user list stats */
#define NFSRV_USER_STAT_DEF_MAX_NODES 1024	/* default active user list size limit */
#define NFSRV_USER_STAT_DEF_IDLE_SEC  7200	/* default idle seconds (node no longer considered active) */

/* active user list globals */
__private_extern__ uint32_t nfsrv_user_stat_enabled;		/* enable/disable active user list */
__private_extern__ uint32_t nfsrv_user_stat_node_count;		/* current count of user stat nodes */
__private_extern__ uint32_t nfsrv_user_stat_max_idle_sec;	/* idle seconds (node no longer considered active) */
__private_extern__ uint32_t nfsrv_user_stat_max_nodes;		/* active user list size limit */
__private_extern__ lck_grp_t *nfsrv_active_user_mutex_group;

/* An active user node represented in the kernel */
struct nfs_user_stat_node {
	TAILQ_ENTRY(nfs_user_stat_node)	lru_link;
	LIST_ENTRY(nfs_user_stat_node)	hash_link;
	uid_t			uid;
	struct sockaddr_storage	sock;
	uint64_t		ops;
	uint64_t		bytes_read;
	uint64_t		bytes_written;
	uint32_t		tm_start;
	uint32_t		tm_last;
};

/* Hash table for active user nodes */
#define NFS_USER_STAT_HASH_SIZE 16	/* MUST be a power of 2 */
#define NFS_USER_STAT_HASH(userhashtbl, uid) \
		&((userhashtbl)[(uid) & (NFS_USER_STAT_HASH_SIZE - 1)])

TAILQ_HEAD(nfs_user_stat_lru_head, nfs_user_stat_node);
LIST_HEAD(nfs_user_stat_hashtbl_head, nfs_user_stat_node);

/* Active user list data structure */
/* One per exported directory */
struct nfs_active_user_list {
	struct nfs_user_stat_lru_head		user_lru;
	struct nfs_user_stat_hashtbl_head	user_hashtbl[NFS_USER_STAT_HASH_SIZE];
	uint32_t				node_count;
	lck_mtx_t user_mutex;
};


/* Network export information */
/* one of these for each exported directory */
struct nfs_export {
	LIST_ENTRY(nfs_export)		nx_next;	/* FS export list */
	LIST_ENTRY(nfs_export)		nx_hash;	/* export hash chain */
	struct nfs_export		*nx_parent;	/* parent export */
	uint32_t			nx_id;		/* export ID */
	uint32_t			nx_flags;	/* export flags */
	struct nfs_exportfs		*nx_fs;		/* exported file system */
	char				*nx_path;	/* exported file system sub-path */
	struct nfs_filehandle		nx_fh;		/* export root file handle */
	struct nfs_export_options	nx_defopt;	/* default options */
	uint32_t			nx_expcnt;	/* # exports in table */
	struct radix_node_head		*nx_rtable[AF_MAX+1]; /* table of exports (netopts) */
	struct nfs_export_stat_counters	nx_stats;	/* statistic counters for this exported directory */
	struct nfs_active_user_list	nx_user_list;	/* Active User List for this exported directory */
	struct timeval			nx_exptime;	/* time of export for write verifier */
};

/* NFS exported file system info */
/* one of these for each exported file system */
struct nfs_exportfs {
	LIST_ENTRY(nfs_exportfs)	nxfs_next;	/* exported file system list */
	uint32_t			nxfs_id;	/* exported file system ID */
	char				*nxfs_path;	/* exported file system path */
	LIST_HEAD(,nfs_export)		nxfs_exports;	/* list of exports for this file system */
};

__private_extern__ LIST_HEAD(nfsrv_expfs_list, nfs_exportfs) nfsrv_exports;
__private_extern__ lck_rw_t nfsrv_export_rwlock;  // lock for export data structures
#define	NFSRVEXPHASHVAL(FSID, EXPID)	\
	(((FSID) >> 24) ^ ((FSID) >> 16) ^ ((FSID) >> 8) ^ (EXPID))
#define	NFSRVEXPHASH(FSID, EXPID)	\
	(&nfsrv_export_hashtbl[NFSRVEXPHASHVAL((FSID),(EXPID)) & nfsrv_export_hash])
__private_extern__ LIST_HEAD(nfsrv_export_hashhead, nfs_export) *nfsrv_export_hashtbl;
__private_extern__ u_long nfsrv_export_hash;

/*
 * NFS server file mod fsevents
 */
struct nfsrv_fmod {
	LIST_ENTRY(nfsrv_fmod)	fm_link;
	vnode_t			fm_vp;
	struct vfs_context	fm_context;
	uint64_t		fm_deadline;
};

#define NFSRVFMODHASHSZ	128
#define NFSRVFMODHASH(vp) (((u_long) vp) & nfsrv_fmod_hash)
__private_extern__ LIST_HEAD(nfsrv_fmod_hashhead, nfsrv_fmod) *nfsrv_fmod_hashtbl;
__private_extern__ u_long nfsrv_fmod_hash;
__private_extern__ lck_mtx_t *nfsrv_fmod_mutex;
__private_extern__ int nfsrv_fmod_pending, nfsrv_fsevents_enabled;
__private_extern__ int nfsrv_async, nfsrv_reqcache_size, nfsrv_sock_max_rec_queue_length;

__private_extern__ struct nfsstats nfsstats;

#endif // KERNEL

/*
 * XXX to allow amd to include nfs.h without nfsproto.h
 */
#ifdef NFS_NPROCS
/*
 * Stats structure
 */
struct nfsstats {
	int	attrcache_hits;
	int	attrcache_misses;
	int	lookupcache_hits;
	int	lookupcache_misses;
	int	direofcache_hits;
	int	direofcache_misses;
	int	biocache_reads;
	int	read_bios;
	int	read_physios;
	int	biocache_writes;
	int	write_bios;
	int	write_physios;
	int	biocache_readlinks;
	int	readlink_bios;
	int	biocache_readdirs;
	int	readdir_bios;
	int	rpccnt[NFS_NPROCS];
	int	rpcretries;
	int	srvrpccnt[NFS_NPROCS];
	int	srvrpc_errs;
	int	srv_errs;
	int	rpcrequests;
	int	rpctimeouts;
	int	rpcunexpected;
	int	rpcinvalid;
	int	srvcache_inproghits;
	int	srvcache_idemdonehits;
	int	srvcache_nonidemdonehits;
	int	srvcache_misses;
	int	srvvop_writes;
	int pageins;
	int pageouts;
};
#endif

/*
 * Flags for nfssvc() system call.
 */
#define	NFSSVC_NFSD	0x004
#define	NFSSVC_ADDSOCK	0x008
#define	NFSSVC_EXPORT	0x200

/*
 * Flags for nfsclnt() system call.
 */
#define NFSCLNT_LOCKDANS	0x200

/*
 * fs.nfs sysctl(3) identifiers
 */
#define NFS_NFSSTATS	1	/* struct: struct nfsstats */
#define NFS_EXPORTSTATS 3	/* gets exported directory stats */
#define NFS_USERSTATS	4	/* gets exported directory active user stats */
#define NFS_USERCOUNT	5	/* gets current count of active nfs users */

#ifndef NFS_WDELAYHASHSIZ
#define	NFS_WDELAYHASHSIZ 16	/* and with this */
#endif

#ifdef KERNEL
#include <sys/kernel_types.h>
#include <kern/thread_call.h>
#include <sys/kdebug.h>

#define NFS_KERNEL_DEBUG KERNEL_DEBUG

/* kernel debug trace macros */
#define FSDBG(A, B, C, D, E) \
	NFS_KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_NONE, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_TOP(A, B, C, D, E) \
	NFS_KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_START, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)
#define FSDBG_BOT(A, B, C, D, E) \
	NFS_KERNEL_DEBUG((FSDBG_CODE(DBG_FSRW, (A))) | DBG_FUNC_END, \
		(int)(B), (int)(C), (int)(D), (int)(E), 0)

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_NFSREQ);
MALLOC_DECLARE(M_NFSMNT);
MALLOC_DECLARE(M_NFSDIROFF);
MALLOC_DECLARE(M_NFSRVDESC);
MALLOC_DECLARE(M_NFSD);
MALLOC_DECLARE(M_NFSBIGFH);
#endif

struct uio; struct vnode_attr; struct nameidata; struct dqblk;	/* XXX */
struct nfsbuf;
struct nfs_vattr;
struct nfs_fsattr;
struct nfsnode;
typedef struct nfsnode * nfsnode_t;
struct nfsreq;

/*
 * The set of signals the interrupt an I/O in progress for NFSMNT_INT mounts.
 * What should be in this set is open to debate, but I believe that since
 * I/O system calls on ufs are never interrupted by signals the set should
 * be minimal. My reasoning is that many current programs that use signals
 * such as SIGALRM will not expect file I/O system calls to be interrupted
 * by them and break.
 */
#define	NFSINT_SIGMASK	(sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGKILL)| \
			 sigmask(SIGHUP)|sigmask(SIGQUIT))

__private_extern__ size_t nfs_mbuf_mhlen, nfs_mbuf_minclsize;

/*
 * NFS mbuf chain structure used for managing the building/dissection of RPCs
 */
struct nfsm_chain {
	mbuf_t		nmc_mhead;	/* mbuf chain head */
	mbuf_t		nmc_mcur;	/* current mbuf */
	caddr_t		nmc_ptr;	/* pointer into current mbuf */
	uint32_t	nmc_left;	/* bytes remaining in current mbuf */
	uint32_t	nmc_flags;	/* flags for this nfsm_chain */
};
#define NFSM_CHAIN_FLAG_ADD_CLUSTERS	0x1	/* always add mbuf clusters */

/*
 * Each retransmission of an RPCSEC_GSS request
 * has an additional sequence number.
 */
struct gss_seq {
	SLIST_ENTRY(gss_seq)	gss_seqnext;
	uint32_t		gss_seqnum;
};

/*
 * async NFS request callback info
 */
struct nfsreq_cbinfo {
	void			(*rcb_func)(struct nfsreq *);	/* async request callback function */
	struct nfsbuf		*rcb_bp;			/* buffer I/O RPC is for */
	uint32_t		rcb_args[2];			/* additional callback args */
};

/*
 * NFS outstanding request list element
 */
struct nfsreq {
	lck_mtx_t		r_mtx;		/* NFS request mutex */
	TAILQ_ENTRY(nfsreq)	r_chain;	/* request queue chain */
	TAILQ_ENTRY(nfsreq)	r_achain;	/* mount's async I/O request queue chain */
	TAILQ_ENTRY(nfsreq)	r_rchain;	/* mount's async I/O resend queue chain */
	TAILQ_ENTRY(nfsreq)	r_cchain;	/* mount's cwnd queue chain */
	mbuf_t			r_mrest;	/* request body mbufs */
	mbuf_t			r_mhead;	/* request header mbufs */
	struct nfsm_chain	r_nmrep;	/* reply mbufs */
	nfsnode_t		r_np;		/* NFS node */
	struct nfsmount		*r_nmp;		/* NFS mount point */
	uint64_t		r_xid;		/* RPC transaction ID */
	uint32_t		r_procnum;	/* NFS procedure number */
	u_long			r_mreqlen;	/* request length */
	int			r_flags;	/* flags on request, see below */
	int			r_lflags;	/* flags protected by list mutex, see below */
	int			r_refs;		/* # outstanding references */
	uint8_t			r_delay;	/* delay to use for jukebox error */
	uint8_t			r_retry;	/* max retransmission count */
	uint8_t			r_rexmit;	/* current retrans count */
	int			r_rtt;		/* RTT for rpc */
	thread_t		r_thread;	/* thread that did I/O system call */
	kauth_cred_t		r_cred;		/* credential used for request */
	long			r_start;	/* request start time */
	long			r_lastmsg;	/* time of last tprintf */
	long			r_resendtime;	/* time of next jukebox error resend */
	struct nfs_gss_clnt_ctx	*r_gss_ctx;	/* RPCSEC_GSS context */
	SLIST_HEAD(, gss_seq)	r_gss_seqlist;	/* RPCSEC_GSS sequence numbers */
	uint32_t		r_gss_argoff;	/* RPCSEC_GSS offset to args */
	uint32_t		r_gss_arglen;	/* RPCSEC_GSS arg length */
	int			r_error;	/* request error */
	struct nfsreq_cbinfo	r_callback;	/* callback info */
};

/*
 * Queue head for nfsreq's
 */
TAILQ_HEAD(nfs_reqqhead, nfsreq);
__private_extern__ struct nfs_reqqhead nfs_reqq;
__private_extern__ lck_grp_t *nfs_request_grp;

#define R_XID32(x)	((x) & 0xffffffff)

#define NFSREQNOLIST ((struct nfsreq *)0xdeadbeef)	/* sentinel value for nfsreq lists */

/* Flag values for r_flags */
#define R_TIMING	0x0001		/* timing request (in mntp) */
#define R_CWND		0x0002		/* request accounted for in congestion window */
#define R_SOFTTERM	0x0004		/* request terminated (e.g. soft mnt) */
#define R_RESTART	0x0008		/* RPC should be restarted. */
#define R_INITTED	0x0010		/* request has been initialized */
#define R_TPRINTFMSG	0x0020		/* Did a tprintf msg. */
#define R_MUSTRESEND	0x0040		/* Must resend request */
#define R_ALLOCATED	0x0080		/* request was allocated */
#define R_SENT		0x0100		/* request has been sent */
#define R_WAITSENT	0x0200		/* someone is waiting for request to be sent */
#define R_RESENDERR	0x0400		/* resend failed */
#define R_JBTPRINTFMSG	0x0800		/* Did a tprintf msg for jukebox error */
#define R_ASYNC		0x1000		/* async request */
#define R_ASYNCWAIT	0x2000		/* async request now being waited on */
#define R_RESENDQ	0x4000		/* async request currently on resendq */

#define R_SETUP		0x8000		/* a setup RPC - during (re)connection */
#define R_OPTMASK	0x8000		/* mask of all RPC option flags */

/* Flag values for r_lflags */
#define RL_BUSY		0x0001		/* Locked. */
#define RL_WAITING	0x0002		/* Someone waiting for lock. */
#define RL_QUEUED	0x0004		/* request is on the queue */

__private_extern__ u_long nfs_xid, nfs_xidwrap;
__private_extern__ int nfs_iosize, nfs_access_cache_timeout, nfs_allow_async, nfs_statfs_rate_limit;
__private_extern__ int nfs_lockd_mounts, nfs_lockd_request_sent;
__private_extern__ int nfs_tprintf_initial_delay, nfs_tprintf_delay;
__private_extern__ int nfsiod_thread_count, nfsiod_thread_max, nfs_max_async_writes;

#define NFSIOD_MAX	(MIN(nfsiod_thread_max, NFS_MAXASYNCTHREAD))

struct nfs_dulookup {
	int du_flags;			/* state of ._ lookup */
#define NFS_DULOOKUP_DOIT	0x1
#define NFS_DULOOKUP_INPROG	0x2
	struct componentname du_cn;	/* ._ name being looked up */
	struct nfsreq du_req;		/* NFS request for lookup */
	char du_smallname[48];		/* buffer for small names */
};

/*
 * Network address hash list element
 */
union nethostaddr {
	u_long had_inetaddr;
	mbuf_t had_nam;
};

/*
 * One nfsrv_sock structure is maintained for each socket the
 * server is servicing requests on.
 */
struct nfsrv_sock {
	TAILQ_ENTRY(nfsrv_sock) ns_chain;	/* List of all nfsrv_sock's */
	TAILQ_ENTRY(nfsrv_sock) ns_svcq;	/* List of sockets needing servicing */
	TAILQ_ENTRY(nfsrv_sock) ns_wgq;		/* List of sockets with a pending write gather */
	lck_rw_t	ns_rwlock;		/* lock for most fields */
	socket_t	ns_so;
	mbuf_t		ns_nam;
	mbuf_t		ns_raw;
	mbuf_t		ns_rawend;
	mbuf_t		ns_rec;
	mbuf_t		ns_recend;
	mbuf_t		ns_frag;
	int		ns_flag;
	int		ns_sotype;
	int		ns_cc;
	int		ns_reclen;
	int		ns_reccnt;
	u_long		ns_sref;
	time_t		ns_timestamp;		/* socket timestamp */
	lck_mtx_t	ns_wgmutex;		/* mutex for write gather fields */
	u_quad_t	ns_wgtime;		/* next Write deadline (usec) */
	LIST_HEAD(, nfsrv_descript) ns_tq;	/* Write gather lists */
	LIST_HEAD(nfsrv_wg_delayhash, nfsrv_descript) ns_wdelayhashtbl[NFS_WDELAYHASHSIZ];
};

/* Bits for "ns_flag" */
#define	SLP_VALID	0x0001 /* nfs sock valid */
#define	SLP_DOREC	0x0002 /* nfs sock has received data to process */
#define	SLP_NEEDQ	0x0004 /* network socket has data to receive */
#define	SLP_DISCONN	0x0008 /* socket needs to be zapped */
#define	SLP_GETSTREAM	0x0010 /* currently in nfsrv_getstream() */
#define	SLP_LASTFRAG	0x0020 /* on last fragment of RPC record */
#define	SLP_DOWRITES	0x0040 /* nfs sock has gathered writes to service */
#define SLP_WORKTODO	0x004e /* mask of all "work to do" flags */
#define SLP_ALLFLAGS	0x007f
#define	SLP_WAITQ	0x4000 /* nfs sock is on the wait queue */
#define	SLP_WORKQ	0x8000 /* nfs sock is on the work queue */
#define	SLP_QUEUED	0xc000 /* nfs sock is on a queue */

#define SLPNOLIST ((struct nfsrv_sock *)0xdeadbeef)	/* sentinel value for sockets not in the nfsrv_sockwg list */

__private_extern__ struct nfsrv_sock *nfsrv_udpsock;

/*
 * global NFS server socket lists:
 *
 * nfsrv_socklist - list of all sockets (ns_chain)
 * nfsrv_sockwait - sockets w/new data waiting to be worked on (ns_svcq)
 * nfsrv_sockwork - sockets being worked on which may have more work to do (ns_svcq)
 * nfsrv_sockwg - sockets with pending write gather input (ns_wgq)
 */
__private_extern__ TAILQ_HEAD(nfsrv_sockhead, nfsrv_sock) nfsrv_socklist, nfsrv_deadsocklist,
						nfsrv_sockwg, nfsrv_sockwait, nfsrv_sockwork;

/* lock groups for nfsrv_sock's */
__private_extern__ lck_grp_t *nfsrv_slp_rwlock_group;
__private_extern__ lck_grp_t *nfsrv_slp_mutex_group;

/*
 * One of these structures is allocated for each nfsd.
 */
struct nfsd {
	TAILQ_ENTRY(nfsd)	nfsd_chain;	/* List of all nfsd's */
	TAILQ_ENTRY(nfsd)	nfsd_queue;	/* List of waiting nfsd's */
	int			nfsd_flag;	/* NFSD_ flags */
	struct nfsrv_sock	*nfsd_slp;	/* Current socket */
	struct nfsrv_descript	*nfsd_nd;	/* Associated nfsrv_descript */
};

/* Bits for "nfsd_flag" */
#define	NFSD_WAITING	0x01
#define	NFSD_REQINPROG	0x02

/*
 * This structure is used by the server for describing each request.
 * Some fields are used only when write request gathering is performed.
 */
struct nfsrv_descript {
	u_quad_t		nd_time;	/* Write deadline (usec) */
	off_t			nd_off;		/* Start byte offset */
	off_t			nd_eoff;	/* and end byte offset */
	LIST_ENTRY(nfsrv_descript) nd_hash;	/* Hash list */
	LIST_ENTRY(nfsrv_descript) nd_tq;	/* and timer list */
	LIST_HEAD(,nfsrv_descript) nd_coalesce;	/* coalesced writes */
	struct nfsm_chain	nd_nmreq;	/* Request mbuf chain */
	mbuf_t			nd_mrep;	/* Reply mbuf list (WG) */
	mbuf_t			nd_nam;		/* and socket addr */
	mbuf_t			nd_nam2;	/* return socket addr */
	u_int32_t		nd_procnum;	/* RPC # */
	int			nd_stable;	/* storage type */
	int			nd_vers;	/* NFS version */
	int			nd_len;		/* Length of this write */
	int			nd_repstat;	/* Reply status */
	u_long			nd_retxid;	/* Reply xid */
	struct timeval		nd_starttime;	/* Time RPC initiated */
	struct nfs_filehandle	nd_fh;		/* File handle */
	uint32_t		nd_sec;		/* Security flavor */
	struct nfs_gss_svc_ctx	*nd_gss_context;/* RPCSEC_GSS context */
	uint32_t		nd_gss_seqnum;	/* RPCSEC_GSS seq num */
	mbuf_t			nd_gss_mb;	/* RPCSEC_GSS results mbuf */
	kauth_cred_t		nd_cr;		/* Credentials */
};

__private_extern__ TAILQ_HEAD(nfsd_head, nfsd) nfsd_head, nfsd_queue;

/* mutex for nfs server */
__private_extern__ lck_mtx_t *nfsd_mutex;
__private_extern__ int nfsd_thread_count, nfsd_thread_max;

/* request list mutex */
__private_extern__ lck_mtx_t *nfs_request_mutex;
__private_extern__ int nfs_request_timer_on;

/* nfs timer call structures */
__private_extern__ thread_call_t	nfs_request_timer_call;
__private_extern__ thread_call_t	nfs_buf_timer_call;
__private_extern__ thread_call_t	nfsrv_deadsock_timer_call;
__private_extern__ thread_call_t	nfsrv_fmod_timer_call;

__BEGIN_DECLS

nfstype	vtonfs_type(enum vtype, int);
enum vtype nfstov_type(nfstype, int);
int	vtonfsv2_mode(enum vtype, mode_t);

void	nfs_mbuf_init(void);

void	nfs_nhinit(void);
void	nfs_nhinit_finish(void);
u_long	nfs_hash(u_char *, int);

int	nfs4_setclientid(struct nfsmount *);
void	nfs4_renew_timer(void *, void *);
int	nfs_connect(struct nfsmount *);
void	nfs_disconnect(struct nfsmount *);
void	nfs_mount_sock_thread_wake(struct nfsmount *);

int	nfs_getattr(nfsnode_t, struct nfs_vattr *, vfs_context_t, int);
int	nfs_getattrcache(nfsnode_t, struct nfs_vattr *, int);
int	nfs_loadattrcache(nfsnode_t, struct nfs_vattr *, u_int64_t *, int);
int	nfs_attrcachetimeout(nfsnode_t);

int	nfs_buf_page_inval(vnode_t vp, off_t offset);
int	nfs_vinvalbuf(vnode_t, int, vfs_context_t, int);
int	nfs_vinvalbuf2(vnode_t, int, thread_t, kauth_cred_t, int);

int	nfs_request_create(nfsnode_t, mount_t, struct nfsm_chain *, int, thread_t, kauth_cred_t, struct nfsreq **);
void	nfs_request_destroy(struct nfsreq *);
void	nfs_request_ref(struct nfsreq *, int);
void	nfs_request_rele(struct nfsreq *);
int	nfs_request_add_header(struct nfsreq *);
int	nfs_request_send(struct nfsreq *, int);
void	nfs_request_wait(struct nfsreq *);
int	nfs_request_finish(struct nfsreq *, struct nfsm_chain *, int *);
int	nfs_request(nfsnode_t, mount_t, struct nfsm_chain *, int, vfs_context_t, struct nfsm_chain *, u_int64_t *, int *);
int	nfs_request2(nfsnode_t, mount_t, struct nfsm_chain *, int, thread_t, kauth_cred_t, int, struct nfsm_chain *, u_int64_t *, int *);
int	nfs_request_async(nfsnode_t, mount_t, struct nfsm_chain *, int, thread_t, kauth_cred_t, struct nfsreq_cbinfo *cb, struct nfsreq **);
int	nfs_request_async_finish(struct nfsreq *, struct nfsm_chain *, u_int64_t *, int *);
void	nfs_request_async_cancel(struct nfsreq *);
void	nfs_request_timer(void *, void *);
int	nfs_sigintr(struct nfsmount *, struct nfsreq *, thread_t, int);
int	nfs_noremotehang(thread_t);

int	nfs_send(struct nfsreq *, int);
int	nfs_sndlock(struct nfsreq *);
void	nfs_sndunlock(struct nfsreq *);

int	nfs_lookitup(nfsnode_t, char *, int, vfs_context_t, nfsnode_t *);
void	nfs_dulookup_init(struct nfs_dulookup *, nfsnode_t, const char *, int);
void	nfs_dulookup_start(struct nfs_dulookup *, nfsnode_t, vfs_context_t);
void	nfs_dulookup_finish(struct nfs_dulookup *, nfsnode_t, vfs_context_t);

int	nfs_parsefattr(struct nfsm_chain *, int, struct nfs_vattr *);
int	nfs4_parsefattr(struct nfsm_chain *, struct nfs_fsattr *, struct nfs_vattr *, fhandle_t *, struct dqblk *);
void	nfs_vattr_set_supported(uint32_t *, struct vnode_attr *);
void	nfs3_pathconf_cache(struct nfsmount *, struct nfs_fsattr *);
int	nfs_node_mode_slot(nfsnode_t, uid_t, int);

int	nfs_vnop_access(struct vnop_access_args *);

int	nfs3_vnop_open(struct vnop_open_args *);
int	nfs3_vnop_close(struct vnop_close_args *);

int	nfs4_vnop_create(struct vnop_create_args *);
int	nfs4_vnop_mknod(struct vnop_mknod_args *);
int	nfs4_vnop_open(struct vnop_open_args *);
int	nfs4_vnop_close(struct vnop_close_args *);
int	nfs4_vnop_getattr(struct vnop_getattr_args *);
int	nfs4_vnop_link(struct vnop_link_args *);
int	nfs4_vnop_mkdir(struct vnop_mkdir_args *);
int	nfs4_vnop_rmdir(struct vnop_rmdir_args *);
int	nfs4_vnop_symlink(struct vnop_symlink_args *);
int	nfs4_vnop_advlock(struct vnop_advlock_args *ap);

int	nfs_read_rpc(nfsnode_t, struct uio *, vfs_context_t);
int	nfs_write_rpc(nfsnode_t, struct uio *, vfs_context_t, int *, uint64_t *);
int	nfs_write_rpc2(nfsnode_t, struct uio *, thread_t, kauth_cred_t, int *, uint64_t *);

int	nfs3_access_rpc(nfsnode_t, u_long *, vfs_context_t);
int	nfs4_access_rpc(nfsnode_t, u_long *, vfs_context_t);
int	nfs3_getattr_rpc(nfsnode_t, mount_t, u_char *, size_t, vfs_context_t, struct nfs_vattr *, u_int64_t *);
int	nfs4_getattr_rpc(nfsnode_t, mount_t, u_char *, size_t, vfs_context_t, struct nfs_vattr *, u_int64_t *);
int	nfs3_setattr_rpc(nfsnode_t, struct vnode_attr *, vfs_context_t, int);
int	nfs4_setattr_rpc(nfsnode_t, struct vnode_attr *, vfs_context_t, int);
int	nfs3_read_rpc_async(nfsnode_t, off_t, size_t, thread_t, kauth_cred_t, struct nfsreq_cbinfo *, struct nfsreq **);
int	nfs4_read_rpc_async(nfsnode_t, off_t, size_t, thread_t, kauth_cred_t, struct nfsreq_cbinfo *, struct nfsreq **);
int	nfs3_read_rpc_async_finish(nfsnode_t, struct nfsreq *, struct uio *, size_t *, int *);
int	nfs4_read_rpc_async_finish(nfsnode_t, struct nfsreq *, struct uio *, size_t *, int *);
int	nfs3_write_rpc_async(nfsnode_t, struct uio *, size_t, thread_t, kauth_cred_t, int, struct nfsreq_cbinfo *, struct nfsreq **);
int	nfs4_write_rpc_async(nfsnode_t, struct uio *, size_t, thread_t, kauth_cred_t, int, struct nfsreq_cbinfo *, struct nfsreq **);
int	nfs3_write_rpc_async_finish(nfsnode_t, struct nfsreq *, int *, size_t *, uint64_t *);
int	nfs4_write_rpc_async_finish(nfsnode_t, struct nfsreq *, int *, size_t *, uint64_t *);
int	nfs3_readdir_rpc(nfsnode_t, struct uio *, vfs_context_t);
int	nfs3_readdirplus_rpc(nfsnode_t, struct uio *, vfs_context_t);
int	nfs4_readdir_rpc(nfsnode_t, struct uio *, vfs_context_t);
int	nfs3_readlink_rpc(nfsnode_t, char *, uint32_t *, vfs_context_t);
int	nfs4_readlink_rpc(nfsnode_t, char *, uint32_t *, vfs_context_t);
int	nfs3_commit_rpc(nfsnode_t, u_int64_t, u_int64_t, kauth_cred_t);
int	nfs4_commit_rpc(nfsnode_t, u_int64_t, u_int64_t, kauth_cred_t);
int	nfs3_lookup_rpc_async(nfsnode_t, char *, int, vfs_context_t, struct nfsreq **);
int	nfs4_lookup_rpc_async(nfsnode_t, char *, int, vfs_context_t, struct nfsreq **);
int	nfs3_lookup_rpc_async_finish(nfsnode_t, vfs_context_t, struct nfsreq *, u_int64_t *, fhandle_t *, struct nfs_vattr *);
int	nfs4_lookup_rpc_async_finish(nfsnode_t, vfs_context_t, struct nfsreq *, u_int64_t *, fhandle_t *, struct nfs_vattr *);
int	nfs3_remove_rpc(nfsnode_t, char *, int, thread_t, kauth_cred_t);
int	nfs4_remove_rpc(nfsnode_t, char *, int, thread_t, kauth_cred_t);
int	nfs3_rename_rpc(nfsnode_t, char *, int, nfsnode_t, char *, int, vfs_context_t);
int	nfs4_rename_rpc(nfsnode_t, char *, int, nfsnode_t, char *, int, vfs_context_t);
int	nfs3_pathconf_rpc(nfsnode_t, struct nfs_fsattr *, vfs_context_t);
int	nfs4_pathconf_rpc(nfsnode_t, struct nfs_fsattr *, vfs_context_t);

void	nfsrv_active_user_list_reclaim(void);
void	nfsrv_cleancache(void);
void	nfsrv_cleanup(void);
int	nfsrv_credcheck(struct nfsrv_descript *, vfs_context_t, struct nfs_export *,
			struct nfs_export_options *);
void	nfsrv_deadsock_timer(void *, void *);
int	nfsrv_dorec(struct nfsrv_sock *, struct nfsd *, struct nfsrv_descript **);
int	nfsrv_errmap(struct nfsrv_descript *, int);
int	nfsrv_export(struct user_nfs_export_args *, vfs_context_t);
int	nfsrv_fhmatch(struct nfs_filehandle *, struct nfs_filehandle *);
int	nfsrv_fhtovp(struct nfs_filehandle *, struct nfsrv_descript *, vnode_t *,
			struct nfs_export **, struct nfs_export_options **);
void	nfsrv_fmod_timer(void *, void *);
int	nfsrv_getcache(struct nfsrv_descript *, struct nfsrv_sock *, mbuf_t *);
void	nfsrv_group_sort(gid_t *, int);
void	nfsrv_init(void);
void	nfsrv_initcache(void);
int	nfsrv_is_initialized(void);
int	nfsrv_namei(struct nfsrv_descript *, vfs_context_t, struct nameidata *,
			struct nfs_filehandle *, vnode_t *,
			struct nfs_export **, struct nfs_export_options **);
void	nfsrv_rcv(socket_t, caddr_t, int);
void	nfsrv_rcv_locked(socket_t, struct nfsrv_sock *, int);
int	nfsrv_rephead(struct nfsrv_descript *, struct nfsrv_sock *, struct nfsm_chain *, size_t);
int	nfsrv_send(struct nfsrv_sock *, mbuf_t, mbuf_t);
void	nfsrv_updatecache(struct nfsrv_descript *, int, mbuf_t);
void	nfsrv_update_user_stat(struct nfs_export *, struct nfsrv_descript *, uid_t, u_int, u_int, u_int);
int	nfsrv_vptofh(struct nfs_export *, int, struct nfs_filehandle *,
			vnode_t, vfs_context_t, struct nfs_filehandle *);
void	nfsrv_wakenfsd(struct nfsrv_sock *);
void	nfsrv_wg_timer(void *, void *);
int	nfsrv_writegather(struct nfsrv_descript **, struct nfsrv_sock *,
			       vfs_context_t, mbuf_t *);

int	nfsrv_access(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_commit(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_create(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_fsinfo(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_getattr(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_link(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_lookup(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_mkdir(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_mknod(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_noop(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_null(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_pathconf(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_read(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_readdir(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_readdirplus(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_readlink(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_remove(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_rename(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_rmdir(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_setattr(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_statfs(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_symlink(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);
int	nfsrv_write(struct nfsrv_descript *, struct nfsrv_sock *, vfs_context_t, mbuf_t *);

void	nfs_interval_timer_start(thread_call_t, int);
void	nfs_up(struct nfsmount *, thread_t, int, const char *);
void	nfs_down(struct nfsmount *, thread_t, int, int, const char *);

int	nfs_mountroot(void);
struct nfs_diskless;
int	nfs_boot_init(struct nfs_diskless *);
int	nfs_boot_getfh(struct nfs_diskless *, int, int);

__END_DECLS

#endif	/* KERNEL */
#endif /* __APPLE_API_PRIVATE */

#endif
