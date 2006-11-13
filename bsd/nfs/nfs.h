/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#define	NFS_MAXIOVEC	34
#define NFS_TICKINTVL	5		/* Desired time for a tick (msec) */
#define NFS_HZ		(hz / nfs_ticks) /* Ticks/sec */
#define	NFS_TIMEO	(1 * NFS_HZ)	/* Default timeout = 1 second */
#define	NFS_MINTIMEO	(1 * NFS_HZ)	/* Min timeout to use */
#define	NFS_MAXTIMEO	(60 * NFS_HZ)	/* Max timeout to backoff to */
#define	NFS_MINIDEMTIMEO (5 * NFS_HZ)	/* Min timeout for non-idempotent ops*/
#define	NFS_MAXREXMIT	100		/* Stop counting after this many */
#define	NFS_MAXWINDOW	1024		/* Max number of outstanding requests */
#define	NFS_RETRANS	10		/* Num of retrans for soft mounts */
#define	NFS_TRYLATERDEL	15		/* Initial try later delay (sec) */
#define	NFS_MAXGRPS	16		/* Max. size of groups list */
#ifndef NFS_MINATTRTIMO
#define	NFS_MINATTRTIMO 5		/* Attribute cache timeout in sec */
#endif
#ifndef NFS_MAXATTRTIMO
#define	NFS_MAXATTRTIMO 60
#endif
#ifndef NFS_MINDIRATTRTIMO
#define	NFS_MINDIRATTRTIMO 5		/* directory attribute cache timeout in sec */
#endif
#ifndef NFS_MAXDIRATTRTIMO
#define	NFS_MAXDIRATTRTIMO 60
#endif
#define	NFS_IOSIZE	(256 * 1024)	/* suggested I/O size */
#define	NFS_WSIZE	16384		/* Def. write data size <= 16K */
#define	NFS_RSIZE	16384		/* Def. read data size <= 16K */
#define	NFS_DGRAM_WSIZE	8192		/* UDP Def. write data size <= 8K */
#define	NFS_DGRAM_RSIZE	8192		/* UDP Def. read data size <= 8K */
#define NFS_READDIRSIZE	8192		/* Def. readdir size */
#define	NFS_DEFRAHEAD	4		/* Def. read ahead # blocks */
#define	NFS_MAXRAHEAD	16		/* Max. read ahead # blocks */
#define	NFS_MAXUIDHASH	64		/* Max. # of hashed uid entries/mp */
#define	NFS_MAXASYNCDAEMON 	32	/* Max. number async_daemons runnable */
#define NFS_MAXGATHERDELAY	100	/* Max. write gather delay (msec) */
#ifndef NFS_GATHERDELAY
#define NFS_GATHERDELAY		10	/* Default write gather delay (msec) */
#endif
#define	NFS_DIRBLKSIZ	4096		/* Must be a multiple of DIRBLKSIZ */
#if defined(KERNEL) && !defined(DIRBLKSIZ)
#define	DIRBLKSIZ	512		/* XXX we used to use ufs's DIRBLKSIZ */
 					/* can't be larger than NFS_FABLKSIZE */
#endif

/*
 * Oddballs
 */
#define	NMOD(a)		((a) % nfs_asyncdaemons)
#define NFS_CMPFH(n, f, s) \
	((n)->n_fhsize == (s) && !bcmp((caddr_t)(n)->n_fhp, (caddr_t)(f), (s)))
#define NFS_ISV3(v)	(VFSTONFS(vnode_mount(v))->nm_flag & NFSMNT_NFSV3)
#define NFS_SRVMAXDATA(n) \
		(((n)->nd_flag & ND_NFSV3) ? (((n)->nd_nam2) ? \
		 NFS_MAXDGRAMDATA : NFS_MAXDATA) : NFS_V2MAXDATA)

/*
 * XXX
 * The NB_INVAFTERWRITE flag should be set to whatever is required by the
 * buffer cache code to say "Invalidate the block after it is written back".
 */
#ifdef __FreeBSD__
#define	NB_INVAFTERWRITE	NB_NOCACHE
#else
#define	NB_INVAFTERWRITE	NB_INVAL
#endif

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
#define NFS_UIDALLOC	128

/*
 * Arguments to mount NFS
 */
#define NFS_ARGSVERSION	4		/* change when nfs_args changes */
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

// LP64todo - should this move?
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
#define	NFSMNT_NFSV3		0x00000200  /* Use NFS Version 3 protocol */
#define	NFSMNT_KERB		0x00000400  /* Use Kerberos authentication */
#define	NFSMNT_DUMBTIMR		0x00000800  /* Don't estimate rtt dynamically */
#define	NFSMNT_READAHEAD	0x00002000  /* set read ahead */
#define	NFSMNT_RESVPORT		0x00008000  /* Allocate a reserved port */
#define	NFSMNT_RDIRPLUS		0x00010000  /* Use Readdirplus for V3 */
#define	NFSMNT_READDIRSIZE	0x00020000  /* Set readdir size */
#define	NFSMNT_NOLOCKS		0x00040000  /* don't support file locking */
#define	NFSMNT_ACREGMIN		0x00100000  /* reg min attr cache timeout */
#define	NFSMNT_ACREGMAX		0x00200000  /* reg max attr cache timeout */
#define	NFSMNT_ACDIRMIN		0x00400000  /* dir min attr cache timeout */
#define	NFSMNT_ACDIRMAX		0x00800000  /* dir max attr cache timeout */

/*
 * NFS mount state flags (nm_state)
 */
#define NFSSTA_LOCKTIMEO	0x00002000  /* experienced a lock req timeout */
#define	NFSSTA_MOUNTED		0x00004000  /* completely mounted */
#define NFSSTA_LOCKSWORK	0x00008000  /* lock ops have worked. */
#define NFSSTA_TIMEO		0x00010000  /* experienced a timeout. */
#define NFSSTA_FORCE		0x00020000  /* doing a forced unmount. */
#define NFSSTA_HASWRITEVERF	0x00040000  /* Has write verifier for V3 */
#define NFSSTA_GOTPATHCONF	0x00080000  /* Got the V3 pathconf info */
#define NFSSTA_GOTFSINFO	0x00100000  /* Got the V3 fsinfo */
#define	NFSSTA_MNTD		0x00200000  /* Mnt server for mnt point */
#define	NFSSTA_SNDLOCK		0x01000000  /* Send socket lock */
#define	NFSSTA_WANTSND		0x02000000  /* Want above */
#define	NFSSTA_RCVLOCK		0x04000000  /* Rcv socket lock */
#define	NFSSTA_WANTRCV		0x08000000  /* Want above */
#define	NFSSTA_WAITAUTH		0x10000000  /* Wait for authentication */
#define	NFSSTA_HASAUTH		0x20000000  /* Has authenticator */
#define	NFSSTA_WANTAUTH		0x40000000  /* Wants an authenticator */
#define	NFSSTA_AUTHERR		0x80000000  /* Authentication error */

/*
 * NFS mount pathconf info flags (nm_fsinfo.pcflags)
 */
#define NFSPCINFO_NOTRUNC		0x01
#define NFSPCINFO_CHOWN_RESTRICTED	0x02
#define NFSPCINFO_CASE_INSENSITIVE	0x04
#define NFSPCINFO_CASE_PRESERVING	0x08

/*
 * Structures for the nfssvc(2) syscall. Not that anyone but nfsd and mount_nfs
 * should ever try and use it.
 */
struct nfsd_args {
	int	sock;		/* Socket to serve */
	caddr_t	name;		/* Client addr for connection based sockets */
	int	namelen;	/* Length of name */
};

// LP64todo - should this move?
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

struct nfsd_srvargs {
	struct nfsd	*nsd_nfsd;	/* Pointer to in kernel nfsd struct */
	uid_t		nsd_uid;	/* Effective uid mapped to cred */
	u_long		nsd_haddr;	/* Ip address of client */
	struct ucred	nsd_cr;		/* Cred. uid maps to */
	int		nsd_authlen;	/* Length of auth string (ret) */
	u_char		*nsd_authstr;	/* Auth string (ret) */
	int		nsd_verflen;	/* and the verfier */
	u_char		*nsd_verfstr;
	struct timeval	nsd_timestamp;	/* timestamp from verifier */
	u_long		nsd_ttl;	/* credential ttl (sec) */
	NFSKERBKEY_T	nsd_key;	/* Session key */
};

struct nfsd_cargs {
	char		*ncd_dirp;	/* Mount dir path */
	uid_t		ncd_authuid;	/* Effective uid */
	int		ncd_authtype;	/* Type of authenticator */
	int		ncd_authlen;	/* Length of authenticator string */
	u_char		*ncd_authstr;	/* Authenticator string */
	int		ncd_verflen;	/* and the verifier */
	u_char		*ncd_verfstr;
	NFSKERBKEY_T	ncd_key;	/* Session key */
};

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
#define	NFSV2_MAX_FID_SIZE	(NFSV2_MAX_FH_SIZE - sizeof(struct nfs_exphandle))

/* NFS server internal view of fhandle_t */
struct nfs_filehandle {
	int			nfh_len;	/* total length of file handle */
	struct nfs_exphandle	nfh_xh;		/* export handle */
	unsigned char		nfh_fid[NFS_MAX_FID_SIZE]; /* File ID */
};

/*
 * NFS export data structures
 */

struct nfs_export_net_args {
	uint32_t		nxna_flags;	/* export flags */
	struct xucred		nxna_cred;	/* mapped credential for root/all user */
	struct sockaddr_storage	nxna_addr;	/* net address to which exported */
	struct sockaddr_storage	nxna_mask;	/* mask for net address */
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

/* export option flags */
#define NX_READONLY		0x0001	/* exported read-only */
#define NX_DEFAULTEXPORT	0x0002	/* exported to the world */
#define NX_MAPROOT		0x0004	/* map root access to anon credential */
#define NX_MAPALL		0x0008	/* map all access to anon credential */
#define NX_KERB			0x0010	/* exported with Kerberos uid mapping */
#define NX_32BITCLIENTS		0x0020	/* restrict directory cookies to 32 bits */

#ifdef KERNEL
struct nfs_exportfs;

struct nfs_export_options {
	uint32_t		nxo_flags;	/* export options */
	kauth_cred_t		nxo_cred;	/* mapped credential */
};

/* Network address lookup element and individual export options */
struct nfs_netopt {
	struct radix_node		no_rnodes[2];	/* radix tree glue */
	struct nfs_export_options	no_opt;		/* export options */
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
};

/* NFS exported file system info */
/* one of these for each exported file system */
struct nfs_exportfs {
	LIST_ENTRY(nfs_exportfs)	nxfs_next;	/* exported file system list */
	uint32_t			nxfs_id;	/* exported file system ID */
	char				*nxfs_path;	/* exported file system path */
	LIST_HEAD(,nfs_export)		nxfs_exports;	/* list of exports for this file system */
};

extern LIST_HEAD(nfsexpfslist, nfs_exportfs) nfs_exports;
extern lck_rw_t nfs_export_rwlock;  // lock for export data structures
#define	NFSEXPHASHVAL(FSID, EXPID)	\
	(((FSID) >> 24) ^ ((FSID) >> 16) ^ ((FSID) >> 8) ^ (EXPID))
#define	NFSEXPHASH(FSID, EXPID)	\
	(&nfsexphashtbl[NFSEXPHASHVAL((FSID),(EXPID)) & nfsexphash])
extern LIST_HEAD(nfsexphashhead, nfs_export) *nfsexphashtbl;
extern u_long nfsexphash;

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
#define	NFSSVC_BIOD	0x002
#define	NFSSVC_NFSD	0x004
#define	NFSSVC_ADDSOCK	0x008
#define	NFSSVC_AUTHIN	0x010
#define	NFSSVC_GOTAUTH	0x040
#define	NFSSVC_AUTHINFAIL 0x080
#define	NFSSVC_MNTD	0x100
#define	NFSSVC_EXPORT	0x200

/*
 * Flags for nfsclnt() system call.
 */
#define NFSCLNT_LOCKDANS	0x200
#define NFSCLNT_LOCKDFD		0x400
#define NFSCLNT_LOCKDWAIT	0x800

/*
 * fs.nfs sysctl(3) identifiers
 */
#define NFS_NFSSTATS	1		/* struct: struct nfsstats */
#define NFS_NFSPRIVPORT	2		/* int: prohibit nfs to resvports */

#define FS_NFS_NAMES { \
		       { 0, 0 }, \
		       { "nfsstats", CTLTYPE_STRUCT }, \
		       { "nfsprivport", CTLTYPE_INT }, \
}

#ifndef NFS_MUIDHASHSIZ
#define NFS_MUIDHASHSIZ	63	/* Tune the size of nfsmount with this */
#endif
#ifndef NFS_WDELAYHASHSIZ
#define	NFS_WDELAYHASHSIZ 16	/* and with this */
#endif

/*
 * The set of signals the interrupt an I/O in progress for NFSMNT_INT mounts.
 * What should be in this set is open to debate, but I believe that since
 * I/O system calls on ufs are never interrupted by signals the set should
 * be minimal. My reasoning is that many current programs that use signals
 * such as SIGALRM will not expect file I/O system calls to be interrupted
 * by them and break.
 */
#ifdef KERNEL
#include <sys/kernel_types.h>

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_NFSREQ);
MALLOC_DECLARE(M_NFSMNT);
MALLOC_DECLARE(M_NFSDIROFF);
MALLOC_DECLARE(M_NFSRVDESC);
MALLOC_DECLARE(M_NFSUID);
MALLOC_DECLARE(M_NFSD);
MALLOC_DECLARE(M_NFSBIGFH);
#endif

struct uio; struct vnode_attr; struct nameidata;	/* XXX */
struct nfsbuf;
struct nfs_vattr;
struct nfsnode;

#define	NFSINT_SIGMASK	(sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGKILL)| \
			 sigmask(SIGHUP)|sigmask(SIGQUIT))

__private_extern__ int nfs_mbuf_mlen, nfs_mbuf_mhlen,
	nfs_mbuf_minclsize, nfs_mbuf_mclbytes;

/*
 * Socket errors ignored for connectionless sockets??
 * For now, ignore them all
 */
#define	NFSIGNORE_SOERROR(s, e) \
		((e) != EINTR && (e) != ERESTART && (e) != EWOULDBLOCK && \
		 (e) != EIO && ((s)) != SOCK_STREAM)

/*
 * Nfs outstanding request list element
 */
struct nfsreq {
	TAILQ_ENTRY(nfsreq) r_chain;
	mbuf_t		r_mreq;
	mbuf_t		r_mrep;
	mbuf_t		r_md;
	caddr_t		r_dpos;
	struct nfsmount *r_nmp;
	vnode_t		r_vp;
	u_long		r_xid;
	int		r_flags;	/* flags on request, see below */
	int		r_retry;	/* max retransmission count */
	int		r_rexmit;	/* current retrans count */
	int		r_timer;	/* tick counter on reply */
	u_int32_t	r_procnum;	/* NFS procedure number */
	int		r_rtt;		/* RTT for rpc */
	proc_t		r_procp;	/* Proc that did I/O system call */
	long		r_lastmsg;	/* time of last tprintf */
};

/*
 * Queue head for nfsreq's
 */
extern TAILQ_HEAD(nfs_reqq, nfsreq) nfs_reqq;

/* Flag values for r_flags */
#define R_TIMING	0x0001		/* timing request (in mntp) */
#define R_SENT		0x0002		/* request has been sent */
#define R_SOFTTERM	0x0004		/* soft mnt, too many retries */
#define R_INTR		0x0008		/* intr mnt, signal pending */
#define R_SOCKERR	0x0010		/* Fatal error on socket */
#define R_TPRINTFMSG	0x0020		/* Did a tprintf msg. */
#define R_MUSTRESEND	0x0040		/* Must resend request */
#define R_BUSY		0x0100		/* Locked. */
#define R_WAITING	0x0200		/* Someone waiting for lock. */
#define R_RESENDERR	0x0400		/* resend failed. */

/*
 * A list of nfssvc_sock structures is maintained with all the sockets
 * that require service by the nfsd.
 * The nfsuid structs hang off of the nfssvc_sock structs in both lru
 * and uid hash lists.
 */
#ifndef NFS_UIDHASHSIZ
#define	NFS_UIDHASHSIZ	13	/* Tune the size of nfssvc_sock with this */
#endif
#define	NUIDHASH(sock, uid) \
	(&(sock)->ns_uidhashtbl[(uid) % NFS_UIDHASHSIZ])
#define	NWDELAYHASH(sock, f) \
	(&(sock)->ns_wdelayhashtbl[(*((u_long *)(f))) % NFS_WDELAYHASHSIZ])
#define	NMUIDHASH(nmp, uid) \
	(&(nmp)->nm_uidhashtbl[(uid) % NFS_MUIDHASHSIZ])
#define	NFSNOHASH(fhsum) \
	(&nfsnodehashtbl[(fhsum) & nfsnodehash])

/*
 * Network address hash list element
 */
union nethostaddr {
	u_long had_inetaddr;
	mbuf_t had_nam;
};

struct nfsuid {
	TAILQ_ENTRY(nfsuid) nu_lru;	/* LRU chain */
	LIST_ENTRY(nfsuid) nu_hash;	/* Hash list */
	int		nu_flag;	/* Flags */
	union nethostaddr nu_haddr;	/* Host addr. for dgram sockets */
	kauth_cred_t	nu_cr;		/* Cred uid mapped to */
	int		nu_expire;	/* Expiry time (sec) */
	struct timeval	nu_timestamp;	/* Kerb. timestamp */
	u_long		nu_nickname;	/* Nickname on server */
	NFSKERBKEY_T	nu_key;		/* and session key */
};

#define	nu_inetaddr	nu_haddr.had_inetaddr
#define	nu_nam		nu_haddr.had_nam
/* Bits for nu_flag */
#define	NU_INETADDR	0x1
#define NU_NAM		0x2
#define NU_NETFAM(u)	(((u)->nu_flag & NU_INETADDR) ? AF_INET : AF_ISO)

#ifdef notyet
/* XXX CSM 12/2/97 When/if we merge queue.h */
struct nfsrv_rec {
	STAILQ_ENTRY(nfsrv_rec) nr_link;
	struct sockaddr	*nr_address;
	mbuf_t		nr_packet;
};
#endif

struct nfssvc_sock {
	TAILQ_ENTRY(nfssvc_sock) ns_chain;	/* List of all nfssvc_sock's */
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
	int		ns_numuids;
	u_long		ns_sref;
	time_t		ns_timestamp;		/* socket timestamp */
	lck_mtx_t	ns_wgmutex;		/* mutex for write gather fields */
	u_quad_t	ns_wgtime;		/* next Write deadline (usec) */
	LIST_HEAD(, nfsrv_descript) ns_tq;	/* Write gather lists */
	LIST_HEAD(nfsrvw_delayhash, nfsrv_descript) ns_wdelayhashtbl[NFS_WDELAYHASHSIZ];
	TAILQ_HEAD(, nfsuid) ns_uidlruhead;
	LIST_HEAD(, nfsuid) ns_uidhashtbl[NFS_UIDHASHSIZ];
};

/* Bits for "ns_flag" */
#define	SLP_VALID	0x01 /* nfs sock valid */
#define	SLP_DOREC	0x02 /* nfs sock has received data to process */
#define	SLP_NEEDQ	0x04 /* network socket has data to receive */
#define	SLP_DISCONN	0x08 /* socket needs to be zapped */
#define	SLP_GETSTREAM	0x10 /* currently in nfsrv_getstream() */
#define	SLP_LASTFRAG	0x20 /* on last fragment of RPC record */
#define SLP_ALLFLAGS	0xff

extern TAILQ_HEAD(nfssvc_sockhead, nfssvc_sock) nfssvc_sockhead, nfssvc_deadsockhead;

/* locks for nfssvc_sock's */
extern lck_grp_attr_t *nfs_slp_group_attr;
extern lck_attr_t *nfs_slp_lock_attr;
extern lck_grp_t *nfs_slp_rwlock_group;
extern lck_grp_t *nfs_slp_mutex_group;

/*
 * One of these structures is allocated for each nfsd.
 */
struct nfsd {
	TAILQ_ENTRY(nfsd) nfsd_chain;	/* List of all nfsd's */
	int		nfsd_flag;	/* NFSD_ flags */
	struct nfssvc_sock *nfsd_slp;	/* Current socket */
	int		nfsd_authlen;	/* Authenticator len */
	u_char		nfsd_authstr[RPCAUTH_MAXSIZ]; /* Authenticator data */
	int		nfsd_verflen;	/* and the Verifier */
	u_char		nfsd_verfstr[RPCVERF_MAXSIZ];
	proc_t		nfsd_procp;	/* Proc ptr */
	struct nfsrv_descript *nfsd_nd;	/* Associated nfsrv_descript */
};

/* Bits for "nfsd_flag" */
#define	NFSD_WAITING	0x01
#define	NFSD_REQINPROG	0x02
#define	NFSD_NEEDAUTH	0x04
#define	NFSD_AUTHFAIL	0x08

/*
 * This structure is used by the server for describing each request.
 * Some fields are used only when write request gathering is performed.
 */
struct nfsrv_descript {
	u_quad_t		nd_time;	/* Write deadline (usec) */
	off_t			nd_off;		/* Start byte offset */
	off_t			nd_eoff;	/* and end byte offset */
	LIST_ENTRY(nfsrv_descript) nd_hash;	/* Hash list */
	LIST_ENTRY(nfsrv_descript) nd_tq;		/* and timer list */
	LIST_HEAD(,nfsrv_descript) nd_coalesce;	/* coalesced writes */
	mbuf_t			nd_mrep;	/* Request mbuf list */
	mbuf_t			nd_md;		/* Current dissect mbuf */
	mbuf_t			nd_mreq;	/* Reply mbuf list */
	mbuf_t			nd_nam;		/* and socket addr */
	mbuf_t			nd_nam2;	/* return socket addr */
	caddr_t			nd_dpos;	/* Current dissect pos */
	u_int32_t		nd_procnum;	/* RPC # */
	int			nd_stable;	/* storage type */
	int			nd_flag;	/* nd_flag */
	int			nd_len;		/* Length of this write */
	int			nd_repstat;	/* Reply status */
	u_long			nd_retxid;	/* Reply xid */
	struct timeval		nd_starttime;	/* Time RPC initiated */
	struct nfs_filehandle	nd_fh;		/* File handle */
	kauth_cred_t		nd_cr;		/* Credentials */
};

/* Bits for "nd_flag" */
#define ND_NFSV3	0x08
#define ND_KERBNICK	0x20
#define ND_KERBFULL	0x40
#define ND_KERBAUTH	(ND_KERBNICK | ND_KERBFULL)

extern TAILQ_HEAD(nfsd_head, nfsd) nfsd_head;
extern int nfsd_head_flag;
#define	NFSD_CHECKSLP	0x01

/*
 * These macros compare nfsrv_descript structures.
 */
#define NFSW_CONTIG(o, n) \
		(((o)->nd_eoff >= (n)->nd_off) && \
		 ((o)->nd_fh.nfh_len == (n)->nd_fh.nfh_len) && \
		 !bcmp((caddr_t)&(o)->nd_fh, (caddr_t)&(n)->nd_fh, (o)->nd_fh.nfh_len))

#define NFSW_SAMECRED(o, n) \
	(((o)->nd_flag & ND_KERBAUTH) == ((n)->nd_flag & ND_KERBAUTH) && \
 	 !bcmp((caddr_t)(o)->nd_cr, (caddr_t)(n)->nd_cr, \
		sizeof (struct ucred)))

/* mutex for nfs server */
extern lck_grp_t * nfsd_lck_grp;
extern lck_grp_attr_t * nfsd_lck_grp_attr;
extern lck_attr_t * nfsd_lck_attr;
extern lck_mtx_t *nfsd_mutex;

extern int nfs_numnfsd, nfsd_waiting;

/*
 * Defines for WebNFS
 */

#define WEBNFS_ESC_CHAR		'%'
#define WEBNFS_SPECCHAR_START	0x80

#define WEBNFS_NATIVE_CHAR	0x80
/*
 * ..
 * Possibly more here in the future.
 */

/*
 * Macro for converting escape characters in WebNFS pathnames.
 * Should really be in libkern.
 */
#define ISHEX(c) \
	((((c) >= 'a') && ((c) <= 'f')) || \
	 (((c) >= 'A') && ((c) <= 'F')) || \
	 (((c) >= '0') && ((c) <= '9')))
#define HEXTOC(c) \
	((c) >= 'a' ? ((c) - ('a' - 10)) : \
	    ((c) >= 'A' ? ((c) - ('A' - 10)) : ((c) - '0')))
#define HEXSTRTOI(p) \
	((HEXTOC(p[0]) << 4) + HEXTOC(p[1]))

__BEGIN_DECLS

int	nfs_init(struct vfsconf *vfsp);
void	nfs_mbuf_init(void);
int	nfs_reply(struct nfsreq *);
int	nfs_getreq(struct nfsrv_descript *,struct nfsd *,int);
int	nfs_send(socket_t, mbuf_t, mbuf_t, struct nfsreq *);
int	nfs_rephead(int, struct nfsrv_descript *, struct nfssvc_sock *,
			 int, mbuf_t *, mbuf_t *, caddr_t *);
int	nfs_sndlock(struct nfsreq *);
void	nfs_sndunlock(struct nfsreq *);
int	nfs_vinvalbuf(vnode_t, int, struct ucred *, proc_t, int);
int	nfs_buf_page_inval(vnode_t vp, off_t offset);
int	nfs_readrpc(vnode_t, struct uio *, struct ucred *, proc_t);
int	nfs_writerpc(vnode_t, struct uio *, struct ucred *, proc_t, int *, int *);
int	nfs_readdirrpc(vnode_t, struct uio *, struct ucred *, proc_t);
int	nfs_readdirplusrpc(vnode_t, struct uio *, struct ucred *, proc_t);
int	nfs_asyncio(struct nfsbuf *, struct ucred *);
int	nfs_doio(struct nfsbuf *, struct ucred *, proc_t);
int	nfs_readlinkrpc(vnode_t, struct uio *, struct ucred *, proc_t);
int	nfs_sigintr(struct nfsmount *, struct nfsreq *, proc_t);
int	nfsm_disct(mbuf_t *, caddr_t *, int, int, caddr_t *);
void	nfsm_srvfattr(struct nfsrv_descript *, struct vnode_attr *, 
			   struct nfs_fattr *);
void	nfsm_srvwcc(struct nfsrv_descript *, int, struct vnode_attr *, int,
			 struct vnode_attr *, mbuf_t *, char **);
void	nfsm_srvpostopattr(struct nfsrv_descript *, int, struct vnode_attr *,
				mbuf_t *, char **);
int	netaddr_match(int, union nethostaddr *, mbuf_t);
int	nfs_request(vnode_t, mount_t, mbuf_t, int, proc_t,
			 struct ucred *, mbuf_t *, mbuf_t *,
			 caddr_t *, u_int64_t *);
int	nfs_parsefattr(mbuf_t *, caddr_t *, int, struct nfs_vattr *);
int	nfs_loadattrcache(struct nfsnode *, struct nfs_vattr *, u_int64_t *, int);
int	nfsm_path_mbuftond(mbuf_t *, caddr_t *, int, int, int *, struct nameidata *);
int	nfs_namei(struct nfsrv_descript *, struct vfs_context *, struct nameidata *,
			struct nfs_filehandle *, mbuf_t, int, vnode_t *,
			struct nfs_export **, struct nfs_export_options **);
void	nfsm_adj(mbuf_t, int, int);
int	nfsm_mbuftouio(mbuf_t *, struct uio *, int, caddr_t *);
void	nfsrv_initcache(void);
int	nfs_getauth(struct nfsmount *, struct nfsreq *, struct ucred *, 
			 char **, int *, char *, int *, NFSKERBKEY_T);
int	nfs_getnickauth(struct nfsmount *, struct ucred *, char **, 
			     int *, char *, int);
int	nfs_savenickauth(struct nfsmount *, struct ucred *, int, 
			      NFSKERBKEY_T, mbuf_t *, char **,
			      mbuf_t);
int	nfs_adv(mbuf_t *, caddr_t *, int, int);
void	nfs_nhinit(void);
void	nfs_timer_funnel(void*);
void	nfs_timer(void*);
u_long	nfs_hash(u_char *, int);
int	nfsrv_dorec(struct nfssvc_sock *, struct nfsd *, 
			 struct nfsrv_descript **);
int	nfsrv_getcache(struct nfsrv_descript *, struct nfssvc_sock *,
			    mbuf_t *);
void	nfsrv_updatecache(struct nfsrv_descript *, int, mbuf_t);
void	nfsrv_cleancache(void);
int	nfs_bind_resv_thread_wake(void);
int	nfs_connect(struct nfsmount *, struct nfsreq *);
void	nfs_disconnect(struct nfsmount *);
int	nfs_getattr_no_vnode(mount_t,u_char *,int,struct ucred *,proc_t,struct nfs_vattr *,u_int64_t *);
int	nfs_getattr(vnode_t vp, struct nfs_vattr *nvap, struct ucred *cred, proc_t p);
int	nfs_getattrcache(vnode_t, struct nfs_vattr *);
int	nfs_attrcachetimeout(vnode_t);
int	nfsm_strtmbuf(mbuf_t *, char **, char *, long);
int	nfs_bioread(vnode_t, struct uio *, int, struct ucred *, proc_t);
int	nfsm_uiotombuf(struct uio *, mbuf_t *, int, caddr_t *);
void	nfsrv_init(int);
int	nfs_commit(vnode_t vp, u_quad_t offset, u_int32_t count,
			struct ucred *cred, proc_t procp);
int	nfs_flushcommits(vnode_t, proc_t, int);
int	nfs_flush(vnode_t,int,struct ucred *,proc_t,int);
void	nfs_clearcommit(mount_t);
int	nfsrv_errmap(struct nfsrv_descript *, int);
void	nfsrvw_sort(gid_t *, int);
void	nfsrv_setcred(struct ucred *, struct ucred *);
int	nfs_buf_write(struct nfsbuf *);
void	nfsrv_wakenfsd(struct nfssvc_sock *slp);
int	nfsrv_writegather(struct nfsrv_descript **, struct nfssvc_sock *,
			       proc_t, mbuf_t *);
int	nfs_fsinfo(struct nfsmount *, vnode_t, struct ucred *, proc_t p);
int	nfs_pathconfrpc(vnode_t, struct nfsv3_pathconf *, kauth_cred_t, proc_t);
void	nfs_pathconf_cache(struct nfsmount *, struct nfsv3_pathconf *);

int	nfsrv3_access(struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   proc_t procp, mbuf_t *mrq);
int	nfsrv_commit(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  proc_t procp, mbuf_t *mrq);
int	nfsrv_create(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  proc_t procp, mbuf_t *mrq);
int	nfsrv_credcheck(struct nfsrv_descript *, struct nfs_export *,
			struct nfs_export_options *);
int	nfsrv_export(struct user_nfs_export_args *, struct vfs_context *);
int	nfsrv_fhmatch(struct nfs_filehandle *fh1, struct nfs_filehandle *fh2);
int	nfsrv_fhtovp(struct nfs_filehandle *, mbuf_t, int, vnode_t *,
			struct nfs_export **, struct nfs_export_options **);
int	nfs_ispublicfh(struct nfs_filehandle *);
int	nfsrv_fsinfo(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  proc_t procp, mbuf_t *mrq);
int	nfsrv_getattr(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			   proc_t procp, mbuf_t *mrq);
int	nfsrv_link(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			proc_t procp, mbuf_t *mrq);
int	nfsrv_lookup(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  proc_t procp, mbuf_t *mrq);
int	nfsrv_mkdir(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 proc_t procp, mbuf_t *mrq);
int	nfsrv_mknod(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 proc_t procp, mbuf_t *mrq);
int	nfsrv_noop(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			proc_t procp, mbuf_t *mrq);
int	nfsrv_null(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			proc_t procp, mbuf_t *mrq);
int	nfsrv_pathconf(struct nfsrv_descript *nfsd,
			    struct nfssvc_sock *slp, proc_t procp,
			    mbuf_t *mrq);
void	nfsrv_rcv(socket_t, caddr_t arg, int waitflag);
void	nfsrv_rcv_locked(socket_t, struct nfssvc_sock *slp, int waitflag);
int	nfsrv_read(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			proc_t procp, mbuf_t *mrq);
int	nfsrv_readdir(struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   proc_t procp, mbuf_t *mrq);
int	nfsrv_readdirplus(struct nfsrv_descript *nfsd,
			       struct nfssvc_sock *slp, proc_t procp,
			       mbuf_t *mrq);
int	nfsrv_readlink(struct nfsrv_descript *nfsd,
			    struct nfssvc_sock *slp, proc_t procp,
			    mbuf_t *mrq);
int	nfsrv_remove(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  proc_t procp, mbuf_t *mrq);
int	nfsrv_rename(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  proc_t procp, mbuf_t *mrq);
int	nfsrv_rmdir(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 proc_t procp, mbuf_t *mrq);
int	nfsrv_setattr(struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   proc_t procp, mbuf_t *mrq);
void	nfsrv_slpderef(struct nfssvc_sock *slp);
void	nfsrv_slpfree(struct nfssvc_sock *slp);
int	nfsrv_statfs(struct nfsrv_descript *nfsd, 
			  struct nfssvc_sock *slp,
			  proc_t procp, mbuf_t *mrq);
int	nfsrv_symlink(struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   proc_t procp, mbuf_t *mrq);
int	nfsrv_write(struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 proc_t procp, mbuf_t *mrq);
int	nfsrv_vptofh( struct nfs_export *, int, struct nfs_filehandle *,
			vnode_t, struct vfs_context *, struct nfs_filehandle *);

void	nfs_up(struct nfsmount *, proc_t, int, const char *);
void	nfs_down(struct nfsmount *, proc_t, int, int, const char *);

struct nfs_diskless;
int	nfs_boot_init(struct nfs_diskless *nd, proc_t procp);
int	nfs_boot_getfh(struct nfs_diskless *nd, proc_t procp, int v3, int sotype);

__END_DECLS

#endif	/* KERNEL */
#endif /* __APPLE_API_PRIVATE */

#endif
