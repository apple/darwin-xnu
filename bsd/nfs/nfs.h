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
#define	NFS_MAXGRPS	16		/* Max. size of groups list */
#ifndef NFS_MINATTRTIMO
#define	NFS_MINATTRTIMO 5		/* Attribute cache timeout in sec */
#endif
#ifndef NFS_MAXATTRTIMO
#define	NFS_MAXATTRTIMO 60
#endif
#define	NFS_WSIZE	8192		/* Def. write data size <= 8192 */
#define	NFS_RSIZE	8192		/* Def. read data size <= 8192 */
#define NFS_READDIRSIZE	8192		/* Def. readdir size */
#define	NFS_DEFRAHEAD	1		/* Def. read ahead # blocks */
#define	NFS_MAXRAHEAD	4		/* Max. read ahead # blocks */
#define	NFS_MAXUIDHASH	64		/* Max. # of hashed uid entries/mp */
#define	NFS_MAXASYNCDAEMON 	20	/* Max. number async_daemons runnable */
#define NFS_MAXGATHERDELAY	100	/* Max. write gather delay (msec) */
#ifndef NFS_GATHERDELAY
#define NFS_GATHERDELAY		10	/* Default write gather delay (msec) */
#endif
#define	NFS_DIRBLKSIZ	4096		/* Must be a multiple of DIRBLKSIZ */

/*
 * Oddballs
 */
#define	NMOD(a)		((a) % nfs_asyncdaemons)
#define NFS_CMPFH(n, f, s) \
	((n)->n_fhsize == (s) && !bcmp((caddr_t)(n)->n_fhp, (caddr_t)(f), (s)))
#define NFS_ISV3(v)	(VFSTONFS((v)->v_mount)->nm_flag & NFSMNT_NFSV3)
#define NFS_SRVMAXDATA(n) \
		(((n)->nd_flag & ND_NFSV3) ? (((n)->nd_nam2) ? \
		 NFS_MAXDGRAMDATA : NFS_MAXDATA) : NFS_V2MAXDATA)

/*
 * XXX
 * The B_INVAFTERWRITE flag should be set to whatever is required by the
 * buffer cache code to say "Invalidate the block after it is written back".
 */
#ifdef __FreeBSD__
#define	B_INVAFTERWRITE	B_NOCACHE
#else
#define	B_INVAFTERWRITE	B_INVAL
#endif

/*
 * The IO_METASYNC flag should be implemented for local file systems.
 * (Until then, it is nothin at all.)
 */
#ifndef IO_METASYNC
#define IO_METASYNC	0
#endif

/*
 * Set the attribute timeout based on how recently the file has been modified.
 */
#define	NFS_ATTRTIMEO(np) \
	((((np)->n_flag & NMODIFIED) || \
	 (time.tv_sec - (np)->n_mtime) / 10 < NFS_MINATTRTIMO) ? NFS_MINATTRTIMO : \
	 ((time.tv_sec - (np)->n_mtime) / 10 > NFS_MAXATTRTIMO ? NFS_MAXATTRTIMO : \
	  (time.tv_sec - (np)->n_mtime) / 10))

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
#define NFS_ARGSVERSION	3		/* change when nfs_args changes */
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
	int		leaseterm;	/* Term (sec) of lease */
	int		deadthresh;	/* Retrans threshold */
	char		*hostname;	/* server's name */
};

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
#define	NFSMNT_NQNFS		0x00000100  /* Use Nqnfs protocol */
#define	NFSMNT_NFSV3		0x00000200  /* Use NFS Version 3 protocol */
#define	NFSMNT_KERB		0x00000400  /* Use Kerberos authentication */
#define	NFSMNT_DUMBTIMR		0x00000800  /* Don't estimate rtt dynamically */
#define	NFSMNT_LEASETERM	0x00001000  /* set lease term (nqnfs) */
#define	NFSMNT_READAHEAD	0x00002000  /* set read ahead */
#define	NFSMNT_DEADTHRESH	0x00004000  /* set dead server retry thresh */
#define	NFSMNT_RESVPORT		0x00008000  /* Allocate a reserved port */
#define	NFSMNT_RDIRPLUS		0x00010000  /* Use Readdirplus for V3 */
#define	NFSMNT_READDIRSIZE	0x00020000  /* Set readdir size */
#define	NFSMNT_INTERNAL		0xfffc0000  /* Bits set internally */
#define NFSMNT_HASWRITEVERF	0x00040000  /* Has write verifier for V3 */
#define NFSMNT_GOTPATHCONF	0x00080000  /* Got the V3 pathconf info */
#define NFSMNT_GOTFSINFO	0x00100000  /* Got the V3 fsinfo */
#define	NFSMNT_MNTD		0x00200000  /* Mnt server for mnt point */
#define	NFSMNT_DISMINPROG	0x00400000  /* Dismount in progress */
#define	NFSMNT_DISMNT		0x00800000  /* Dismounted */
#define	NFSMNT_SNDLOCK		0x01000000  /* Send socket lock */
#define	NFSMNT_WANTSND		0x02000000  /* Want above */
#define	NFSMNT_RCVLOCK		0x04000000  /* Rcv socket lock */
#define	NFSMNT_WANTRCV		0x08000000  /* Want above */
#define	NFSMNT_WAITAUTH		0x10000000  /* Wait for authentication */
#define	NFSMNT_HASAUTH		0x20000000  /* Has authenticator */
#define	NFSMNT_WANTAUTH		0x40000000  /* Wants an authenticator */
#define	NFSMNT_AUTHERR		0x80000000  /* Authentication error */

/*
 * Structures for the nfssvc(2) syscall. Not that anyone but nfsd and mount_nfs
 * should ever try and use it.
 */
struct nfsd_args {
	int	sock;		/* Socket to serve */
	caddr_t	name;		/* Client addr for connection based sockets */
	int	namelen;	/* Length of name */
};

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
	int	srvnqnfs_leases;
	int	srvnqnfs_maxleases;
	int	srvnqnfs_getleases;
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

#ifdef MALLOC_DECLARE
MALLOC_DECLARE(M_NFSREQ);
MALLOC_DECLARE(M_NFSMNT);
MALLOC_DECLARE(M_NFSDIROFF);
MALLOC_DECLARE(M_NFSRVDESC);
MALLOC_DECLARE(M_NFSUID);
MALLOC_DECLARE(M_NQLEASE);
MALLOC_DECLARE(M_NFSD);
MALLOC_DECLARE(M_NFSBIGFH);
#endif

struct uio; struct buf; struct vattr; struct nameidata;	/* XXX */

#define	NFSINT_SIGMASK	(sigmask(SIGINT)|sigmask(SIGTERM)|sigmask(SIGKILL)| \
			 sigmask(SIGHUP)|sigmask(SIGQUIT))

/*
 * Socket errors ignored for connectionless sockets??
 * For now, ignore them all
 */
#define	NFSIGNORE_SOERROR(s, e) \
		((e) != EINTR && (e) != ERESTART && (e) != EWOULDBLOCK && \
		((s) & PR_CONNREQUIRED) == 0)

/*
 * Nfs outstanding request list element
 */
struct nfsreq {
	TAILQ_ENTRY(nfsreq) r_chain;
	struct mbuf	*r_mreq;
	struct mbuf	*r_mrep;
	struct mbuf	*r_md;
	caddr_t		r_dpos;
	struct nfsmount *r_nmp;
	struct vnode	*r_vp;
	u_long		r_xid;
	int		r_flags;	/* flags on request, see below */
	int		r_retry;	/* max retransmission count */
	int		r_rexmit;	/* current retrans count */
	int		r_timer;	/* tick counter on reply */
	u_int32_t	r_procnum;	/* NFS procedure number */
	int		r_rtt;		/* RTT for rpc */
	struct proc	*r_procp;	/* Proc that did I/O system call */
};

/*
 * Queue head for nfsreq's
 */
extern TAILQ_HEAD(nfs_reqq, nfsreq) nfs_reqq;

/* Flag values for r_flags */
#define R_TIMING	0x01		/* timing request (in mntp) */
#define R_SENT		0x02		/* request has been sent */
#define	R_SOFTTERM	0x04		/* soft mnt, too many retries */
#define	R_INTR		0x08		/* intr mnt, signal pending */
#define	R_SOCKERR	0x10		/* Fatal error on socket */
#define	R_TPRINTFMSG	0x20		/* Did a tprintf msg. */
#define	R_MUSTRESEND	0x40		/* Must resend request */
#define	R_GETONEREP	0x80		/* Probe for one reply only */

/*
 * A list of nfssvc_sock structures is maintained with all the sockets
 * that require service by the nfsd.
 * The nfsuid structs hang off of the nfssvc_sock structs in both lru
 * and uid hash lists.
 */
#ifndef NFS_UIDHASHSIZ
#define	NFS_UIDHASHSIZ	29	/* Tune the size of nfssvc_sock with this */
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
	struct mbuf *had_nam;
};

struct nfsuid {
	TAILQ_ENTRY(nfsuid) nu_lru;	/* LRU chain */
	LIST_ENTRY(nfsuid) nu_hash;	/* Hash list */
	int		nu_flag;	/* Flags */
	union nethostaddr nu_haddr;	/* Host addr. for dgram sockets */
	struct ucred	nu_cr;		/* Cred uid mapped to */
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
	struct mbuf	*nr_packet;
};
#endif

struct nfssvc_sock {
	TAILQ_ENTRY(nfssvc_sock) ns_chain;	/* List of all nfssvc_sock's */
	TAILQ_HEAD(, nfsuid) ns_uidlruhead;
	struct file	*ns_fp;
	struct socket	*ns_so;
	struct mbuf	*ns_nam;
	struct mbuf	*ns_raw;
	struct mbuf	*ns_rawend;
	struct mbuf	*ns_rec;
	struct mbuf	*ns_recend;
	struct mbuf	*ns_frag;
	int		ns_flag;
	int		ns_solock;
	int		ns_cc;
	int		ns_reclen;
	int		ns_numuids;
	u_long		ns_sref;
	LIST_HEAD(, nfsrv_descript) ns_tq;	/* Write gather lists */
	LIST_HEAD(, nfsuid) ns_uidhashtbl[NFS_UIDHASHSIZ];
	LIST_HEAD(nfsrvw_delayhash, nfsrv_descript) ns_wdelayhashtbl[NFS_WDELAYHASHSIZ];
};

/* Bits for "ns_flag" */
#define	SLP_VALID	0x01
#define	SLP_DOREC	0x02
#define	SLP_NEEDQ	0x04
#define	SLP_DISCONN	0x08
#define	SLP_GETSTREAM	0x10
#define	SLP_LASTFRAG	0x20
#define SLP_ALLFLAGS	0xff

extern TAILQ_HEAD(nfssvc_sockhead, nfssvc_sock) nfssvc_sockhead;
extern int nfssvc_sockhead_flag;
#define	SLP_INIT	0x01
#define	SLP_WANTINIT	0x02

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
	struct proc	*nfsd_procp;	/* Proc ptr */
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
	struct mbuf		*nd_mrep;	/* Request mbuf list */
	struct mbuf		*nd_md;		/* Current dissect mbuf */
	struct mbuf		*nd_mreq;	/* Reply mbuf list */
	struct mbuf		*nd_nam;	/* and socket addr */
	struct mbuf		*nd_nam2;	/* return socket addr */
	caddr_t			nd_dpos;	/* Current dissect pos */
	u_int32_t		nd_procnum;	/* RPC # */
	int			nd_stable;	/* storage type */
	int			nd_flag;	/* nd_flag */
	int			nd_len;		/* Length of this write */
	int			nd_repstat;	/* Reply status */
	u_long			nd_retxid;	/* Reply xid */
	u_long			nd_duration;	/* Lease duration */
	struct timeval		nd_starttime;	/* Time RPC initiated */
	fhandle_t		nd_fh;		/* File handle */
	struct ucred		nd_cr;		/* Credentials */
};

/* Bits for "nd_flag" */
#define	ND_READ		LEASE_READ
#define ND_WRITE	LEASE_WRITE
#define ND_CHECK	0x04
#define ND_LEASE	(ND_READ | ND_WRITE | ND_CHECK)
#define ND_NFSV3	0x08
#define ND_NQNFS	0x10
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
		((o)->nd_eoff >= (n)->nd_off && \
		 !bcmp((caddr_t)&(o)->nd_fh, (caddr_t)&(n)->nd_fh, NFSX_V3FH))

#define NFSW_SAMECRED(o, n) \
	(((o)->nd_flag & ND_KERBAUTH) == ((n)->nd_flag & ND_KERBAUTH) && \
 	 !bcmp((caddr_t)&(o)->nd_cr, (caddr_t)&(n)->nd_cr, \
		sizeof (struct ucred)))

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

#define HEXTOC(c) \
	((c) >= 'a' ? ((c) - ('a' - 10)) : \
	    ((c) >= 'A' ? ((c) - ('A' - 10)) : ((c) - '0')))
#define HEXSTRTOI(p) \
	((HEXTOC(p[0]) << 4) + HEXTOC(p[1]))

#define NFSDIAG 0
#if NFSDIAG

extern int nfs_debug;
#define NFS_DEBUG_ASYNCIO	1 /* asynchronous i/o */
#define NFS_DEBUG_WG		2 /* server write gathering */
#define NFS_DEBUG_RC		4 /* server request caching */
#define NFS_DEBUG_SILLY		8 /* nfs_sillyrename (.nfsXXX aka turd files) */
#define NFS_DEBUG_DUP		16 /* debug duplicate requests */
#define NFS_DEBUG_ATTR		32

#define NFS_DPF(cat, args)					\
	do {							\
		if (nfs_debug & NFS_DEBUG_##cat) kprintf args;	\
	} while (0)

#else

#define NFS_DPF(cat, args)

#endif /* NFSDIAG */

int	nfs_init __P((struct vfsconf *vfsp));
int	nfs_reply __P((struct nfsreq *));
int	nfs_getreq __P((struct nfsrv_descript *,struct nfsd *,int));
int	nfs_send __P((struct socket *, struct mbuf *, struct mbuf *, 
		      struct nfsreq *));
int	nfs_rephead __P((int, struct nfsrv_descript *, struct nfssvc_sock *,
			 int, int, u_quad_t *, struct mbuf **, struct mbuf **,
			 caddr_t *));
int	nfs_sndlock __P((int *, struct nfsreq *));
void	nfs_sndunlock __P((int *flagp));
int	nfs_disct __P((struct mbuf **, caddr_t *, int, int, caddr_t *));
int	nfs_vinvalbuf __P((struct vnode *, int, struct ucred *, struct proc *,
			   int));
int	nfs_readrpc __P((struct vnode *, struct uio *, struct ucred *));
int	nfs_writerpc __P((struct vnode *, struct uio *, struct ucred *, int *, 
			  int *));
int	nfs_readdirrpc __P((struct vnode *, struct uio *, struct ucred *));
int	nfs_asyncio __P((struct buf *, struct ucred *));
int	nfs_doio __P((struct buf *, struct ucred *, struct proc *));
int	nfs_readlinkrpc __P((struct vnode *, struct uio *, struct ucred *));
int	nfs_sigintr __P((struct nfsmount *, struct nfsreq *, struct proc *));
int	nfs_readdirplusrpc __P((struct vnode *, struct uio *, struct ucred *));
int	nfsm_disct __P((struct mbuf **, caddr_t *, int, int, caddr_t *));
void	nfsm_srvfattr __P((struct nfsrv_descript *, struct vattr *, 
			   struct nfs_fattr *));
void	nfsm_srvwcc __P((struct nfsrv_descript *, int, struct vattr *, int,
			 struct vattr *, struct mbuf **, char **));
void	nfsm_srvpostopattr __P((struct nfsrv_descript *, int, struct vattr *,
				struct mbuf **, char **));
int	netaddr_match __P((int, union nethostaddr *, struct mbuf *));
int	nfs_request __P((struct vnode *, struct mbuf *, int, struct proc *,
			 struct ucred *, struct mbuf **, struct mbuf **,
			 caddr_t *, u_int64_t *));
int	nfs_loadattrcache __P((struct vnode **, struct mbuf **, caddr_t *,
			       struct vattr *, int, u_int64_t *));
int	nfs_namei __P((struct nameidata *, fhandle_t *, int,
		       struct nfssvc_sock *, struct mbuf *, struct mbuf **,
		       caddr_t *, struct vnode **, struct proc *, int, int));
void	nfsm_adj __P((struct mbuf *, int, int));
int	nfsm_mbuftouio __P((struct mbuf **, struct uio *, int, caddr_t *));
void	nfsrv_initcache __P((void));
int	nfs_getauth __P((struct nfsmount *, struct nfsreq *, struct ucred *, 
			 char **, int *, char *, int *, NFSKERBKEY_T));
int	nfs_getnickauth __P((struct nfsmount *, struct ucred *, char **, 
			     int *, char *, int));
int	nfs_savenickauth __P((struct nfsmount *, struct ucred *, int, 
			      NFSKERBKEY_T, struct mbuf **, char **,
			      struct mbuf *));
int	nfs_adv __P((struct mbuf **, caddr_t *, int, int));
void	nfs_nhinit __P((void));
void	nfs_timer __P((void*));
u_long	nfs_hash __P((nfsfh_t *, int));
int	nfsrv_dorec __P((struct nfssvc_sock *, struct nfsd *, 
			 struct nfsrv_descript **));
int	nfsrv_getcache __P((struct nfsrv_descript *, struct nfssvc_sock *,
			    struct mbuf **));
void	nfsrv_updatecache __P((struct nfsrv_descript *, int, struct mbuf *));
void	nfsrv_cleancache __P((void));
int	nfs_connect __P((struct nfsmount *, struct nfsreq *));
void	nfs_disconnect __P((struct nfsmount *));
int	nfs_getattrcache __P((struct vnode *, struct vattr *));
int	nfsm_strtmbuf __P((struct mbuf **, char **, char *, long));
int	nfs_bioread __P((struct vnode *, struct uio *, int, struct ucred *,
			 int));
int	nfsm_uiotombuf __P((struct uio *, struct mbuf **, int, caddr_t *));
void	nfsrv_init __P((int));
void	nfs_clearcommit __P((struct mount *));
int	nfsrv_errmap __P((struct nfsrv_descript *, int));
void	nfsrvw_sort __P((gid_t *, int));
void	nfsrv_setcred __P((struct ucred *, struct ucred *));
int	nfs_writebp __P((struct buf *, int));
int	nfsrv_object_create __P((struct vnode *));
void	nfsrv_wakenfsd __P((struct nfssvc_sock *slp));
int	nfsrv_writegather __P((struct nfsrv_descript **, struct nfssvc_sock *,
			       struct proc *, struct mbuf **));
int	nfs_fsinfo __P((struct nfsmount *, struct vnode *, struct ucred *,
			struct proc *p));

int	nfsrv3_access __P((struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   struct proc *procp, struct mbuf **mrq));
int	nfsrv_commit __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  struct proc *procp, struct mbuf **mrq));
int	nfsrv_create __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  struct proc *procp, struct mbuf **mrq));
int	nfsrv_fhtovp __P((fhandle_t *, int, struct vnode **, struct ucred *,
			  struct nfssvc_sock *, struct mbuf *, int *,
			  int, int));
int	nfsrv_setpublicfs __P((struct mount *, struct netexport *,
			       struct export_args *));
int	nfs_ispublicfh __P((fhandle_t *));
int	nfsrv_fsinfo __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  struct proc *procp, struct mbuf **mrq));
int	nfsrv_getattr __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			   struct proc *procp, struct mbuf **mrq));
int	nfsrv_link __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			struct proc *procp, struct mbuf **mrq));
int	nfsrv_lookup __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  struct proc *procp, struct mbuf **mrq));
int	nfsrv_mkdir __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 struct proc *procp, struct mbuf **mrq));
int	nfsrv_mknod __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 struct proc *procp, struct mbuf **mrq));
int	nfsrv_noop __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			struct proc *procp, struct mbuf **mrq));
int	nfsrv_null __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			struct proc *procp, struct mbuf **mrq));
int	nfsrv_pathconf __P((struct nfsrv_descript *nfsd,
			    struct nfssvc_sock *slp, struct proc *procp,
			    struct mbuf **mrq));
int	nfsrv_read __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			struct proc *procp, struct mbuf **mrq));
int	nfsrv_readdir __P((struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   struct proc *procp, struct mbuf **mrq));
int	nfsrv_readdirplus __P((struct nfsrv_descript *nfsd,
			       struct nfssvc_sock *slp, struct proc *procp,
			       struct mbuf **mrq));
int	nfsrv_readlink __P((struct nfsrv_descript *nfsd,
			    struct nfssvc_sock *slp, struct proc *procp,
			    struct mbuf **mrq));
int	nfsrv_remove __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  struct proc *procp, struct mbuf **mrq));
int	nfsrv_rename __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			  struct proc *procp, struct mbuf **mrq));
int	nfsrv_rmdir __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 struct proc *procp, struct mbuf **mrq));
int	nfsrv_setattr __P((struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   struct proc *procp, struct mbuf **mrq));
int	nfsrv_statfs __P((struct nfsrv_descript *nfsd, 
			  struct nfssvc_sock *slp,
			  struct proc *procp, struct mbuf **mrq));
int	nfsrv_symlink __P((struct nfsrv_descript *nfsd, 
			   struct nfssvc_sock *slp,
			   struct proc *procp, struct mbuf **mrq));
int	nfsrv_write __P((struct nfsrv_descript *nfsd, struct nfssvc_sock *slp,
			 struct proc *procp, struct mbuf **mrq));
void	nfsrv_rcv __P((struct socket *so, caddr_t arg, int waitflag));
void	nfsrv_slpderef __P((struct nfssvc_sock *slp));

/*
 * NFSTRACE points were changed to FSDBG (KERNEL_DEBUG)
 * But some of this code may prove useful someday...
 */
#undef NFSDIAG
#if NFSDIAG

extern int nfstraceindx;
#define NFSTBUFSIZ 8912
struct nfstracerec { uint i1, i2, i3, i4; };
extern struct nfstracerec nfstracebuf[NFSTBUFSIZ];
extern uint nfstracemask; /* 32 bits - trace points over 31 are unconditional */

/* 0x0000000f nfs_getattrcache trace points */
#define NFSTRC_GAC_MISS 0x00	/* 0x00000001 cache miss */
#define NFSTRC_GAC_HIT	0x01	/* 0x00000002 cache hit */
#define NFSTRC_GAC_NP	0x02	/* 0x00000004 np size mismatch - vp... */
/* 0x00000038 nfs_loadattrcache trace points */
#define NFSTRC_LAC	0x03	/* 0x00000008 function entry point - vp */
#define NFSTRC_LAC_INIT	0x04	/* 0x00000010 new vp & init n_mtime - vp */
#define NFSTRC_LAC_NP	0x05	/* 0x00000020 np size mismatch - vp... */
/* 0x000000c0 nfs_getattr trace points */
#define NFSTRC_GA_INV	0x06	/* 0x00000040 times mismatch - vp */
#define NFSTRC_GA_INV1	0x07	/* 0x00000080 invalidate ok - vp */
/* 0x00000100 vmp_invalidate trace points */
#define NFSTRC_VMP_INV	0x08	/* 0x00000100 function entry point - vmp */
/* 0x00000200 nfs_request trace points */
#define NFSTRC_REQ	0x09	/* 0x00000200 - alternates vp and procnum */
/* 0x00000c00 vmp_push_range trace points */
#define NFSTRC_VPR	0xa	/* 0x00000400 entry point - vp... */
#define NFSTRC_VPR_DONE	0xb	/* 0x00000800 tail exit - error # */
/* 0x00003000 nfs_doio trace points */
#define NFSTRC_DIO	0xc	/* 0x00001000 entry point - vp */
#define NFSTRC_DIO_DONE	0xd	/* 0x00002000 exit points - vp */
/* 0x000fc000 congestion window trace points */
#define NFSTRC_CWND_INIT      0xe
#define NFSTRC_CWND_REPLY     0xf
#define NFSTRC_CWND_TIMER     0x10
#define NFSTRC_CWND_REQ1      0x11
#define NFSTRC_CWND_REQ2      0x12
#define NFSTRC_CWND_SOFT      0x13
/* 0xfff00000 nfs_rcvlock & nfs_rcvunlock trace points */
#define NFSTRC_ECONN	0x14
#define NFSTRC_RCVERR	0x15
#define NFSTRC_REQFREE	0x16
#define NFSTRC_NOTMINE	0x17
#define NFSTRC_6	0x18
#define NFSTRC_7	0x19
#define NFSTRC_RCVLCKINTR	0x1a
#define NFSTRC_RCVALREADY	0x1b
#define NFSTRC_RCVLCKW	0x1c	/* 0x10000000 seeking recieve lock (waiting) */
#define NFSTRC_RCVLCK	0x1d	/* 0x20000000 getting recieve lock */ 
#define NFSTRC_RCVUNLW	0x1e	/* 0x40000000 releasing rcv lock w/ wakeup */
#define NFSTRC_RCVUNL	0x1f	/* 0x80000000 releasing rcv lock w/o wakeup */
/* trace points beyond 31 are on if any of above points are on */
#define NFSTRC_GA_INV2	0x20	/* nfs_getattr invalidate - error# */
#define NFSTRC_VBAD	0x21
#define NFSTRC_REQERR	0x22
#define NFSTRC_RPCERR	0x23
#define NFSTRC_DISSECTERR	0x24
#define NFSTRC_CONTINUE	0xff	/* continuation record for previous entry */

#define NFSTRACEX(a1, a2, a3, a4) \
( \
	nfstracebuf[nfstraceindx].i1 = (uint)(a1), \
	nfstracebuf[nfstraceindx].i2 = (uint)(a2), \
	nfstracebuf[nfstraceindx].i3 = (uint)(a3), \
	nfstracebuf[nfstraceindx].i4 = (uint)(a4), \
	nfstraceindx = (nfstraceindx + 1) % NFSTBUFSIZ, \
	1 \
)

#define NFSTRACE(cnst, fptr) \
( \
	(nfstracemask && ((cnst) > 31 || nfstracemask & 1<<(cnst))) ? \
		NFSTRACEX((cnst), (fptr), current_thread(), \
			  clock_get_system_value().tv_nsec) : \
		0 \
)

#define NFSTRACE4(cnst, fptr, a2, a3, a4) \
( \
	NFSTRACE(cnst,fptr) ? \
		NFSTRACEX(NFSTRC_CONTINUE, a2, a3, a4) : \
		0 \
)

#else	/* NFSDIAG */

	#define NFSTRACE(cnst, fptr)
	#define NFSTRACE4(cnst, fptr, a2, a3, a4)

#endif	/* NFSDIAG */

#endif	/* KERNEL */

#endif
