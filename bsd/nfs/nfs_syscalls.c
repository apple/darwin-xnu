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
 * Copyright (c) 1989, 1993
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
 *	@(#)nfs_syscalls.c	8.5 (Berkeley) 3/30/95
 * FreeBSD-Id: nfs_syscalls.c,v 1.32 1997/11/07 08:53:25 phk Exp $
 */

#include <sys/param.h>
#include <sys/systm.h>
/* XXX CSM 11/25/97 FreeBSD's generated syscall prototypes */
#ifdef notyet
#include <sys/sysproto.h>
#endif
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/namei.h>
#include <sys/syslog.h>
#include <sys/user.h>
#include <machine/spl.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#if ISO
#include <netiso/iso.h>
#endif
#include <nfs/xdr_subs.h>
#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfsrvcache.h>
#include <nfs/nfsmount.h>
#include <nfs/nfsnode.h>
#include <nfs/nqnfs.h>
#include <nfs/nfsrtt.h>


/* Global defs. */
extern int (*nfsrv3_procs[NFS_NPROCS]) __P((struct nfsrv_descript *nd,
					    struct nfssvc_sock *slp,
					    struct proc *procp,
					    struct mbuf **mreqp));
extern int nfs_numasync;
extern time_t nqnfsstarttime;
extern int nqsrv_writeslack;
extern int nfsrtton;
extern struct nfsstats nfsstats;
extern int nfsrvw_procrastinate;
extern int nfsrvw_procrastinate_v3;
struct nfssvc_sock *nfs_udpsock, *nfs_cltpsock;
static int nuidhash_max = NFS_MAXUIDHASH;

static void	nfsrv_zapsock __P((struct nfssvc_sock *slp));
static int	nfssvc_iod __P((struct proc *));

#define	TRUE	1
#define	FALSE	0

static int nfs_asyncdaemon[NFS_MAXASYNCDAEMON];

#ifndef NFS_NOSERVER
int nfsd_waiting = 0;
static struct nfsdrt nfsdrt;
static int nfs_numnfsd = 0;
static int notstarted = 1;
static int modify_flag = 0;
static void	nfsd_rt __P((int sotype, struct nfsrv_descript *nd,
			     int cacherep));
static int	nfssvc_addsock __P((struct file *, struct mbuf *,
				    struct proc *));
static int	nfssvc_nfsd __P((struct nfsd_srvargs *,caddr_t,struct proc *));

static int nfs_privport = 0;
/* XXX CSM 11/25/97 Upgrade sysctl.h someday */
#ifdef notyet
SYSCTL_INT(_vfs_nfs, NFS_NFSPRIVPORT, nfs_privport, CTLFLAG_RW, &nfs_privport, 0, "");
SYSCTL_INT(_vfs_nfs, OID_AUTO, gatherdelay, CTLFLAG_RW, &nfsrvw_procrastinate, 0, "");
SYSCTL_INT(_vfs_nfs, OID_AUTO, gatherdelay_v3, CTLFLAG_RW, &nfsrvw_procrastinate_v3, 0, "");
#endif

/*
 * NFS server system calls
 * getfh() lives here too, but maybe should move to kern/vfs_syscalls.c
 */

/*
 * Get file handle system call
 */
#ifndef _SYS_SYSPROTO_H_
struct getfh_args {
	char	*fname;
	fhandle_t *fhp;
};
#endif
int
getfh(p, uap)
	struct proc *p;
	register struct getfh_args *uap;
{
	register struct vnode *vp;
	fhandle_t fh;
	int error;
	struct nameidata nd;

	/*
	 * Must be super user
	 */
	error = suser(p->p_ucred, &p->p_acflag);
	if(error)
		return (error);
	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE, uap->fname, p);
	error = namei(&nd);
	if (error)
		return (error);
	vp = nd.ni_vp;
	bzero((caddr_t)&fh, sizeof(fh));
	fh.fh_fsid = vp->v_mount->mnt_stat.f_fsid;
	error = VFS_VPTOFH(vp, &fh.fh_fid);
	vput(vp);
	if (error)
		return (error);
	error = copyout((caddr_t)&fh, (caddr_t)uap->fhp, sizeof (fh));
	return (error);
}

#endif /* NFS_NOSERVER */
/*
 * Nfs server psuedo system call for the nfsd's
 * Based on the flag value it either:
 * - adds a socket to the selection list
 * - remains in the kernel as an nfsd
 * - remains in the kernel as an nfsiod
 */
#ifndef _SYS_SYSPROTO_H_
struct nfssvc_args {
	int flag;
	caddr_t argp;
};
#endif
int
nfssvc(p, uap)
	struct proc *p;
	register struct nfssvc_args *uap;
{
#ifndef NFS_NOSERVER
	struct nameidata nd;
	struct file *fp;
	struct mbuf *nam;
	struct nfsd_args nfsdarg;
	struct nfsd_srvargs nfsd_srvargs, *nsd = &nfsd_srvargs;
	struct nfsd_cargs ncd;
	struct nfsd *nfsd;
	struct nfssvc_sock *slp;
	struct nfsuid *nuidp;
	struct nfsmount *nmp;
#endif /* NFS_NOSERVER */
	int error;

	/*
	 * Must be super user
	 */
	error = suser(p->p_ucred, &p->p_acflag);
	if(error)
		return (error);
	while (nfssvc_sockhead_flag & SLP_INIT) {
		 nfssvc_sockhead_flag |= SLP_WANTINIT;
		(void) tsleep((caddr_t)&nfssvc_sockhead, PSOCK, "nfsd init", 0);
	}
	if (uap->flag & NFSSVC_BIOD)
		error = nfssvc_iod(p);
#ifdef NFS_NOSERVER
	else
		error = ENXIO;
#else /* !NFS_NOSERVER */
	else if (uap->flag & NFSSVC_MNTD) {
		error = copyin(uap->argp, (caddr_t)&ncd, sizeof (ncd));
		if (error)
			return (error);
		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF, UIO_USERSPACE,
			ncd.ncd_dirp, p);
		error = namei(&nd);
		if (error)
			return (error);
		if ((nd.ni_vp->v_flag & VROOT) == 0)
			error = EINVAL;
		nmp = VFSTONFS(nd.ni_vp->v_mount);
		vput(nd.ni_vp);
		if (error)
			return (error);

		/* disable split funnels now */
		thread_funnel_merge(kernel_flock, network_flock);

		if ((nmp->nm_flag & NFSMNT_MNTD) &&
			(uap->flag & NFSSVC_GOTAUTH) == 0)
			return (0);
		nmp->nm_flag |= NFSMNT_MNTD;
		error = nqnfs_clientd(nmp, p->p_ucred, &ncd, uap->flag,
			uap->argp, p);
	} else if (uap->flag & NFSSVC_ADDSOCK) {
		error = copyin(uap->argp, (caddr_t)&nfsdarg, sizeof(nfsdarg));
		if (error)
			return (error);
		error = getsock(p->p_fd, nfsdarg.sock, &fp);
		if (error)
			return (error);
		/*
		 * Get the client address for connected sockets.
		 */
		if (nfsdarg.name == NULL || nfsdarg.namelen == 0)
			nam = (struct mbuf *)0;
		else {
			error = sockargs(&nam, nfsdarg.name, nfsdarg.namelen,
				MT_SONAME);
			if (error)
				return (error);
		}
		error = nfssvc_addsock(fp, nam, p);
	} else {
		error = copyin(uap->argp, (caddr_t)nsd, sizeof (*nsd));
		if (error)
			return (error);

		/* disable split funnels now */
		thread_funnel_merge(kernel_flock, network_flock);

		if ((uap->flag & NFSSVC_AUTHIN) && ((nfsd = nsd->nsd_nfsd)) &&
			(nfsd->nfsd_slp->ns_flag & SLP_VALID)) {
			slp = nfsd->nfsd_slp;

			/*
			 * First check to see if another nfsd has already
			 * added this credential.
			 */
			for (nuidp = NUIDHASH(slp,nsd->nsd_cr.cr_uid)->lh_first;
			    nuidp != 0; nuidp = nuidp->nu_hash.le_next) {
				if (nuidp->nu_cr.cr_uid == nsd->nsd_cr.cr_uid &&
				    (!nfsd->nfsd_nd->nd_nam2 ||
				     netaddr_match(NU_NETFAM(nuidp),
				     &nuidp->nu_haddr, nfsd->nfsd_nd->nd_nam2)))
					break;
			}
			if (nuidp) {
			    nfsrv_setcred(&nuidp->nu_cr,&nfsd->nfsd_nd->nd_cr);
			    nfsd->nfsd_nd->nd_flag |= ND_KERBFULL;
			} else {
			    /*
			     * Nope, so we will.
			     */
			    if (slp->ns_numuids < nuidhash_max) {
				slp->ns_numuids++;
				nuidp = (struct nfsuid *)
				   _MALLOC_ZONE(sizeof (struct nfsuid),
							M_NFSUID, M_WAITOK);
			    } else
				nuidp = (struct nfsuid *)0;
			    if ((slp->ns_flag & SLP_VALID) == 0) {
				if (nuidp)
				    _FREE_ZONE((caddr_t)nuidp,
					sizeof (struct nfsuid), M_NFSUID);
			    } else {
				if (nuidp == (struct nfsuid *)0) {
				    nuidp = slp->ns_uidlruhead.tqh_first;
				    LIST_REMOVE(nuidp, nu_hash);
				    TAILQ_REMOVE(&slp->ns_uidlruhead, nuidp,
					nu_lru);
				    if (nuidp->nu_flag & NU_NAM)
					m_freem(nuidp->nu_nam);
			        }
				nuidp->nu_flag = 0;
				nuidp->nu_cr = nsd->nsd_cr;
				if (nuidp->nu_cr.cr_ngroups > NGROUPS)
				    nuidp->nu_cr.cr_ngroups = NGROUPS;
				nuidp->nu_cr.cr_ref = 1;
				nuidp->nu_timestamp = nsd->nsd_timestamp;
				nuidp->nu_expire = time.tv_sec + nsd->nsd_ttl;
				/*
				 * and save the session key in nu_key.
				 */
				bcopy(nsd->nsd_key, nuidp->nu_key,
				    sizeof (nsd->nsd_key));
				if (nfsd->nfsd_nd->nd_nam2) {
				    struct sockaddr_in *saddr;

				    saddr = mtod(nfsd->nfsd_nd->nd_nam2,
					 struct sockaddr_in *);
				    switch (saddr->sin_family) {
				    case AF_INET:
					nuidp->nu_flag |= NU_INETADDR;
					nuidp->nu_inetaddr =
					     saddr->sin_addr.s_addr;
					break;
				    case AF_ISO:
				    default:
					nuidp->nu_flag |= NU_NAM;
					nuidp->nu_nam = m_copym(
					    nfsd->nfsd_nd->nd_nam2, 0,
					     M_COPYALL, M_WAIT);
					break;
				    };
				}
				TAILQ_INSERT_TAIL(&slp->ns_uidlruhead, nuidp,
					nu_lru);
				LIST_INSERT_HEAD(NUIDHASH(slp, nsd->nsd_uid),
					nuidp, nu_hash);
				nfsrv_setcred(&nuidp->nu_cr,
				    &nfsd->nfsd_nd->nd_cr);
				nfsd->nfsd_nd->nd_flag |= ND_KERBFULL;
			    }
			}
		}
		if ((uap->flag & NFSSVC_AUTHINFAIL) && (nfsd = nsd->nsd_nfsd))
			nfsd->nfsd_flag |= NFSD_AUTHFAIL;
		error = nfssvc_nfsd(nsd, uap->argp, p);
	}
#endif /* NFS_NOSERVER */
	if (error == EINTR || error == ERESTART)
		error = 0;
	return (error);
}

#ifndef NFS_NOSERVER
/*
 * Adds a socket to the list for servicing by nfsds.
 */
static int
nfssvc_addsock(fp, mynam, p)
	struct file *fp;
	struct mbuf *mynam;
	struct proc *p;
{
	register struct mbuf *m;
	register int siz;
	register struct nfssvc_sock *slp;
	register struct socket *so;
	struct nfssvc_sock *tslp;
	int error, s;

	so = (struct socket *)fp->f_data;
	tslp = (struct nfssvc_sock *)0;
	/*
	 * Add it to the list, as required.
	 */
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	if (so->so_proto->pr_protocol == IPPROTO_UDP) {
		tslp = nfs_udpsock;
		if (tslp->ns_flag & SLP_VALID) {
			m_freem(mynam);
			thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
			return (EPERM);
		}
#if ISO
	} else if (so->so_proto->pr_protocol == ISOPROTO_CLTP) {
		tslp = nfs_cltpsock;
		if (tslp->ns_flag & SLP_VALID) {
			m_freem(mynam);
			thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
			return (EPERM);
		}
#endif /* ISO */
	}
	if (so->so_type == SOCK_STREAM)
		siz = NFS_MAXPACKET + sizeof (u_long);
	else
		siz = NFS_MAXPACKET;
	error = soreserve(so, siz, siz);
	if (error) {
		m_freem(mynam);
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		return (error);
	}

	/*
	 * Set protocol specific options { for now TCP only } and
	 * reserve some space. For datagram sockets, this can get called
	 * repeatedly for the same socket, but that isn't harmful.
	 */
	if (so->so_type == SOCK_STREAM) {
		struct sockopt sopt;
		int val;

		bzero(&sopt, sizeof sopt);
		sopt.sopt_level = SOL_SOCKET;
		sopt.sopt_name = SO_KEEPALIVE;
		sopt.sopt_val = &val;
		sopt.sopt_valsize = sizeof val;
		val = 1;
		sosetopt(so, &sopt);
	}
	if (so->so_proto->pr_domain->dom_family == AF_INET &&
	    so->so_proto->pr_protocol == IPPROTO_TCP) {
		struct sockopt sopt;
		int val;

		bzero(&sopt, sizeof sopt);
		sopt.sopt_level = IPPROTO_TCP;
		sopt.sopt_name = TCP_NODELAY;
		sopt.sopt_val = &val;
		sopt.sopt_valsize = sizeof val;
		val = 1;
		sosetopt(so, &sopt);
	}

	so->so_rcv.sb_flags &= ~SB_NOINTR;
	so->so_rcv.sb_timeo = 0;
	so->so_snd.sb_flags &= ~SB_NOINTR;
	so->so_snd.sb_timeo = 0;
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	if (tslp)
		slp = tslp;
	else {
		MALLOC(slp, struct nfssvc_sock *, sizeof(struct nfssvc_sock),
				M_NFSSVC, M_WAITOK);
		bzero((caddr_t)slp, sizeof (struct nfssvc_sock));
		TAILQ_INIT(&slp->ns_uidlruhead);
		TAILQ_INSERT_TAIL(&nfssvc_sockhead, slp, ns_chain);
	}
	slp->ns_so = so;
	slp->ns_nam = mynam;
	slp->ns_fp = fp;
	(void)fref(fp);
	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
	s = splnet();
	so->so_upcallarg = (caddr_t)slp;
	so->so_upcall = nfsrv_rcv;
	so->so_rcv.sb_flags |= SB_UPCALL; /* required for freebsd merge */
	thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
	slp->ns_flag = (SLP_VALID | SLP_NEEDQ);
	nfsrv_wakenfsd(slp);
	splx(s);
	return (0);
}

/*
 * Called by nfssvc() for nfsds. Just loops around servicing rpc requests
 * until it is killed by a signal.
 */
static int
nfssvc_nfsd(nsd, argp, p)
	struct nfsd_srvargs *nsd;
	caddr_t argp;
	struct proc *p;
{
	register struct mbuf *m;
	register int siz;
	register struct nfssvc_sock *slp;
	register struct socket *so;
	register int *solockp;
	struct nfsd *nfsd = nsd->nsd_nfsd;
	struct nfsrv_descript *nd = NULL;
	struct mbuf *mreq;
	int error = 0, cacherep, s, sotype, writes_todo;
	int procrastinate;
	u_quad_t cur_usec;
	extern void	nfs_aio_thread_init();

#ifndef nolint
	cacherep = RC_DOIT;
	writes_todo = 0;
#endif
	s = splnet();
	if (nfsd == (struct nfsd *)0) {
		MALLOC(nfsd, struct nfsd *, sizeof(struct nfsd), M_NFSD, M_WAITOK);
		nsd->nsd_nfsd = nfsd;
		bzero((caddr_t)nfsd, sizeof (struct nfsd));
		nfsd->nfsd_procp = p;
		TAILQ_INSERT_TAIL(&nfsd_head, nfsd, nfsd_chain);
		nfs_numnfsd++;
		nfs_aio_thread_init();
	}
	/*
	 * Loop getting rpc requests until SIGKILL.
	 */
	for (;;) {
		if ((nfsd->nfsd_flag & NFSD_REQINPROG) == 0) {
			while (nfsd->nfsd_slp == (struct nfssvc_sock *)0 &&
			    (nfsd_head_flag & NFSD_CHECKSLP) == 0) {
				nfsd->nfsd_flag |= NFSD_WAITING;
				nfsd_waiting++;
				error = tsleep((caddr_t)nfsd, PSOCK | PCATCH,
				    "nfsd", 0);
				nfsd_waiting--;
				if (error)
					goto done;
			}
			if (nfsd->nfsd_slp == (struct nfssvc_sock *)0 &&
			    (nfsd_head_flag & NFSD_CHECKSLP) != 0) {
				for (slp = nfssvc_sockhead.tqh_first; slp != 0;
				    slp = slp->ns_chain.tqe_next) {
				    if ((slp->ns_flag & (SLP_VALID | SLP_DOREC))
					== (SLP_VALID | SLP_DOREC)) {
					    slp->ns_flag &= ~SLP_DOREC;
					    slp->ns_sref++;
					    nfsd->nfsd_slp = slp;
					    break;
				    }
				}
				if (slp == 0)
					nfsd_head_flag &= ~NFSD_CHECKSLP;
			}
			if ((slp = nfsd->nfsd_slp) == (struct nfssvc_sock *)0)
				continue;
			if (slp->ns_flag & SLP_VALID) {
				if (slp->ns_flag & SLP_DISCONN)
					nfsrv_zapsock(slp);
				else if (slp->ns_flag & SLP_NEEDQ) {
					slp->ns_flag &= ~SLP_NEEDQ;
					(void) nfs_sndlock(&slp->ns_solock,
						(struct nfsreq *)0);
				 	thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
					nfsrv_rcv(slp->ns_so, (caddr_t)slp,
						M_WAIT);
					thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
					nfs_sndunlock(&slp->ns_solock);
				}
				error = nfsrv_dorec(slp, nfsd, &nd);
				cur_usec = (u_quad_t)time.tv_sec * 1000000 +
					(u_quad_t)time.tv_usec;
				if (error && slp->ns_tq.lh_first &&
				    slp->ns_tq.lh_first->nd_time <= cur_usec) {
					error = 0;
					cacherep = RC_DOIT;
					writes_todo = 1;
				} else
					writes_todo = 0;
				nfsd->nfsd_flag |= NFSD_REQINPROG;
			}
		} else {
			error = 0;
			slp = nfsd->nfsd_slp;
		}
		if (error || (slp->ns_flag & SLP_VALID) == 0) {
			if (nd) {
				_FREE_ZONE((caddr_t)nd,
						sizeof *nd, M_NFSRVDESC);
				nd = NULL;
			}
			nfsd->nfsd_slp = (struct nfssvc_sock *)0;
			nfsd->nfsd_flag &= ~NFSD_REQINPROG;
			nfsrv_slpderef(slp);
			continue;
		}
		splx(s);
		so = slp->ns_so;
		sotype = so->so_type;
		if (so->so_proto->pr_flags & PR_CONNREQUIRED)
			solockp = &slp->ns_solock;
		else
			solockp = (int *)0;
		if (nd) {
		    nd->nd_starttime = time;
		    if (nd->nd_nam2)
			nd->nd_nam = nd->nd_nam2;
		    else
			nd->nd_nam = slp->ns_nam;

		    /*
		     * Check to see if authorization is needed.
		     */
		    if (nfsd->nfsd_flag & NFSD_NEEDAUTH) {
			nfsd->nfsd_flag &= ~NFSD_NEEDAUTH;
			nsd->nsd_haddr = mtod(nd->nd_nam,
			    struct sockaddr_in *)->sin_addr.s_addr;
			nsd->nsd_authlen = nfsd->nfsd_authlen;
			nsd->nsd_verflen = nfsd->nfsd_verflen;
			if (!copyout(nfsd->nfsd_authstr,nsd->nsd_authstr,
				nfsd->nfsd_authlen) &&
			    !copyout(nfsd->nfsd_verfstr, nsd->nsd_verfstr,
				nfsd->nfsd_verflen) &&
			    !copyout((caddr_t)nsd, argp, sizeof (*nsd)))
			    return (ENEEDAUTH);
			cacherep = RC_DROPIT;
		    } else
			cacherep = nfsrv_getcache(nd, slp, &mreq);

		    /*
		     * Check for just starting up for NQNFS and send
		     * fake "try again later" replies to the NQNFS clients.
		     */
		    if (notstarted && nqnfsstarttime <= time.tv_sec) {
			if (modify_flag) {
				nqnfsstarttime = time.tv_sec + nqsrv_writeslack;
				modify_flag = 0;
			} else
				notstarted = 0;
		    }
		    if (notstarted) {
			if ((nd->nd_flag & ND_NQNFS) == 0)
				cacherep = RC_DROPIT;
			else if (nd->nd_procnum != NFSPROC_WRITE) {
				nd->nd_procnum = NFSPROC_NOOP;
				nd->nd_repstat = NQNFS_TRYLATER;
				cacherep = RC_DOIT;
			} else
				modify_flag = 1;
		    } else if (nfsd->nfsd_flag & NFSD_AUTHFAIL) {
			nfsd->nfsd_flag &= ~NFSD_AUTHFAIL;
			nd->nd_procnum = NFSPROC_NOOP;
			nd->nd_repstat = (NFSERR_AUTHERR | AUTH_TOOWEAK);
			cacherep = RC_DOIT;
		    } else if (nfs_privport) {
			/* Check if source port is privileged */
			u_short port;
			struct sockaddr *nam = nd->nd_nam;
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)nam;
			port = ntohs(sin->sin_port);
			if (port >= IPPORT_RESERVED && 
			    nd->nd_procnum != NFSPROC_NULL) {
			    nd->nd_procnum = NFSPROC_NOOP;
			    nd->nd_repstat = (NFSERR_AUTHERR | AUTH_TOOWEAK);
			    cacherep = RC_DOIT;
			    printf("NFS request from unprivileged port (%s:%d)\n",
				   (char *)(inet_ntoa(sin->sin_addr)), port);
			}
		    }

		}

		/*
		 * Loop to get all the write rpc relies that have been
		 * gathered together.
		 */
		do {
		    switch (cacherep) {
		    case RC_DOIT:
			if (nd && (nd->nd_flag & ND_NFSV3))
			    procrastinate = nfsrvw_procrastinate_v3;
			else
			    procrastinate = nfsrvw_procrastinate;
			if (writes_todo || (nd->nd_procnum == NFSPROC_WRITE &&
			    procrastinate > 0 && !notstarted))
			    error = nfsrv_writegather(&nd, slp,
				nfsd->nfsd_procp, &mreq);
			else
			    error = (*(nfsrv3_procs[nd->nd_procnum]))(nd,
				slp, nfsd->nfsd_procp, &mreq);
			if (mreq == NULL)
				break;
			if (error) {
				if (nd->nd_procnum != NQNFSPROC_VACATED)
					nfsstats.srv_errs++;
				nfsrv_updatecache(nd, FALSE, mreq);
				if (nd->nd_nam2)
					m_freem(nd->nd_nam2);
				break;
			}
			nfsstats.srvrpccnt[nd->nd_procnum]++;
			nfsrv_updatecache(nd, TRUE, mreq);
			nd->nd_mrep = (struct mbuf *)0;
		    case RC_REPLY:
			m = mreq;
			siz = 0;
			while (m) {
				siz += m->m_len;
				m = m->m_next;
			}
			if (siz <= 0 || siz > NFS_MAXPACKET) {
				printf("mbuf siz=%d\n",siz);
				panic("Bad nfs svc reply");
			}
			m = mreq;
			m->m_pkthdr.len = siz;
			m->m_pkthdr.rcvif = (struct ifnet *)0;
			/*
			 * For stream protocols, prepend a Sun RPC
			 * Record Mark.
			 */
			if (sotype == SOCK_STREAM) {
				M_PREPEND(m, NFSX_UNSIGNED, M_WAIT);
				*mtod(m, u_long *) = htonl(0x80000000 | siz);
			}
			if (solockp)
				(void) nfs_sndlock(solockp, (struct nfsreq *)0);
			if (slp->ns_flag & SLP_VALID)
			    error = nfs_send(so, nd->nd_nam2, m, NULL);
			else {
			    error = EPIPE;
			    m_freem(m);
			}
			if (nfsrtton)
				nfsd_rt(sotype, nd, cacherep);
			if (nd->nd_nam2)
				MFREE(nd->nd_nam2, m);
			if (nd->nd_mrep)
				m_freem(nd->nd_mrep);
			if (error == EPIPE)
				nfsrv_zapsock(slp);
			if (solockp)
				nfs_sndunlock(solockp);
			if (error == EINTR || error == ERESTART) {
				_FREE_ZONE((caddr_t)nd,
						sizeof *nd, M_NFSRVDESC);
				nfsrv_slpderef(slp);
				s = splnet();
				goto done;
			}
			break;
		    case RC_DROPIT:
			if (nfsrtton)
				nfsd_rt(sotype, nd, cacherep);
			m_freem(nd->nd_mrep);
			m_freem(nd->nd_nam2);
			break;
		    };
		    if (nd) {
			FREE_ZONE((caddr_t)nd, sizeof *nd, M_NFSRVDESC);
			nd = NULL;
		    }

		    /*
		     * Check to see if there are outstanding writes that
		     * need to be serviced.
		     */
		    cur_usec = (u_quad_t)time.tv_sec * 1000000 +
			(u_quad_t)time.tv_usec;
		    s = splsoftclock();
		    if (slp->ns_tq.lh_first &&
			slp->ns_tq.lh_first->nd_time <= cur_usec) {
			cacherep = RC_DOIT;
			writes_todo = 1;
		    } else
			writes_todo = 0;
		    splx(s);
		} while (writes_todo);
		s = splnet();
		if (nfsrv_dorec(slp, nfsd, &nd)) {
			nfsd->nfsd_flag &= ~NFSD_REQINPROG;
			nfsd->nfsd_slp = NULL;
			nfsrv_slpderef(slp);
		}
	}
done:
	TAILQ_REMOVE(&nfsd_head, nfsd, nfsd_chain);
	splx(s);
	_FREE((caddr_t)nfsd, M_NFSD);
	nsd->nsd_nfsd = (struct nfsd *)0;
	if (--nfs_numnfsd == 0)
		nfsrv_init(TRUE);	/* Reinitialize everything */
	return (error);
}
#endif /* NFS_NOSERVER */

int nfs_defect = 0;
/* XXX CSM 11/25/97 Upgrade sysctl.h someday */
#ifdef notyet
SYSCTL_INT(_vfs_nfs, OID_AUTO, defect, CTLFLAG_RW, &nfs_defect, 0, "");
#endif

static int nfssvc_iod_continue(int);

/*
 * Asynchronous I/O daemons for client nfs.
 * They do read-ahead and write-behind operations on the block I/O cache.
 * Never returns unless it fails or gets killed.
 */
static int
nfssvc_iod(p)
	struct proc *p;
{
	register struct buf *bp;
	register int i, myiod;
	struct nfsmount *nmp;
	int error = 0;
	struct uthread *ut;

	/*
	 * Assign my position or return error if too many already running
	 */
	myiod = -1;
	for (i = 0; i < NFS_MAXASYNCDAEMON; i++)
		if (nfs_asyncdaemon[i] == 0) {
			nfs_asyncdaemon[i]++;
			myiod = i;
			break;
		}
	if (myiod == -1)
		return (EBUSY);
	nfs_numasync++;

	/* stuff myiod into uthread to get off local stack for
       continuation */

	ut = get_bsdthread_info(current_act());
	ut->uu_state.uu_nfs_myiod = myiod;  /* squirrel away for continuation */

	nfssvc_iod_continue(0);
	/* NOTREACHED */

}

/*
 * Continuation for Asynchronous I/O daemons for client nfs.
 */
static int
nfssvc_iod_continue(error)
{
	register struct buf *bp;
	register int i, myiod;
	struct nfsmount *nmp;
	struct uthread *ut;
	struct proc *p;

	/*
	 * real myiod is stored in uthread, recover it
	 */
	ut = get_bsdthread_info(current_act());
	myiod = ut->uu_state.uu_nfs_myiod;
	p = current_proc();

	/*
	 * Just loop around doin our stuff until SIGKILL
     *  - actually we don't loop with continuations...
	 */
	for (;;) {
	    while (((nmp = nfs_iodmount[myiod]) == NULL
		    || nmp->nm_bufq.tqh_first == NULL)
		   && error == 0) {
		if (nmp)
		    nmp->nm_bufqiods--;
		nfs_iodwant[myiod] = p;
		nfs_iodmount[myiod] = NULL;
		error = tsleep0((caddr_t)&nfs_iodwant[myiod],
			PWAIT | PCATCH, "nfsidl", 0, nfssvc_iod_continue);
		/* NOTREACHED */
	    }
	    if (error) {
		nfs_asyncdaemon[myiod] = 0;
		if (nmp) nmp->nm_bufqiods--;
		nfs_iodwant[myiod] = NULL;
		nfs_iodmount[myiod] = NULL;
		nfs_numasync--;
		if (error == EINTR || error == ERESTART)
		  error = 0;
#if defined (__i386__)
		return(error);
#else
		unix_syscall_return(error);
#endif
	    }
	    while ((bp = nmp->nm_bufq.tqh_first) != NULL) {
		/* Take one off the front of the list */
		TAILQ_REMOVE(&nmp->nm_bufq, bp, b_freelist);
		nmp->nm_bufqlen--;
		if (nmp->nm_bufqwant && nmp->nm_bufqlen < 2 * nfs_numasync) {
		    nmp->nm_bufqwant = FALSE;
		    wakeup(&nmp->nm_bufq);
		}
		if (ISSET(bp->b_flags, B_READ))
		    (void) nfs_doio(bp, bp->b_rcred, (struct proc *)0);
		else
		    (void) nfs_doio(bp, bp->b_wcred, (struct proc *)0);

		/*
		 * If there are more than one iod on this mount, then defect
		 * so that the iods can be shared out fairly between the mounts
		 */
		if (nfs_defect && nmp->nm_bufqiods > 1) {
		    NFS_DPF(ASYNCIO,
			    ("nfssvc_iod: iod %d defecting from mount %p\n",
			     myiod, nmp));
		    nfs_iodmount[myiod] = NULL;
		    nmp->nm_bufqiods--;
		    break;
		}
	    }
	}
}

/*
 * Shut down a socket associated with an nfssvc_sock structure.
 * Should be called with the send lock set, if required.
 * The trick here is to increment the sref at the start, so that the nfsds
 * will stop using it and clear ns_flag at the end so that it will not be
 * reassigned during cleanup.
 */
static void
nfsrv_zapsock(slp)
	register struct nfssvc_sock *slp;
{
	register struct nfsuid *nuidp, *nnuidp;
	register struct nfsrv_descript *nwp, *nnwp;
	struct socket *so;
	struct file *fp;
	struct mbuf *m;
	int s;

	slp->ns_flag &= ~SLP_ALLFLAGS;
	fp = slp->ns_fp;
	if (fp) {
		slp->ns_fp = (struct file *)0;
		so = slp->ns_so;
		thread_funnel_switch(KERNEL_FUNNEL, NETWORK_FUNNEL);
		so->so_upcall = NULL;
		so->so_rcv.sb_flags &= ~SB_UPCALL;
		soshutdown(so, 2);
		thread_funnel_switch(NETWORK_FUNNEL, KERNEL_FUNNEL);
		closef(fp, (struct proc *)0);
		if (slp->ns_nam)
			MFREE(slp->ns_nam, m);
		m_freem(slp->ns_raw);
		m_freem(slp->ns_rec);
		for (nuidp = slp->ns_uidlruhead.tqh_first; nuidp != 0;
		    nuidp = nnuidp) {
			nnuidp = nuidp->nu_lru.tqe_next;
			LIST_REMOVE(nuidp, nu_hash);
			TAILQ_REMOVE(&slp->ns_uidlruhead, nuidp, nu_lru);
			if (nuidp->nu_flag & NU_NAM)
				m_freem(nuidp->nu_nam);
			_FREE_ZONE((caddr_t)nuidp,
					sizeof (struct nfsuid), M_NFSUID);
		}
		s = splsoftclock();
		for (nwp = slp->ns_tq.lh_first; nwp; nwp = nnwp) {
			nnwp = nwp->nd_tq.le_next;
			LIST_REMOVE(nwp, nd_tq);
			_FREE_ZONE((caddr_t)nwp, sizeof *nwp, M_NFSRVDESC);
		}
		LIST_INIT(&slp->ns_tq);
		splx(s);
	}
}

/*
 * Get an authorization string for the uid by having the mount_nfs sitting
 * on this mount point porpous out of the kernel and do it.
 */
int
nfs_getauth(nmp, rep, cred, auth_str, auth_len, verf_str, verf_len, key)
	register struct nfsmount *nmp;
	struct nfsreq *rep;
	struct ucred *cred;
	char **auth_str;
	int *auth_len;
	char *verf_str;
	int *verf_len;
	NFSKERBKEY_T key;		/* return session key */
{
	int error = 0;

	while ((nmp->nm_flag & NFSMNT_WAITAUTH) == 0) {
		nmp->nm_flag |= NFSMNT_WANTAUTH;
		(void) tsleep((caddr_t)&nmp->nm_authtype, PSOCK,
			"nfsauth1", 2 * hz);
		error = nfs_sigintr(nmp, rep, rep->r_procp);
		if (error) {
			nmp->nm_flag &= ~NFSMNT_WANTAUTH;
			return (error);
		}
	}
	nmp->nm_flag &= ~(NFSMNT_WAITAUTH | NFSMNT_WANTAUTH);
	MALLOC(*auth_str, char *, RPCAUTH_MAXSIZ, M_TEMP, M_WAITOK);
	nmp->nm_authstr = *auth_str;
	nmp->nm_authlen = RPCAUTH_MAXSIZ;
	nmp->nm_verfstr = verf_str;
	nmp->nm_verflen = *verf_len;
	nmp->nm_authuid = cred->cr_uid;
	wakeup((caddr_t)&nmp->nm_authstr);

	/*
	 * And wait for mount_nfs to do its stuff.
	 */
	while ((nmp->nm_flag & NFSMNT_HASAUTH) == 0 && error == 0) {
		(void) tsleep((caddr_t)&nmp->nm_authlen, PSOCK,
			"nfsauth2", 2 * hz);
		error = nfs_sigintr(nmp, rep, rep->r_procp);
	}
	if (nmp->nm_flag & NFSMNT_AUTHERR) {
		nmp->nm_flag &= ~NFSMNT_AUTHERR;
		error = EAUTH;
	}
	if (error)
		_FREE((caddr_t)*auth_str, M_TEMP);
	else {
		*auth_len = nmp->nm_authlen;
		*verf_len = nmp->nm_verflen;
		bcopy((caddr_t)nmp->nm_key, (caddr_t)key, sizeof (key));
	}
	nmp->nm_flag &= ~NFSMNT_HASAUTH;
	nmp->nm_flag |= NFSMNT_WAITAUTH;
	if (nmp->nm_flag & NFSMNT_WANTAUTH) {
		nmp->nm_flag &= ~NFSMNT_WANTAUTH;
		wakeup((caddr_t)&nmp->nm_authtype);
	}
	return (error);
}

/*
 * Get a nickname authenticator and verifier.
 */
int
nfs_getnickauth(nmp, cred, auth_str, auth_len, verf_str, verf_len)
	struct nfsmount *nmp;
	struct ucred *cred;
	char **auth_str;
	int *auth_len;
	char *verf_str;
	int verf_len;
{
	register struct nfsuid *nuidp;
	register u_long *nickp, *verfp;
	struct timeval ktvin, ktvout;

#if DIAGNOSTIC
	if (verf_len < (4 * NFSX_UNSIGNED))
		panic("nfs_getnickauth verf too small");
#endif
	for (nuidp = NMUIDHASH(nmp, cred->cr_uid)->lh_first;
	    nuidp != 0; nuidp = nuidp->nu_hash.le_next) {
		if (nuidp->nu_cr.cr_uid == cred->cr_uid)
			break;
	}
	if (!nuidp || nuidp->nu_expire < time.tv_sec)
		return (EACCES);

	/*
	 * Move to the end of the lru list (end of lru == most recently used).
	 */
	TAILQ_REMOVE(&nmp->nm_uidlruhead, nuidp, nu_lru);
	TAILQ_INSERT_TAIL(&nmp->nm_uidlruhead, nuidp, nu_lru);

	MALLOC(nickp, u_long *, 2 * NFSX_UNSIGNED, M_TEMP, M_WAITOK);
	*nickp++ = txdr_unsigned(RPCAKN_NICKNAME);
	*nickp = txdr_unsigned(nuidp->nu_nickname);
	*auth_str = (char *)nickp;
	*auth_len = 2 * NFSX_UNSIGNED;

	/*
	 * Now we must encrypt the verifier and package it up.
	 */
	verfp = (u_long *)verf_str;
	*verfp++ = txdr_unsigned(RPCAKN_NICKNAME);
	if (time.tv_sec > nuidp->nu_timestamp.tv_sec ||
	    (time.tv_sec == nuidp->nu_timestamp.tv_sec &&
	     time.tv_usec > nuidp->nu_timestamp.tv_usec))
		nuidp->nu_timestamp = time;
	else
		nuidp->nu_timestamp.tv_usec++;
	ktvin.tv_sec = txdr_unsigned(nuidp->nu_timestamp.tv_sec);
	ktvin.tv_usec = txdr_unsigned(nuidp->nu_timestamp.tv_usec);

	/*
	 * Now encrypt the timestamp verifier in ecb mode using the session
	 * key.
	 */
#if NFSKERB
	XXX
#endif

	*verfp++ = ktvout.tv_sec;
	*verfp++ = ktvout.tv_usec;
	*verfp = 0;
	return (0);
}

/*
 * Save the current nickname in a hash list entry on the mount point.
 */
int
nfs_savenickauth(nmp, cred, len, key, mdp, dposp, mrep)
	register struct nfsmount *nmp;
	struct ucred *cred;
	int len;
	NFSKERBKEY_T key;
	struct mbuf **mdp;
	char **dposp;
	struct mbuf *mrep;
{
	register struct nfsuid *nuidp;
	register u_long *tl;
	register long t1;
	struct mbuf *md = *mdp;
	struct timeval ktvin, ktvout;
	u_long nick;
	char *dpos = *dposp, *cp2;
	int deltasec, error = 0;

	if (len == (3 * NFSX_UNSIGNED)) {
		nfsm_dissect(tl, u_long *, 3 * NFSX_UNSIGNED);
		ktvin.tv_sec = *tl++;
		ktvin.tv_usec = *tl++;
		nick = fxdr_unsigned(u_long, *tl);

		/*
		 * Decrypt the timestamp in ecb mode.
		 */
#if NFSKERB
		XXX
#endif
		ktvout.tv_sec = fxdr_unsigned(long, ktvout.tv_sec);
		ktvout.tv_usec = fxdr_unsigned(long, ktvout.tv_usec);
		deltasec = time.tv_sec - ktvout.tv_sec;
		if (deltasec < 0)
			deltasec = -deltasec;
		/*
		 * If ok, add it to the hash list for the mount point.
		 */
		if (deltasec <= NFS_KERBCLOCKSKEW) {
			if (nmp->nm_numuids < nuidhash_max) {
				nmp->nm_numuids++;
				MALLOC_ZONE(nuidp, struct nfsuid *,
						sizeof (struct nfsuid),
							M_NFSUID, M_WAITOK);
			} else {
				nuidp = nmp->nm_uidlruhead.tqh_first;
				LIST_REMOVE(nuidp, nu_hash);
				TAILQ_REMOVE(&nmp->nm_uidlruhead, nuidp,
					nu_lru);
			}
			nuidp->nu_flag = 0;
			nuidp->nu_cr.cr_uid = cred->cr_uid;
			nuidp->nu_expire = time.tv_sec + NFS_KERBTTL;
			nuidp->nu_timestamp = ktvout;
			nuidp->nu_nickname = nick;
			bcopy(key, nuidp->nu_key, sizeof (key));
			TAILQ_INSERT_TAIL(&nmp->nm_uidlruhead, nuidp,
				nu_lru);
			LIST_INSERT_HEAD(NMUIDHASH(nmp, cred->cr_uid),
				nuidp, nu_hash);
		}
	} else
		nfsm_adv(nfsm_rndup(len));
nfsmout:
	*mdp = md;
	*dposp = dpos;
	return (error);
}

#ifndef NFS_NOSERVER

/*
 * Derefence a server socket structure. If it has no more references and
 * is no longer valid, you can throw it away.
 */
void
nfsrv_slpderef(slp)
	register struct nfssvc_sock *slp;
{
	if (--(slp->ns_sref) == 0 && (slp->ns_flag & SLP_VALID) == 0) {
		TAILQ_REMOVE(&nfssvc_sockhead, slp, ns_chain);
		_FREE((caddr_t)slp, M_NFSSVC);
	}
}

/*
 * Initialize the data structures for the server.
 * Handshake with any new nfsds starting up to avoid any chance of
 * corruption.
 */
void
nfsrv_init(terminating)
	int terminating;
{
	register struct nfssvc_sock *slp, *nslp;

	if (nfssvc_sockhead_flag & SLP_INIT)
		panic("nfsd init");
	nfssvc_sockhead_flag |= SLP_INIT;
	if (terminating) {
		for (slp = nfssvc_sockhead.tqh_first; slp != 0; slp = nslp) {
			nslp = slp->ns_chain.tqe_next;
			if (slp->ns_flag & SLP_VALID)
				nfsrv_zapsock(slp);
			TAILQ_REMOVE(&nfssvc_sockhead, slp, ns_chain);
			_FREE((caddr_t)slp, M_NFSSVC);
		}
		nfsrv_cleancache();	/* And clear out server cache */
/* XXX CSM 12/4/97 Revisit when enabling WebNFS */
#ifdef notyet
	} else
		nfs_pub.np_valid = 0;
#else
	}
#endif

	TAILQ_INIT(&nfssvc_sockhead);
	nfssvc_sockhead_flag &= ~SLP_INIT;
	if (nfssvc_sockhead_flag & SLP_WANTINIT) {
		nfssvc_sockhead_flag &= ~SLP_WANTINIT;
		wakeup((caddr_t)&nfssvc_sockhead);
	}

	TAILQ_INIT(&nfsd_head);
	nfsd_head_flag &= ~NFSD_CHECKSLP;

	MALLOC(nfs_udpsock, struct nfssvc_sock *, sizeof(struct nfssvc_sock),
			M_NFSSVC, M_WAITOK);
	bzero((caddr_t)nfs_udpsock, sizeof (struct nfssvc_sock));
	TAILQ_INIT(&nfs_udpsock->ns_uidlruhead);
	TAILQ_INSERT_HEAD(&nfssvc_sockhead, nfs_udpsock, ns_chain);

	MALLOC(nfs_cltpsock, struct nfssvc_sock *, sizeof(struct nfssvc_sock),
			M_NFSSVC, M_WAITOK);
	bzero((caddr_t)nfs_cltpsock, sizeof (struct nfssvc_sock));
	TAILQ_INIT(&nfs_cltpsock->ns_uidlruhead);
	TAILQ_INSERT_TAIL(&nfssvc_sockhead, nfs_cltpsock, ns_chain);
}

/*
 * Add entries to the server monitor log.
 */
static void
nfsd_rt(sotype, nd, cacherep)
	int sotype;
	register struct nfsrv_descript *nd;
	int cacherep;
{
	register struct drt *rt;

	rt = &nfsdrt.drt[nfsdrt.pos];
	if (cacherep == RC_DOIT)
		rt->flag = 0;
	else if (cacherep == RC_REPLY)
		rt->flag = DRT_CACHEREPLY;
	else
		rt->flag = DRT_CACHEDROP;
	if (sotype == SOCK_STREAM)
		rt->flag |= DRT_TCP;
	if (nd->nd_flag & ND_NQNFS)
		rt->flag |= DRT_NQNFS;
	else if (nd->nd_flag & ND_NFSV3)
		rt->flag |= DRT_NFSV3;
	rt->proc = nd->nd_procnum;
	if (mtod(nd->nd_nam, struct sockaddr *)->sa_family == AF_INET)
	    rt->ipadr = mtod(nd->nd_nam, struct sockaddr_in *)->sin_addr.s_addr;
	else
	    rt->ipadr = INADDR_ANY;
	rt->resptime = ((time.tv_sec - nd->nd_starttime.tv_sec) * 1000000) +
		(time.tv_usec - nd->nd_starttime.tv_usec);
	rt->tstamp = time;
	nfsdrt.pos = (nfsdrt.pos + 1) % NFSRTTLOGSIZ;
}
#endif /* NFS_NOSERVER */
