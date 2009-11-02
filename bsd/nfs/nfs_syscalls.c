/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/file_internal.h>
#include <sys/filedesc.h>
#include <sys/stat.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/proc_internal.h> /* for fdflags */
#include <sys/kauth.h>
#include <sys/sysctl.h>
#include <sys/ubc.h>
#include <sys/uio.h>
#include <sys/malloc.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/domain.h>
#include <sys/protosw.h>
#include <sys/fcntl.h>
#include <sys/lockf.h>
#include <sys/syslog.h>
#include <sys/user.h>
#include <sys/sysproto.h>
#include <sys/kpi_socket.h>
#include <libkern/OSAtomic.h>

#include <bsm/audit_kernel.h>

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
#include <nfs/nfsrtt.h>
#include <nfs/nfs_lock.h>

extern void unix_syscall_return(int);

/* Global defs. */
extern int (*nfsrv3_procs[NFS_NPROCS])(struct nfsrv_descript *nd,
					    struct nfssvc_sock *slp,
					    proc_t procp,
					    mbuf_t *mreqp);
extern int nfs_numasync;
extern int nfs_ioddelwri;
extern int nfsrtton;
extern struct nfsstats nfsstats;
extern int nfsrvw_procrastinate;
extern int nfsrvw_procrastinate_v3;

struct nfssvc_sock *nfs_udpsock, *nfs_cltpsock;
static int nuidhash_max = NFS_MAXUIDHASH;

static void	nfsrv_zapsock(struct nfssvc_sock *slp);
static int	nfssvc_iod(proc_t);
static int	nfskerb_clientd(struct nfsmount *, struct nfsd_cargs *, int, user_addr_t, proc_t);

static int nfs_asyncdaemon[NFS_MAXASYNCDAEMON];

#ifndef NFS_NOSERVER
int nfsd_waiting = 0;
static struct nfsdrt nfsdrt;
int nfs_numnfsd = 0;
static void	nfsd_rt(int sotype, struct nfsrv_descript *nd, int cacherep);
static int	nfssvc_addsock(socket_t, mbuf_t, proc_t);
static int	nfssvc_nfsd(struct nfsd_srvargs *,user_addr_t, proc_t);
static int	nfssvc_export(user_addr_t, proc_t);

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
int
getfh(proc_t p, struct getfh_args *uap, __unused int *retval)
{
	vnode_t vp;
	struct nfs_filehandle nfh;
	int error;
	struct nameidata nd;
	struct vfs_context context;
	char path[MAXPATHLEN], *ptr;
	u_int pathlen;
	struct nfs_exportfs *nxfs;
	struct nfs_export *nx;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();

	/*
	 * Must be super user
	 */
	error = proc_suser(p);
	if (error)
		return (error);

	error = copyinstr(uap->fname, path, MAXPATHLEN, (size_t *)&pathlen);
	if (error)
		return (error);

	NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1, 
			UIO_SYSSPACE, path, &context);
	error = namei(&nd);
	if (error)
		return (error);
	nameidone(&nd);

	vp = nd.ni_vp;

	// find exportfs that matches f_mntonname
	lck_rw_lock_shared(&nfs_export_rwlock);
	ptr = vnode_mount(vp)->mnt_vfsstat.f_mntonname;
	LIST_FOREACH(nxfs, &nfs_exports, nxfs_next) {
		if (!strcmp(nxfs->nxfs_path, ptr))
			break;
	}
	if (!nxfs || strncmp(nxfs->nxfs_path, path, strlen(nxfs->nxfs_path))) {
		error = EINVAL;
		goto out;
	}
	// find export that best matches remainder of path
	ptr = path + strlen(nxfs->nxfs_path);
	while (*ptr && (*ptr == '/'))
		ptr++;
	LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
		int len = strlen(nx->nx_path);
		if (len == 0)  // we've hit the export entry for the root directory
			break;
		if (!strncmp(nx->nx_path, ptr, len))
			break;
	}
	if (!nx) {
		error = EINVAL;
		goto out;
	}

	bzero(&nfh, sizeof(nfh));
	nfh.nfh_xh.nxh_version = NFS_FH_VERSION;
	nfh.nfh_xh.nxh_fsid = nxfs->nxfs_id;
	nfh.nfh_xh.nxh_expid = nx->nx_id;
	nfh.nfh_xh.nxh_flags = 0;
	nfh.nfh_xh.nxh_reserved = 0;
	nfh.nfh_len = NFS_MAX_FID_SIZE;
	error = VFS_VPTOFH(vp, &nfh.nfh_len, &nfh.nfh_fid[0], NULL);
	if (nfh.nfh_len > (int)NFS_MAX_FID_SIZE)
		error = EOVERFLOW;
	nfh.nfh_xh.nxh_fidlen = nfh.nfh_len;
	nfh.nfh_len += sizeof(nfh.nfh_xh);

out:
	lck_rw_done(&nfs_export_rwlock);
	vnode_put(vp);
	if (error)
		return (error);
	error = copyout((caddr_t)&nfh, uap->fhp, sizeof(nfh));
	return (error);
}

#endif /* NFS_NOSERVER */

extern struct fileops vnops;

/*
 * syscall for the rpc.lockd to use to translate a NFS file handle into
 * an open descriptor.
 *
 * warning: do not remove the suser() call or this becomes one giant
 * security hole.
 */
int
fhopen( proc_t p,
	struct fhopen_args *uap,
	register_t *retval)
{
	vnode_t vp;
	struct nfs_filehandle nfh;
	struct nfs_export *nx;
	struct nfs_export_options *nxo;
	struct flock lf;
	struct fileproc *fp, *nfp;
	int fmode, error, type;
	int indx;
	kauth_cred_t cred = proc_ucred(p);
	struct vfs_context context;
	kauth_action_t action;

	context.vc_proc = p;
	context.vc_ucred = cred;

	/*
	 * Must be super user
	 */
	error = suser(cred, 0);
	if (error)
		return (error);

	fmode = FFLAGS(uap->flags);
	/* why not allow a non-read/write open for our lockd? */
	if (((fmode & (FREAD | FWRITE)) == 0) || (fmode & O_CREAT))
		return (EINVAL);

	error = copyin(uap->u_fhp, &nfh.nfh_len, sizeof(nfh.nfh_len));
	if (error)
		return (error);
	if ((nfh.nfh_len < (int)sizeof(struct nfs_exphandle)) ||
	    (nfh.nfh_len > (int)NFS_MAX_FH_SIZE))
		return (EINVAL);
	error = copyin(uap->u_fhp, &nfh, sizeof(nfh.nfh_len) + nfh.nfh_len);
	if (error)
		return (error);

	lck_rw_lock_shared(&nfs_export_rwlock);
	/* now give me my vnode, it gets returned to me with a reference */
	error = nfsrv_fhtovp(&nfh, NULL, TRUE, &vp, &nx, &nxo);
	lck_rw_done(&nfs_export_rwlock);
	if (error)
		return (error);

	/*
	 * From now on we have to make sure not
	 * to forget about the vnode.
	 * Any error that causes an abort must vnode_put(vp).
	 * Just set error = err and 'goto bad;'.
	 */

	/*
	 * from vn_open  
	 */      
	if (vnode_vtype(vp) == VSOCK) {
		error = EOPNOTSUPP;
		goto bad;      
	}

	/* disallow write operations on directories */
	if (vnode_isdir(vp) && (fmode & (FWRITE | O_TRUNC))) {
		error = EISDIR;
		goto bad;
	}

	/* compute action to be authorized */
	action = 0;
	if (fmode & FREAD)
		action |= KAUTH_VNODE_READ_DATA;
	if (fmode & (FWRITE | O_TRUNC))
		action |= KAUTH_VNODE_WRITE_DATA;
	if ((error = vnode_authorize(vp, NULL, action, &context)) != 0)
		goto bad;

	if ((error = VNOP_OPEN(vp, fmode, &context)))
		goto bad;
	if ((error = vnode_ref_ext(vp, fmode)))
		goto bad;

	/*
	 * end of vn_open code
	 */

	// starting here... error paths should call vn_close/vnode_put
	if ((error = falloc(p, &nfp, &indx)) != 0) {
		vn_close(vp, fmode & FMASK, cred, p);
		goto bad;
	}
	fp = nfp;

	fp->f_fglob->fg_flag = fmode & FMASK;
	fp->f_fglob->fg_type = DTYPE_VNODE;
	fp->f_fglob->fg_ops = &vnops;
	fp->f_fglob->fg_data = (caddr_t)vp;

	// XXX do we really need to support this with fhopen()?
	if (fmode & (O_EXLOCK | O_SHLOCK)) {
		lf.l_whence = SEEK_SET;
		lf.l_start = 0;
		lf.l_len = 0;
		if (fmode & O_EXLOCK)
			lf.l_type = F_WRLCK;
		else
			lf.l_type = F_RDLCK;
		type = F_FLOCK;
		if ((fmode & FNONBLOCK) == 0)
			type |= F_WAIT;
		if ((error = VNOP_ADVLOCK(vp, (caddr_t)fp->f_fglob, F_SETLK, &lf, type, &context))) {
			vn_close(vp, fp->f_fglob->fg_flag, fp->f_fglob->fg_cred, p);
			fp_free(p, indx, fp);
			return (error);
		}
		fp->f_fglob->fg_flag |= FHASLOCK;
	}

	vnode_put(vp);

	proc_fdlock(p);
	procfdtbl_releasefd(p, indx, NULL);
	fp_drop(p, indx, fp, 1);
	proc_fdunlock(p);

	*retval = indx;
	return (0);

bad:
	vnode_put(vp);
	return (error);
}

/*
 * Nfs server psuedo system call for the nfsd's
 * Based on the flag value it either:
 * - adds a socket to the selection list
 * - remains in the kernel as an nfsd
 * - remains in the kernel as an nfsiod
 */
int
nfssvc(proc_t p, struct nfssvc_args *uap, __unused int *retval)
{
#ifndef NFS_NOSERVER
	struct nameidata nd;
	mbuf_t nam;
	struct user_nfsd_args user_nfsdarg;
	struct nfsd_srvargs nfsd_srvargs, *nsd = &nfsd_srvargs;
	struct nfsd_cargs ncd;
	struct nfsd *nfsd;
	struct nfssvc_sock *slp;
	struct nfsuid *nuidp;
	struct nfsmount *nmp;
	struct timeval now;
	socket_t so;
	struct vfs_context context;
	struct ucred temp_cred;
#endif /* NFS_NOSERVER */
	int error;

	AUDIT_ARG(cmd, uap->flag);

	/*
	 * Must be super user
	 */
	error = proc_suser(p);
	if(error)
		return (error);
	if (uap->flag & NFSSVC_BIOD)
		error = nfssvc_iod(p);
#ifdef NFS_NOSERVER
	else
		error = ENXIO;
#else /* !NFS_NOSERVER */
	else if (uap->flag & NFSSVC_MNTD) {

		context.vc_proc = p;
		context.vc_ucred = kauth_cred_get();

		error = copyin(uap->argp, (caddr_t)&ncd, sizeof (ncd));
		if (error)
			return (error);

		NDINIT(&nd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1, 
			(proc_is64bit(p) ? UIO_USERSPACE64 : UIO_USERSPACE32),
			CAST_USER_ADDR_T(ncd.ncd_dirp), &context);
		error = namei(&nd);
		if (error)
			return (error);
		nameidone(&nd);

		if (vnode_isvroot(nd.ni_vp) == 0)
			error = EINVAL;
		nmp = VFSTONFS(vnode_mount(nd.ni_vp));
		vnode_put(nd.ni_vp);
		if (error)
			return (error);

		if ((nmp->nm_state & NFSSTA_MNTD) &&
			(uap->flag & NFSSVC_GOTAUTH) == 0)
			return (0);
		nmp->nm_state |= NFSSTA_MNTD;
		error = nfskerb_clientd(nmp, &ncd, uap->flag, uap->argp, p);
	} else if (uap->flag & NFSSVC_ADDSOCK) {
		if (IS_64BIT_PROCESS(p)) {
			error = copyin(uap->argp, (caddr_t)&user_nfsdarg, sizeof(user_nfsdarg));
		} else {
			struct nfsd_args    tmp_args;
			error = copyin(uap->argp, (caddr_t)&tmp_args, sizeof(tmp_args));
			if (error == 0) {
				user_nfsdarg.sock = tmp_args.sock;
				user_nfsdarg.name = CAST_USER_ADDR_T(tmp_args.name);
				user_nfsdarg.namelen = tmp_args.namelen;
			}
		}
		if (error)
			return (error);
		/* get the socket */
		error = file_socket(user_nfsdarg.sock, &so);
		if (error)
			return (error);
		/* Get the client address for connected sockets. */
		if (user_nfsdarg.name == USER_ADDR_NULL || user_nfsdarg.namelen == 0) {
			nam = NULL;
		} else {
			error = sockargs(&nam, user_nfsdarg.name, user_nfsdarg.namelen, MBUF_TYPE_SONAME);
			if (error) {
				/* drop the iocount file_socket() grabbed on the file descriptor */
				file_drop(user_nfsdarg.sock);
				return (error);
			}
		}
		/*
		 * nfssvc_addsock() will grab a retain count on the socket
		 * to keep the socket from being closed when nfsd closes its
		 * file descriptor for it.
		 */
		error = nfssvc_addsock(so, nam, p);
		/* drop the iocount file_socket() grabbed on the file descriptor */
		file_drop(user_nfsdarg.sock);
	} else if (uap->flag & NFSSVC_NFSD) {
		error = copyin(uap->argp, (caddr_t)nsd, sizeof (*nsd));
		if (error)
			return (error);

		if ((uap->flag & NFSSVC_AUTHIN) && ((nfsd = nsd->nsd_nfsd)) &&
			(nfsd->nfsd_slp->ns_flag & SLP_VALID)) {
			slp = nfsd->nfsd_slp;

			/*
			 * First check to see if another nfsd has already
			 * added this credential.
			 */
			for (nuidp = NUIDHASH(slp,nsd->nsd_cr.cr_uid)->lh_first;
			    nuidp != 0; nuidp = nuidp->nu_hash.le_next) {
				if (kauth_cred_getuid(nuidp->nu_cr) == nsd->nsd_cr.cr_uid &&
				    (!nfsd->nfsd_nd->nd_nam2 ||
				     netaddr_match(NU_NETFAM(nuidp),
				     &nuidp->nu_haddr, nfsd->nfsd_nd->nd_nam2)))
					break;
			}
			if (nuidp) {
			    nfsrv_setcred(nuidp->nu_cr,nfsd->nfsd_nd->nd_cr);
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
				if (nuidp) {
				    FREE_ZONE((caddr_t)nuidp,
					sizeof (struct nfsuid), M_NFSUID);
				    slp->ns_numuids--;
				}
			    } else {
				if (nuidp == (struct nfsuid *)0) {
				    nuidp = slp->ns_uidlruhead.tqh_first;
				    if (!nuidp)
					return (ENOMEM);
				    LIST_REMOVE(nuidp, nu_hash);
				    TAILQ_REMOVE(&slp->ns_uidlruhead, nuidp,
					nu_lru);
				    if (nuidp->nu_flag & NU_NAM)
					mbuf_freem(nuidp->nu_nam);
				    kauth_cred_rele(nuidp->nu_cr);
				}
				nuidp->nu_flag = 0;

				if (nsd->nsd_cr.cr_ngroups > NGROUPS)
				    nsd->nsd_cr.cr_ngroups = NGROUPS;

				nfsrv_setcred(&nsd->nsd_cr, &temp_cred);
				nuidp->nu_cr = kauth_cred_create(&temp_cred);

				if (!nuidp->nu_cr) {
					FREE_ZONE(nuidp, sizeof(struct nfsuid), M_NFSUID);
					slp->ns_numuids--;
					return (ENOMEM);
				}
				nuidp->nu_timestamp = nsd->nsd_timestamp;
				microtime(&now);
				nuidp->nu_expire = now.tv_sec + nsd->nsd_ttl;
				/*
				 * and save the session key in nu_key.
				 */
				bcopy(nsd->nsd_key, nuidp->nu_key,
				    sizeof (nsd->nsd_key));
				if (nfsd->nfsd_nd->nd_nam2) {
				    struct sockaddr_in *saddr;

				    saddr = mbuf_data(nfsd->nfsd_nd->nd_nam2);
				    switch (saddr->sin_family) {
				    case AF_INET:
					nuidp->nu_flag |= NU_INETADDR;
					nuidp->nu_inetaddr =
					     saddr->sin_addr.s_addr;
					break;
				    case AF_ISO:
				    default:
					nuidp->nu_flag |= NU_NAM;
					error = mbuf_copym(nfsd->nfsd_nd->nd_nam2, 0,
							MBUF_COPYALL, MBUF_WAITOK,
							&nuidp->nu_nam);
					if (error) {
						kauth_cred_rele(nuidp->nu_cr);
						FREE_ZONE(nuidp, sizeof(struct nfsuid), M_NFSUID);
						slp->ns_numuids--;
						return (error);
					}
					break;
				    };
				}
				TAILQ_INSERT_TAIL(&slp->ns_uidlruhead, nuidp,
					nu_lru);
				LIST_INSERT_HEAD(NUIDHASH(slp, nsd->nsd_uid),
					nuidp, nu_hash);
				nfsrv_setcred(nuidp->nu_cr,
				    nfsd->nfsd_nd->nd_cr);
				nfsd->nfsd_nd->nd_flag |= ND_KERBFULL;
			    }
			}
		}
		if ((uap->flag & NFSSVC_AUTHINFAIL) && (nfsd = nsd->nsd_nfsd))
			nfsd->nfsd_flag |= NFSD_AUTHFAIL;
		error = nfssvc_nfsd(nsd, uap->argp, p);
	} else if (uap->flag & NFSSVC_EXPORT) {
		error = nfssvc_export(uap->argp, p);
	} else {
		error = EINVAL;
	}
#endif /* NFS_NOSERVER */
	if (error == EINTR || error == ERESTART)
		error = 0;
	return (error);
}

/*
 * NFSKERB client helper daemon.
 * Gets authorization strings for "kerb" mounts.
 */
static int
nfskerb_clientd(
	struct nfsmount *nmp,
	struct nfsd_cargs *ncd,
	int flag,
	user_addr_t argp,
	proc_t p)
{
	struct nfsuid *nuidp, *nnuidp;
	int error = 0;
	struct nfsreq *rp;
	struct timeval now;

	/*
	 * First initialize some variables
	 */
	microtime(&now);

	/*
	 * If an authorization string is being passed in, get it.
	 */
	if ((flag & NFSSVC_GOTAUTH) && (nmp->nm_state & NFSSTA_MOUNTED) &&
	    ((nmp->nm_state & NFSSTA_WAITAUTH) == 0)) {
	    if (nmp->nm_state & NFSSTA_HASAUTH)
		panic("cld kerb");
	    if ((flag & NFSSVC_AUTHINFAIL) == 0) {
		if (ncd->ncd_authlen <= nmp->nm_authlen &&
		    ncd->ncd_verflen <= nmp->nm_verflen &&
		    !copyin(CAST_USER_ADDR_T(ncd->ncd_authstr),nmp->nm_authstr,ncd->ncd_authlen)&&
		    !copyin(CAST_USER_ADDR_T(ncd->ncd_verfstr),nmp->nm_verfstr,ncd->ncd_verflen)){
		    nmp->nm_authtype = ncd->ncd_authtype;
		    nmp->nm_authlen = ncd->ncd_authlen;
		    nmp->nm_verflen = ncd->ncd_verflen;
#if NFSKERB
		    nmp->nm_key = ncd->ncd_key;
#endif
		} else
		    nmp->nm_state |= NFSSTA_AUTHERR;
	    } else
		nmp->nm_state |= NFSSTA_AUTHERR;
	    nmp->nm_state |= NFSSTA_HASAUTH;
	    wakeup((caddr_t)&nmp->nm_authlen);
	} else {
	    nmp->nm_state |= NFSSTA_WAITAUTH;
	}

	/*
	 * Loop every second updating queue until there is a termination sig.
	 */
	while (nmp->nm_state & NFSSTA_MOUNTED) {
	    /* Get an authorization string, if required. */
	    if ((nmp->nm_state & (NFSSTA_WAITAUTH | NFSSTA_HASAUTH)) == 0) {
		ncd->ncd_authuid = nmp->nm_authuid;
		if (copyout((caddr_t)ncd, argp, sizeof (struct nfsd_cargs)))
			nmp->nm_state |= NFSSTA_WAITAUTH;
		else
			return (ENEEDAUTH);
	    }
	    /* Wait a bit (no pun) and do it again. */
	    if ((nmp->nm_state & NFSSTA_MOUNTED) &&
		(nmp->nm_state & (NFSSTA_WAITAUTH | NFSSTA_HASAUTH))) {
		    error = tsleep((caddr_t)&nmp->nm_authstr, PSOCK | PCATCH,
			"nfskrbtimr", hz / 3);
		    if (error == EINTR || error == ERESTART)
				dounmount(nmp->nm_mountp, 0, 0, p);
	    }
	}

	/*
	 * Finally, we can free up the mount structure.
	 */
	for (nuidp = nmp->nm_uidlruhead.tqh_first; nuidp != 0; nuidp = nnuidp) {
		nnuidp = nuidp->nu_lru.tqe_next;
		LIST_REMOVE(nuidp, nu_hash);
		TAILQ_REMOVE(&nmp->nm_uidlruhead, nuidp, nu_lru);
		kauth_cred_rele(nuidp->nu_cr);
		FREE_ZONE((caddr_t)nuidp, sizeof (struct nfsuid), M_NFSUID);
	}
	/*
	 * Loop through outstanding request list and remove dangling
	 * references to defunct nfsmount struct
	 */
	for (rp = nfs_reqq.tqh_first; rp; rp = rp->r_chain.tqe_next)
		if (rp->r_nmp == nmp)
			rp->r_nmp = (struct nfsmount *)0;
	/* Need to wake up any rcvlock waiters so they notice the unmount. */
	if (nmp->nm_state & NFSSTA_WANTRCV) {
		nmp->nm_state &= ~NFSSTA_WANTRCV;
		wakeup(&nmp->nm_state);
	}
	FREE_ZONE((caddr_t)nmp, sizeof (struct nfsmount), M_NFSMNT);
	if (error == EWOULDBLOCK)
		error = 0;
	return (error);
}

#ifndef NFS_NOSERVER
/*
 * Adds a socket to the list for servicing by nfsds.
 */
static int
nfssvc_addsock(
	socket_t so,
	mbuf_t mynam,
	__unused proc_t p)
{
	int siz;
	struct nfssvc_sock *slp;
	struct nfssvc_sock *tslp = NULL;
	int error, sodomain, sotype, soprotocol, on = 1;
	struct timeval timeo;

	/* make sure mbuf constants are set up */
	if (!nfs_mbuf_mlen)
		nfs_mbuf_init();

	sock_gettype(so, &sodomain, &sotype, &soprotocol);

	/*
	 * Add it to the list, as required.
	 */
	if (soprotocol == IPPROTO_UDP) {
		tslp = nfs_udpsock;
		if (!tslp || (tslp->ns_flag & SLP_VALID)) {
			mbuf_freem(mynam);
			return (EPERM);
		}
#if ISO
	} else if (soprotocol == ISOPROTO_CLTP) {
		tslp = nfs_cltpsock;
		if (!tslp || (tslp->ns_flag & SLP_VALID)) {
			mbuf_freem(mynam);
			return (EPERM);
		}
#endif /* ISO */
	}
	/* reserve buffer space for 2 maximally-sized packets */
	siz = NFS_MAXPACKET;
	if (sotype == SOCK_STREAM)
		siz += sizeof (u_long);
	siz *= 2;
	if (siz > NFS_MAXSOCKBUF)
		siz = NFS_MAXSOCKBUF;
	if ((error = sock_setsockopt(so, SOL_SOCKET, SO_SNDBUF, &siz, sizeof(siz))) ||
	    (error = sock_setsockopt(so, SOL_SOCKET, SO_RCVBUF, &siz, sizeof(siz)))) {
		mbuf_freem(mynam);
		return (error);
	}

	/*
	 * Set protocol specific options { for now TCP only } and
	 * reserve some space. For datagram sockets, this can get called
	 * repeatedly for the same socket, but that isn't harmful.
	 */
	if (sotype == SOCK_STREAM) {
		sock_setsockopt(so, SOL_SOCKET, SO_KEEPALIVE, &on, sizeof(on));
	}
	if (sodomain == AF_INET && soprotocol == IPPROTO_TCP) {
		sock_setsockopt(so, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on));
	}

	sock_nointerrupt(so, 0);

	timeo.tv_usec = 0;
	timeo.tv_sec = 0;
	error = sock_setsockopt(so, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo));
	error = sock_setsockopt(so, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo));

	if (tslp) {
		slp = tslp;
		lck_mtx_lock(nfsd_mutex);
	} else {
		MALLOC(slp, struct nfssvc_sock *, sizeof(struct nfssvc_sock),
				M_NFSSVC, M_WAITOK);
		if (!slp) {
			mbuf_freem(mynam);
			return (ENOMEM);
		}
		bzero((caddr_t)slp, sizeof (struct nfssvc_sock));
		lck_rw_init(&slp->ns_rwlock, nfs_slp_rwlock_group, nfs_slp_lock_attr);
		lck_mtx_init(&slp->ns_wgmutex, nfs_slp_mutex_group, nfs_slp_lock_attr);
		TAILQ_INIT(&slp->ns_uidlruhead);
		lck_mtx_lock(nfsd_mutex);
		TAILQ_INSERT_TAIL(&nfssvc_sockhead, slp, ns_chain);
	}

	sock_retain(so); /* grab a retain count on the socket */
	slp->ns_so = so;
	slp->ns_sotype = sotype;
	slp->ns_nam = mynam;

	socket_lock(so, 1);
	so->so_upcallarg = (caddr_t)slp;
	so->so_upcall = nfsrv_rcv;
	so->so_rcv.sb_flags |= SB_UPCALL; /* required for freebsd merge */
	socket_unlock(so, 1);

	slp->ns_flag = SLP_VALID | SLP_NEEDQ;

	nfsrv_wakenfsd(slp);
	lck_mtx_unlock(nfsd_mutex);

	return (0);
}

/*
 * Called by nfssvc() for nfsds. Just loops around servicing rpc requests
 * until it is killed by a signal.
 */
static int
nfssvc_nfsd(nsd, argp, p)
	struct nfsd_srvargs *nsd;
	user_addr_t argp;
	proc_t p;
{
	mbuf_t m, mreq;
	struct nfssvc_sock *slp;
	struct nfsd *nfsd = nsd->nsd_nfsd;
	struct nfsrv_descript *nd = NULL;
	int error = 0, cacherep, writes_todo;
	int siz, procrastinate;
	u_quad_t cur_usec;
	struct timeval now;
	boolean_t funnel_state;

#ifndef nolint
	cacherep = RC_DOIT;
	writes_todo = 0;
#endif
	if (nfsd == (struct nfsd *)0) {
		MALLOC(nfsd, struct nfsd *, sizeof(struct nfsd), M_NFSD, M_WAITOK);
		if (!nfsd)
			return (ENOMEM);
		nsd->nsd_nfsd = nfsd;
		bzero((caddr_t)nfsd, sizeof (struct nfsd));
		nfsd->nfsd_procp = p;
		lck_mtx_lock(nfsd_mutex);
		TAILQ_INSERT_TAIL(&nfsd_head, nfsd, nfsd_chain);
		nfs_numnfsd++;
		lck_mtx_unlock(nfsd_mutex);
	}

	funnel_state = thread_funnel_set(kernel_flock, FALSE);

	/*
	 * Loop getting rpc requests until SIGKILL.
	 */
	for (;;) {
		if ((nfsd->nfsd_flag & NFSD_REQINPROG) == 0) {
			lck_mtx_lock(nfsd_mutex);
			while ((nfsd->nfsd_slp == NULL) && !(nfsd_head_flag & NFSD_CHECKSLP)) {
				nfsd->nfsd_flag |= NFSD_WAITING;
				nfsd_waiting++;
				error = msleep(nfsd, nfsd_mutex, PSOCK | PCATCH, "nfsd", 0);
				nfsd_waiting--;
				if (error) {
					lck_mtx_unlock(nfsd_mutex);
					goto done;
				}
			}
			if ((nfsd->nfsd_slp == NULL) && (nfsd_head_flag & NFSD_CHECKSLP)) {
				TAILQ_FOREACH(slp, &nfssvc_sockhead, ns_chain) {
				    lck_rw_lock_shared(&slp->ns_rwlock);
				    if ((slp->ns_flag & (SLP_VALID | SLP_DOREC))
					== (SLP_VALID | SLP_DOREC)) {
					    if (lck_rw_lock_shared_to_exclusive(&slp->ns_rwlock)) {
						/* upgrade failed and we lost the lock; take exclusive and recheck */
						lck_rw_lock_exclusive(&slp->ns_rwlock);
						if ((slp->ns_flag & (SLP_VALID | SLP_DOREC))
						    != (SLP_VALID | SLP_DOREC)) {
						    /* flags no longer set, so skip this socket */
						    lck_rw_done(&slp->ns_rwlock);
						    continue;
						}
					    }
					    slp->ns_flag &= ~SLP_DOREC;
					    slp->ns_sref++;
					    nfsd->nfsd_slp = slp;
					    lck_rw_done(&slp->ns_rwlock);
					    break;
				    }
				    lck_rw_done(&slp->ns_rwlock);
				}
				if (slp == 0)
					nfsd_head_flag &= ~NFSD_CHECKSLP;
			}
			lck_mtx_unlock(nfsd_mutex);
			if ((slp = nfsd->nfsd_slp) == NULL)
				continue;
			lck_rw_lock_exclusive(&slp->ns_rwlock);
			if (slp->ns_flag & SLP_VALID) {
				if ((slp->ns_flag & (SLP_NEEDQ|SLP_DISCONN)) == SLP_NEEDQ) {
					slp->ns_flag &= ~SLP_NEEDQ;
					nfsrv_rcv_locked(slp->ns_so, slp, MBUF_WAITOK);
				}
				if (slp->ns_flag & SLP_DISCONN)
					nfsrv_zapsock(slp);
				error = nfsrv_dorec(slp, nfsd, &nd);
				microuptime(&now);
				cur_usec = (u_quad_t)now.tv_sec * 1000000 +
					(u_quad_t)now.tv_usec;
				if (error && slp->ns_wgtime && (slp->ns_wgtime <= cur_usec)) {
					error = 0;
					cacherep = RC_DOIT;
					writes_todo = 1;
				} else
					writes_todo = 0;
				nfsd->nfsd_flag |= NFSD_REQINPROG;
			}
			lck_rw_done(&slp->ns_rwlock);
		} else {
			error = 0;
			slp = nfsd->nfsd_slp;
		}
		if (error || (slp->ns_flag & SLP_VALID) == 0) {
			if (nd) {
				if (nd->nd_mrep)
					mbuf_freem(nd->nd_mrep);
				if (nd->nd_nam2)
					mbuf_freem(nd->nd_nam2);
				if (nd->nd_cr)
					kauth_cred_rele(nd->nd_cr);
				FREE_ZONE((caddr_t)nd,
						sizeof *nd, M_NFSRVDESC);
				nd = NULL;
			}
			nfsd->nfsd_slp = NULL;
			nfsd->nfsd_flag &= ~NFSD_REQINPROG;
			nfsrv_slpderef(slp);
			continue;
		}
		if (nd) {
		    microuptime(&nd->nd_starttime);
		    if (nd->nd_nam2)
			nd->nd_nam = nd->nd_nam2;
		    else
			nd->nd_nam = slp->ns_nam;

		    /*
		     * Check to see if authorization is needed.
		     */
		    if (nfsd->nfsd_flag & NFSD_NEEDAUTH) {
			nfsd->nfsd_flag &= ~NFSD_NEEDAUTH;
			nsd->nsd_haddr = ((struct sockaddr_in *)mbuf_data(nd->nd_nam))->sin_addr.s_addr;
			nsd->nsd_authlen = nfsd->nfsd_authlen;
			nsd->nsd_verflen = nfsd->nfsd_verflen;
			if (!copyout(nfsd->nfsd_authstr,CAST_USER_ADDR_T(nsd->nsd_authstr),
				nfsd->nfsd_authlen) &&
			    !copyout(nfsd->nfsd_verfstr, CAST_USER_ADDR_T(nsd->nsd_verfstr),
				nfsd->nfsd_verflen) &&
			    !copyout((caddr_t)nsd, argp, sizeof (*nsd))) {
			    thread_funnel_set(kernel_flock, funnel_state);
			    return (ENEEDAUTH);
			}
			cacherep = RC_DROPIT;
		    } else
			cacherep = nfsrv_getcache(nd, slp, &mreq);

		    if (nfsd->nfsd_flag & NFSD_AUTHFAIL) {
			nfsd->nfsd_flag &= ~NFSD_AUTHFAIL;
			nd->nd_procnum = NFSPROC_NOOP;
			nd->nd_repstat = (NFSERR_AUTHERR | AUTH_TOOWEAK);
			cacherep = RC_DOIT;
		    } else if (nfs_privport) {
			/* Check if source port is privileged */
			u_short port;
			struct sockaddr *nam = mbuf_data(nd->nd_nam);
			struct sockaddr_in *sin;

			sin = (struct sockaddr_in *)nam;
			port = ntohs(sin->sin_port);
			if (port >= IPPORT_RESERVED && 
			    nd->nd_procnum != NFSPROC_NULL) {
			    char strbuf[MAX_IPv4_STR_LEN];
			    nd->nd_procnum = NFSPROC_NOOP;
			    nd->nd_repstat = (NFSERR_AUTHERR | AUTH_TOOWEAK);
			    cacherep = RC_DOIT;
			    printf("NFS request from unprivileged port (%s:%d)\n",
			    	inet_ntop(AF_INET, &sin->sin_addr, strbuf, sizeof(strbuf)),
			    	port);
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
			lck_rw_lock_shared(&nfs_export_rwlock);
			if (writes_todo || ((nd->nd_procnum == NFSPROC_WRITE) && (procrastinate > 0)))
			    error = nfsrv_writegather(&nd, slp, nfsd->nfsd_procp, &mreq);
			else {
			    error = (*(nfsrv3_procs[nd->nd_procnum]))(nd, slp, nfsd->nfsd_procp, &mreq);
			    if (mreq == NULL)
			    	nd->nd_mrep = NULL;
			}
			lck_rw_done(&nfs_export_rwlock);
			if (mreq == NULL)
				break;
			if (error) {
				OSAddAtomic(1, (SInt32*)&nfsstats.srv_errs);
				nfsrv_updatecache(nd, FALSE, mreq);
				if (nd->nd_nam2) {
					mbuf_freem(nd->nd_nam2);
					nd->nd_nam2 = NULL;
				}
				nd->nd_mrep = NULL;
				break;
			}
			OSAddAtomic(1, (SInt32*)&nfsstats.srvrpccnt[nd->nd_procnum]);
			nfsrv_updatecache(nd, TRUE, mreq);
			nd->nd_mrep = NULL;
		    case RC_REPLY:
			m = mreq;
			siz = 0;
			while (m) {
				siz += mbuf_len(m);
				m = mbuf_next(m);
			}
			if (siz <= 0 || siz > NFS_MAXPACKET) {
				printf("mbuf siz=%d\n",siz);
				panic("Bad nfs svc reply");
			}
			m = mreq;
			mbuf_pkthdr_setlen(m, siz);
			error = mbuf_pkthdr_setrcvif(m, NULL);
			if (error)
				panic("nfsd setrcvif failed: %d", error);
			/*
			 * For stream protocols, prepend a Sun RPC
			 * Record Mark.
			 */
			if (slp->ns_sotype == SOCK_STREAM) {
				error = mbuf_prepend(&m, NFSX_UNSIGNED, MBUF_WAITOK);
				if (!error)
					*(u_long*)mbuf_data(m) = htonl(0x80000000 | siz);
			}
			if (!error) {
				if (slp->ns_flag & SLP_VALID) {
				    error = nfs_send(slp->ns_so, nd->nd_nam2, m, NULL);
				} else {
				    error = EPIPE;
				    mbuf_freem(m);
				}
			} else {
				mbuf_freem(m);
			}
			mreq = NULL;
			if (nfsrtton)
				nfsd_rt(slp->ns_sotype, nd, cacherep);
			if (nd->nd_nam2) {
				mbuf_freem(nd->nd_nam2);
				nd->nd_nam2 = NULL;
			}
			if (nd->nd_mrep) {
				mbuf_freem(nd->nd_mrep);
				nd->nd_mrep = NULL;
			}
			if (error == EPIPE) {
				lck_rw_lock_exclusive(&slp->ns_rwlock);
				nfsrv_zapsock(slp);
				lck_rw_done(&slp->ns_rwlock);
			}
			if (error == EINTR || error == ERESTART) {
				if (nd->nd_cr)
					kauth_cred_rele(nd->nd_cr);
				FREE_ZONE((caddr_t)nd, sizeof *nd, M_NFSRVDESC);
				nfsrv_slpderef(slp);
				goto done;
			}
			break;
		    case RC_DROPIT:
			if (nfsrtton)
				nfsd_rt(slp->ns_sotype, nd, cacherep);
			mbuf_freem(nd->nd_mrep);
			mbuf_freem(nd->nd_nam2);
			nd->nd_mrep = nd->nd_nam2 = NULL;
			break;
		    };
		    if (nd) {
			if (nd->nd_mrep)
				mbuf_freem(nd->nd_mrep);
			if (nd->nd_nam2)
				mbuf_freem(nd->nd_nam2);
			if (nd->nd_cr)
				kauth_cred_rele(nd->nd_cr);
			FREE_ZONE((caddr_t)nd, sizeof *nd, M_NFSRVDESC);
			nd = NULL;
		    }

		    /*
		     * Check to see if there are outstanding writes that
		     * need to be serviced.
		     */
		    microuptime(&now);
		    cur_usec = (u_quad_t)now.tv_sec * 1000000 +
			(u_quad_t)now.tv_usec;
		    if (slp->ns_wgtime && (slp->ns_wgtime <= cur_usec)) {
			cacherep = RC_DOIT;
			writes_todo = 1;
		    } else {
			writes_todo = 0;
		    }
		} while (writes_todo);
		lck_rw_lock_exclusive(&slp->ns_rwlock);
		if (nfsrv_dorec(slp, nfsd, &nd)) {
			lck_rw_done(&slp->ns_rwlock);
			nfsd->nfsd_flag &= ~NFSD_REQINPROG;
			nfsd->nfsd_slp = NULL;
			nfsrv_slpderef(slp);
		} else {
			lck_rw_done(&slp->ns_rwlock);
		}
	}
done:
	thread_funnel_set(kernel_flock, funnel_state);
	lck_mtx_lock(nfsd_mutex);
	TAILQ_REMOVE(&nfsd_head, nfsd, nfsd_chain);
	FREE(nfsd, M_NFSD);
	nsd->nsd_nfsd = (struct nfsd *)0;
	if (--nfs_numnfsd == 0)
		nfsrv_init(TRUE);	/* Reinitialize everything */
	lck_mtx_unlock(nfsd_mutex);
	return (error);
}

static int
nfssvc_export(user_addr_t argp, proc_t p)
{
	int error = 0, is_64bit;
	struct user_nfs_export_args unxa;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_get();
	is_64bit = IS_64BIT_PROCESS(p);

	/* copy in pointers to path and export args */
	if (is_64bit) {
		error = copyin(argp, (caddr_t)&unxa, sizeof(unxa));
	} else {
		struct nfs_export_args tnxa;
		error = copyin(argp, (caddr_t)&tnxa, sizeof(tnxa));
		if (error == 0) {
			/* munge into LP64 version of nfs_export_args structure */
			unxa.nxa_fsid = tnxa.nxa_fsid;
			unxa.nxa_expid = tnxa.nxa_expid;
			unxa.nxa_fspath = CAST_USER_ADDR_T(tnxa.nxa_fspath);
			unxa.nxa_exppath = CAST_USER_ADDR_T(tnxa.nxa_exppath);
			unxa.nxa_flags = tnxa.nxa_flags;
			unxa.nxa_netcount = tnxa.nxa_netcount;
			unxa.nxa_nets = CAST_USER_ADDR_T(tnxa.nxa_nets);
		}
	}
	if (error)
		return (error);

	error = nfsrv_export(&unxa, &context);

	return (error);
}

#endif /* NFS_NOSERVER */

int nfs_defect = 0;
/* XXX CSM 11/25/97 Upgrade sysctl.h someday */
#ifdef notyet
SYSCTL_INT(_vfs_nfs, OID_AUTO, defect, CTLFLAG_RW, &nfs_defect, 0, "");
#endif

int
nfsclnt(proc_t p, struct nfsclnt_args *uap, __unused int *retval)
{
	struct lockd_ans la;
	int error;

	if (uap->flag == NFSCLNT_LOCKDWAIT) {
		return (nfslockdwait(p));
	}
	if (uap->flag == NFSCLNT_LOCKDANS) {
		error = copyin(uap->argp, &la, sizeof(la));
		return (error != 0 ? error : nfslockdans(p, &la));
	}
	if (uap->flag == NFSCLNT_LOCKDFD)
		return (nfslockdfd(p, CAST_DOWN(int, uap->argp)));
	return EINVAL;
}


static int nfssvc_iod_continue(int);

/*
 * Asynchronous I/O daemons for client nfs.
 * They do read-ahead and write-behind operations on the block I/O cache.
 * Never returns unless it fails or gets killed.
 */
static int
nfssvc_iod(__unused proc_t p)
{
	register int i, myiod;
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

	/* stuff myiod into uthread to get off local stack for continuation */

	ut = (struct uthread *)get_bsdthread_info(current_thread());
	ut->uu_state.uu_nfs_myiod = myiod;  /* squirrel away for continuation */

	nfssvc_iod_continue(0);
	/* NOTREACHED */
	return (0);
}

/*
 * Continuation for Asynchronous I/O daemons for client nfs.
 */
static int
nfssvc_iod_continue(int error)
{
	register struct nfsbuf *bp;
	register int i, myiod;
	struct nfsmount *nmp;
	struct uthread *ut;
	proc_t p;
	int exiterror = 0;

	/*
	 * real myiod is stored in uthread, recover it
	 */
	ut = (struct uthread *)get_bsdthread_info(current_thread());
	myiod = ut->uu_state.uu_nfs_myiod;
	p = current_proc(); // XXX

	/*
	 * Just loop around doin our stuff until SIGKILL
	 *  - actually we don't loop with continuations...
	 */
	lck_mtx_lock(nfs_iod_mutex);
	for (;;) {
	    while (((nmp = nfs_iodmount[myiod]) == NULL
		    || nmp->nm_bufq.tqh_first == NULL)
		   && error == 0 && nfs_ioddelwri == 0) {
		if (nmp)
		    nmp->nm_bufqiods--;
		nfs_iodwant[myiod] = p; // XXX this doesn't need to be a proc_t
		nfs_iodmount[myiod] = NULL;
		error = msleep0((caddr_t)&nfs_iodwant[myiod], nfs_iod_mutex,
			PWAIT | PCATCH | PDROP, "nfsidl", 0, nfssvc_iod_continue);
		lck_mtx_lock(nfs_iod_mutex);
	    }
	    if (error && !exiterror && nmp && (nmp->nm_bufqiods == 1) &&
	        !TAILQ_EMPTY(&nmp->nm_bufq)) {
		/*
		 * Finish processing the queued buffers before exitting.
		 * Decrement the iod count now to make sure nfs_asyncio()
		 * doesn't keep queueing up more work.
		 */
		nmp->nm_bufqiods--;
		exiterror = error;
		error = 0;
	    }
	    if (error) {
		nfs_asyncdaemon[myiod] = 0;
		if (nmp && !exiterror)
			nmp->nm_bufqiods--;
		nfs_iodwant[myiod] = NULL;
		nfs_iodmount[myiod] = NULL;
		lck_mtx_unlock(nfs_iod_mutex);
		nfs_numasync--;
		if (error == EINTR || error == ERESTART)
		  error = 0;
		unix_syscall_return(error);
	    }
	    if (nmp != NULL) {
		while ((bp = TAILQ_FIRST(&nmp->nm_bufq)) != NULL) {
		    /* Take one off the front of the list */
		    TAILQ_REMOVE(&nmp->nm_bufq, bp, nb_free);
		    bp->nb_free.tqe_next = NFSNOLIST;
		    nmp->nm_bufqlen--;
		    if (nmp->nm_bufqwant && nmp->nm_bufqlen < 2 * nfs_numasync) {
			nmp->nm_bufqwant = FALSE;
			lck_mtx_unlock(nfs_iod_mutex);
			wakeup(&nmp->nm_bufq);
		    } else {
			lck_mtx_unlock(nfs_iod_mutex);
		    }

		    SET(bp->nb_flags, NB_IOD);
		    if (ISSET(bp->nb_flags, NB_READ))
			nfs_doio(bp, bp->nb_rcred, NULL);
		    else
			nfs_doio(bp, bp->nb_wcred, NULL);

		    lck_mtx_lock(nfs_iod_mutex);
		    /*
		     * If there are more than one iod on this mount, then defect
		     * so that the iods can be shared out fairly between the mounts
		     */
		    if (!exiterror && nfs_defect && nmp->nm_bufqiods > 1) {
			nfs_iodmount[myiod] = NULL;
			nmp->nm_bufqiods--;
			break;
		    }
		}
	    }
	    lck_mtx_unlock(nfs_iod_mutex);

	    if (nfs_ioddelwri) {
		i = 0;
		nfs_ioddelwri = 0;
		lck_mtx_lock(nfs_buf_mutex);
		while (i < 8 && (bp = TAILQ_FIRST(&nfsbufdelwri)) != NULL) {
			struct nfsnode *np = VTONFS(bp->nb_vp);
			nfs_buf_remfree(bp);
			nfs_buf_refget(bp);
			while ((error = nfs_buf_acquire(bp, 0, 0, 0)) == EAGAIN);
			nfs_buf_refrele(bp);
			if (error)
				break;
			if (!bp->nb_vp) {
				/* buffer is no longer valid */
				nfs_buf_drop(bp);
				continue;
			}
			if (ISSET(bp->nb_flags, NB_NEEDCOMMIT))
				nfs_buf_check_write_verifier(np, bp);
			if (ISSET(bp->nb_flags, NB_NEEDCOMMIT)) {
				/* put buffer at end of delwri list */
				TAILQ_INSERT_TAIL(&nfsbufdelwri, bp, nb_free);
				nfsbufdelwricnt++;
				nfs_buf_drop(bp);
				lck_mtx_unlock(nfs_buf_mutex);
				nfs_flushcommits(np->n_vnode, NULL, 1);
			} else {
				SET(bp->nb_flags, (NB_ASYNC | NB_IOD));
				lck_mtx_unlock(nfs_buf_mutex);
				nfs_buf_write(bp);
			}
			i++;
			lck_mtx_lock(nfs_buf_mutex);
		}
		lck_mtx_unlock(nfs_buf_mutex);
	    }

	    lck_mtx_lock(nfs_iod_mutex);
	    if (exiterror)
	    	error = exiterror;
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
nfsrv_zapsock(struct nfssvc_sock *slp)
{
	socket_t so;

	if ((slp->ns_flag & SLP_VALID) == 0)
		return;
	slp->ns_flag &= ~SLP_ALLFLAGS;

	so = slp->ns_so;
	if (so == NULL)
		return;

	/*
	 * Attempt to deter future upcalls, but leave the
	 * upcall info in place to avoid a race with the
	 * networking code.
	 */
	socket_lock(so, 1);
	so->so_rcv.sb_flags &= ~SB_UPCALL;
	socket_unlock(so, 1);

	sock_shutdown(so, SHUT_RDWR);
}

/*
 * Get an authorization string for the uid by having the mount_nfs sitting
 * on this mount point porpous out of the kernel and do it.
 */
int
nfs_getauth(nmp, rep, cred, auth_str, auth_len, verf_str, verf_len, key)
	register struct nfsmount *nmp;
	struct nfsreq *rep;
	kauth_cred_t cred;
	char **auth_str;
	int *auth_len;
	char *verf_str;
	int *verf_len;
	NFSKERBKEY_T key;		/* return session key */
{
	int error = 0;

	while ((nmp->nm_state & NFSSTA_WAITAUTH) == 0) {
		nmp->nm_state |= NFSSTA_WANTAUTH;
		(void) tsleep((caddr_t)&nmp->nm_authtype, PSOCK,
			"nfsauth1", 2 * hz);
		error = nfs_sigintr(nmp, rep, rep->r_procp);
		if (error) {
			nmp->nm_state &= ~NFSSTA_WANTAUTH;
			return (error);
		}
	}
	nmp->nm_state &= ~NFSSTA_WANTAUTH;
	MALLOC(*auth_str, char *, RPCAUTH_MAXSIZ, M_TEMP, M_WAITOK);
	if (!*auth_str)
		return (ENOMEM);
	nmp->nm_authstr = *auth_str;
	nmp->nm_authlen = RPCAUTH_MAXSIZ;
	nmp->nm_verfstr = verf_str;
	nmp->nm_verflen = *verf_len;
	nmp->nm_authuid = kauth_cred_getuid(cred);
	nmp->nm_state &= ~NFSSTA_WAITAUTH;
	wakeup((caddr_t)&nmp->nm_authstr);

	/*
	 * And wait for mount_nfs to do its stuff.
	 */
	while ((nmp->nm_state & NFSSTA_HASAUTH) == 0 && error == 0) {
		(void) tsleep((caddr_t)&nmp->nm_authlen, PSOCK,
			"nfsauth2", 2 * hz);
		error = nfs_sigintr(nmp, rep, rep->r_procp);
	}
	if (nmp->nm_state & NFSSTA_AUTHERR) {
		nmp->nm_state &= ~NFSSTA_AUTHERR;
		error = EAUTH;
	}
	if (error)
		FREE(*auth_str, M_TEMP);
	else {
		*auth_len = nmp->nm_authlen;
		*verf_len = nmp->nm_verflen;
		bcopy((caddr_t)nmp->nm_key, (caddr_t)key, sizeof (key));
	}
	nmp->nm_state &= ~NFSSTA_HASAUTH;
	nmp->nm_state |= NFSSTA_WAITAUTH;
	if (nmp->nm_state & NFSSTA_WANTAUTH) {
		nmp->nm_state &= ~NFSSTA_WANTAUTH;
		wakeup((caddr_t)&nmp->nm_authtype);
	}
	return (error);
}

/*
 * Get a nickname authenticator and verifier.
 */
int
nfs_getnickauth(
	struct nfsmount *nmp,
	kauth_cred_t cred,
	char **auth_str,
	int *auth_len,
	char *verf_str,
	__unused int verf_len)
{
	register struct nfsuid *nuidp;
	register u_long *nickp, *verfp;
	struct timeval ktvin, ktvout, now;

#if DIAGNOSTIC
	if (verf_len < (4 * NFSX_UNSIGNED))
		panic("nfs_getnickauth verf too small");
#endif
	for (nuidp = NMUIDHASH(nmp, kauth_cred_getuid(cred))->lh_first;
	    nuidp != 0; nuidp = nuidp->nu_hash.le_next) {
		if (kauth_cred_getuid(nuidp->nu_cr) == kauth_cred_getuid(cred))
			break;
	}
	microtime(&now);
	if (!nuidp || nuidp->nu_expire < now.tv_sec)
		return (EACCES);

	MALLOC(nickp, u_long *, 2 * NFSX_UNSIGNED, M_TEMP, M_WAITOK);
	if (!nickp)
		return (ENOMEM);

	/*
	 * Move to the end of the lru list (end of lru == most recently used).
	 */
	TAILQ_REMOVE(&nmp->nm_uidlruhead, nuidp, nu_lru);
	TAILQ_INSERT_TAIL(&nmp->nm_uidlruhead, nuidp, nu_lru);

	*nickp++ = txdr_unsigned(RPCAKN_NICKNAME);
	*nickp = txdr_unsigned(nuidp->nu_nickname);
	*auth_str = (char *)nickp;
	*auth_len = 2 * NFSX_UNSIGNED;

	/*
	 * Now we must encrypt the verifier and package it up.
	 */
	verfp = (u_long *)verf_str;
	*verfp++ = txdr_unsigned(RPCAKN_NICKNAME);
	microtime(&now);
	if (now.tv_sec > nuidp->nu_timestamp.tv_sec ||
	    (now.tv_sec == nuidp->nu_timestamp.tv_sec &&
	     now.tv_usec > nuidp->nu_timestamp.tv_usec))
		nuidp->nu_timestamp = now;
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
	kauth_cred_t cred;
	int len;
	NFSKERBKEY_T key;
	mbuf_t *mdp;
	char **dposp;
	mbuf_t mrep;
{
	register struct nfsuid *nuidp;
	register u_long *tl;
	register long t1;
	mbuf_t md = *mdp;
	struct timeval ktvin, ktvout, now;
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
		microtime(&now);
		deltasec = now.tv_sec - ktvout.tv_sec;
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
				nuidp = NULL;
			}
			if (!nuidp) {
				nuidp = nmp->nm_uidlruhead.tqh_first;
				if (!nuidp) {
					error = ENOMEM;
					goto nfsmout;
				}
				LIST_REMOVE(nuidp, nu_hash);
				TAILQ_REMOVE(&nmp->nm_uidlruhead, nuidp, nu_lru);
				kauth_cred_rele(nuidp->nu_cr);
			}
			nuidp->nu_flag = 0;
			kauth_cred_ref(cred);
			nuidp->nu_cr = cred;
			nuidp->nu_expire = now.tv_sec + NFS_KERBTTL;
			nuidp->nu_timestamp = ktvout;
			nuidp->nu_nickname = nick;
			bcopy(key, nuidp->nu_key, sizeof (key));
			TAILQ_INSERT_TAIL(&nmp->nm_uidlruhead, nuidp, nu_lru);
			LIST_INSERT_HEAD(NMUIDHASH(nmp, kauth_cred_getuid(cred)),
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
 * cleanup and release a server socket structure.
 */
void
nfsrv_slpfree(struct nfssvc_sock *slp)
{
	struct nfsuid *nuidp, *nnuidp;
	struct nfsrv_descript *nwp, *nnwp;

	if (slp->ns_so) {
		sock_release(slp->ns_so);
		slp->ns_so = NULL;
	}
	if (slp->ns_nam)
		mbuf_free(slp->ns_nam);
	if (slp->ns_raw)
		mbuf_freem(slp->ns_raw);
	if (slp->ns_rec)
		mbuf_freem(slp->ns_rec);
	slp->ns_nam = slp->ns_raw = slp->ns_rec = NULL;

	for (nuidp = slp->ns_uidlruhead.tqh_first; nuidp != 0;
	    nuidp = nnuidp) {
		nnuidp = nuidp->nu_lru.tqe_next;
		LIST_REMOVE(nuidp, nu_hash);
		TAILQ_REMOVE(&slp->ns_uidlruhead, nuidp, nu_lru);
		if (nuidp->nu_flag & NU_NAM)
			mbuf_freem(nuidp->nu_nam);
		kauth_cred_rele(nuidp->nu_cr);
		FREE_ZONE((caddr_t)nuidp,
				sizeof (struct nfsuid), M_NFSUID);
	}

	for (nwp = slp->ns_tq.lh_first; nwp; nwp = nnwp) {
		nnwp = nwp->nd_tq.le_next;
		LIST_REMOVE(nwp, nd_tq);
		if (nwp->nd_cr)
			kauth_cred_rele(nwp->nd_cr);
		FREE_ZONE((caddr_t)nwp, sizeof *nwp, M_NFSRVDESC);
	}
	LIST_INIT(&slp->ns_tq);

	lck_rw_destroy(&slp->ns_rwlock, nfs_slp_rwlock_group);
	lck_mtx_destroy(&slp->ns_wgmutex, nfs_slp_mutex_group);
	FREE(slp, M_NFSSVC);
}

/*
 * Derefence a server socket structure. If it has no more references and
 * is no longer valid, you can throw it away.
 */
void
nfsrv_slpderef(struct nfssvc_sock *slp)
{
	struct timeval now;

	lck_mtx_lock(nfsd_mutex);
	lck_rw_lock_exclusive(&slp->ns_rwlock);
	slp->ns_sref--;
	if (slp->ns_sref || (slp->ns_flag & SLP_VALID)) {
		lck_rw_done(&slp->ns_rwlock);
		lck_mtx_unlock(nfsd_mutex);
		return;
	}

	/* queue the socket up for deletion */
	microuptime(&now);
	slp->ns_timestamp = now.tv_sec;
	TAILQ_REMOVE(&nfssvc_sockhead, slp, ns_chain);
	TAILQ_INSERT_TAIL(&nfssvc_deadsockhead, slp, ns_chain);
	lck_rw_done(&slp->ns_rwlock);
	if (slp == nfs_udpsock)
		nfs_udpsock = NULL;
#if ISO
	else if (slp == nfs_cltpsock)
		nfs_cltpsock = NULL;
#endif
	lck_mtx_unlock(nfsd_mutex);
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
	struct nfssvc_sock *slp, *nslp;
	struct timeval now;

	if (terminating) {
		microuptime(&now);
		for (slp = TAILQ_FIRST(&nfssvc_sockhead); slp != 0; slp = nslp) {
			nslp = TAILQ_NEXT(slp, ns_chain);
			if (slp->ns_flag & SLP_VALID) {
				lck_rw_lock_exclusive(&slp->ns_rwlock);
				nfsrv_zapsock(slp);
				lck_rw_done(&slp->ns_rwlock);
			}
			/* queue the socket up for deletion */
			slp->ns_timestamp = now.tv_sec;
			TAILQ_REMOVE(&nfssvc_sockhead, slp, ns_chain);
			TAILQ_INSERT_TAIL(&nfssvc_deadsockhead, slp, ns_chain);
			if (slp == nfs_udpsock)
				nfs_udpsock = NULL;
#if ISO
			else if (slp == nfs_cltpsock)
				nfs_cltpsock = NULL;
#endif
		}
		nfsrv_cleancache();	/* And clear out server cache */
/* XXX Revisit when enabling WebNFS */
#ifdef WEBNFS_ENABLED
	} else
		nfs_pub.np_valid = 0;
#else
	}
#endif

	if (!terminating) {
		TAILQ_INIT(&nfssvc_sockhead);
		TAILQ_INIT(&nfssvc_deadsockhead);
		TAILQ_INIT(&nfsd_head);
		nfsd_head_flag &= ~NFSD_CHECKSLP;
	}

	MALLOC(nfs_udpsock, struct nfssvc_sock *, sizeof(struct nfssvc_sock),
			M_NFSSVC, M_WAITOK);
	if (nfs_udpsock) {
		bzero((caddr_t)nfs_udpsock, sizeof (struct nfssvc_sock));
		lck_rw_init(&nfs_udpsock->ns_rwlock, nfs_slp_rwlock_group, nfs_slp_lock_attr);
		lck_mtx_init(&nfs_udpsock->ns_wgmutex, nfs_slp_mutex_group, nfs_slp_lock_attr);
		TAILQ_INIT(&nfs_udpsock->ns_uidlruhead);
		TAILQ_INSERT_HEAD(&nfssvc_sockhead, nfs_udpsock, ns_chain);
	} else {
		printf("nfsrv_init() failed to allocate UDP socket\n");
	}

#if ISO
	MALLOC(nfs_cltpsock, struct nfssvc_sock *, sizeof(struct nfssvc_sock),
			M_NFSSVC, M_WAITOK);
	if (nfs_cltpsock) {
		bzero((caddr_t)nfs_cltpsock, sizeof (struct nfssvc_sock));
		lck_rw_init(&nfs_cltpsock->ns_rwlock, nfs_slp_rwlock_group, nfs_slp_lock_attr);
		lck_mtx_init(&nfs_cltpsock->ns_wgmutex, nfs_slp_mutex_group, nfs_slp_lock_attr);
		TAILQ_INIT(&nfs_cltpsock->ns_uidlruhead);
		TAILQ_INSERT_TAIL(&nfssvc_sockhead, nfs_cltpsock, ns_chain);
	} else {
		printf("nfsrv_init() failed to allocate CLTP socket\n");
	}
#endif
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
	struct timeval now;

	rt = &nfsdrt.drt[nfsdrt.pos];
	if (cacherep == RC_DOIT)
		rt->flag = 0;
	else if (cacherep == RC_REPLY)
		rt->flag = DRT_CACHEREPLY;
	else
		rt->flag = DRT_CACHEDROP;
	if (sotype == SOCK_STREAM)
		rt->flag |= DRT_TCP;
	else if (nd->nd_flag & ND_NFSV3)
		rt->flag |= DRT_NFSV3;
	rt->proc = nd->nd_procnum;
	if (((struct sockaddr *)mbuf_data(nd->nd_nam))->sa_family == AF_INET)
	    rt->ipadr = ((struct sockaddr_in *)mbuf_data(nd->nd_nam))->sin_addr.s_addr;
	else
	    rt->ipadr = INADDR_ANY;
	microuptime(&now);
	rt->resptime = ((now.tv_sec - nd->nd_starttime.tv_sec) * 1000000) +
		(now.tv_usec - nd->nd_starttime.tv_usec);
	microtime(&rt->tstamp); // XXX unused
	nfsdrt.pos = (nfsdrt.pos + 1) % NFSRTTLOGSIZ;
}
#endif /* NFS_NOSERVER */
