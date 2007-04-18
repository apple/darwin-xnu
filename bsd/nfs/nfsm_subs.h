/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 *	@(#)nfsm_subs.h	8.2 (Berkeley) 3/30/95
 * FreeBSD-Id: nfsm_subs.h,v 1.13 1997/07/16 09:06:30 dfr Exp $
 */


#ifndef _NFS_NFSM_SUBS_H_
#define _NFS_NFSM_SUBS_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
/*
 * These macros do strange and peculiar things to mbuf chains for
 * the assistance of the nfs code. To attempt to use them for any
 * other purpose will be dangerous. (they make weird assumptions)
 */

/*
 * First define what the actual subs. return
 */
int nfsm_reqh(int hsiz, caddr_t *bposp, mbuf_t *mbp);
int nfsm_rpchead(struct ucred *cr, int nmflag, int procid,
			       int auth_type, int auth_len, char *auth_str,
			       int verf_len, char *verf_str,
			       mbuf_t mrest, int mrest_len,
			       mbuf_t *mbp, u_long *xidp, mbuf_t *mreqp);

/*
 * Now for the macros that do the simple stuff and call the functions
 * for the hard stuff.
 * These macros use several vars. declared in nfsm_reqhead and these
 * vars. must not be used elsewhere unless you are careful not to corrupt
 * them. The vars. starting with pN and tN (N=1,2,3,..) are temporaries
 * that may be used so long as the value is not expected to retained
 * after a macro.
 * I know, this is kind of dorkey, but it makes the actual op functions
 * fairly clean and deals with the mess caused by the xdr discriminating
 * unions.
 */

#define	nfsm_build(a,c,s) \
		{ if ((s) > mbuf_trailingspace(mb)) { \
			int __nfsm_error; \
			__nfsm_error = mbuf_get(MBUF_WAITOK, MBUF_TYPE_DATA, &mb2); \
			if (__nfsm_error) \
				panic("nfsm_build mbuf_get error %d", __nfsm_error); \
			if ((s) > mbuf_maxlen(mb2)) \
				panic("nfsm_build size error"); \
			__nfsm_error = mbuf_setnext(mb, mb2); \
			if (__nfsm_error) \
				panic("nfsm_build mbuf_setnext error %d", __nfsm_error); \
			mb = mb2; \
			bpos = mbuf_data(mb); \
		} \
		(a) = (c)(bpos); \
		mbuf_setlen(mb, (mbuf_len(mb) + (s))); \
		bpos += (s); }

#define	nfsm_dissect(a, c, s) \
		{ t1 = ((caddr_t)mbuf_data(md)) + mbuf_len(md) - dpos; \
		if (t1 >= (s)) { \
			(a) = (c)(dpos); \
			dpos += (s); \
		} else if ((t1 = nfsm_disct(&md, &dpos, (s), t1, &cp2))) { \
			error = t1; \
			mbuf_freem(mrep); \
			goto nfsmout; \
		} else { \
			(a) = (c)cp2; \
		} }

#define nfsm_fhtom(v, v3) \
	      { if (v3) { \
			t2 = nfsm_rndup(VTONFS(v)->n_fhsize) + NFSX_UNSIGNED; \
			if (t2 <= mbuf_trailingspace(mb)) { \
				nfsm_build(tl, u_long *, t2); \
				*tl++ = txdr_unsigned(VTONFS(v)->n_fhsize); \
				*(tl + ((t2>>2) - 2)) = 0; \
				bcopy((caddr_t)VTONFS(v)->n_fhp,(caddr_t)tl, \
					VTONFS(v)->n_fhsize); \
			} else if ((t2 = nfsm_strtmbuf(&mb, &bpos, \
				(caddr_t)VTONFS(v)->n_fhp, VTONFS(v)->n_fhsize))) { \
				error = t2; \
				mbuf_freem(mreq); \
				goto nfsmout; \
			} \
		} else { \
			nfsm_build(cp, caddr_t, NFSX_V2FH); \
			bcopy((caddr_t)VTONFS(v)->n_fhp, cp, NFSX_V2FH); \
		} }

#define nfsm_srvfhtom(f, v3) \
		{ if (v3) { \
			nfsm_build(tl, u_long *, NFSX_UNSIGNED + (unsigned)(f)->nfh_len); \
			*tl++ = txdr_unsigned((f)->nfh_len); \
			bcopy((caddr_t)&(f)->nfh_xh, (caddr_t)tl, (f)->nfh_len); \
		} else { \
			nfsm_build(cp, caddr_t, NFSX_V2FH); \
			bcopy((caddr_t)&(f)->nfh_xh, cp, NFSX_V2FH); \
		} }

#define nfsm_srvpostop_fh(f) \
		{ nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED + (unsigned)(f)->nfh_len); \
		*tl++ = nfs_true; \
		*tl++ = txdr_unsigned((f)->nfh_len); \
		bcopy((caddr_t)&(f)->nfh_xh, (caddr_t)tl, (f)->nfh_len); \
		}

#define nfsm_mtofh(d, cnp, v, v3, xp, f) \
		{ \
		struct nfsnode *ttnp; u_char *ttfhp = NULL; \
		int ttfhsize = 0, ttgotfh = 1, ttgotattr = 1, ttgotnode = 0; \
		struct nfs_vattr ttvattr; \
		(v) = NULL; \
		/* XXX would be nice to not bail to nfsmout on error */ \
		if (v3) { /* check for file handle */ \
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
			ttgotfh = fxdr_unsigned(int, *tl); \
		} \
		if (ttgotfh) { \
			/* get file handle */ \
			nfsm_getfh(ttfhp, ttfhsize, (v3)); \
		} \
		if (v3) { /* check for attributes */ \
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
			ttgotattr = fxdr_unsigned(int, *tl); \
		} \
		/* get attributes */ \
		if (ttgotattr) { \
			if (!ttgotfh) { \
				nfsm_adv(NFSX_V3FATTR); \
			} else { \
				nfsm_attr_get(v3, &ttvattr); \
			} \
		} else if (ttgotfh) { \
			/* We need valid attributes in order */ \
			/* to call nfs_nget/vnode_create().  */ \
			t1 = nfs_getattr_no_vnode(vnode_mount(d), \
				ttfhp, ttfhsize, cred, p, &ttvattr, xp); \
			if (t1) \
				ttgotattr = 0; \
		} \
		if (ttgotfh && ttgotattr) { \
			int ttngflags = NG_MAKEENTRY; \
			if ((t1 = nfs_nget(vnode_mount(d), d, cnp, ttfhp, ttfhsize, \
					&ttvattr, xp, ttngflags, &ttnp))) { \
				error = t1; \
				ttgotnode = 0; \
			} else { \
				ttgotnode = 1; \
				(v) = NFSTOV(ttnp); \
			} \
		} \
		(f) = ttgotnode;  \
		}

#define nfsm_getfh(f, s, v3) \
		{ if (v3) { \
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
			if (((s) = fxdr_unsigned(int, *tl)) <= 0 || \
				(s) > NFSX_V3FHMAX) { \
				mbuf_freem(mrep); \
				error = EBADRPC; \
				goto nfsmout; \
			} \
		} else { \
			(s) = NFSX_V2FH; \
		} \
		nfsm_dissect((f), u_char *, nfsm_rndup(s)); }

#define	nfsm_loadattr(v, v3, a, x) \
		{ struct nfs_vattr ttvattr; \
		if ((t1 = nfs_parsefattr(&md, &dpos, v3, &ttvattr))) { \
			error = t1; \
			mbuf_freem(mrep); \
			goto nfsmout; \
		} \
		if ((t1 = nfs_loadattrcache(VTONFS(v), &ttvattr, (x), 0))) { \
			error = t1; \
			mbuf_freem(mrep); \
			goto nfsmout; \
		} \
		if (a) { \
			bcopy(&ttvattr, (a), sizeof(ttvattr)); \
		} \
		}

#define	nfsm_attr_get(v3, vap) \
		{ \
		if ((t1 = nfs_parsefattr(&md, &dpos, v3, vap))) { \
			error = t1; \
			mbuf_freem(mrep); \
			goto nfsmout; \
		} \
		}

#define	nfsm_postop_attr_get(v3, f, vap) \
		{ \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		if (((f) = fxdr_unsigned(int, *tl))) { \
			if ((t1 = nfs_parsefattr(&md, &dpos, v3, vap))) { \
				error = t1; \
				(f) = 0; \
				mbuf_freem(mrep); \
				goto nfsmout; \
			} \
		} }

#define	nfsm_postop_attr_update(v, v3, f, x) \
		{ \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		if (((f) = fxdr_unsigned(int, *tl))) { \
			struct nfs_vattr ttvattr; \
			if ((t1 = nfs_parsefattr(&md, &dpos, v3, &ttvattr))) { \
				error = t1; \
				(f) = 0; \
				mbuf_freem(mrep); \
				goto nfsmout; \
			} \
			if ((t1 = nfs_loadattrcache(VTONFS(v), &ttvattr, (x), 1))) { \
				error = t1; \
				(f) = 0; \
				mbuf_freem(mrep); \
				goto nfsmout; \
			} \
			if (*(x) == 0) \
				(f) = 0; \
		} }

#define	nfsm_wcc_data(v, premtime, newpostattr, x) \
		{ \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		if (*tl == nfs_true) { \
			nfsm_dissect(tl, u_long *, 6 * NFSX_UNSIGNED); \
			(premtime)->tv_sec = fxdr_unsigned(time_t, *(tl + 2)); \
			(premtime)->tv_nsec = fxdr_unsigned(time_t, *(tl + 3)); \
		} else { \
			(premtime)->tv_sec = 0; \
			(premtime)->tv_nsec = 0; \
		} \
		nfsm_postop_attr_update((v), 1, (newpostattr), (x)); \
		}

#define nfsm_v3sattr(vap) \
		{\
		struct timeval now; \
		if (VATTR_IS_ACTIVE(vap, va_mode)) { \
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED); \
			*tl++ = nfs_true; \
			*tl = txdr_unsigned(vap->va_mode); \
		} else { \
			nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
			*tl = nfs_false; \
		} \
		if (VATTR_IS_ACTIVE(vap, va_uid)) { \
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED); \
			*tl++ = nfs_true; \
			*tl = txdr_unsigned(vap->va_uid); \
		} else { \
			nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
			*tl = nfs_false; \
		} \
		if (VATTR_IS_ACTIVE(vap, va_gid)) { \
			nfsm_build(tl, u_long *, 2 * NFSX_UNSIGNED); \
			*tl++ = nfs_true; \
			*tl = txdr_unsigned(vap->va_gid); \
		} else { \
			nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
			*tl = nfs_false; \
		} \
		if (VATTR_IS_ACTIVE(vap, va_data_size)) { \
			nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED); \
			*tl++ = nfs_true; \
			txdr_hyper(&vap->va_data_size, tl); \
		} else { \
			nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
			*tl = nfs_false; \
		} \
		microtime(&now); \
		if (VATTR_IS_ACTIVE(vap, va_access_time)) { \
			if (vap->va_access_time.tv_sec != now.tv_sec) { \
				nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED); \
				*tl++ = txdr_unsigned(NFSV3SATTRTIME_TOCLIENT); \
				txdr_nfsv3time(&vap->va_access_time, tl); \
			} else { \
				nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
				*tl = txdr_unsigned(NFSV3SATTRTIME_TOSERVER); \
			} \
		} else { \
			nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
			*tl = txdr_unsigned(NFSV3SATTRTIME_DONTCHANGE); \
		} \
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) { \
			if (vap->va_modify_time.tv_sec != now.tv_sec) { \
				nfsm_build(tl, u_long *, 3 * NFSX_UNSIGNED); \
				*tl++ = txdr_unsigned(NFSV3SATTRTIME_TOCLIENT); \
				txdr_nfsv3time(&vap->va_modify_time, tl); \
			} else { \
				nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
				*tl = txdr_unsigned(NFSV3SATTRTIME_TOSERVER); \
			} \
		} else { \
			nfsm_build(tl, u_long *, NFSX_UNSIGNED); \
			*tl = txdr_unsigned(NFSV3SATTRTIME_DONTCHANGE); \
		} \
		}

#define	nfsm_strsiz(s,m,v3) \
		{ nfsm_dissect(tl,u_long *,NFSX_UNSIGNED); \
		(s) = fxdr_unsigned(long,*tl); \
		if (!(v3) && ((s) > (m))) { \
			mbuf_freem(mrep); \
			error = EBADRPC; \
			goto nfsmout; \
		} }

#define	nfsm_srvstrsiz(s,m) \
		{ nfsm_dissect(tl,u_long *,NFSX_UNSIGNED); \
		if (((s) = fxdr_unsigned(long,*tl)) > (m) || (s) <= 0) { \
			error = EBADRPC; \
			nfsm_reply(0); \
		} }

#define	nfsm_srvnamesiz(s,v3) \
		{ nfsm_dissect(tl,u_long *,NFSX_UNSIGNED); \
		(s) = fxdr_unsigned(long,*tl); \
		if (!(v3) && ((s) > NFS_MAXNAMLEN)) \
			error = NFSERR_NAMETOL; \
		if ((s) <= 0) \
			error = EBADRPC; \
		if (error) \
			nfsm_reply(0); \
		}

#define nfsm_mtouio(p,s) \
		if ((s) > 0 && \
		   (t1 = nfsm_mbuftouio(&md,(p),(s),&dpos))) { \
			error = t1; \
			mbuf_freem(mrep); \
			goto nfsmout; \
		}

#define nfsm_uiotom(p,s) \
		if ((t1 = nfsm_uiotombuf((p),&mb,(s),&bpos))) { \
			error = t1; \
			mbuf_freem(mreq); \
			goto nfsmout; \
		}

#define	nfsm_reqhead(s) \
		error = nfsm_reqh((s), &bpos, &mreq); \
		mb = mreq;

#define nfsm_reqdone	mbuf_freem(mrep); \
		nfsmout:

#define nfsm_rndup(a)	(((a)+3)&(~0x3))

#define	nfsm_request(v, t, p, c, x)	\
		if ((error = nfs_request((v), vnode_mount(v), mreq, (t), (p), \
		   (c), &mrep, &md, &dpos, (x)))) { \
			if (error & NFSERR_RETERR) \
				error &= ~NFSERR_RETERR; \
			else \
				goto nfsmout; \
                }

#define	nfsm_strtom(a,s,m,v3) \
		if (!(v3) && ((s) > (m))) { \
			mbuf_freem(mreq); \
			error = ENAMETOOLONG; \
			goto nfsmout; \
		} \
		t2 = nfsm_rndup(s)+NFSX_UNSIGNED; \
		if (t2 <= mbuf_trailingspace(mb)) { \
			nfsm_build(tl,u_long *,t2); \
			*tl++ = txdr_unsigned(s); \
			*(tl+((t2>>2)-2)) = 0; \
			bcopy((caddr_t)(a), (caddr_t)tl, (s)); \
		} else if ((t2 = nfsm_strtmbuf(&mb, &bpos, (a), (s)))) { \
			error = t2; \
			mbuf_freem(mreq); \
			goto nfsmout; \
		}

#define	nfsm_srvdone \
		nfsmout: \
		return(error)

#define	nfsm_reply(s) \
		{ \
		nfsd->nd_repstat = error; \
		if (error && !(nfsd->nd_flag & ND_NFSV3)) \
		   nfs_rephead(0, nfsd, slp, error, mrq, &mb, &bpos); \
		else \
		   nfs_rephead((s), nfsd, slp, error, mrq, &mb, &bpos); \
		mbuf_freem(mrep); \
		mrep = NULL; \
		mreq = *mrq; \
		if (error && (!(nfsd->nd_flag & ND_NFSV3) || \
			error == EBADRPC)) { \
			error = 0; \
			goto nfsmout; \
		} \
		}

#define	nfsm_writereply(s, v3) \
		{ \
		nfsd->nd_repstat = error; \
		if (error && !(v3)) \
		   nfs_rephead(0, nfsd, slp, error, &mreq, &mb, &bpos); \
		else \
		   nfs_rephead((s), nfsd, slp, error, &mreq, &mb, &bpos); \
		}

#define	nfsm_adv(s) \
		{ t1 = ((caddr_t)mbuf_data(md)) + mbuf_len(md) - dpos; \
		if (t1 >= (s)) { \
			dpos += (s); \
		} else if ((t1 = nfs_adv(&md, &dpos, (s), t1))) { \
			error = t1; \
			mbuf_freem(mrep); \
			goto nfsmout; \
		} }

#define nfsm_srvmtofh(f) \
		{ \
		if (nfsd->nd_flag & ND_NFSV3) { \
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
			(f)->nfh_len = fxdr_unsigned(int, *tl); \
			if (((f)->nfh_len < (int)sizeof(struct nfs_exphandle)) || \
			    ((f)->nfh_len > NFSX_V3FHMAX)) { \
				error = EBADRPC; \
				nfsm_reply(0); \
			} \
		} else { \
			(f)->nfh_len = NFSX_V2FH; \
		} \
		nfsm_dissect(tl, u_long *, (f)->nfh_len); \
		bcopy((caddr_t)tl, (caddr_t)&(f)->nfh_xh, (f)->nfh_len); \
		}

#define	nfsm_clget \
		if (bp >= be) { \
			int __nfsm_error, __nfsm_len; \
			if (mp == mb) \
				mbuf_setlen(mp, mbuf_len(mp) + bp - bpos); \
			mp = NULL; \
			__nfsm_error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, &mp); \
			if (__nfsm_error) \
				panic("nfsm_clget: mbuf_mclget error %d", __nfsm_error); \
			__nfsm_len = mbuf_maxlen(mp); \
			mbuf_setlen(mp, __nfsm_len); \
			__nfsm_error = mbuf_setnext(mp2, mp); \
			if (__nfsm_error) \
				panic("nfsm_clget: mbuf_setnext error %d", __nfsm_error); \
			mp2 = mp; \
			bp = mbuf_data(mp); \
			be = bp + __nfsm_len; \
		} \
		tl = (u_long *)bp

#define	nfsm_srv_vattr_init(vap, v3) \
		{ \
		VATTR_INIT(vap); \
		VATTR_WANTED((vap), va_type); \
		VATTR_WANTED((vap), va_mode); \
		VATTR_WANTED((vap), va_nlink); \
		VATTR_WANTED((vap), va_uid); \
		VATTR_WANTED((vap), va_gid); \
		VATTR_WANTED((vap), va_data_size); \
		VATTR_WANTED((vap), va_data_alloc); \
		VATTR_WANTED((vap), va_rdev); \
		VATTR_WANTED((vap), va_fsid); \
		VATTR_WANTED((vap), va_fileid); \
		VATTR_WANTED((vap), va_access_time); \
		VATTR_WANTED((vap), va_modify_time); \
		VATTR_WANTED((vap), va_change_time); \
		if (!v3) VATTR_WANTED((vap), va_iosize); \
		}

#define	nfsm_srv_pre_vattr_init(vap, v3) \
		{ \
		VATTR_INIT(vap); \
		VATTR_WANTED((vap), va_data_size); \
		VATTR_WANTED((vap), va_modify_time); \
		VATTR_WANTED((vap), va_change_time); \
		}

#define	nfsm_srvfillattr(a, f) \
		nfsm_srvfattr(nfsd, (a), (f))

#define nfsm_srvwcc_data(br, b, ar, a) \
		nfsm_srvwcc(nfsd, (br), (b), (ar), (a), &mb, &bpos)

#define nfsm_srvpostop_attr(r, a) \
		nfsm_srvpostopattr(nfsd, (r), (a), &mb, &bpos)

#define nfsm_srvsattr(a) \
		{ \
		struct timespec now; \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		if (*tl == nfs_true) { \
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
			VATTR_SET(a, va_mode, nfstov_mode(*tl)); \
		} \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		if (*tl == nfs_true) { \
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
			VATTR_SET(a, va_uid, fxdr_unsigned(uid_t, *tl)); \
		} \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		if (*tl == nfs_true) { \
			nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
			VATTR_SET(a, va_gid, fxdr_unsigned(gid_t, *tl)); \
		} \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		if (*tl == nfs_true) { \
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED); \
			fxdr_hyper(tl, &(a)->va_data_size); \
			VATTR_SET_ACTIVE(a, va_data_size); \
		} \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		nanotime(&now); \
		switch (fxdr_unsigned(int, *tl)) { \
		case NFSV3SATTRTIME_TOCLIENT: \
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED); \
			fxdr_nfsv3time(tl, &(a)->va_access_time); \
			VATTR_SET_ACTIVE(a, va_access_time); \
			break; \
		case NFSV3SATTRTIME_TOSERVER: \
			VATTR_SET(a, va_access_time, now); \
			break; \
		}; \
		nfsm_dissect(tl, u_long *, NFSX_UNSIGNED); \
		switch (fxdr_unsigned(int, *tl)) { \
		case NFSV3SATTRTIME_TOCLIENT: \
			nfsm_dissect(tl, u_long *, 2 * NFSX_UNSIGNED); \
			fxdr_nfsv3time(tl, &(a)->va_modify_time); \
			VATTR_SET_ACTIVE(a, va_modify_time); \
			break; \
		case NFSV3SATTRTIME_TOSERVER: \
			VATTR_SET(a, va_modify_time, now); \
			break; \
		}; }

#endif /* __APPLE_API_PRIVATE */
#endif /* _NFS_NFSM_SUBS_H_ */
