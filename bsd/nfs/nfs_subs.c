/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 *	@(#)nfs_subs.c	8.8 (Berkeley) 5/22/95
 * FreeBSD-Id: nfs_subs.c,v 1.47 1997/11/07 08:53:24 phk Exp $
 */

/*
 * These functions support the macros and help fiddle mbuf chains for
 * the nfs op functions. They do things like create the rpc header and
 * copy data between mbuf chains and uio lists.
 */
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/mount_internal.h>
#include <sys/vnode_internal.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/malloc.h>
#include <sys/syscall.h>
#include <sys/ubc_internal.h>
#include <sys/fcntl.h>
#include <sys/uio_internal.h>
#include <sys/domain.h>
#include <libkern/OSAtomic.h>
#include <kern/thread_call.h>

#include <sys/vm.h>
#include <sys/vmparam.h>

#include <sys/time.h>
#include <kern/clock.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsnode.h>
#include <nfs/xdr_subs.h>
#include <nfs/nfsm_subs.h>
#include <nfs/nfs_gss.h>
#include <nfs/nfsmount.h>
#include <nfs/nfs_lock.h>

#include <miscfs/specfs/specdev.h>

#include <netinet/in.h>
#include <net/kpi_interface.h>

/*
 * NFS globals
 */
struct nfsstats	nfsstats;
size_t nfs_mbuf_mhlen = 0, nfs_mbuf_minclsize = 0;

/*
 * functions to convert between NFS and VFS types
 */
nfstype
vtonfs_type(enum vtype vtype, int nfsvers)
{
	switch (vtype) {
	case VNON:
		return NFNON;
	case VREG:
		return NFREG;
	case VDIR:
		return NFDIR;
	case VBLK:
		return NFBLK;
	case VCHR:
		return NFCHR;
	case VLNK:
		return NFLNK;
	case VSOCK:
		if (nfsvers > NFS_VER2)
			return NFSOCK;
	case VFIFO:
		if (nfsvers > NFS_VER2)
			return NFFIFO;
	case VBAD:
	case VSTR:
	case VCPLX:
	default:
		return NFNON;
	}
}

enum vtype
nfstov_type(nfstype nvtype, int nfsvers)
{
	switch (nvtype) {
	case NFNON:
		return VNON;
	case NFREG:
		return VREG;
	case NFDIR:
		return VDIR;
	case NFBLK:
		return VBLK;
	case NFCHR:
		return VCHR;
	case NFLNK:
		return VLNK;
	case NFSOCK:
		if (nfsvers > NFS_VER2)
			return VSOCK;
	case NFFIFO:
		if (nfsvers > NFS_VER2)
			return VFIFO;
	case NFATTRDIR:
		if (nfsvers > NFS_VER3)
			return VDIR;
	case NFNAMEDATTR:
		if (nfsvers > NFS_VER3)
			return VREG;
	default:
		return VNON;
	}
}

int
vtonfsv2_mode(enum vtype vtype, mode_t m)
{
	if (vtype == VFIFO)
		return vnode_makeimode(VCHR, m);
	return vnode_makeimode(vtype, m);
}

#if NFSSERVER

/*
 * Mapping of old NFS Version 2 RPC numbers to generic numbers.
 */
int nfsv3_procid[NFS_NPROCS] = {
	NFSPROC_NULL,
	NFSPROC_GETATTR,
	NFSPROC_SETATTR,
	NFSPROC_NOOP,
	NFSPROC_LOOKUP,
	NFSPROC_READLINK,
	NFSPROC_READ,
	NFSPROC_NOOP,
	NFSPROC_WRITE,
	NFSPROC_CREATE,
	NFSPROC_REMOVE,
	NFSPROC_RENAME,
	NFSPROC_LINK,
	NFSPROC_SYMLINK,
	NFSPROC_MKDIR,
	NFSPROC_RMDIR,
	NFSPROC_READDIR,
	NFSPROC_FSSTAT,
	NFSPROC_NOOP,
	NFSPROC_NOOP,
	NFSPROC_NOOP,
	NFSPROC_NOOP,
	NFSPROC_NOOP
};

#endif /* NFSSERVER */

/*
 * and the reverse mapping from generic to Version 2 procedure numbers
 */
int nfsv2_procid[NFS_NPROCS] = {
	NFSV2PROC_NULL,
	NFSV2PROC_GETATTR,
	NFSV2PROC_SETATTR,
	NFSV2PROC_LOOKUP,
	NFSV2PROC_NOOP,
	NFSV2PROC_READLINK,
	NFSV2PROC_READ,
	NFSV2PROC_WRITE,
	NFSV2PROC_CREATE,
	NFSV2PROC_MKDIR,
	NFSV2PROC_SYMLINK,
	NFSV2PROC_CREATE,
	NFSV2PROC_REMOVE,
	NFSV2PROC_RMDIR,
	NFSV2PROC_RENAME,
	NFSV2PROC_LINK,
	NFSV2PROC_READDIR,
	NFSV2PROC_NOOP,
	NFSV2PROC_STATFS,
	NFSV2PROC_NOOP,
	NFSV2PROC_NOOP,
	NFSV2PROC_NOOP,
	NFSV2PROC_NOOP
};


/*
 * initialize NFS's cache of mbuf constants
 */
void
nfs_mbuf_init(void)
{
	struct mbuf_stat ms;

	mbuf_stats(&ms);
	nfs_mbuf_mhlen = ms.mhlen;
	nfs_mbuf_minclsize = ms.minclsize;
}

#if NFSSERVER

/*
 * allocate a list of mbufs to hold the given amount of data
 */
int
nfsm_mbuf_get_list(size_t size, mbuf_t *mp, int *mbcnt)
{
	int error, cnt;
	mbuf_t mhead, mlast, m;
	size_t len, mlen;

	error = cnt = 0;
	mhead = mlast = NULL;
	len = 0;

	while (len < size) {
		nfsm_mbuf_get(error, &m, (size - len));
		if (error)
			break;
		if (!mhead)
			mhead = m;
		if (mlast && ((error = mbuf_setnext(mlast, m)))) {
			mbuf_free(m);
			break;
		}
		mlen = mbuf_maxlen(m);
		if ((len + mlen) > size)
			mlen = size - len;
		mbuf_setlen(m, mlen);
		len += mlen;
		cnt++;
		mlast = m;
	}

	if (!error) {
		*mp = mhead;
		*mbcnt = cnt;
	}
	return (error);
}

#endif /* NFSSERVER */

/*
 * nfsm_chain_new_mbuf()
 *
 * Add a new mbuf to the given chain.
 */
int
nfsm_chain_new_mbuf(struct nfsm_chain *nmc, size_t sizehint)
{
	mbuf_t mb;
	int error = 0;

	if (nmc->nmc_flags & NFSM_CHAIN_FLAG_ADD_CLUSTERS)
		sizehint = nfs_mbuf_minclsize;

	/* allocate a new mbuf */
	nfsm_mbuf_get(error, &mb, sizehint);
	if (error)
		return (error);
	if (mb == NULL)
		panic("got NULL mbuf?");

	/* do we have a current mbuf? */
	if (nmc->nmc_mcur) {
		/* first cap off current mbuf */
		mbuf_setlen(nmc->nmc_mcur, nmc->nmc_ptr - (caddr_t)mbuf_data(nmc->nmc_mcur));
		/* then append the new mbuf */
		error = mbuf_setnext(nmc->nmc_mcur, mb);
		if (error) {
			mbuf_free(mb);
			return (error);
		}
	}

	/* set up for using the new mbuf */
	nmc->nmc_mcur = mb;
	nmc->nmc_ptr = mbuf_data(mb);
	nmc->nmc_left = mbuf_trailingspace(mb);

	return (0);
}

/*
 * nfsm_chain_add_opaque_f()
 *
 * Add "len" bytes of opaque data pointed to by "buf" to the given chain.
 */
int
nfsm_chain_add_opaque_f(struct nfsm_chain *nmc, const u_char *buf, uint32_t len)
{
	uint32_t paddedlen, tlen;
	int error;

	paddedlen = nfsm_rndup(len);

	while (paddedlen) {
		if (!nmc->nmc_left) {
			error = nfsm_chain_new_mbuf(nmc, paddedlen);
			if (error)
				return (error);
		}
		tlen = MIN(nmc->nmc_left, paddedlen);
		if (tlen) {
			if (len) {
				if (tlen > len)
					tlen = len;
				bcopy(buf, nmc->nmc_ptr, tlen);
			} else {
				bzero(nmc->nmc_ptr, tlen);
			}
			nmc->nmc_ptr += tlen;
			nmc->nmc_left -= tlen;
			paddedlen -= tlen;
			if (len) {
				buf += tlen;
				len -= tlen;
			}
		}
	}
	return (0);
}

/*
 * nfsm_chain_add_opaque_nopad_f()
 *
 * Add "len" bytes of opaque data pointed to by "buf" to the given chain.
 * Do not XDR pad.
 */
int
nfsm_chain_add_opaque_nopad_f(struct nfsm_chain *nmc, const u_char *buf, uint32_t len)
{
	uint32_t tlen;
	int error;

	while (len > 0) {
		if (nmc->nmc_left <= 0) {
			error = nfsm_chain_new_mbuf(nmc, len);
			if (error)
				return (error);
		}
		tlen = MIN(nmc->nmc_left, len);
		bcopy(buf, nmc->nmc_ptr, tlen);
		nmc->nmc_ptr += tlen;
		nmc->nmc_left -= tlen;
		len -= tlen;
		buf += tlen;
	}
	return (0);
}

/*
 * nfsm_chain_add_uio()
 *
 * Add "len" bytes of data from "uio" to the given chain.
 */
int
nfsm_chain_add_uio(struct nfsm_chain *nmc, struct uio *uiop, uint32_t len)
{
	uint32_t paddedlen, tlen;
	int error;

	paddedlen = nfsm_rndup(len);

	while (paddedlen) {
		if (!nmc->nmc_left) {
			error = nfsm_chain_new_mbuf(nmc, paddedlen);
			if (error)
				return (error);
		}
		tlen = MIN(nmc->nmc_left, paddedlen);
		if (tlen) {
			if (len) {
				if (tlen > len)
					tlen = len;
				uiomove(nmc->nmc_ptr, tlen, uiop);
			} else {
				bzero(nmc->nmc_ptr, tlen);
			}
			nmc->nmc_ptr += tlen;
			nmc->nmc_left -= tlen;
			paddedlen -= tlen;
			if (len)
				len -= tlen;
		}
	}
	return (0);
}

/*
 * Find the length of the NFS mbuf chain
 * up to the current encoding/decoding offset.
 */
int
nfsm_chain_offset(struct nfsm_chain *nmc)
{
	mbuf_t mb;
	int len = 0;

	for (mb = nmc->nmc_mhead; mb; mb = mbuf_next(mb)) {
		if (mb == nmc->nmc_mcur)
			return (len + (nmc->nmc_ptr - (caddr_t) mbuf_data(mb)));
		len += mbuf_len(mb);
	}

	return (len);
}

/*
 * nfsm_chain_advance()
 *
 * Advance an nfsm_chain by "len" bytes.
 */
int
nfsm_chain_advance(struct nfsm_chain *nmc, uint32_t len)
{
	mbuf_t mb;

	while (len) {
		if (nmc->nmc_left >= len) {
			nmc->nmc_left -= len;
			nmc->nmc_ptr += len;
			return (0);
		}
		len -= nmc->nmc_left;
		nmc->nmc_mcur = mb = mbuf_next(nmc->nmc_mcur);
		if (!mb)
			return (EBADRPC);
		nmc->nmc_ptr = mbuf_data(mb);
		nmc->nmc_left = mbuf_len(mb);
	}

	return (0);
}

/*
 * nfsm_chain_reverse()
 *
 * Reverse decode offset in an nfsm_chain by "len" bytes.
 */
int
nfsm_chain_reverse(struct nfsm_chain *nmc, uint32_t len)
{
	uint32_t mlen, new_offset;
	int error = 0;

	mlen = nmc->nmc_ptr - (caddr_t) mbuf_data(nmc->nmc_mcur);
	if (len <= mlen) {
		nmc->nmc_ptr -= len;
		nmc->nmc_left += len;
		return (0);
	}

	new_offset = nfsm_chain_offset(nmc) - len;
	nfsm_chain_dissect_init(error, nmc, nmc->nmc_mhead);
	if (error)
		return (error);

	return (nfsm_chain_advance(nmc, new_offset));
}

/*
 * nfsm_chain_get_opaque_pointer_f()
 *
 * Return a pointer to the next "len" bytes of contiguous data in
 * the mbuf chain.  If the next "len" bytes are not contiguous, we
 * try to manipulate the mbuf chain so that it is.
 *
 * The nfsm_chain is advanced by nfsm_rndup("len") bytes.
 */
int
nfsm_chain_get_opaque_pointer_f(struct nfsm_chain *nmc, uint32_t len, u_char **pptr)
{
	mbuf_t mbcur, mb;
	uint32_t left, need, mblen, cplen, padlen;
	u_char *ptr;
	int error = 0;

	/* move to next mbuf with data */
	while (nmc->nmc_mcur && (nmc->nmc_left == 0)) {
		mb = mbuf_next(nmc->nmc_mcur);
		nmc->nmc_mcur = mb;
		if (!mb)
			break;
		nmc->nmc_ptr = mbuf_data(mb);
		nmc->nmc_left = mbuf_len(mb);
	}
	/* check if we've run out of data */
	if (!nmc->nmc_mcur)
		return (EBADRPC);

	/* do we already have a contiguous buffer? */
	if (nmc->nmc_left >= len) {
		/* the returned pointer will be the current pointer */
		*pptr = (u_char*)nmc->nmc_ptr;
		error = nfsm_chain_advance(nmc, nfsm_rndup(len));
		return (error);
	}

	padlen = nfsm_rndup(len) - len;

	/* we need (len - left) more bytes */
	mbcur = nmc->nmc_mcur;
	left = nmc->nmc_left;
	need = len - left;

	if (need > mbuf_trailingspace(mbcur)) {
		/*
		 * The needed bytes won't fit in the current mbuf so we'll
		 * allocate a new mbuf to hold the contiguous range of data.
		 */
		nfsm_mbuf_get(error, &mb, len);
		if (error)
			return (error);
		/* double check that this mbuf can hold all the data */
		if (mbuf_maxlen(mb) < len) {
			mbuf_free(mb);
			return (EOVERFLOW);
		}

		/* the returned pointer will be the new mbuf's data pointer */
		*pptr = ptr = mbuf_data(mb);

		/* copy "left" bytes to the new mbuf */
		bcopy(nmc->nmc_ptr, ptr, left);
		ptr += left;
		mbuf_setlen(mb, left);

		/* insert the new mbuf between the current and next mbufs */
		error = mbuf_setnext(mb, mbuf_next(mbcur));
		if (!error)
			error = mbuf_setnext(mbcur, mb);
		if (error) {
			mbuf_free(mb);
			return (error);
		}

		/* reduce current mbuf's length by "left" */
		mbuf_setlen(mbcur, mbuf_len(mbcur) - left);

		/*
		 * update nmc's state to point at the end of the mbuf
		 * where the needed data will be copied to.
		 */
		nmc->nmc_mcur = mbcur = mb;
		nmc->nmc_left = 0;
		nmc->nmc_ptr = (caddr_t)ptr;
	} else {
		/* The rest of the data will fit in this mbuf. */

		/* the returned pointer will be the current pointer */
		*pptr = (u_char*)nmc->nmc_ptr;

		/*
		 * update nmc's state to point at the end of the mbuf
		 * where the needed data will be copied to.
		 */
		nmc->nmc_ptr += left;
		nmc->nmc_left = 0;
	}

	/*
	 * move the next "need" bytes into the current
	 * mbuf from the mbufs that follow
	 */

	/* extend current mbuf length */
	mbuf_setlen(mbcur, mbuf_len(mbcur) + need);

	/* mb follows mbufs we're copying/compacting data from */
	mb = mbuf_next(mbcur);

	while (need && mb) {
		/* copy as much as we need/can */
		ptr = mbuf_data(mb);
		mblen = mbuf_len(mb);
		cplen = MIN(mblen, need);
		if (cplen) {
			bcopy(ptr, nmc->nmc_ptr, cplen);
			/*
			 * update the mbuf's pointer and length to reflect that
			 * the data was shifted to an earlier mbuf in the chain
			 */
			error = mbuf_setdata(mb, ptr + cplen, mblen - cplen);
			if (error) {
				mbuf_setlen(mbcur, mbuf_len(mbcur) - need);
				return (error);
			}
			/* update pointer/need */
			nmc->nmc_ptr += cplen;
			need -= cplen;
		}
		/* if more needed, go to next mbuf */
		if (need)
			mb = mbuf_next(mb);
	}

	/* did we run out of data in the mbuf chain? */
	if (need) {
		mbuf_setlen(mbcur, mbuf_len(mbcur) - need);
		return (EBADRPC);
	}

	/*
	 * update nmc's state to point after this contiguous data
	 *
	 * "mb" points to the last mbuf we copied data from so we
	 * just set nmc to point at whatever remains in that mbuf.
	 */
	nmc->nmc_mcur = mb;
	nmc->nmc_ptr = mbuf_data(mb);
	nmc->nmc_left = mbuf_len(mb);

	/* move past any padding */
	if (padlen)
		error = nfsm_chain_advance(nmc, padlen);

	return (error);
}

/*
 * nfsm_chain_get_opaque_f()
 *
 * Read the next "len" bytes in the chain into "buf".
 * The nfsm_chain is advanced by nfsm_rndup("len") bytes.
 */
int
nfsm_chain_get_opaque_f(struct nfsm_chain *nmc, uint32_t len, u_char *buf)
{
	uint32_t cplen, padlen;
	int error = 0;

	padlen = nfsm_rndup(len) - len;

	/* loop through mbufs copying all the data we need */
	while (len && nmc->nmc_mcur) {
		/* copy as much as we need/can */
		cplen = MIN(nmc->nmc_left, len);
		if (cplen) {
			bcopy(nmc->nmc_ptr, buf, cplen);
			nmc->nmc_ptr += cplen;
			nmc->nmc_left -= cplen;
			buf += cplen;
			len -= cplen;
		}
		/* if more needed, go to next mbuf */
		if (len) {
			mbuf_t mb = mbuf_next(nmc->nmc_mcur);
			nmc->nmc_mcur = mb;
			nmc->nmc_ptr = mb ? mbuf_data(mb) : NULL;
			nmc->nmc_left = mb ? mbuf_len(mb) : 0;
		}
	}

	/* did we run out of data in the mbuf chain? */
	if (len)
		return (EBADRPC);

	if (padlen)
		nfsm_chain_adv(error, nmc, padlen);

	return (error);
}

/*
 * nfsm_chain_get_uio()
 *
 * Read the next "len" bytes in the chain into the given uio.
 * The nfsm_chain is advanced by nfsm_rndup("len") bytes.
 */
int
nfsm_chain_get_uio(struct nfsm_chain *nmc, uint32_t len, struct uio *uiop)
{
	uint32_t cplen, padlen;
	int error = 0;

	padlen = nfsm_rndup(len) - len;

	/* loop through mbufs copying all the data we need */
	while (len && nmc->nmc_mcur) {
		/* copy as much as we need/can */
		cplen = MIN(nmc->nmc_left, len);
		if (cplen) {
			error = uiomove(nmc->nmc_ptr, cplen, uiop);
			if (error)
				return (error);
			nmc->nmc_ptr += cplen;
			nmc->nmc_left -= cplen;
			len -= cplen;
		}
		/* if more needed, go to next mbuf */
		if (len) {
			mbuf_t mb = mbuf_next(nmc->nmc_mcur);
			nmc->nmc_mcur = mb;
			nmc->nmc_ptr = mb ? mbuf_data(mb) : NULL;
			nmc->nmc_left = mb ? mbuf_len(mb) : 0;
		}
	}

	/* did we run out of data in the mbuf chain? */
	if (len)
		return (EBADRPC);

	if (padlen)
		nfsm_chain_adv(error, nmc, padlen);

	return (error);
}

#if NFSCLIENT

/*
 * Add an NFSv2 "sattr" structure to an mbuf chain
 */
int
nfsm_chain_add_v2sattr_f(struct nfsm_chain *nmc, struct vnode_attr *vap, uint32_t szrdev)
{
	int error = 0;

	nfsm_chain_add_32(error, nmc, vtonfsv2_mode(vap->va_type,
		(VATTR_IS_ACTIVE(vap, va_mode) ? vap->va_mode : 0600)));
	nfsm_chain_add_32(error, nmc,
		VATTR_IS_ACTIVE(vap, va_uid) ? vap->va_uid : (uint32_t)-1);
	nfsm_chain_add_32(error, nmc,
		VATTR_IS_ACTIVE(vap, va_gid) ? vap->va_gid : (uint32_t)-1);
	nfsm_chain_add_32(error, nmc, szrdev);
	nfsm_chain_add_v2time(error, nmc,
		VATTR_IS_ACTIVE(vap, va_access_time) ?
		&vap->va_access_time : NULL);
	nfsm_chain_add_v2time(error, nmc,
		VATTR_IS_ACTIVE(vap, va_modify_time) ?
		&vap->va_modify_time : NULL);

	return (error);
}

/*
 * Add an NFSv3 "sattr" structure to an mbuf chain
 */
int
nfsm_chain_add_v3sattr_f(struct nfsm_chain *nmc, struct vnode_attr *vap)
{
	int error = 0;

	if (VATTR_IS_ACTIVE(vap, va_mode)) {
		nfsm_chain_add_32(error, nmc, TRUE);
		nfsm_chain_add_32(error, nmc, vap->va_mode);
	} else {
		nfsm_chain_add_32(error, nmc, FALSE);
	}
	if (VATTR_IS_ACTIVE(vap, va_uid)) {
		nfsm_chain_add_32(error, nmc, TRUE);
		nfsm_chain_add_32(error, nmc, vap->va_uid);
	} else {
		nfsm_chain_add_32(error, nmc, FALSE);
	}
	if (VATTR_IS_ACTIVE(vap, va_gid)) {
		nfsm_chain_add_32(error, nmc, TRUE);
		nfsm_chain_add_32(error, nmc, vap->va_gid);
	} else {
		nfsm_chain_add_32(error, nmc, FALSE);
	}
	if (VATTR_IS_ACTIVE(vap, va_data_size)) {
		nfsm_chain_add_32(error, nmc, TRUE);
		nfsm_chain_add_64(error, nmc, vap->va_data_size);
	} else {
		nfsm_chain_add_32(error, nmc, FALSE);
	}
	if (vap->va_vaflags & VA_UTIMES_NULL) {
		nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_SERVER);
		nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_SERVER);
	} else {
		if (VATTR_IS_ACTIVE(vap, va_access_time)) {
			nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_CLIENT);
			nfsm_chain_add_32(error, nmc, vap->va_access_time.tv_sec);
			nfsm_chain_add_32(error, nmc, vap->va_access_time.tv_nsec);
		} else {
			nfsm_chain_add_32(error, nmc, NFS_TIME_DONT_CHANGE);
		}
		if (VATTR_IS_ACTIVE(vap, va_modify_time)) {
			nfsm_chain_add_32(error, nmc, NFS_TIME_SET_TO_CLIENT);
			nfsm_chain_add_32(error, nmc, vap->va_modify_time.tv_sec);
			nfsm_chain_add_32(error, nmc, vap->va_modify_time.tv_nsec);
		} else {
			nfsm_chain_add_32(error, nmc, NFS_TIME_DONT_CHANGE);
		}
	}

	return (error);
}


/*
 * nfsm_chain_get_fh_attr()
 *
 * Get the file handle and attributes from an mbuf chain. (NFSv2/v3)
 */
int
nfsm_chain_get_fh_attr(
	struct nfsm_chain *nmc,
	nfsnode_t dnp,
	vfs_context_t ctx,
	int nfsvers,
	uint64_t *xidp,
	fhandle_t *fhp,
	struct nfs_vattr *nvap)
{
	int error = 0, gotfh, gotattr;

	gotfh = gotattr = 1;

	if (nfsvers == NFS_VER3) /* check for file handle */
		nfsm_chain_get_32(error, nmc, gotfh);
	if (!error && gotfh) /* get file handle */
		nfsm_chain_get_fh(error, nmc, nfsvers, fhp);
	else
		fhp->fh_len = 0;
	if (nfsvers == NFS_VER3) /* check for file attributes */
		nfsm_chain_get_32(error, nmc, gotattr);
	nfsmout_if(error);
	if (gotattr) {
		if (!gotfh) /* skip attributes */
			nfsm_chain_adv(error, nmc, NFSX_V3FATTR);
		else /* get attributes */
			error = nfs_parsefattr(nmc, nfsvers, nvap);
	} else if (gotfh) {
		/* we need valid attributes in order to call nfs_nget() */
		if (nfs3_getattr_rpc(NULL, NFSTOMP(dnp), fhp->fh_data, fhp->fh_len, ctx, nvap, xidp)) {
			gotattr = 0;
			fhp->fh_len = 0;
		}
	}
nfsmout:
	return (error);
}

/*
 * Get and process NFSv3 WCC data from an mbuf chain
 */
int
nfsm_chain_get_wcc_data_f(
	struct nfsm_chain *nmc,
	nfsnode_t np,
	struct timespec *premtime,
	int *newpostattr,
	u_int64_t *xidp)
{
	int error = 0;
	uint32_t flag = 0;

	nfsm_chain_get_32(error, nmc, flag);
	if (!error && flag) {
		nfsm_chain_adv(error, nmc, 2 * NFSX_UNSIGNED);
		nfsm_chain_get_32(error, nmc, premtime->tv_sec);
		nfsm_chain_get_32(error, nmc, premtime->tv_nsec);
		nfsm_chain_adv(error, nmc, 2 * NFSX_UNSIGNED);
	} else {
		premtime->tv_sec = 0;
		premtime->tv_nsec = 0;
	}
	nfsm_chain_postop_attr_update_flag(error, nmc, np, *newpostattr, xidp);

	return (error);
}

/*
 * Build the RPC header and fill in the authorization info.
 * Returns the head of the mbuf list and the xid.
 */

int
nfsm_rpchead(
	struct nfsreq *req,
	int auth_len,
	mbuf_t mrest,
	u_int64_t *xidp,
	mbuf_t *mreqp)
{
	struct nfsmount *nmp = req->r_nmp;
	int nfsvers = nmp->nm_vers;
	int proc = ((nfsvers == NFS_VER2) ? nfsv2_procid[req->r_procnum] : (int)req->r_procnum);
	int auth_type = (!auth_len && !req->r_cred) ? RPCAUTH_NULL : nmp->nm_auth;

	return nfsm_rpchead2(nmp->nm_sotype, NFS_PROG, nfsvers, proc,
		auth_type, auth_len, req->r_cred, req, mrest, xidp, mreqp);
}

int
nfsm_rpchead2(int sotype, int prog, int vers, int proc, int auth_type, int auth_len,
	kauth_cred_t cred, struct nfsreq *req, mbuf_t mrest, u_int64_t *xidp, mbuf_t *mreqp)
{
	mbuf_t mreq, mb;
	int error, i, grpsiz, authsiz, reqlen;
	size_t headlen;
	struct timeval tv;
	struct nfsm_chain nmreq;

	/* allocate the packet */
	authsiz = nfsm_rndup(auth_len);
	headlen = authsiz + 10 * NFSX_UNSIGNED;
	if (sotype == SOCK_STREAM) /* also include room for any RPC Record Mark */
		headlen += NFSX_UNSIGNED;
	if (headlen >= nfs_mbuf_minclsize) {
		error = mbuf_getpacket(MBUF_WAITOK, &mreq);
	} else {
		error = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, &mreq);
		if (!error) {
			if (headlen < nfs_mbuf_mhlen)
				mbuf_align_32(mreq, headlen);
			else
				mbuf_align_32(mreq, 8 * NFSX_UNSIGNED);
		}
	}
	if (error) {
		/* unable to allocate packet */
		/* XXX should we keep statistics for these errors? */
		return (error);
	}

	/*
	 * If the caller gave us a non-zero XID then use it because
	 * it may be a higher-level resend with a GSSAPI credential.
	 * Otherwise, allocate a new one.
	 */
	if (*xidp == 0) {
		lck_mtx_lock(nfs_request_mutex);
		if (!nfs_xid) {
			/*
			 * Derive initial xid from system time.
			 *
			 * Note: it's OK if this code inits nfs_xid to 0 (for example,
			 * due to a broken clock) because we immediately increment it
			 * and we guarantee to never use xid 0.  So, nfs_xid should only
			 * ever be 0 the first time this function is called.
			 */
			microtime(&tv);
			nfs_xid = tv.tv_sec << 12;
		}
		if (++nfs_xid == 0) {
			/* Skip zero xid if it should ever happen. */
			nfs_xidwrap++;
			nfs_xid++;
		}
		*xidp = nfs_xid + ((u_int64_t)nfs_xidwrap << 32);
		lck_mtx_unlock(nfs_request_mutex);
	}

	/* build the header(s) */
	nmreq.nmc_mcur = nmreq.nmc_mhead = mreq;
	nmreq.nmc_ptr = mbuf_data(nmreq.nmc_mcur);
	nmreq.nmc_left = mbuf_trailingspace(nmreq.nmc_mcur);

	/* First, if it's a TCP stream insert space for an RPC record mark */
	if (sotype == SOCK_STREAM)
		nfsm_chain_add_32(error, &nmreq, 0);

	/* Then the RPC header. */
	nfsm_chain_add_32(error, &nmreq, (*xidp & 0xffffffff));
	nfsm_chain_add_32(error, &nmreq, RPC_CALL);
	nfsm_chain_add_32(error, &nmreq, RPC_VER2);
	nfsm_chain_add_32(error, &nmreq, prog);
	nfsm_chain_add_32(error, &nmreq, vers);
	nfsm_chain_add_32(error, &nmreq, proc);

add_cred:
	switch (auth_type) {
	case RPCAUTH_NULL:
		nfsm_chain_add_32(error, &nmreq, RPCAUTH_NULL); /* auth */
		nfsm_chain_add_32(error, &nmreq, 0);		/* length */
		nfsm_chain_add_32(error, &nmreq, RPCAUTH_NULL);	/* verf */
		nfsm_chain_add_32(error, &nmreq, 0);		/* length */
		nfsm_chain_build_done(error, &nmreq);
		break;
	case RPCAUTH_UNIX:
		nfsm_chain_add_32(error, &nmreq, RPCAUTH_UNIX);
		nfsm_chain_add_32(error, &nmreq, authsiz);
		nfsm_chain_add_32(error, &nmreq, 0);	/* stamp */
		nfsm_chain_add_32(error, &nmreq, 0);	/* zero-length hostname */
		nfsm_chain_add_32(error, &nmreq, kauth_cred_getuid(cred));	/* UID */
		nfsm_chain_add_32(error, &nmreq, cred->cr_groups[0]);	/* GID */
		grpsiz = (auth_len >> 2) - 5;
		nfsm_chain_add_32(error, &nmreq, grpsiz);/* additional GIDs */
		for (i = 1; i <= grpsiz; i++)
			nfsm_chain_add_32(error, &nmreq, cred->cr_groups[i]);

		/* And the verifier... */
		nfsm_chain_add_32(error, &nmreq, RPCAUTH_NULL);	/* flavor */
		nfsm_chain_add_32(error, &nmreq, 0);		/* length */
		nfsm_chain_build_done(error, &nmreq);

		/* Append the args mbufs */
		if (!error)
			error = mbuf_setnext(nmreq.nmc_mcur, mrest);
		break;
	case RPCAUTH_KRB5:
	case RPCAUTH_KRB5I:
	case RPCAUTH_KRB5P:
		error = nfs_gss_clnt_cred_put(req, &nmreq, mrest);
		if (error == ENEEDAUTH) {
			/*
			 * Use sec=sys for this user
			 */
			error = 0;
			auth_type = RPCAUTH_UNIX;
			goto add_cred;
		}
		break;
	};

	/* finish setting up the packet */
	if (!error)
		error = mbuf_pkthdr_setrcvif(mreq, 0);

	if (error) {
		mbuf_freem(mreq);
		return (error);
	}

	/* Calculate the size of the request */
	reqlen = 0;
	for (mb = nmreq.nmc_mhead; mb; mb = mbuf_next(mb))
		reqlen += mbuf_len(mb);

	mbuf_pkthdr_setlen(mreq, reqlen);

	/*
	 * If the request goes on a TCP stream,
	 * set its size in the RPC record mark.
	 * The record mark count doesn't include itself
	 * and the last fragment bit is set.
	 */
	if (sotype == SOCK_STREAM)
		nfsm_chain_set_recmark(error, &nmreq,
			(reqlen - NFSX_UNSIGNED) | 0x80000000);

	*mreqp = mreq;
	return (0);
}

/*
 * Parse an NFS file attribute structure out of an mbuf chain.
 */
int
nfs_parsefattr(struct nfsm_chain *nmc, int nfsvers, struct nfs_vattr *nvap)
{
	int error = 0;
	enum vtype vtype;
	u_short vmode;
	uint32_t val, val2;
	dev_t rdev;

	val = val2 = 0;

	nfsm_chain_get_32(error, nmc, vtype);
	nfsm_chain_get_32(error, nmc, vmode);
	nfsmout_if(error);

	if (nfsvers == NFS_VER3) {
		nvap->nva_type = nfstov_type(vtype, nfsvers);
	} else {
		/*
		 * The duplicate information returned in fa_type and fa_mode
		 * is an ambiguity in the NFS version 2 protocol.
		 *
		 * VREG should be taken literally as a regular file.  If a
		 * server intends to return some type information differently
		 * in the upper bits of the mode field (e.g. for sockets, or
		 * FIFOs), NFSv2 mandates fa_type to be VNON.  Anyway, we
		 * leave the examination of the mode bits even in the VREG
		 * case to avoid breakage for bogus servers, but we make sure
		 * that there are actually type bits set in the upper part of
		 * fa_mode (and failing that, trust the va_type field).
		 *
		 * NFSv3 cleared the issue, and requires fa_mode to not
		 * contain any type information (while also introducing
		 * sockets and FIFOs for fa_type).
		 */
		vtype = nfstov_type(vtype, nfsvers);
		if ((vtype == VNON) || ((vtype == VREG) && ((vmode & S_IFMT) != 0)))
			vtype = IFTOVT(vmode);
		nvap->nva_type = vtype;
	}

	nvap->nva_mode = (vmode & 07777);

	nfsm_chain_get_32(error, nmc, nvap->nva_nlink);
	nfsm_chain_get_32(error, nmc, nvap->nva_uid);
	nfsm_chain_get_32(error, nmc, nvap->nva_gid);

	if (nfsvers == NFS_VER3) {
		nfsm_chain_get_64(error, nmc, nvap->nva_size);
		nfsm_chain_get_64(error, nmc, nvap->nva_bytes);
		nfsm_chain_get_32(error, nmc, nvap->nva_rawdev.specdata1);
		nfsm_chain_get_32(error, nmc, nvap->nva_rawdev.specdata2);
		nfsmout_if(error);
		nfsm_chain_get_64(error, nmc, nvap->nva_fsid.major);
		nvap->nva_fsid.minor = 0;
		nfsm_chain_get_64(error, nmc, nvap->nva_fileid);
	} else {
		nfsm_chain_get_32(error, nmc, nvap->nva_size);
		nfsm_chain_adv(error, nmc, NFSX_UNSIGNED);
		nfsm_chain_get_32(error, nmc, rdev);
		nfsmout_if(error);
		nvap->nva_rawdev.specdata1 = major(rdev);
		nvap->nva_rawdev.specdata2 = minor(rdev);
		nfsm_chain_get_32(error, nmc, val); /* blocks */
		nfsmout_if(error);
		nvap->nva_bytes = val * NFS_FABLKSIZE;
		nfsm_chain_get_32(error, nmc, val);
		nfsmout_if(error);
		nvap->nva_fsid.major = (uint64_t)val;
		nvap->nva_fsid.minor = 0;
		nfsm_chain_get_32(error, nmc, val);
		nfsmout_if(error);
		nvap->nva_fileid = (uint64_t)val;
		/* Really ugly NFSv2 kludge. */
		if ((vtype == VCHR) && (rdev == (dev_t)0xffffffff))
			nvap->nva_type = VFIFO;
	}
	nfsm_chain_get_time(error, nmc, nfsvers,
		nvap->nva_timesec[NFSTIME_ACCESS],
		nvap->nva_timensec[NFSTIME_ACCESS]);
	nfsm_chain_get_time(error, nmc, nfsvers,
		nvap->nva_timesec[NFSTIME_MODIFY],
		nvap->nva_timensec[NFSTIME_MODIFY]);
	nfsm_chain_get_time(error, nmc, nfsvers,
		nvap->nva_timesec[NFSTIME_CHANGE],
		nvap->nva_timensec[NFSTIME_CHANGE]);
nfsmout:
	return (error);
}

/*
 * Load the attribute cache (that lives in the nfsnode entry) with
 * the value pointed to by nvap, unless the file type in the attribute
 * cache doesn't match the file type in the nvap, in which case log a
 * warning and return ESTALE.
 *
 * If the dontshrink flag is set, then it's not safe to call ubc_setsize()
 * to shrink the size of the file.
 */
int
nfs_loadattrcache(
	nfsnode_t np,
	struct nfs_vattr *nvap,
	u_int64_t *xidp,
	int dontshrink)
{
	mount_t mp;
	vnode_t vp;
	struct timeval now;
	struct nfs_vattr *npnvap;

	if (np->n_hflag & NHINIT) {
		vp = NULL;
		mp = np->n_mount;
	} else {
		vp = NFSTOV(np);
		mp = vnode_mount(vp);
	}

	FSDBG_TOP(527, np, vp, *xidp >> 32, *xidp);

	if (!VFSTONFS(mp)) {
		FSDBG_BOT(527, ENXIO, 1, 0, *xidp);
		return (ENXIO);
	}

	if (*xidp < np->n_xid) {
		/*
		 * We have already updated attributes with a response from
		 * a later request.  The attributes we have here are probably
		 * stale so we drop them (just return).  However, our
		 * out-of-order receipt could be correct - if the requests were
		 * processed out of order at the server.  Given the uncertainty
		 * we invalidate our cached attributes.  *xidp is zeroed here
		 * to indicate the attributes were dropped - only getattr
		 * cares - it needs to retry the rpc.
		 */
		NATTRINVALIDATE(np);
		FSDBG_BOT(527, 0, np, np->n_xid, *xidp);
		*xidp = 0;
		return (0);
	}

	if (vp && (nvap->nva_type != vnode_vtype(vp))) {
		/*
		 * The filehandle has changed type on us.  This can be
		 * caused by either the server not having unique filehandles
		 * or because another client has removed the previous
		 * filehandle and a new object (of a different type)
		 * has been created with the same filehandle.
		 *
		 * We can't simply switch the type on the vnode because
		 * there may be type-specific fields that need to be
		 * cleaned up or set up.
		 *
		 * So, what should we do with this vnode?
		 *
		 * About the best we can do is log a warning and return
		 * an error.  ESTALE is about the closest error, but it
		 * is a little strange that we come up with this error
		 * internally instead of simply passing it through from
		 * the server.  Hopefully, the vnode will be reclaimed
		 * soon so the filehandle can be reincarnated as the new
		 * object type.
		 */
		printf("nfs loadattrcache vnode changed type, was %d now %d\n",
			vnode_vtype(vp), nvap->nva_type);
		FSDBG_BOT(527, ESTALE, 3, 0, *xidp);
		return (ESTALE);
	}

	microuptime(&now);
	np->n_attrstamp = now.tv_sec;
	np->n_xid = *xidp;

	npnvap = &np->n_vattr;
	bcopy((caddr_t)nvap, (caddr_t)npnvap, sizeof(*nvap));

	if (nvap->nva_size != np->n_size) {
		/*
		 * n_size is protected by the data lock, so we need to
		 * defer updating it until it's safe.  We save the new size
		 * and set a flag and it'll get updated the next time we get/drop
		 * the data lock or the next time we do a getattr.
		 */
		np->n_newsize = nvap->nva_size;
		FSDBG(527, np, nvap->nva_size, np->n_size, (nvap->nva_type == VREG) | (np->n_flag & NMODIFIED ? 6 : 4));
		SET(np->n_flag, NUPDATESIZE);
		if (vp && (nvap->nva_type == VREG)) {
			if (!UBCINFOEXISTS(vp) || (dontshrink && (np->n_newsize < np->n_size))) {
				/* asked not to shrink, so stick with current size */
				FSDBG(527, np, np->n_size, np->n_vattr.nva_size, 0xf00d0001);
				nvap->nva_size = np->n_size;
				CLR(np->n_flag, NUPDATESIZE);
				NATTRINVALIDATE(np);
			} else if ((np->n_flag & NMODIFIED) && (nvap->nva_size < np->n_size)) {
				/* if we've modified, use larger size */
				FSDBG(527, np, np->n_size, np->n_vattr.nva_size, 0xf00d0002);
				nvap->nva_size = np->n_size;
				CLR(np->n_flag, NUPDATESIZE);
			}
		}
	}

	if (np->n_flag & NCHG) {
		if (np->n_flag & NACC) {
			nvap->nva_timesec[NFSTIME_ACCESS] = np->n_atim.tv_sec;
			nvap->nva_timensec[NFSTIME_ACCESS] = np->n_atim.tv_nsec;
		}
		if (np->n_flag & NUPD) {
			nvap->nva_timesec[NFSTIME_MODIFY] = np->n_mtim.tv_sec;
			nvap->nva_timensec[NFSTIME_MODIFY] = np->n_mtim.tv_nsec;
		}
	}

	FSDBG_BOT(527, 0, np, np->n_size, *xidp);
	return (0);
}

/*
 * Calculate the attribute timeout based on
 * how recently the file has been modified.
 */
int
nfs_attrcachetimeout(nfsnode_t np)
{
	struct nfsmount *nmp;
	struct timeval now;
	int isdir, timeo;

	if (!(nmp = NFSTONMP(np)))
		return (0);

	isdir = vnode_isdir(NFSTOV(np));

	if ((np)->n_flag & NMODIFIED)
		timeo = isdir ? nmp->nm_acdirmin : nmp->nm_acregmin;
	else {
		/* Note that if the client and server clocks are way out of sync, */
		/* timeout will probably get clamped to a min or max value */
		microtime(&now);
		timeo = (now.tv_sec - (np)->n_mtime.tv_sec) / 10;
		if (isdir) {
			if (timeo < nmp->nm_acdirmin)
				timeo = nmp->nm_acdirmin;
			else if (timeo > nmp->nm_acdirmax)
				timeo = nmp->nm_acdirmax;
		} else {
			if (timeo < nmp->nm_acregmin)
				timeo = nmp->nm_acregmin;
			else if (timeo > nmp->nm_acregmax)
				timeo = nmp->nm_acregmax;
		}
	}

	return (timeo);
}

/*
 * Check the time stamp
 * If the cache is valid, copy contents to *nvaper and return 0
 * otherwise return an error
 */
int
nfs_getattrcache(nfsnode_t np, struct nfs_vattr *nvaper, int alreadylocked)
{
	struct nfs_vattr *nvap;
	struct timeval nowup;
	int32_t timeo;

	if (!alreadylocked && nfs_lock(np, NFS_NODE_LOCK_SHARED)) {
		FSDBG(528, np, 0, 0xffffff00, ENOENT);
		OSAddAtomic(1, (SInt32*)&nfsstats.attrcache_misses);
		return (ENOENT);
	}

	if (!NATTRVALID(np)) {
		if (!alreadylocked)
			nfs_unlock(np);
		FSDBG(528, np, 0, 0xffffff01, ENOENT);
		OSAddAtomic(1, (SInt32*)&nfsstats.attrcache_misses);
		return (ENOENT);
	}

	timeo = nfs_attrcachetimeout(np);

	microuptime(&nowup);
	if ((nowup.tv_sec - np->n_attrstamp) >= timeo) {
		if (!alreadylocked)
			nfs_unlock(np);
		FSDBG(528, np, 0, 0xffffff02, ENOENT);
		OSAddAtomic(1, (SInt32*)&nfsstats.attrcache_misses);
		return (ENOENT);
	}

	nvap = &np->n_vattr;
	FSDBG(528, np, nvap->nva_size, np->n_size, 0xcace);
	OSAddAtomic(1, (SInt32*)&nfsstats.attrcache_hits);

	if (nvap->nva_size != np->n_size) {
		/*
		 * n_size is protected by the data lock, so we need to
		 * defer updating it until it's safe.  We save the new size
		 * and set a flag and it'll get updated the next time we get/drop
		 * the data lock or the next time we do a getattr.
		 */
		if (!alreadylocked) {
			/* need to upgrade shared lock to exclusive */
			if (lck_rw_lock_shared_to_exclusive(&np->n_lock) == FALSE)
				lck_rw_lock_exclusive(&np->n_lock);
		}
		np->n_newsize = nvap->nva_size;
		FSDBG(528, np, nvap->nva_size, np->n_size, (nvap->nva_type == VREG) | (np->n_flag & NMODIFIED ? 6 : 4));
		SET(np->n_flag, NUPDATESIZE);
		if ((nvap->nva_type == VREG) && (np->n_flag & NMODIFIED) &&
		    (nvap->nva_size < np->n_size)) {
			/* if we've modified, use larger size */
			nvap->nva_size = np->n_size;
			CLR(np->n_flag, NUPDATESIZE);
		}
	}

	bcopy((caddr_t)nvap, (caddr_t)nvaper, sizeof(struct nfs_vattr));
	if (np->n_flag & NCHG) {
		if (np->n_flag & NACC) {
			nvaper->nva_timesec[NFSTIME_ACCESS] = np->n_atim.tv_sec;
			nvaper->nva_timensec[NFSTIME_ACCESS] = np->n_atim.tv_nsec;
		}
		if (np->n_flag & NUPD) {
			nvaper->nva_timesec[NFSTIME_MODIFY] = np->n_mtim.tv_sec;
			nvaper->nva_timensec[NFSTIME_MODIFY] = np->n_mtim.tv_nsec;
		}
	}
	if (!alreadylocked)
		nfs_unlock(np);
	return (0);
}


static nfsuint64 nfs_nullcookie = { { 0, 0 } };
/*
 * This function finds the directory cookie that corresponds to the
 * logical byte offset given.
 */
nfsuint64 *
nfs_getcookie(nfsnode_t dnp, off_t off, int add)
{
	struct nfsdmap *dp, *dp2;
	int pos;

	pos = off / NFS_DIRBLKSIZ;
	if (pos == 0)
		return (&nfs_nullcookie);
	pos--;
	dp = dnp->n_cookies.lh_first;
	if (!dp) {
		if (add) {
			MALLOC_ZONE(dp, struct nfsdmap *, sizeof(struct nfsdmap),
					M_NFSDIROFF, M_WAITOK);
			if (!dp)
				return ((nfsuint64 *)0);
			dp->ndm_eocookie = 0;
			LIST_INSERT_HEAD(&dnp->n_cookies, dp, ndm_list);
		} else
			return ((nfsuint64 *)0);
	}
	while (pos >= NFSNUMCOOKIES) {
		pos -= NFSNUMCOOKIES;
		if (dp->ndm_list.le_next) {
			if (!add && dp->ndm_eocookie < NFSNUMCOOKIES &&
				pos >= dp->ndm_eocookie)
				return ((nfsuint64 *)0);
			dp = dp->ndm_list.le_next;
		} else if (add) {
			MALLOC_ZONE(dp2, struct nfsdmap *, sizeof(struct nfsdmap),
					M_NFSDIROFF, M_WAITOK);
			if (!dp2)
				return ((nfsuint64 *)0);
			dp2->ndm_eocookie = 0;
			LIST_INSERT_AFTER(dp, dp2, ndm_list);
			dp = dp2;
		} else
			return ((nfsuint64 *)0);
	}
	if (pos >= dp->ndm_eocookie) {
		if (add)
			dp->ndm_eocookie = pos + 1;
		else
			return ((nfsuint64 *)0);
	}
	return (&dp->ndm_cookies[pos]);
}

/*
 * Invalidate cached directory information, except for the actual directory
 * blocks (which are invalidated separately).
 * Done mainly to avoid the use of stale offset cookies.
 */
void
nfs_invaldir(nfsnode_t dnp)
{
	if (vnode_vtype(NFSTOV(dnp)) != VDIR) {
		printf("nfs: invaldir not dir\n");
		return;
	}
	dnp->n_direofoffset = 0;
	dnp->n_cookieverf.nfsuquad[0] = 0;
	dnp->n_cookieverf.nfsuquad[1] = 0;
	if (dnp->n_cookies.lh_first)
		dnp->n_cookies.lh_first->ndm_eocookie = 0;
}

#endif /* NFSCLIENT */

/*
 * Schedule a callout thread to run an NFS timer function
 * interval milliseconds in the future.
 */
void
nfs_interval_timer_start(thread_call_t call, int interval)
{
	uint64_t deadline;

	clock_interval_to_deadline(interval, 1000 * 1000, &deadline);
	thread_call_enter_delayed(call, deadline);
}


#if NFSSERVER

static void nfsrv_init_user_list(struct nfs_active_user_list *);
static void nfsrv_free_user_list(struct nfs_active_user_list *);

/*
 * add NFSv3 WCC data to an mbuf chain
 */
int
nfsm_chain_add_wcc_data_f(
	struct nfsrv_descript *nd,
	struct nfsm_chain *nmc,
	int preattrerr,
	struct vnode_attr *prevap,
	int postattrerr,
	struct vnode_attr *postvap)
{
	int error = 0;

	if (preattrerr) {
		nfsm_chain_add_32(error, nmc, FALSE);
	} else {
		nfsm_chain_add_32(error, nmc, TRUE);
		nfsm_chain_add_64(error, nmc, prevap->va_data_size);
		nfsm_chain_add_time(error, nmc, NFS_VER3, &prevap->va_modify_time);
		nfsm_chain_add_time(error, nmc, NFS_VER3, &prevap->va_change_time);
	}
	nfsm_chain_add_postop_attr(error, nd, nmc, postattrerr, postvap);

	return (error);
}

/*
 * Extract a lookup path from the given mbufs and store it in
 * a newly allocated buffer saved in the given nameidata structure.
 */
int
nfsm_chain_get_path_namei(
	struct nfsm_chain *nmc,
	uint32_t len,
	struct nameidata *nip)
{
	struct componentname *cnp = &nip->ni_cnd;
	int error = 0;
	char *cp;

	if (len > (MAXPATHLEN - 1))
		return (ENAMETOOLONG);

	/*
	 * Get a buffer for the name to be translated, and copy the
	 * name into the buffer.
	 */
	MALLOC_ZONE(cnp->cn_pnbuf, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (!cnp->cn_pnbuf)
		return (ENOMEM);
	cnp->cn_pnlen = MAXPATHLEN;
	cnp->cn_flags |= HASBUF;

	/* Copy the name from the mbuf list to the string */
	cp = cnp->cn_pnbuf;
	nfsm_chain_get_opaque(error, nmc, len, cp);
	if (error)
		goto out;
	cnp->cn_pnbuf[len] = '\0';

	/* sanity check the string */
	if ((strlen(cp) != len) || strchr(cp, '/'))
		error = EACCES;
out:
	if (error) {
		if (cnp->cn_pnbuf)
			FREE_ZONE(cnp->cn_pnbuf, MAXPATHLEN, M_NAMEI);
		cnp->cn_flags &= ~HASBUF;
	} else {
		nip->ni_pathlen = len;
	}
	return (error);
}

/*
 * Set up nameidata for a lookup() call and do it.
 */
int
nfsrv_namei(
	struct nfsrv_descript *nd,
	vfs_context_t ctx,
	struct nameidata *nip,
	struct nfs_filehandle *nfhp,
	vnode_t *retdirp,
	struct nfs_export **nxp,
	struct nfs_export_options **nxop)
{
	vnode_t dp;
	int error;
	struct componentname *cnp = &nip->ni_cnd;
	char *tmppn;

	*retdirp = NULL;

	/*
	 * Extract and set starting directory.
	 */
	error = nfsrv_fhtovp(nfhp, nd, &dp, nxp, nxop);
	if (error)
		goto out;
	error = nfsrv_credcheck(nd, ctx, *nxp, *nxop);
	if (error || (vnode_vtype(dp) != VDIR)) {
		vnode_put(dp);
		error = ENOTDIR;
		goto out;
	}
	*retdirp = dp;

	nip->ni_cnd.cn_context = ctx;

	if (*nxop && ((*nxop)->nxo_flags & NX_READONLY))
		cnp->cn_flags |= RDONLY;

	cnp->cn_flags |= NOCROSSMOUNT;
	cnp->cn_nameptr = cnp->cn_pnbuf;
	nip->ni_usedvp = nip->ni_startdir = dp;

	/*
	 * And call lookup() to do the real work
	 */
	error = lookup(nip);
	if (error)
		goto out;

	/* Check for encountering a symbolic link */
	if (cnp->cn_flags & ISSYMLINK) {
	        if ((cnp->cn_flags & FSNODELOCKHELD)) {
		        cnp->cn_flags &= ~FSNODELOCKHELD;
			unlock_fsnode(nip->ni_dvp, NULL);
		}
		if (cnp->cn_flags & (LOCKPARENT | WANTPARENT))
			vnode_put(nip->ni_dvp);
		if (nip->ni_vp) {
			vnode_put(nip->ni_vp);
			nip->ni_vp = NULL;
		}
		error = EINVAL;
	}
out:
	if (error) {
		tmppn = cnp->cn_pnbuf;
		cnp->cn_pnbuf = NULL;
		cnp->cn_flags &= ~HASBUF;
		FREE_ZONE(tmppn, cnp->cn_pnlen, M_NAMEI);
	}
	return (error);
}

/*
 * A fiddled version of m_adj() that ensures null fill to a long
 * boundary and only trims off the back end
 */
void
nfsm_adj(mbuf_t mp, int len, int nul)
{
	mbuf_t m, mnext;
	int count, i, mlen;
	char *cp;

	/*
	 * Trim from tail.  Scan the mbuf chain,
	 * calculating its length and finding the last mbuf.
	 * If the adjustment only affects this mbuf, then just
	 * adjust and return.  Otherwise, rescan and truncate
	 * after the remaining size.
	 */
	count = 0;
	m = mp;
	for (;;) {
		mlen = mbuf_len(m);
		count += mlen;
		mnext = mbuf_next(m);
		if (mnext == NULL)
			break;
		m = mnext;
	}
	if (mlen > len) {
		mlen -= len;
		mbuf_setlen(m, mlen);
		if (nul > 0) {
			cp = (caddr_t)mbuf_data(m) + mlen - nul;
			for (i = 0; i < nul; i++)
				*cp++ = '\0';
		}
		return;
	}
	count -= len;
	if (count < 0)
		count = 0;
	/*
	 * Correct length for chain is "count".
	 * Find the mbuf with last data, adjust its length,
	 * and toss data from remaining mbufs on chain.
	 */
	for (m = mp; m; m = mbuf_next(m)) {
		mlen = mbuf_len(m);
		if (mlen >= count) {
			mlen = count;
			mbuf_setlen(m, count);
			if (nul > 0) {
				cp = (caddr_t)mbuf_data(m) + mlen - nul;
				for (i = 0; i < nul; i++)
					*cp++ = '\0';
			}
			break;
		}
		count -= mlen;
	}
	for (m = mbuf_next(m); m; m = mbuf_next(m))
		mbuf_setlen(m, 0);
}

/*
 * Trim the header out of the mbuf list and trim off any trailing
 * junk so that the mbuf list has only the write data.
 */
int
nfsm_chain_trim_data(struct nfsm_chain *nmc, int len, int *mlen)
{
	int cnt = 0, dlen, adjust;
	caddr_t data;
	mbuf_t m;

	if (mlen)
		*mlen = 0;

	/* trim header */
	for (m = nmc->nmc_mhead; m && (m != nmc->nmc_mcur); m = mbuf_next(m))
		mbuf_setlen(m, 0);
	if (!m)
		return (EIO);

	/* trim current mbuf */
	data = mbuf_data(m);
	dlen = mbuf_len(m);
	adjust = nmc->nmc_ptr - data;
	dlen -= adjust;
	if ((dlen > 0) && (adjust > 0)) {
		if (mbuf_setdata(m, nmc->nmc_ptr, dlen))
			return(EIO);
	} else
		mbuf_setlen(m, dlen);

	/* skip next len bytes  */
	for (; m && (cnt < len); m = mbuf_next(m)) {
		dlen = mbuf_len(m);
		cnt += dlen;
		if (cnt > len) {
			/* truncate to end of data */
			mbuf_setlen(m, dlen - (cnt - len));
			if (m == nmc->nmc_mcur)
				nmc->nmc_left -= (cnt - len);
			cnt = len;
		}
	}
	if (mlen)
		*mlen = cnt;

	/* trim any trailing data */
	if (m == nmc->nmc_mcur)
		nmc->nmc_left = 0;
	for (; m; m = mbuf_next(m))
		mbuf_setlen(m, 0);

	return (0);
}

int
nfsm_chain_add_fattr(
	struct nfsrv_descript *nd,
	struct nfsm_chain *nmc,
	struct vnode_attr *vap)
{
	int error = 0;

	// XXX Should we assert here that all fields are supported?

	nfsm_chain_add_32(error, nmc, vtonfs_type(vap->va_type, nd->nd_vers));
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_32(error, nmc, vap->va_mode & 07777);
	} else {
		nfsm_chain_add_32(error, nmc, vtonfsv2_mode(vap->va_type, vap->va_mode));
	}
	nfsm_chain_add_32(error, nmc, vap->va_nlink);
	nfsm_chain_add_32(error, nmc, vap->va_uid);
	nfsm_chain_add_32(error, nmc, vap->va_gid);
	if (nd->nd_vers == NFS_VER3) {
		nfsm_chain_add_64(error, nmc, vap->va_data_size);
		nfsm_chain_add_64(error, nmc, vap->va_data_alloc);
		nfsm_chain_add_32(error, nmc, major(vap->va_rdev));
		nfsm_chain_add_32(error, nmc, minor(vap->va_rdev));
		nfsm_chain_add_64(error, nmc, vap->va_fsid);
		nfsm_chain_add_64(error, nmc, vap->va_fileid);
	} else {
		nfsm_chain_add_32(error, nmc, vap->va_data_size);
		nfsm_chain_add_32(error, nmc, NFS_FABLKSIZE);
		if (vap->va_type == VFIFO)
			nfsm_chain_add_32(error, nmc, 0xffffffff);
		else
			nfsm_chain_add_32(error, nmc, vap->va_rdev);
		nfsm_chain_add_32(error, nmc, vap->va_data_alloc / NFS_FABLKSIZE);
		nfsm_chain_add_32(error, nmc, vap->va_fsid);
		nfsm_chain_add_32(error, nmc, vap->va_fileid);
	}
	nfsm_chain_add_time(error, nmc, nd->nd_vers, &vap->va_access_time);
	nfsm_chain_add_time(error, nmc, nd->nd_vers, &vap->va_modify_time);
	nfsm_chain_add_time(error, nmc, nd->nd_vers, &vap->va_change_time);

	return (error);
}

int
nfsm_chain_get_sattr(
	struct nfsrv_descript *nd,
	struct nfsm_chain *nmc,
	struct vnode_attr *vap)
{
	int error = 0, nullflag = 0;
	uint32_t val = 0;
	uint64_t val64;
	struct timespec now;

	if (nd->nd_vers == NFS_VER2) {
		/*
		 * There is/was a bug in the Sun client that puts 0xffff in the mode
		 * field of sattr when it should put in 0xffffffff.  The u_short
		 * doesn't sign extend.  So check the low order 2 bytes for 0xffff.
		 */
		nfsm_chain_get_32(error, nmc, val);
		if ((val & 0xffff) != 0xffff) {
			VATTR_SET(vap, va_mode, val & 07777);
			/* save the "type" bits for NFSv2 create */
			VATTR_SET(vap, va_type, IFTOVT(val));
			VATTR_CLEAR_ACTIVE(vap, va_type);
		}
		nfsm_chain_get_32(error, nmc, val);
		if (val != (uint32_t)-1)
			VATTR_SET(vap, va_uid, val);
		nfsm_chain_get_32(error, nmc, val);
		if (val != (uint32_t)-1)
			VATTR_SET(vap, va_gid, val);
		/* save the "size" bits for NFSv2 create (even if they appear unset) */
		nfsm_chain_get_32(error, nmc, val);
		VATTR_SET(vap, va_data_size, val);
		if (val == (uint32_t)-1)
			VATTR_CLEAR_ACTIVE(vap, va_data_size);
		nfsm_chain_get_time(error, nmc, NFS_VER2,
			vap->va_access_time.tv_sec,
			vap->va_access_time.tv_nsec);
		if (vap->va_access_time.tv_sec != -1)
			VATTR_SET_ACTIVE(vap, va_access_time);
		nfsm_chain_get_time(error, nmc, NFS_VER2,
			vap->va_modify_time.tv_sec,
			vap->va_modify_time.tv_nsec);
		if (vap->va_modify_time.tv_sec != -1)
			VATTR_SET_ACTIVE(vap, va_modify_time);
		return (error);
	}

	/* NFSv3 */
	nfsm_chain_get_32(error, nmc, val);
	if (val) {
		nfsm_chain_get_32(error, nmc, val);
		VATTR_SET(vap, va_mode, val & 07777);
	}
	nfsm_chain_get_32(error, nmc, val);
	if (val) {
		nfsm_chain_get_32(error, nmc, val);
		VATTR_SET(vap, va_uid, val);
	}
	nfsm_chain_get_32(error, nmc, val);
	if (val) {
		nfsm_chain_get_32(error, nmc, val);
		VATTR_SET(vap, va_gid, val);
	}
	nfsm_chain_get_32(error, nmc, val);
	if (val) {
		nfsm_chain_get_64(error, nmc, val64);
		VATTR_SET(vap, va_data_size, val64);
	}
	nanotime(&now);
	nfsm_chain_get_32(error, nmc, val);
	switch (val) {
	case NFS_TIME_SET_TO_CLIENT:
		nfsm_chain_get_time(error, nmc, nd->nd_vers,
			vap->va_access_time.tv_sec,
			vap->va_access_time.tv_nsec);
		VATTR_SET_ACTIVE(vap, va_access_time);
		break;
	case NFS_TIME_SET_TO_SERVER:
		VATTR_SET(vap, va_access_time, now);
		nullflag = VA_UTIMES_NULL;
		break;
	}
	nfsm_chain_get_32(error, nmc, val);
	switch (val) {
	case NFS_TIME_SET_TO_CLIENT:
		nfsm_chain_get_time(error, nmc, nd->nd_vers,
			vap->va_modify_time.tv_sec,
			vap->va_modify_time.tv_nsec);
		VATTR_SET_ACTIVE(vap, va_modify_time);
		break;
	case NFS_TIME_SET_TO_SERVER:
		VATTR_SET(vap, va_modify_time, now);
		vap->va_vaflags |= nullflag;
		break;
	}

	return (error);
}

/*
 * Compare two security flavor structs
 */
static int
nfsrv_cmp_secflavs(struct nfs_sec *sf1, struct nfs_sec *sf2)
{
	int i;

	if (sf1->count != sf2->count)
		return 1;
	for (i = 0; i < sf1->count; i++)
		if (sf1->flavors[i] != sf2->flavors[i])
			return 1;
	return 0;
}

/*
 * Build hash lists of net addresses and hang them off the NFS export.
 * Called by nfsrv_export() to set up the lists of export addresses.
 */
static int
nfsrv_hang_addrlist(struct nfs_export *nx, struct user_nfs_export_args *unxa)
{
	struct nfs_export_net_args nxna;
	struct nfs_netopt *no, *rn_no;
	struct radix_node_head *rnh;
	struct radix_node *rn;
	struct sockaddr *saddr, *smask;
	struct domain *dom;
	int i, error;
	unsigned int net;
	user_addr_t uaddr;
	kauth_cred_t cred;
	struct ucred temp_cred;

	uaddr = unxa->nxa_nets;
	for (net = 0; net < unxa->nxa_netcount; net++, uaddr += sizeof(nxna)) {
		error = copyin(uaddr, &nxna, sizeof(nxna));
		if (error)
			return (error);

		if (nxna.nxna_flags & (NX_MAPROOT|NX_MAPALL)) {
		        bzero(&temp_cred, sizeof(temp_cred));
			temp_cred.cr_uid = nxna.nxna_cred.cr_uid;
			temp_cred.cr_ngroups = nxna.nxna_cred.cr_ngroups;
			for (i=0; i < nxna.nxna_cred.cr_ngroups && i < NGROUPS; i++)
				temp_cred.cr_groups[i] = nxna.nxna_cred.cr_groups[i];
			cred = kauth_cred_create(&temp_cred);
			if (!IS_VALID_CRED(cred))
				return (ENOMEM);
		} else {
			cred = NOCRED;
		}

		if (nxna.nxna_addr.ss_len == 0) {
			/* No address means this is a default/world export */
			if (nx->nx_flags & NX_DEFAULTEXPORT) {
			        if (IS_VALID_CRED(cred))
				        kauth_cred_unref(&cred);
				return (EEXIST);
			}
			nx->nx_flags |= NX_DEFAULTEXPORT;
			nx->nx_defopt.nxo_flags = nxna.nxna_flags;
			nx->nx_defopt.nxo_cred = cred;
			bcopy(&nxna.nxna_sec, &nx->nx_defopt.nxo_sec, sizeof(struct nfs_sec));
			nx->nx_expcnt++;
			continue;
		}

		i = sizeof(struct nfs_netopt);
		i += nxna.nxna_addr.ss_len + nxna.nxna_mask.ss_len;
		MALLOC(no, struct nfs_netopt *, i, M_NETADDR, M_WAITOK);
		if (!no) {
			if (IS_VALID_CRED(cred))
				kauth_cred_unref(&cred);
			return (ENOMEM);
		}
		bzero(no, sizeof(struct nfs_netopt));
		no->no_opt.nxo_flags = nxna.nxna_flags;
		no->no_opt.nxo_cred = cred;
		bcopy(&nxna.nxna_sec, &no->no_opt.nxo_sec, sizeof(struct nfs_sec));

		saddr = (struct sockaddr *)(no + 1);
		bcopy(&nxna.nxna_addr, saddr, nxna.nxna_addr.ss_len);
		if (nxna.nxna_mask.ss_len) {
			smask = (struct sockaddr *)((caddr_t)saddr + nxna.nxna_addr.ss_len);
			bcopy(&nxna.nxna_mask, smask, nxna.nxna_mask.ss_len);
		} else {
			smask = NULL;
		}
		i = saddr->sa_family;
		if ((rnh = nx->nx_rtable[i]) == 0) {
			/*
			 * Seems silly to initialize every AF when most are not
			 * used, do so on demand here
			 */
			for (dom = domains; dom; dom = dom->dom_next)
				if (dom->dom_family == i && dom->dom_rtattach) {
					dom->dom_rtattach((void **)&nx->nx_rtable[i],
						dom->dom_rtoffset);
					break;
				}
			if ((rnh = nx->nx_rtable[i]) == 0) {
			        if (IS_VALID_CRED(cred))
				        kauth_cred_unref(&cred);
				_FREE(no, M_NETADDR);
				return (ENOBUFS);
			}
		}
		rn = (*rnh->rnh_addaddr)((caddr_t)saddr, (caddr_t)smask, rnh, no->no_rnodes);
		if (rn == 0) {
			/*
			 * One of the reasons that rnh_addaddr may fail is that
			 * the entry already exists. To check for this case, we
			 * look up the entry to see if it is there. If so, we
			 * do not need to make a new entry but do continue.
			 *
			 * XXX should this be rnh_lookup() instead?
			 */
			int matched = 0;
			rn = (*rnh->rnh_matchaddr)((caddr_t)saddr, rnh);
			rn_no = (struct nfs_netopt *)rn;
			if (rn != 0 && (rn->rn_flags & RNF_ROOT) == 0 &&
			    (rn_no->no_opt.nxo_flags == nxna.nxna_flags) &&
			    (!nfsrv_cmp_secflavs(&rn_no->no_opt.nxo_sec, &nxna.nxna_sec))) {
				kauth_cred_t cred2 = rn_no->no_opt.nxo_cred;
				if (cred == cred2) {
					/* creds are same (or both NULL) */
					matched = 1;
				} else if (cred && cred2 && (cred->cr_uid == cred2->cr_uid) &&
				    (cred->cr_ngroups == cred2->cr_ngroups)) {
					for (i=0; i < cred2->cr_ngroups && i < NGROUPS; i++)
						if (cred->cr_groups[i] != cred2->cr_groups[i])
							break;
					if (i >= cred2->cr_ngroups || i >= NGROUPS)
						matched = 1;
				}
			}
			if (IS_VALID_CRED(cred))
			        kauth_cred_unref(&cred);
			_FREE(no, M_NETADDR);
			if (matched)
				continue;
			return (EPERM);
		}
		nx->nx_expcnt++;
	}

	return (0);
}

/*
 * In order to properly track an export's netopt count, we need to pass
 * an additional argument to nfsrv_free_netopt() so that it can decrement
 * the export's netopt count.
 */
struct nfsrv_free_netopt_arg {
	uint32_t *cnt;
	struct radix_node_head *rnh;
};

static int
nfsrv_free_netopt(struct radix_node *rn, void *w)
{
	struct nfsrv_free_netopt_arg *fna = (struct nfsrv_free_netopt_arg *)w;
	struct radix_node_head *rnh = fna->rnh;
	uint32_t *cnt = fna->cnt;
	struct nfs_netopt *nno = (struct nfs_netopt *)rn;

	(*rnh->rnh_deladdr)(rn->rn_key, rn->rn_mask, rnh);
	if (IS_VALID_CRED(nno->no_opt.nxo_cred))
		kauth_cred_unref(&nno->no_opt.nxo_cred);
	_FREE((caddr_t)rn, M_NETADDR);
	*cnt -= 1;
	return (0);
}

/*
 * Free the net address hash lists that are hanging off the mount points.
 */
static int
nfsrv_free_addrlist(struct nfs_export *nx, struct user_nfs_export_args *unxa)
{
	struct nfs_export_net_args nxna;
	struct radix_node_head *rnh;
	struct radix_node *rn;
	struct nfsrv_free_netopt_arg fna;
	struct nfs_netopt *nno;
	user_addr_t uaddr;
	unsigned int net;
	int i, error;

	if (!unxa || !unxa->nxa_netcount) {
		/* delete everything */
		for (i = 0; i <= AF_MAX; i++)
			if ( (rnh = nx->nx_rtable[i]) ) {
				fna.rnh = rnh;
				fna.cnt = &nx->nx_expcnt;
				(*rnh->rnh_walktree)(rnh, nfsrv_free_netopt, (caddr_t)&fna);
				_FREE((caddr_t)rnh, M_RTABLE);
				nx->nx_rtable[i] = 0;
			}
		return (0);
	}

	/* delete only the exports specified */
	uaddr = unxa->nxa_nets;
	for (net = 0; net < unxa->nxa_netcount; net++, uaddr += sizeof(nxna)) {
		error = copyin(uaddr, &nxna, sizeof(nxna));
		if (error)
			return (error);

		if (nxna.nxna_addr.ss_len == 0) {
			/* No address means this is a default/world export */
			if (nx->nx_flags & NX_DEFAULTEXPORT) {
				nx->nx_flags &= ~NX_DEFAULTEXPORT;
				if (IS_VALID_CRED(nx->nx_defopt.nxo_cred)) {
					kauth_cred_unref(&nx->nx_defopt.nxo_cred);
				}
				nx->nx_expcnt--;
			}
			continue;
		}

		if ((rnh = nx->nx_rtable[nxna.nxna_addr.ss_family]) == 0) {
			/* AF not initialized? */
			if (!(unxa->nxa_flags & NXA_ADD))
				printf("nfsrv_free_addrlist: address not found (0)\n");
			continue;
		}

		rn = (*rnh->rnh_lookup)(&nxna.nxna_addr,
			nxna.nxna_mask.ss_len ? &nxna.nxna_mask : NULL, rnh);
		if (!rn || (rn->rn_flags & RNF_ROOT)) {
			if (!(unxa->nxa_flags & NXA_ADD))
				printf("nfsrv_free_addrlist: address not found (1)\n");
			continue;
		}

		(*rnh->rnh_deladdr)(rn->rn_key, rn->rn_mask, rnh);
		nno = (struct nfs_netopt *)rn;
		if (IS_VALID_CRED(nno->no_opt.nxo_cred))
			kauth_cred_unref(&nno->no_opt.nxo_cred);
		_FREE((caddr_t)rn, M_NETADDR);

		nx->nx_expcnt--;
		if (nx->nx_expcnt == ((nx->nx_flags & NX_DEFAULTEXPORT) ? 1 : 0)) {
			/* no more entries in rnh, so free it up */
			_FREE((caddr_t)rnh, M_RTABLE);
			nx->nx_rtable[nxna.nxna_addr.ss_family] = 0;
		}
	}

	return (0);
}

void enablequotas(struct mount *mp, vfs_context_t ctx); // XXX

int
nfsrv_export(struct user_nfs_export_args *unxa, vfs_context_t ctx)
{
	int error = 0, pathlen;
	struct nfs_exportfs *nxfs, *nxfs2, *nxfs3;
	struct nfs_export *nx, *nx2, *nx3;
	struct nfs_filehandle nfh;
	struct nameidata mnd, xnd;
	vnode_t mvp = NULL, xvp = NULL;
	mount_t mp = NULL;
	char path[MAXPATHLEN];
	int expisroot;

	if (unxa->nxa_flags & NXA_DELETE_ALL) {
		/* delete all exports on all file systems */
		lck_rw_lock_exclusive(&nfsrv_export_rwlock);
		while ((nxfs = LIST_FIRST(&nfsrv_exports))) {
			mp = vfs_getvfs_by_mntonname(nxfs->nxfs_path);
			if (mp)
				vfs_clearflags(mp, MNT_EXPORTED);
			/* delete all exports on this file system */
			while ((nx = LIST_FIRST(&nxfs->nxfs_exports))) {
				LIST_REMOVE(nx, nx_next);
				LIST_REMOVE(nx, nx_hash);
				/* delete all netopts for this export */
				nfsrv_free_addrlist(nx, NULL);
				nx->nx_flags &= ~NX_DEFAULTEXPORT;
				if (IS_VALID_CRED(nx->nx_defopt.nxo_cred)) {
					kauth_cred_unref(&nx->nx_defopt.nxo_cred);
				}
				/* free active user list for this export */
				nfsrv_free_user_list(&nx->nx_user_list);
				FREE(nx->nx_path, M_TEMP);
				FREE(nx, M_TEMP);
			}
			LIST_REMOVE(nxfs, nxfs_next);
			FREE(nxfs->nxfs_path, M_TEMP);
			FREE(nxfs, M_TEMP);
		}
		lck_rw_done(&nfsrv_export_rwlock);
		return (0);
	}

	error = copyinstr(unxa->nxa_fspath, path, MAXPATHLEN, (size_t *)&pathlen);
	if (error)
		return (error);

	lck_rw_lock_exclusive(&nfsrv_export_rwlock);

	// first check if we've already got an exportfs with the given ID
	LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next) {
		if (nxfs->nxfs_id == unxa->nxa_fsid)
			break;
	}
	if (nxfs) {
		/* verify exported FS path matches given path */
		if (strncmp(path, nxfs->nxfs_path, MAXPATHLEN)) {
			error = EEXIST;
			goto unlock_out;
		}
		if ((unxa->nxa_flags & (NXA_ADD|NXA_OFFLINE)) == NXA_ADD) {
			/* if adding, verify that the mount is still what we expect */
			mp = vfs_getvfs_by_mntonname(nxfs->nxfs_path);
			/* find exported FS root vnode */
			NDINIT(&mnd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
				UIO_SYSSPACE, CAST_USER_ADDR_T(nxfs->nxfs_path), ctx);
			error = namei(&mnd);
			if (error)
				goto unlock_out;
			mvp = mnd.ni_vp;
			/* make sure it's (still) the root of a file system */
			if (!vnode_isvroot(mvp)) {
				error = EINVAL;
				goto out;
			}
			/* sanity check: this should be same mount */
			if (mp != vnode_mount(mvp)) {
				error = EINVAL;
				goto out;
			}
		}
	} else {
		/* no current exported file system with that ID */
		if (!(unxa->nxa_flags & NXA_ADD)) {
			error = ENOENT;
			goto unlock_out;
		}

		/* find exported FS root vnode */
		NDINIT(&mnd, LOOKUP, FOLLOW | LOCKLEAF | AUDITVNPATH1,
			UIO_SYSSPACE, CAST_USER_ADDR_T(path), ctx);
		error = namei(&mnd);
		if (error) {
			if (!(unxa->nxa_flags & NXA_OFFLINE))
				goto unlock_out;
		} else {
			mvp = mnd.ni_vp;
			/* make sure it's the root of a file system */
			if (!vnode_isvroot(mvp)) {
				/* bail if not marked offline */
				if (!(unxa->nxa_flags & NXA_OFFLINE)) {
					error = EINVAL;
					goto out;
				}
				vnode_put(mvp);
				nameidone(&mnd);
				mvp = NULL;
			} else {
				mp = vnode_mount(mvp);

				/* make sure the file system is NFS-exportable */
				nfh.nfh_len = NFSV3_MAX_FID_SIZE;
				error = VFS_VPTOFH(mvp, (int*)&nfh.nfh_len, &nfh.nfh_fid[0], NULL);
				if (!error && (nfh.nfh_len > (int)NFSV3_MAX_FID_SIZE))
					error = EIO;
				if (error)
					goto out;
			}
		}

		/* add an exportfs for it */
		MALLOC(nxfs, struct nfs_exportfs *, sizeof(struct nfs_exportfs), M_TEMP, M_WAITOK);
		if (!nxfs) {
			error = ENOMEM;
			goto out;
		}
		bzero(nxfs, sizeof(struct nfs_exportfs));
		nxfs->nxfs_id = unxa->nxa_fsid;
		MALLOC(nxfs->nxfs_path, char*, pathlen, M_TEMP, M_WAITOK);
		if (!nxfs->nxfs_path) {
			FREE(nxfs, M_TEMP);
			error = ENOMEM;
			goto out;
		}
		bcopy(path, nxfs->nxfs_path, pathlen);
		/* insert into list in reverse-sorted order */
		nxfs3 = NULL;
		LIST_FOREACH(nxfs2, &nfsrv_exports, nxfs_next) {
			if (strncmp(nxfs->nxfs_path, nxfs2->nxfs_path, MAXPATHLEN) > 0)
				break;
			nxfs3 = nxfs2;
		}
		if (nxfs2)
			LIST_INSERT_BEFORE(nxfs2, nxfs, nxfs_next);
		else if (nxfs3)
			LIST_INSERT_AFTER(nxfs3, nxfs, nxfs_next);
		else
			LIST_INSERT_HEAD(&nfsrv_exports, nxfs, nxfs_next);

		/* make sure any quotas are enabled before we export the file system */
		if (mp)
			enablequotas(mp, ctx);
	}

	if (unxa->nxa_exppath) {
		error = copyinstr(unxa->nxa_exppath, path, MAXPATHLEN, (size_t *)&pathlen);
		if (error)
			goto out;
		LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
			if (nx->nx_id == unxa->nxa_expid)
				break;
		}
		if (nx) {
			/* verify exported FS path matches given path */
			if (strncmp(path, nx->nx_path, MAXPATHLEN)) {
				error = EEXIST;
				goto out;
			}
		} else {
			/* no current export with that ID */
			if (!(unxa->nxa_flags & NXA_ADD)) {
				error = ENOENT;
				goto out;
			}
			/* add an export for it */
			MALLOC(nx, struct nfs_export *, sizeof(struct nfs_export), M_TEMP, M_WAITOK);
			if (!nx) {
				error = ENOMEM;
				goto out1;
			}
			bzero(nx, sizeof(struct nfs_export));
			nx->nx_id = unxa->nxa_expid;
			nx->nx_fs = nxfs;
			microtime(&nx->nx_exptime);
			MALLOC(nx->nx_path, char*, pathlen, M_TEMP, M_WAITOK);
			if (!nx->nx_path) {
				error = ENOMEM;
				FREE(nx, M_TEMP);
				nx = NULL;
				goto out1;
			}
			bcopy(path, nx->nx_path, pathlen);
			/* initialize the active user list */
			nfsrv_init_user_list(&nx->nx_user_list);
			/* insert into list in reverse-sorted order */
			nx3 = NULL;
			LIST_FOREACH(nx2, &nxfs->nxfs_exports, nx_next) {
				if (strncmp(nx->nx_path, nx2->nx_path, MAXPATHLEN) > 0)
					break;
				nx3 = nx2;
			}
			if (nx2)
				LIST_INSERT_BEFORE(nx2, nx, nx_next);
			else if (nx3)
				LIST_INSERT_AFTER(nx3, nx, nx_next);
			else
				LIST_INSERT_HEAD(&nxfs->nxfs_exports, nx, nx_next);
			/* insert into hash */
			LIST_INSERT_HEAD(NFSRVEXPHASH(nxfs->nxfs_id, nx->nx_id), nx, nx_hash);

			/*
			 * We don't allow/support nested exports.  Check if the new entry
			 * nests with the entries before and after or if there's an
			 * entry for the file system root and subdirs.
			 */
			error = 0;
			if ((nx3 && !strncmp(nx3->nx_path, nx->nx_path, pathlen - 1) &&
				    (nx3->nx_path[pathlen-1] == '/')) ||
			    (nx2 && !strncmp(nx2->nx_path, nx->nx_path, strlen(nx2->nx_path)) &&
			    	    (nx->nx_path[strlen(nx2->nx_path)] == '/')))
				error = EINVAL;
			if (!error) {
				/* check export conflict with fs root export and vice versa */
				expisroot = !nx->nx_path[0] ||
					    ((nx->nx_path[0] == '.') && !nx->nx_path[1]);
				LIST_FOREACH(nx2, &nxfs->nxfs_exports, nx_next) {
					if (expisroot) {
						if (nx2 != nx)
							break;
					} else if (!nx2->nx_path[0])
						break;
					else if ((nx2->nx_path[0] == '.') && !nx2->nx_path[1])
						break;
				}
				if (nx2)
					error = EINVAL;
			}
			if (error) {
				/*
				 * Don't actually return an error because mountd is
				 * probably about to delete the conflicting export.
				 * This can happen when a new export momentarily conflicts
				 * with an old export while the transition is being made.
				 * Theoretically, mountd could be written to avoid this
				 * transient situation - but it would greatly increase the
				 * complexity of mountd for very little overall benefit.
				 */
				printf("nfsrv_export: warning: nested exports: %s/%s\n",
					nxfs->nxfs_path, nx->nx_path);
				error = 0;
			}
			nx->nx_fh.nfh_xh.nxh_flags = NXHF_INVALIDFH;
		}
		/* make sure file handle is set up */
		if ((nx->nx_fh.nfh_xh.nxh_version != htonl(NFS_FH_VERSION)) ||
		    (nx->nx_fh.nfh_xh.nxh_flags & NXHF_INVALIDFH)) {
			/* try to set up export root file handle */
			nx->nx_fh.nfh_xh.nxh_version = htonl(NFS_FH_VERSION);
			nx->nx_fh.nfh_xh.nxh_fsid = htonl(nx->nx_fs->nxfs_id);
			nx->nx_fh.nfh_xh.nxh_expid = htonl(nx->nx_id);
			nx->nx_fh.nfh_xh.nxh_flags = 0;
			nx->nx_fh.nfh_xh.nxh_reserved = 0;
			nx->nx_fh.nfh_fhp = (u_char*)&nx->nx_fh.nfh_xh;
			bzero(&nx->nx_fh.nfh_fid[0], NFSV2_MAX_FID_SIZE);
			if (mvp) {
				/* find export root vnode */
				if (!nx->nx_path[0] || ((nx->nx_path[0] == '.') && !nx->nx_path[1])) {
					/* exporting file system's root directory */
					xvp = mvp;
					vnode_get(xvp);
				} else {
					xnd.ni_cnd.cn_nameiop = LOOKUP;
					xnd.ni_cnd.cn_flags = LOCKLEAF;
					xnd.ni_pathlen = pathlen - 1;
					xnd.ni_cnd.cn_nameptr = xnd.ni_cnd.cn_pnbuf = path;
					xnd.ni_startdir = mvp;
					xnd.ni_usedvp   = mvp;
					xnd.ni_cnd.cn_context = ctx;
					error = lookup(&xnd);
					if (error)
						goto out1;
					xvp = xnd.ni_vp;
				}

				if (vnode_vtype(xvp) != VDIR) {
					error = EINVAL;
					vnode_put(xvp);
					goto out1;
				}

				/* grab file handle */
				nx->nx_fh.nfh_len = NFSV3_MAX_FID_SIZE;
				error = VFS_VPTOFH(xvp, (int*)&nx->nx_fh.nfh_len, &nx->nx_fh.nfh_fid[0], NULL);
				if (!error && (nx->nx_fh.nfh_len > (int)NFSV3_MAX_FID_SIZE)) {
					error = EIO;
				} else {
					nx->nx_fh.nfh_xh.nxh_fidlen = nx->nx_fh.nfh_len;
					nx->nx_fh.nfh_len += sizeof(nx->nx_fh.nfh_xh);
				}

				vnode_put(xvp);
				if (error)
					goto out1;
			} else {
				nx->nx_fh.nfh_xh.nxh_flags = NXHF_INVALIDFH;
				nx->nx_fh.nfh_xh.nxh_fidlen = 0;
				nx->nx_fh.nfh_len = sizeof(nx->nx_fh.nfh_xh);
			}
		}
	} else {
		nx = NULL;
	}

	/* perform the export changes */
	if (unxa->nxa_flags & NXA_DELETE) {
		if (!nx) {
			/* delete all exports on this file system */
			while ((nx = LIST_FIRST(&nxfs->nxfs_exports))) {
				LIST_REMOVE(nx, nx_next);
				LIST_REMOVE(nx, nx_hash);
				/* delete all netopts for this export */
				nfsrv_free_addrlist(nx, NULL);
				nx->nx_flags &= ~NX_DEFAULTEXPORT;
				if (IS_VALID_CRED(nx->nx_defopt.nxo_cred)) {
					kauth_cred_unref(&nx->nx_defopt.nxo_cred);
				}
				/* delete active user list for this export */
				nfsrv_free_user_list(&nx->nx_user_list);
				FREE(nx->nx_path, M_TEMP);
				FREE(nx, M_TEMP);
			}
			goto out1;
		} else if (!unxa->nxa_netcount) {
			/* delete all netopts for this export */
			nfsrv_free_addrlist(nx, NULL);
			nx->nx_flags &= ~NX_DEFAULTEXPORT;
			if (IS_VALID_CRED(nx->nx_defopt.nxo_cred)) {
				kauth_cred_unref(&nx->nx_defopt.nxo_cred);
			}
		} else {
			/* delete only the netopts for the given addresses */
			error = nfsrv_free_addrlist(nx, unxa);
			if (error)
				goto out1;
		}
	}
	if (unxa->nxa_flags & NXA_ADD) {
		/* 
		 * If going offline set the export time so that when
		 * coming back on line we will present a new write verifier
		 * to the client.
		 */
		if (unxa->nxa_flags & NXA_OFFLINE)
			microtime(&nx->nx_exptime);

		error = nfsrv_hang_addrlist(nx, unxa);
		if (!error && mp)
			vfs_setflags(mp, MNT_EXPORTED);
	}

out1:
	if (nx && !nx->nx_expcnt) {
		/* export has no export options */
		LIST_REMOVE(nx, nx_next);
		LIST_REMOVE(nx, nx_hash);
		/* delete active user list for this export */
		nfsrv_free_user_list(&nx->nx_user_list);
		FREE(nx->nx_path, M_TEMP);
		FREE(nx, M_TEMP);
	}
	if (LIST_EMPTY(&nxfs->nxfs_exports)) {
		/* exported file system has no more exports */
		LIST_REMOVE(nxfs, nxfs_next);
		FREE(nxfs->nxfs_path, M_TEMP);
		FREE(nxfs, M_TEMP);
		if (mp)
			vfs_clearflags(mp, MNT_EXPORTED);
	}

out:
	if (mvp) {
		vnode_put(mvp);
		nameidone(&mnd);
	}
unlock_out:
	lck_rw_done(&nfsrv_export_rwlock);
	return (error);
}

static struct nfs_export_options *
nfsrv_export_lookup(struct nfs_export *nx, mbuf_t nam)
{
	struct nfs_export_options *nxo = NULL;
	struct nfs_netopt *no = NULL;
	struct radix_node_head *rnh;
	struct sockaddr *saddr;

	/* Lookup in the export list first. */
	if (nam != NULL) {
		saddr = mbuf_data(nam);
		rnh = nx->nx_rtable[saddr->sa_family];
		if (rnh != NULL) {
			no = (struct nfs_netopt *)
				(*rnh->rnh_matchaddr)((caddr_t)saddr, rnh);
			if (no && no->no_rnodes->rn_flags & RNF_ROOT)
				no = NULL;
			if (no)
				nxo = &no->no_opt;
		}
	}
	/* If no address match, use the default if it exists. */
	if ((nxo == NULL) && (nx->nx_flags & NX_DEFAULTEXPORT))
		nxo = &nx->nx_defopt;
	return (nxo);
}

/* find an export for the given handle */
static struct nfs_export *
nfsrv_fhtoexport(struct nfs_filehandle *nfhp)
{
	struct nfs_exphandle *nxh = (struct nfs_exphandle*)nfhp->nfh_fhp;
	struct nfs_export *nx;
	uint32_t fsid, expid;

	fsid = ntohl(nxh->nxh_fsid);
	expid = ntohl(nxh->nxh_expid);
	nx = NFSRVEXPHASH(fsid, expid)->lh_first;
	for (; nx; nx = LIST_NEXT(nx, nx_hash)) {
		if (nx->nx_fs->nxfs_id != fsid)
			continue;
		if (nx->nx_id != expid)
			continue;
		break;
	}
	return nx;
}

/*
 * nfsrv_fhtovp() - convert FH to vnode and export info
 */
int
nfsrv_fhtovp(
	struct nfs_filehandle *nfhp,
	struct nfsrv_descript *nd,
	vnode_t *vpp,
	struct nfs_export **nxp,
	struct nfs_export_options **nxop)
{
	struct nfs_exphandle *nxh = (struct nfs_exphandle*)nfhp->nfh_fhp;
	struct nfs_export_options *nxo;
	u_char *fidp;
	int error;
	struct mount *mp;
	mbuf_t nam = NULL;
	uint32_t v;
	int i, valid;

	*vpp = NULL;
	*nxp = NULL;
	*nxop = NULL;

	if (nd != NULL)
		nam = nd->nd_nam;

	v = ntohl(nxh->nxh_version);
	if (v != NFS_FH_VERSION) {
		/* file handle format not supported */
		return (ESTALE);
	}
	if (nfhp->nfh_len > NFSV3_MAX_FH_SIZE)
		return (EBADRPC);
	if (nfhp->nfh_len < (int)sizeof(struct nfs_exphandle))
		return (ESTALE);
	v = ntohs(nxh->nxh_flags);
	if (v & NXHF_INVALIDFH)
		return (ESTALE);

	*nxp = nfsrv_fhtoexport(nfhp);
	if (!*nxp)
		return (ESTALE);

	/* Get the export option structure for this <export, client> tuple. */
	*nxop = nxo = nfsrv_export_lookup(*nxp, nam);
	if (nam && (*nxop == NULL))
		return (EACCES);

	if (nd != NULL) {
		/* Validate the security flavor of the request */
		for (i = 0, valid = 0; i < nxo->nxo_sec.count; i++) {
			if (nd->nd_sec == nxo->nxo_sec.flavors[i]) {
				valid = 1;
				break;
			}
		}
		if (!valid) {
			/*
			 * RFC 2623 section 2.3.2 recommends no authentication
			 * requirement for certain NFS procedures used for mounting.
			 * This allows an unauthenticated superuser on the client
			 * to do mounts for the benefit of authenticated users.
			 */
			if (nd->nd_vers == NFS_VER2)
				if (nd->nd_procnum == NFSV2PROC_GETATTR ||
				    nd->nd_procnum == NFSV2PROC_STATFS)
					valid = 1;
			if (nd->nd_vers == NFS_VER3)
				if (nd->nd_procnum == NFSPROC_FSINFO)
					valid = 1;

			if (!valid)
				return (NFSERR_AUTHERR | AUTH_REJECTCRED);
		}
	}

	if (nxo && (nxo->nxo_flags & NX_OFFLINE))
		return ((nd->nd_vers == NFS_VER2) ? ESTALE : NFSERR_TRYLATER);

	/* find mount structure */
	mp = vfs_getvfs_by_mntonname((*nxp)->nx_fs->nxfs_path);
	if (!mp) {
		/*
		 * We have an export, but no mount?
		 * Perhaps the export just hasn't been marked offline yet.
		 */
		return ((nd->nd_vers == NFS_VER2) ? ESTALE : NFSERR_TRYLATER);
	}

	fidp = nfhp->nfh_fhp + sizeof(*nxh);
	error = VFS_FHTOVP(mp, nxh->nxh_fidlen, fidp, vpp, NULL);
	if (error)
		return (error);
	/* vnode pointer should be good at this point or ... */
	if (*vpp == NULL)
		return (ESTALE);
	return (0);
}

/*
 * nfsrv_credcheck() - check/map credentials according
 * to given export options.
 */
int
nfsrv_credcheck(
	struct nfsrv_descript *nd,
	vfs_context_t ctx,
	__unused struct nfs_export *nx,
	struct nfs_export_options *nxo)
{
	if (nxo && nxo->nxo_cred) {
		if ((nxo->nxo_flags & NX_MAPALL) ||
		    ((nxo->nxo_flags & NX_MAPROOT) && !suser(nd->nd_cr, NULL))) {
			kauth_cred_ref(nxo->nxo_cred);
			kauth_cred_unref(&nd->nd_cr);
			nd->nd_cr = nxo->nxo_cred;
		}
	}
	ctx->vc_ucred = nd->nd_cr;
	return (0);
}

/*
 * nfsrv_vptofh() - convert vnode to file handle for given export
 *
 * If the caller is passing in a vnode for a ".." directory entry,
 * they can pass a directory NFS file handle (dnfhp) which will be
 * checked against the root export file handle.  If it matches, we
 * refuse to provide the file handle for the out-of-export directory.
 */
int
nfsrv_vptofh(
	struct nfs_export *nx,
	int nfsvers,
	struct nfs_filehandle *dnfhp,
	vnode_t vp,
	vfs_context_t ctx,
	struct nfs_filehandle *nfhp)
{
	int error;
	uint32_t maxfidsize;

	nfhp->nfh_fhp = (u_char*)&nfhp->nfh_xh;
	nfhp->nfh_xh.nxh_version = htonl(NFS_FH_VERSION);
	nfhp->nfh_xh.nxh_fsid = htonl(nx->nx_fs->nxfs_id);
	nfhp->nfh_xh.nxh_expid = htonl(nx->nx_id);
	nfhp->nfh_xh.nxh_flags = 0;
	nfhp->nfh_xh.nxh_reserved = 0;

	if (nfsvers == NFS_VER2)
		bzero(&nfhp->nfh_fid[0], NFSV2_MAX_FID_SIZE);

	/* if directory FH matches export root, return invalid FH */
	if (dnfhp && nfsrv_fhmatch(dnfhp, &nx->nx_fh)) {
		if (nfsvers == NFS_VER2)
			nfhp->nfh_len = NFSX_V2FH;
		else
			nfhp->nfh_len = sizeof(nfhp->nfh_xh);
		nfhp->nfh_xh.nxh_fidlen = 0;
		nfhp->nfh_xh.nxh_flags = htons(NXHF_INVALIDFH);
		return (0);
	}

	if (nfsvers == NFS_VER2)
		maxfidsize = NFSV2_MAX_FID_SIZE;
	else
		maxfidsize = NFSV3_MAX_FID_SIZE;
	nfhp->nfh_len = maxfidsize;

	error = VFS_VPTOFH(vp, (int*)&nfhp->nfh_len, &nfhp->nfh_fid[0], ctx);
	if (error)
		return (error);
	if (nfhp->nfh_len > maxfidsize)
		return (EOVERFLOW);
	nfhp->nfh_xh.nxh_fidlen = nfhp->nfh_len;
	nfhp->nfh_len += sizeof(nfhp->nfh_xh);
	if ((nfsvers == NFS_VER2) && (nfhp->nfh_len < NFSX_V2FH))
		nfhp->nfh_len = NFSX_V2FH;

	return (0);
}

/*
 * Compare two file handles to see it they're the same.
 * Note that we don't use nfh_len because that may include
 * padding in an NFSv2 file handle.
 */
int
nfsrv_fhmatch(struct nfs_filehandle *fh1, struct nfs_filehandle *fh2)
{
	struct nfs_exphandle *nxh1, *nxh2;
	int len1, len2;

	nxh1 = (struct nfs_exphandle *)fh1->nfh_fhp;
	nxh2 = (struct nfs_exphandle *)fh2->nfh_fhp;
	len1 = sizeof(fh1->nfh_xh) + nxh1->nxh_fidlen;
	len2 = sizeof(fh2->nfh_xh) + nxh2->nxh_fidlen;
	if (len1 != len2)
		return (0);
	if (bcmp(nxh1, nxh2, len1))
		return (0);
	return (1);
}

/*
 * Functions for dealing with active user lists
 */

/*
 * Compare address fields of two sockaddr_storage structures.
 * Returns zero if they match.
 */
static int
nfsrv_cmp_sockaddr(struct sockaddr_storage *sock1, struct sockaddr_storage *sock2)
{
	struct sockaddr_in	*ipv4_sock1, *ipv4_sock2;
	struct sockaddr_in6	*ipv6_sock1, *ipv6_sock2;

	/* check for valid parameters */
	if (sock1 == NULL || sock2 == NULL)
		return 1;

	/* check address length */
	if (sock1->ss_len != sock2->ss_len)
		return 1;

	/* Check address family */
	if (sock1->ss_family != sock2->ss_family)
		return 1;

	if (sock1->ss_family == AF_INET) {
		/* IPv4 */
		ipv4_sock1 = (struct sockaddr_in *)sock1;
		ipv4_sock2 = (struct sockaddr_in *)sock2;

		if (!bcmp(&ipv4_sock1->sin_addr, &ipv4_sock2->sin_addr, sizeof(struct in_addr)))
			return 0;
	} else {
		/* IPv6 */
		ipv6_sock1 = (struct sockaddr_in6 *)sock1;
		ipv6_sock2 = (struct sockaddr_in6 *)sock2;

		if (!bcmp(&ipv6_sock1->sin6_addr, &ipv6_sock2->sin6_addr, sizeof(struct in6_addr)))
			return 0;
	}
	return 1;
}

/*
 * Search the hash table for a user node with a matching IP address and uid field.
 * If found, the node's tm_last timestamp is updated and the node is returned.
 *
 * If not found, a new node is allocated (or reclaimed via LRU), initialized, and returned.
 * Returns NULL if a new node could not be allcoated.
 *
 * The list's user_mutex lock MUST be held.
 */
static struct nfs_user_stat_node *
nfsrv_get_user_stat_node(struct nfs_active_user_list *list, struct sockaddr_storage *sock, uid_t uid)
{
	struct nfs_user_stat_node		*unode;
	struct timeval				now;
	struct nfs_user_stat_hashtbl_head	*head;

	/* seach the hash table */
	head = NFS_USER_STAT_HASH(list->user_hashtbl, uid);
	LIST_FOREACH(unode, head, hash_link) {
		if (uid == unode->uid && nfsrv_cmp_sockaddr(sock, &unode->sock) == 0) {
			/* found matching node */
			break;
		}
	}

	if (unode) {
		/* found node in the hash table, now update lru position */
		TAILQ_REMOVE(&list->user_lru, unode, lru_link);
		TAILQ_INSERT_TAIL(&list->user_lru, unode, lru_link);

		/* update time stamp */
		microtime(&now);
		unode->tm_last = (uint32_t)now.tv_sec;
		return unode;
	}

	if (list->node_count < nfsrv_user_stat_max_nodes) {
		/* Allocate a new node */
		MALLOC(unode, struct nfs_user_stat_node *, sizeof(struct nfs_user_stat_node),
			M_TEMP, M_WAITOK | M_ZERO);

		if (!unode)
			return NULL;

		/* increment node count */
		OSAddAtomic(1, (SInt32*)&nfsrv_user_stat_node_count);
		list->node_count++;
	} else {
		/* reuse the oldest node in the lru list */
		unode = TAILQ_FIRST(&list->user_lru);

		if (!unode)
			return NULL;

		/* Remove the node */
		TAILQ_REMOVE(&list->user_lru, unode, lru_link);
		LIST_REMOVE(unode, hash_link);
	}

	/* Initialize the node */
	unode->uid = uid;
	bcopy(sock, &unode->sock, sock->ss_len);
	microtime(&now);
	unode->ops = 0;
	unode->bytes_read = 0;
	unode->bytes_written = 0;
	unode->tm_start = (uint32_t)now.tv_sec;
	unode->tm_last = (uint32_t)now.tv_sec;

	/* insert the node  */
	TAILQ_INSERT_TAIL(&list->user_lru, unode, lru_link);
	LIST_INSERT_HEAD(head, unode, hash_link);

	return unode;
}

void
nfsrv_update_user_stat(struct nfs_export *nx, struct nfsrv_descript *nd, uid_t uid, u_int ops, u_int rd_bytes, u_int wr_bytes)
{
	struct nfs_user_stat_node	*unode;
	struct nfs_active_user_list	*ulist;
	struct sockaddr_storage		*sock_stor;

	if ((!nfsrv_user_stat_enabled) || (!nx) || (!nd) || (!nd->nd_nam))
		return;

	sock_stor = (struct sockaddr_storage *)mbuf_data(nd->nd_nam);

	/* check address family before going any further */
	if ((sock_stor->ss_family != AF_INET) && (sock_stor->ss_family != AF_INET6))
		return;

	ulist = &nx->nx_user_list;

	/* lock the active user list */
	lck_mtx_lock(&ulist->user_mutex);

	/* get the user node */
	unode = nfsrv_get_user_stat_node(ulist, sock_stor, uid);

	if (!unode) {
		lck_mtx_unlock(&ulist->user_mutex);
		return;
	}

	/* update counters */
	unode->ops += ops;
	unode->bytes_read += rd_bytes;
	unode->bytes_written += wr_bytes;

	/* done */
	lck_mtx_unlock(&ulist->user_mutex);
}

/* initialize an active user list */
static void
nfsrv_init_user_list(struct nfs_active_user_list *ulist)
{
	uint i;

	/* initialize the lru */
	TAILQ_INIT(&ulist->user_lru);

	/* initialize the hash table */
	for(i = 0; i < NFS_USER_STAT_HASH_SIZE; i++)
		LIST_INIT(&ulist->user_hashtbl[i]);
	ulist->node_count = 0;

	lck_mtx_init(&ulist->user_mutex, nfsrv_active_user_mutex_group, LCK_ATTR_NULL);
}

/* Free all nodes in an active user list */
static void
nfsrv_free_user_list(struct nfs_active_user_list *ulist)
{
	struct nfs_user_stat_node *unode;

	if (!ulist)
		return;

	while ((unode = TAILQ_FIRST(&ulist->user_lru))) {
		/* Remove node and free */
		TAILQ_REMOVE(&ulist->user_lru, unode, lru_link);
		LIST_REMOVE(unode, hash_link);
		FREE(unode, M_TEMP);

		/* decrement node count */
		OSAddAtomic(-1, (SInt32*)&nfsrv_user_stat_node_count);
	}
	ulist->node_count = 0;

	lck_mtx_destroy(&ulist->user_mutex, nfsrv_active_user_mutex_group);
}

/* Reclaim old expired user nodes from active user lists. */
void
nfsrv_active_user_list_reclaim(void)
{
	struct nfs_exportfs			*nxfs;
	struct nfs_export			*nx;
	struct nfs_active_user_list		*ulist;
	struct nfs_user_stat_hashtbl_head	oldlist;
	struct nfs_user_stat_node		*unode, *unode_next;
	struct timeval				now;
	uint32_t				tstale;

	LIST_INIT(&oldlist);

	lck_rw_lock_shared(&nfsrv_export_rwlock);
	microtime(&now);
	tstale = now.tv_sec - nfsrv_user_stat_max_idle_sec;
	LIST_FOREACH(nxfs, &nfsrv_exports, nxfs_next) {
		LIST_FOREACH(nx, &nxfs->nxfs_exports, nx_next) {
			/* Scan through all user nodes of this export */
			ulist = &nx->nx_user_list;
			lck_mtx_lock(&ulist->user_mutex);
			for (unode = TAILQ_FIRST(&ulist->user_lru); unode; unode = unode_next) {
				unode_next = TAILQ_NEXT(unode, lru_link);

				/* check if this node has expired */
				if (unode->tm_last >= tstale)
					break;

				/* Remove node from the active user list */
				TAILQ_REMOVE(&ulist->user_lru, unode, lru_link);
				LIST_REMOVE(unode, hash_link);

				/* Add node to temp list */
				LIST_INSERT_HEAD(&oldlist, unode, hash_link);

				/* decrement node count */
				OSAddAtomic(-1, (SInt32*)&nfsrv_user_stat_node_count);
				ulist->node_count--;
			}
			/* can unlock this export's list now */
			lck_mtx_unlock(&ulist->user_mutex);
		}
	}
        lck_rw_done(&nfsrv_export_rwlock);

	/* Free expired nodes */
        while ((unode = LIST_FIRST(&oldlist))) {
		LIST_REMOVE(unode, hash_link);
		FREE(unode, M_TEMP);
	}
}

/*
 * Maps errno values to nfs error numbers.
 * Use NFSERR_IO as the catch all for ones not specifically defined in
 * RFC 1094.
 */
static u_char nfsrv_v2errmap[] = {
  NFSERR_PERM,	NFSERR_NOENT,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_NXIO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_ACCES,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_EXIST,	NFSERR_IO,	NFSERR_NODEV,	NFSERR_NOTDIR,
  NFSERR_ISDIR,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_FBIG,	NFSERR_NOSPC,	NFSERR_IO,	NFSERR_ROFS,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,	NFSERR_IO,
  NFSERR_IO,	NFSERR_IO,	NFSERR_NAMETOL,	NFSERR_IO,	NFSERR_IO,
  NFSERR_NOTEMPTY, NFSERR_IO,	NFSERR_IO,	NFSERR_DQUOT,	NFSERR_STALE,
};

/*
 * Maps errno values to nfs error numbers.
 * Although it is not obvious whether or not NFS clients really care if
 * a returned error value is in the specified list for the procedure, the
 * safest thing to do is filter them appropriately. For Version 2, the
 * X/Open XNFS document is the only specification that defines error values
 * for each RPC (The RFC simply lists all possible error values for all RPCs),
 * so I have decided to not do this for Version 2.
 * The first entry is the default error return and the rest are the valid
 * errors for that RPC in increasing numeric order.
 */
static short nfsv3err_null[] = {
	0,
	0,
};

static short nfsv3err_getattr[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_setattr[] = {
	NFSERR_IO,
	NFSERR_PERM,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOT_SYNC,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_lookup[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_NAMETOL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_access[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_readlink[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_read[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_NXIO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_write[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_INVAL,
	NFSERR_FBIG,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_create[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_mkdir[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_symlink[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_mknod[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_BADTYPE,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_remove[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_rmdir[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_NOTDIR,
	NFSERR_INVAL,
	NFSERR_ROFS,
	NFSERR_NAMETOL,
	NFSERR_NOTEMPTY,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_rename[] = {
	NFSERR_IO,
	NFSERR_NOENT,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_XDEV,
	NFSERR_NOTDIR,
	NFSERR_ISDIR,
	NFSERR_INVAL,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_MLINK,
	NFSERR_NAMETOL,
	NFSERR_NOTEMPTY,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_link[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_EXIST,
	NFSERR_XDEV,
	NFSERR_NOTDIR,
	NFSERR_INVAL,
	NFSERR_NOSPC,
	NFSERR_ROFS,
	NFSERR_MLINK,
	NFSERR_NAMETOL,
	NFSERR_DQUOT,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_NOTSUPP,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_readdir[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_BAD_COOKIE,
	NFSERR_TOOSMALL,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_readdirplus[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_ACCES,
	NFSERR_NOTDIR,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_BAD_COOKIE,
	NFSERR_NOTSUPP,
	NFSERR_TOOSMALL,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_fsstat[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_fsinfo[] = {
	NFSERR_STALE,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_pathconf[] = {
	NFSERR_STALE,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short nfsv3err_commit[] = {
	NFSERR_IO,
	NFSERR_IO,
	NFSERR_STALE,
	NFSERR_BADHANDLE,
	NFSERR_SERVERFAULT,
	NFSERR_TRYLATER,
	0,
};

static short *nfsrv_v3errmap[] = {
	nfsv3err_null,
	nfsv3err_getattr,
	nfsv3err_setattr,
	nfsv3err_lookup,
	nfsv3err_access,
	nfsv3err_readlink,
	nfsv3err_read,
	nfsv3err_write,
	nfsv3err_create,
	nfsv3err_mkdir,
	nfsv3err_symlink,
	nfsv3err_mknod,
	nfsv3err_remove,
	nfsv3err_rmdir,
	nfsv3err_rename,
	nfsv3err_link,
	nfsv3err_readdir,
	nfsv3err_readdirplus,
	nfsv3err_fsstat,
	nfsv3err_fsinfo,
	nfsv3err_pathconf,
	nfsv3err_commit,
};

/*
 * Map errnos to NFS error numbers. For Version 3 also filter out error
 * numbers not specified for the associated procedure.
 */
int
nfsrv_errmap(struct nfsrv_descript *nd, int err)
{
	short *defaulterrp, *errp;

	if (nd->nd_vers == NFS_VER2) {
		if (err <= (int)sizeof(nfsrv_v2errmap))
			return ((int)nfsrv_v2errmap[err - 1]);
		return (NFSERR_IO);
	}
	/* NFSv3 */
	if (nd->nd_procnum > NFSPROC_COMMIT)
		return (err & 0xffff);
	errp = defaulterrp = nfsrv_v3errmap[nd->nd_procnum];
	while (*++errp) {
		if (*errp == err)
			return (err);
		else if (*errp > err)
			break;
	}
	return ((int)*defaulterrp);
}

#endif /* NFSSERVER */

