/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1982, 1986, 1990, 1993, 1995
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Robert Elz at The University of Melbourne.
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
 *	@(#)vfs_quota.c
 *	derived from @(#)ufs_quota.c	8.5 (Berkeley) 5/20/95
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/quota.h>


static u_int32_t quotamagic[MAXQUOTAS] = INITQMAGICS;


/*
 * Code pertaining to management of the in-core dquot data structures.
 */
#define DQHASH(dqvp, id) \
	(&dqhashtbl[((((int)(dqvp)) >> 8) + id) & dqhash])
LIST_HEAD(dqhash, dquot) *dqhashtbl;
u_long dqhash;

/*
 * Dquot free list.
 */
#define	DQUOTINC	5	/* minimum free dquots desired */
TAILQ_HEAD(dqfreelist, dquot) dqfreelist;
long numdquot, desireddquot = DQUOTINC;

/*
 * Dquot dirty orphans list.
 */
TAILQ_HEAD(dqdirtylist, dquot) dqdirtylist;


static int dqlookup(struct quotafile *, u_long, struct	dqblk *, u_int32_t *);


/*
 * Initialize the quota system.
 */
void
dqinit()
{

	dqhashtbl = hashinit(desiredvnodes, M_DQUOT, &dqhash);
	TAILQ_INIT(&dqfreelist);
	TAILQ_INIT(&dqdirtylist);
}


/*
 * Initialize a quota file
 */
int
dqfileopen(qfp, type)
	struct quotafile *qfp;
	int type;
{
	struct dqfilehdr header;
	struct vattr vattr;
	struct iovec aiov;
	struct uio auio;
	int error;

	/* Obtain the file size */
	error = VOP_GETATTR(qfp->qf_vp, &vattr, qfp->qf_cred, current_proc());
	if (error)
		return (error);

	/* Read the file header */
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	aiov.iov_base = (caddr_t)&header;
	aiov.iov_len = sizeof (header);
	auio.uio_resid = sizeof (header);
	auio.uio_offset = (off_t)(0);
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_procp = (struct proc *)0;
	error = VOP_READ(qfp->qf_vp, &auio, 0, qfp->qf_cred);
	if (error)
		return (error);
	else if (auio.uio_resid)
		return (EINVAL);

	/* Sanity check the quota file header. */
	if ((header.dqh_magic != quotamagic[type]) ||
	    (header.dqh_version > QF_VERSION) ||
	    (!powerof2(header.dqh_maxentries)) ||
	    (header.dqh_maxentries > (vattr.va_size / sizeof(struct dqblk))))
		return (EINVAL);

	/* Set up the time limits for this quota. */
	if (header.dqh_btime > 0)
		qfp->qf_btime = header.dqh_btime;
	else
		qfp->qf_btime = MAX_DQ_TIME;
	if (header.dqh_itime > 0)
		qfp->qf_itime = header.dqh_itime;
	else
		qfp->qf_itime = MAX_IQ_TIME;

	/* Calculate the hash table constants. */
	qfp->qf_maxentries = header.dqh_maxentries;
	qfp->qf_entrycnt = header.dqh_entrycnt;
	qfp->qf_shift = dqhashshift(header.dqh_maxentries);

	return (0);
}

/*
 * Close down a quota file
 */
void
dqfileclose(qfp, type)
	struct quotafile *qfp;
	int type;
{
	struct dqfilehdr header;
	struct iovec aiov;
	struct uio auio;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	aiov.iov_base = (caddr_t)&header;
	aiov.iov_len = sizeof (header);
	auio.uio_resid = sizeof (header);
	auio.uio_offset = (off_t)(0);
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_READ;
	auio.uio_procp = (struct proc *)0;
	if (VOP_READ(qfp->qf_vp, &auio, 0, qfp->qf_cred) == 0) {
		header.dqh_entrycnt = qfp->qf_entrycnt;

		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		aiov.iov_base = (caddr_t)&header;
		aiov.iov_len = sizeof (header);
		auio.uio_resid = sizeof (header);
		auio.uio_offset = (off_t)(0);
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_rw = UIO_WRITE;
		auio.uio_procp = (struct proc *)0;
		(void) VOP_WRITE(qfp->qf_vp, &auio, 0, qfp->qf_cred);
	}
}


/*
 * Obtain a dquot structure for the specified identifier and quota file
 * reading the information from the file if necessary.
 */
int
dqget(vp, id, qfp, type, dqp)
	struct vnode *vp;
	u_long id;
	struct quotafile *qfp;
	register int type;
	struct dquot **dqp;
{
	struct proc *p = current_proc();		/* XXX */
	struct dquot *dq;
	struct dqhash *dqh;
	struct vnode *dqvp;
	int error = 0;

	dqvp = qfp->qf_vp;
	if (id == 0 || dqvp == NULLVP || (qfp->qf_qflags & QTF_CLOSING)) {
		*dqp = NODQUOT;
		return (EINVAL);
	}
	/*
	 * Check the cache first.
	 */
	dqh = DQHASH(dqvp, id);
	for (dq = dqh->lh_first; dq; dq = dq->dq_hash.le_next) {
		if (dq->dq_id != id ||
		    dq->dq_qfile->qf_vp != dqvp)
			continue;
		/*
		 * Cache hit with no references.  Take
		 * the structure off the free list.
		 */
		if (dq->dq_cnt == 0) {
			if (dq->dq_flags & DQ_MOD)
				TAILQ_REMOVE(&dqdirtylist, dq, dq_freelist);
			else
				TAILQ_REMOVE(&dqfreelist, dq, dq_freelist);
		}
		DQREF(dq);
		*dqp = dq;
		return (0);
	}
	/*
	 * Not in cache, allocate a new one.
	 */
	if (dqfreelist.tqh_first == NODQUOT &&
	    numdquot < MAXQUOTAS * desiredvnodes)
		desireddquot += DQUOTINC;
	if (numdquot < desireddquot) {
		dq = (struct dquot *)_MALLOC(sizeof *dq, M_DQUOT, M_WAITOK);
		bzero((char *)dq, sizeof *dq);
		numdquot++;
	} else {
		if ((dq = dqfreelist.tqh_first) == NULL) {
			tablefull("dquot");
			*dqp = NODQUOT;
			return (EUSERS);
		}
		if (dq->dq_cnt || (dq->dq_flags & DQ_MOD))
			panic("free dquot isn't");
		TAILQ_REMOVE(&dqfreelist, dq, dq_freelist);
		LIST_REMOVE(dq, dq_hash);
	}
	/*
	 * Initialize the contents of the dquot structure.
	 */
	if (vp != dqvp)
		vn_lock(dqvp, LK_EXCLUSIVE | LK_RETRY, p);
	LIST_INSERT_HEAD(dqh, dq, dq_hash);
	DQREF(dq);
	dq->dq_flags = DQ_LOCK;
	dq->dq_id = id;
	dq->dq_qfile = qfp;
	dq->dq_type = type;
	error = dqlookup(qfp, id, &dq->dq_dqb, &dq->dq_index);

	if (vp != dqvp)
		VOP_UNLOCK(dqvp, 0, p);
	if (dq->dq_flags & DQ_WANT)
		wakeup((caddr_t)dq);
	dq->dq_flags = 0;
	/*
	 * I/O error in reading quota file, release
	 * quota structure and reflect problem to caller.
	 */
	if (error) {
		LIST_REMOVE(dq, dq_hash);
		dqrele(vp, dq);
		*dqp = NODQUOT;
		return (error);
	}
	/*
	 * Check for no limit to enforce.
	 * Initialize time values if necessary.
	 */
	if (dq->dq_isoftlimit == 0 && dq->dq_bsoftlimit == 0 &&
	    dq->dq_ihardlimit == 0 && dq->dq_bhardlimit == 0)
		dq->dq_flags |= DQ_FAKE;
	if (dq->dq_id != 0) {
		if (dq->dq_btime == 0)
			dq->dq_btime = time.tv_sec + qfp->qf_btime;
		if (dq->dq_itime == 0)
			dq->dq_itime = time.tv_sec + qfp->qf_itime;
	}
	*dqp = dq;
	return (0);
}

/*
 * Lookup a dqblk structure for the specified identifier and
 * quota file.  If there is no enetry for this identifier then
 * one is inserted.  The actual hash table index is returned.
 */
static int
dqlookup(qfp, id, dqb, index)
	struct quotafile *qfp;
	u_long id;
	struct	dqblk *dqb;
	u_int32_t *index;
{
	struct vnode *dqvp;
	struct ucred *cred;
	struct iovec aiov;
	struct uio auio;
	int i, skip, last;
	u_long mask;
	int error = 0;

	if (id == 0)
		return (EINVAL);
	dqvp = qfp->qf_vp;
	cred = qfp->qf_cred;

	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_procp = (struct proc *)0;

	mask = qfp->qf_maxentries - 1;
	i = dqhash1(id, qfp->qf_shift, mask);
	skip = dqhash2(id, mask);

	for (last = (i + (qfp->qf_maxentries-1) * skip) & mask;
	     i != last;
	     i = (i + skip) & mask) {

		aiov.iov_base = (caddr_t)dqb;
		aiov.iov_len = sizeof (struct dqblk);
		auio.uio_resid = sizeof (struct dqblk);
		auio.uio_offset = (off_t)dqoffset(i);
		auio.uio_rw = UIO_READ;
		error = VOP_READ(dqvp, &auio, 0, cred);
		if (error) {
			printf("dqlookup: error %d looking up id %d at index %d\n", error, id, i);
			break;
		} else if (auio.uio_resid) {
			error = EIO;
			printf("dqlookup: error looking up id %d at index %d\n", id, i);
			break;
		}
		/*
		 * An empty entry means there is no entry
		 * with that id.  In this case a new dqb
		 * record will be inserted.
		 */
		if (dqb->dqb_id == 0) {
			bzero(dqb, sizeof(struct dqblk));
			dqb->dqb_id = id;
			/*
			 * Write back to reserve entry for this id
			 */
			aiov.iov_base = (caddr_t)dqb;
			aiov.iov_len = sizeof (struct dqblk);
			auio.uio_resid = sizeof (struct dqblk);
			auio.uio_offset = (off_t)dqoffset(i);
			auio.uio_rw = UIO_WRITE;
			error = VOP_WRITE(dqvp, &auio, 0, cred);
			if (auio.uio_resid && error == 0)
				error = EIO;
			if (error == 0)
				++qfp->qf_entrycnt;
			break;
		}
		/* An id match means an entry was found. */
		if (dqb->dqb_id == id)
			break;
	}
	
	*index = i;  /* remember index so we don't have to recompute it later */
	return (error);
}

/*
 * Obtain a reference to a dquot.
 */
void
dqref(dq)
	struct dquot *dq;
{

	dq->dq_cnt++;
}

/*
 * Release a reference to a dquot.
 */
void
dqrele(vp, dq)
	struct vnode *vp;
	register struct dquot *dq;
{

	if (dq == NODQUOT)
		return;
	if (dq->dq_cnt > 1) {
		dq->dq_cnt--;
		return;
	}
	if (dq->dq_flags & DQ_MOD)
		(void) dqsync(vp, dq);
	if (--dq->dq_cnt > 0)
		return;
	TAILQ_INSERT_TAIL(&dqfreelist, dq, dq_freelist);
}

/*
 * Release a reference to a dquot but don't do any I/O.
 */
void
dqreclaim(vp, dq)
	struct vnode *vp;
	register struct dquot *dq;
{
	if (dq == NODQUOT)
		return;

	if (--dq->dq_cnt > 0)
		return;

	if (dq->dq_flags & DQ_MOD)
		TAILQ_INSERT_TAIL(&dqdirtylist, dq, dq_freelist);
	else
		TAILQ_INSERT_TAIL(&dqfreelist, dq, dq_freelist);
}

/*
 * Update a quota file's orphaned disk quotas.
 */
void
dqsync_orphans(qfp)
	struct quotafile *qfp;
{
	struct dquot *dq;

  loop:
	TAILQ_FOREACH(dq, &dqdirtylist, dq_freelist) {
		if ((dq->dq_flags & DQ_MOD) == 0)
			panic("dqsync_orphans: dirty dquot isn't");
		if (dq->dq_cnt != 0)
			panic("dqsync_orphans: dquot in use");

		if (dq->dq_qfile == qfp) {
			TAILQ_REMOVE(&dqdirtylist, dq, dq_freelist);

			dq->dq_cnt++;
			(void) dqsync(NULLVP, dq);
			dq->dq_cnt--;

			if ((dq->dq_cnt == 0) && (dq->dq_flags & DQ_MOD) == 0)
				TAILQ_INSERT_TAIL(&dqfreelist, dq, dq_freelist);

			goto loop;
		}
	}
}

/*
 * Update the disk quota in the quota file.
 */
int
dqsync(vp, dq)
	struct vnode *vp;
	struct dquot *dq;
{
	struct proc *p = current_proc();		/* XXX */
	struct vnode *dqvp;
	struct iovec aiov;
	struct uio auio;
	int error;

	if (dq == NODQUOT)
		panic("dqsync: dquot");
	if ((dq->dq_flags & DQ_MOD) == 0)
		return (0);
	if (dq->dq_id == 0)
		return(0);
	if ((dqvp = dq->dq_qfile->qf_vp) == NULLVP)
		panic("dqsync: file");
	if (vp != dqvp)
		vn_lock(dqvp, LK_EXCLUSIVE | LK_RETRY, p);
	while (dq->dq_flags & DQ_LOCK) {
		dq->dq_flags |= DQ_WANT;
		sleep((caddr_t)dq, PINOD+2);
		if ((dq->dq_flags & DQ_MOD) == 0) {
			if (vp != dqvp)
				VOP_UNLOCK(dqvp, 0, p);
			return (0);
		}
	}
	dq->dq_flags |= DQ_LOCK;
	auio.uio_iov = &aiov;
	auio.uio_iovcnt = 1;
	aiov.iov_base = (caddr_t)&dq->dq_dqb;
	aiov.iov_len = sizeof (struct dqblk);
	auio.uio_resid = sizeof (struct dqblk);
	auio.uio_offset = (off_t)dqoffset(dq->dq_index);
	auio.uio_segflg = UIO_SYSSPACE;
	auio.uio_rw = UIO_WRITE;
	auio.uio_procp = (struct proc *)0;
	error = VOP_WRITE(dqvp, &auio, 0, dq->dq_qfile->qf_cred);
	if (auio.uio_resid && error == 0)
		error = EIO;
	if (dq->dq_flags & DQ_WANT)
		wakeup((caddr_t)dq);
	dq->dq_flags &= ~(DQ_MOD|DQ_LOCK|DQ_WANT);
	if (vp != dqvp)
		VOP_UNLOCK(dqvp, 0, p);
	return (error);
}

/*
 * Flush all entries from the cache for a particular vnode.
 */
void
dqflush(vp)
	register struct vnode *vp;
{
	register struct dquot *dq, *nextdq;
	struct dqhash *dqh;

	/*
	 * Move all dquot's that used to refer to this quota
	 * file off their hash chains (they will eventually
	 * fall off the head of the free list and be re-used).
	 */
	for (dqh = &dqhashtbl[dqhash]; dqh >= dqhashtbl; dqh--) {
		for (dq = dqh->lh_first; dq; dq = nextdq) {
			nextdq = dq->dq_hash.le_next;
			if (dq->dq_qfile->qf_vp != vp)
				continue;
			if (dq->dq_cnt)
				panic("dqflush: stray dquot");
			LIST_REMOVE(dq, dq_hash);
			dq->dq_qfile = (struct quotafile *)0;
		}
	}
}
