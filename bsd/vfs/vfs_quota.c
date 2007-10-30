/*
 * Copyright (c) 2002-2006 Apple Computer, Inc. All rights reserved.
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
#include <sys/file_internal.h>
#include <sys/proc_internal.h>
#include <sys/vnode_internal.h>
#include <sys/mount_internal.h>
#include <sys/quota.h>
#include <sys/uio_internal.h>

#include <libkern/OSByteOrder.h>


/* vars for quota file lock */
lck_grp_t	* qf_lck_grp;
lck_grp_attr_t	* qf_lck_grp_attr;
lck_attr_t	* qf_lck_attr;

/* vars for quota list lock */
lck_grp_t	* quota_list_lck_grp;
lck_grp_attr_t	* quota_list_lck_grp_attr;
lck_attr_t	* quota_list_lck_attr;
lck_mtx_t	* quota_list_mtx_lock;

/* Routines to lock and unlock the quota global data */
static int dq_list_lock(void);
static void dq_list_unlock(void);

static void dq_lock_internal(struct dquot *dq);
static void dq_unlock_internal(struct dquot *dq);

static u_int32_t quotamagic[MAXQUOTAS] = INITQMAGICS;


/*
 * Code pertaining to management of the in-core dquot data structures.
 */
#define DQHASH(dqvp, id) \
	(&dqhashtbl[((((int)(dqvp)) >> 8) + id) & dqhash])
LIST_HEAD(dqhash, dquot) *dqhashtbl;
u_long dqhash;

#define	DQUOTINC	5	/* minimum free dquots desired */
long numdquot, desireddquot = DQUOTINC;

/*
 * Dquot free list.
 */
TAILQ_HEAD(dqfreelist, dquot) dqfreelist;
/*
 * Dquot dirty orphans list
 */
TAILQ_HEAD(dqdirtylist, dquot) dqdirtylist;


static int  dqlookup(struct quotafile *, u_long, struct	dqblk *, u_int32_t *);
static int  dqsync_locked(struct dquot *dq);

static void qf_lock(struct quotafile *);
static void qf_unlock(struct quotafile *);
static int  qf_ref(struct quotafile *);
static void qf_rele(struct quotafile *);


/*
 * Initialize locks for the quota system.
 */
void
dqinit(void)
{
	/*
	 * Allocate quota list lock group attribute and group
	 */
	quota_list_lck_grp_attr= lck_grp_attr_alloc_init();
	quota_list_lck_grp = lck_grp_alloc_init("quota list",  quota_list_lck_grp_attr);
	
	/*
	 * Allocate qouta list lock attribute
	 */
	quota_list_lck_attr = lck_attr_alloc_init();

	/*
	 * Allocate quota list lock
	 */
	quota_list_mtx_lock = lck_mtx_alloc_init(quota_list_lck_grp, quota_list_lck_attr);


	/*
	 * allocate quota file lock group attribute and group
	 */
	qf_lck_grp_attr= lck_grp_attr_alloc_init();
	qf_lck_grp = lck_grp_alloc_init("quota file", qf_lck_grp_attr);

	/*
	 * Allocate quota file lock attribute
	 */
	qf_lck_attr = lck_attr_alloc_init();
}

/*
 * Report whether dqhashinit has been run.
 */
int
dqisinitialized(void)
{
	return (dqhashtbl != NULL);
}

/*
 * Initialize hash table for dquot structures.
 */
void
dqhashinit(void)
{
	dq_list_lock();
	if (dqisinitialized())
		goto out;

	TAILQ_INIT(&dqfreelist);
	TAILQ_INIT(&dqdirtylist);
	dqhashtbl = hashinit(desiredvnodes, M_DQUOT, &dqhash);
out:
	dq_list_unlock();
}


static volatile int dq_list_lock_cnt = 0;

static int
dq_list_lock(void)
{
	lck_mtx_lock(quota_list_mtx_lock);
	return ++dq_list_lock_cnt;
}

static int
dq_list_lock_changed(int oldval) {
	return (dq_list_lock_cnt != oldval);
}

static int
dq_list_lock_val(void) {
	return dq_list_lock_cnt;
}

void
dq_list_unlock(void)
{
	lck_mtx_unlock(quota_list_mtx_lock);
}


/*
 * must be called with the quota_list_lock held
 */
void
dq_lock_internal(struct dquot *dq)
{
        while (dq->dq_lflags & DQ_LLOCK) {
	        dq->dq_lflags |= DQ_LWANT;
	        msleep(&dq->dq_lflags, quota_list_mtx_lock, PVFS, "dq_lock_internal", NULL);
	}
	dq->dq_lflags |= DQ_LLOCK;
}

/*
 * must be called with the quota_list_lock held
 */
void
dq_unlock_internal(struct dquot *dq)
{
        int wanted = dq->dq_lflags & DQ_LWANT;

	dq->dq_lflags &= ~(DQ_LLOCK | DQ_LWANT);

	if (wanted)
	        wakeup(&dq->dq_lflags);
}

void
dqlock(struct dquot *dq) {

	lck_mtx_lock(quota_list_mtx_lock);

	dq_lock_internal(dq);

	lck_mtx_unlock(quota_list_mtx_lock);
}

void
dqunlock(struct dquot *dq) {

	lck_mtx_lock(quota_list_mtx_lock);

	dq_unlock_internal(dq);

	lck_mtx_unlock(quota_list_mtx_lock);
}



int
qf_get(struct quotafile *qfp, int type)
{
        int error = 0;

        dq_list_lock();
  
        switch (type) {

	case QTF_OPENING:
	        while ( (qfp->qf_qflags & (QTF_OPENING | QTF_CLOSING)) ) {
	                if ( (qfp->qf_qflags & QTF_OPENING) ) {
		                error = EBUSY;
				break;
			}
			if ( (qfp->qf_qflags & QTF_CLOSING) ) {
		                qfp->qf_qflags |= QTF_WANTED;
				msleep(&qfp->qf_qflags, quota_list_mtx_lock, PVFS, "qf_get", NULL);
			}
		}
		if (qfp->qf_vp != NULLVP)
		        error = EBUSY;
		if (error == 0)
		        qfp->qf_qflags |= QTF_OPENING;
		break;

	case QTF_CLOSING:
	        if ( (qfp->qf_qflags & QTF_CLOSING) ) {
		        error = EBUSY;
			break;
		}
		qfp->qf_qflags |= QTF_CLOSING;

		while ( (qfp->qf_qflags & QTF_OPENING) || qfp->qf_refcnt ) {
		        qfp->qf_qflags |= QTF_WANTED;
			msleep(&qfp->qf_qflags, quota_list_mtx_lock, PVFS, "qf_get", NULL);
		}
		if (qfp->qf_vp == NULLVP) {
		        qfp->qf_qflags &= ~QTF_CLOSING;
			error = EBUSY;
		}
		break;
	}
	dq_list_unlock();

	return (error);
}

void
qf_put(struct quotafile *qfp, int type)
{

        dq_list_lock();

        switch (type) {

	case QTF_OPENING:
	case QTF_CLOSING:
	        qfp->qf_qflags &= ~type;
		break;
	}
	if ( (qfp->qf_qflags & QTF_WANTED) ) {
	        qfp->qf_qflags &= ~QTF_WANTED;
		wakeup(&qfp->qf_qflags);
	}
	dq_list_unlock();
}


static void
qf_lock(struct quotafile *qfp)
{
	lck_mtx_lock(&qfp->qf_lock);
}

static void
qf_unlock(struct quotafile *qfp)
{
	lck_mtx_unlock(&qfp->qf_lock);
}


/*
 * take a reference on the quota file while we're
 * in dqget... this will prevent a quota_off from
 * occurring while we're potentially playing with
 * the quota file... the quota_off will stall until
 * all the current references 'die'... once we start
 * into quoto_off, all new references will be rejected
 * we also don't want any dqgets being processed while
 * we're in the middle of the quota_on... once we've
 * actually got the quota file open and the associated
 * struct quotafile inited, we can let them come through
 *
 * quota list lock must be held on entry
 */
static int
qf_ref(struct quotafile *qfp)
{
        int error = 0;

	if ( (qfp->qf_qflags & (QTF_OPENING | QTF_CLOSING)) || (qfp->qf_vp == NULLVP) )
	        error = EINVAL;
	else
	        qfp->qf_refcnt++;

	return (error);
}

/*
 * drop our reference and wakeup any waiters if 
 * we were the last one holding a ref
 *
 * quota list lock must be held on entry
 */
static void
qf_rele(struct quotafile *qfp)
{
	qfp->qf_refcnt--;

	if ( (qfp->qf_qflags & QTF_WANTED) && qfp->qf_refcnt == 0) {
	        qfp->qf_qflags &= ~QTF_WANTED;
	        wakeup(&qfp->qf_qflags);
	}
}


void
dqfileinit(struct quotafile *qfp)
{
        qfp->qf_vp = NULLVP;
	qfp->qf_qflags = 0;

	lck_mtx_init(&qfp->qf_lock, qf_lck_grp, qf_lck_attr);
}


/*
 * Initialize a quota file
 *
 * must be called with the quota file lock held
 */
int
dqfileopen(struct quotafile *qfp, int type)
{
	struct dqfilehdr header;
	struct vfs_context context;
	off_t file_size;
	uio_t auio;
	int error = 0;
	char uio_buf[ UIO_SIZEOF(1) ];

	context.vc_thread = current_thread();
	context.vc_ucred = qfp->qf_cred;
	
	/* Obtain the file size */
	if ((error = vnode_size(qfp->qf_vp, &file_size, &context)) != 0)
	        goto out;

	/* Read the file header */
	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
				    &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(&header), sizeof (header));
	error = VNOP_READ(qfp->qf_vp, auio, 0, &context);
	if (error)
	        goto out;
	else if (uio_resid(auio)) {
		error = EINVAL;
		goto out;
	}
	/* Sanity check the quota file header. */
	if ((OSSwapBigToHostInt32(header.dqh_magic) != quotamagic[type]) ||
	    (OSSwapBigToHostInt32(header.dqh_version) > QF_VERSION) ||
	    (!powerof2(OSSwapBigToHostInt32(header.dqh_maxentries))) ||
	    (OSSwapBigToHostInt32(header.dqh_maxentries) > (file_size / sizeof(struct dqblk)))) {
		error = EINVAL;
		goto out;
	}
	/* Set up the time limits for this quota. */
	if (header.dqh_btime != 0)
		qfp->qf_btime = OSSwapBigToHostInt32(header.dqh_btime);
	else
		qfp->qf_btime = MAX_DQ_TIME;
	if (header.dqh_itime != 0)
		qfp->qf_itime = OSSwapBigToHostInt32(header.dqh_itime);
	else
		qfp->qf_itime = MAX_IQ_TIME;

	/* Calculate the hash table constants. */
	qfp->qf_maxentries = OSSwapBigToHostInt32(header.dqh_maxentries);
	qfp->qf_entrycnt = OSSwapBigToHostInt32(header.dqh_entrycnt);
	qfp->qf_shift = dqhashshift(qfp->qf_maxentries);
out:
	return (error);
}

/*
 * Close down a quota file
 */
void
dqfileclose(struct quotafile *qfp, __unused int type)
{
	struct dqfilehdr header;
	struct vfs_context context;
	uio_t auio;
	char uio_buf[ UIO_SIZEOF(1) ];

	auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
								  &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(&header), sizeof (header));

	context.vc_thread = current_thread();
	context.vc_ucred = qfp->qf_cred;
	
	if (VNOP_READ(qfp->qf_vp, auio, 0, &context) == 0) {
		header.dqh_entrycnt = OSSwapHostToBigInt32(qfp->qf_entrycnt);
		uio_reset(auio, 0, UIO_SYSSPACE, UIO_WRITE);
		uio_addiov(auio, CAST_USER_ADDR_T(&header), sizeof (header));
		(void) VNOP_WRITE(qfp->qf_vp, auio, 0, &context);
	}
}


/*
 * Obtain a dquot structure for the specified identifier and quota file
 * reading the information from the file if necessary.
 */
int
dqget(u_long id, struct quotafile *qfp, int type, struct dquot **dqp)
{
	struct dquot *dq;
	struct dquot *ndq = NULL;
	struct dquot *fdq = NULL;
	struct dqhash *dqh;
	struct vnode *dqvp;
	int error = 0;
	int listlockval = 0;

	if (!dqisinitialized()) {
		*dqp = NODQUOT;
		return (EINVAL);
	}

	if ( id == 0 || qfp->qf_vp == NULLVP ) {
		*dqp = NODQUOT;
		return (EINVAL);
	}
	dq_list_lock();

	if ( (qf_ref(qfp)) ) {
	        dq_list_unlock();

		*dqp = NODQUOT;
		return (EINVAL);
	}
	if ( (dqvp = qfp->qf_vp) == NULLVP ) {
	        qf_rele(qfp);
		dq_list_unlock();

		*dqp = NODQUOT;
		return (EINVAL);
	}
	dqh = DQHASH(dqvp, id);

relookup:
	listlockval = dq_list_lock_val();

	/*
	 * Check the cache first.
	 */
	for (dq = dqh->lh_first; dq; dq = dq->dq_hash.le_next) {
		if (dq->dq_id != id ||
		    dq->dq_qfile->qf_vp != dqvp)
			continue;

		dq_lock_internal(dq);
		if (dq_list_lock_changed(listlockval)) {
			dq_unlock_internal(dq);
			goto relookup;
		}

		/*
		 * dq_lock_internal may drop the quota_list_lock to msleep, so
		 * we need to re-evaluate the identity of this dq
		 */
		if (dq->dq_id != id || dq->dq_qfile == NULL ||
		    dq->dq_qfile->qf_vp != dqvp) {
		        dq_unlock_internal(dq);
			goto relookup;
		}
		/*
		 * Cache hit with no references.  Take
		 * the structure off the free list.
		 */
		if (dq->dq_cnt++ == 0) {
			if (dq->dq_flags & DQ_MOD)
				TAILQ_REMOVE(&dqdirtylist, dq, dq_freelist);
			else
				TAILQ_REMOVE(&dqfreelist, dq, dq_freelist);
		}
		dq_unlock_internal(dq);

		if (fdq != NULL) {
		        /*
			 * we grabbed this from the free list in the first pass
			 * but we found the dq we were looking for in
			 * the cache the 2nd time through
			 * so stick it back on the free list and return the cached entry
			 */
		        TAILQ_INSERT_HEAD(&dqfreelist, fdq, dq_freelist);
		}
		qf_rele(qfp);
	        dq_list_unlock();
		
		if (ndq != NULL) {
		        /*
			 * we allocated this in the first pass
			 * but we found the dq we were looking for in
			 * the cache the 2nd time through so free it
			 */
		        _FREE(ndq, M_DQUOT);
		}
		*dqp = dq;

		return (0);
	}
	/*
	 * Not in cache, allocate a new one.
	 */
	if (TAILQ_EMPTY(&dqfreelist) &&
	    numdquot < MAXQUOTAS * desiredvnodes)
		desireddquot += DQUOTINC;

	if (fdq != NULL) {
	        /*
		 * we captured this from the free list
		 * in the first pass through, so go
		 * ahead and use it
		 */
	        dq = fdq;
		fdq = NULL;
	} else if (numdquot < desireddquot) {
	        if (ndq == NULL) {
		        /*
			 * drop the quota list lock since MALLOC may block
			 */
		        dq_list_unlock();

			ndq = (struct dquot *)_MALLOC(sizeof *dq, M_DQUOT, M_WAITOK);
			bzero((char *)ndq, sizeof *dq);

		        listlockval = dq_list_lock();
			/*
			 * need to look for the entry again in the cache
			 * since we dropped the quota list lock and
			 * someone else may have beaten us to creating it
			 */
			goto relookup;
		} else {
		        /*
			 * we allocated this in the first pass through
			 * and we're still under out target, so go
			 * ahead and use it
			 */
		        dq = ndq;
			ndq = NULL;
			numdquot++;
		}
	} else {
	        if (TAILQ_EMPTY(&dqfreelist)) {
		        qf_rele(qfp);
		        dq_list_unlock();

			if (ndq) {
			        /*
				 * we allocated this in the first pass through
				 * but we're now at the limit of our cache size
				 * so free it
				 */
			        _FREE(ndq, M_DQUOT);
			}
			tablefull("dquot");
			*dqp = NODQUOT;
			return (EUSERS);
		}
		dq = TAILQ_FIRST(&dqfreelist);

		dq_lock_internal(dq);

		if (dq_list_lock_changed(listlockval) || dq->dq_cnt || (dq->dq_flags & DQ_MOD)) {
		        /*
			 * we lost the race while we weren't holding
			 * the quota list lock... dq_lock_internal
			 * will drop it to msleep... this dq has been
			 * reclaimed... go find another
			 */
		        dq_unlock_internal(dq);

			/*
			 * need to look for the entry again in the cache
			 * since we dropped the quota list lock and
			 * someone else may have beaten us to creating it
			 */
			goto relookup;
		}
		TAILQ_REMOVE(&dqfreelist, dq, dq_freelist);

		if (dq->dq_qfile != NULL) {
		        LIST_REMOVE(dq, dq_hash);
			dq->dq_qfile = NULL;
			dq->dq_id = 0;
		}
		dq_unlock_internal(dq);

		/*
		 * because we may have dropped the quota list lock
		 * in the call to dq_lock_internal, we need to 
		 * relookup in the hash in case someone else
		 * caused a dq with this identity to be created...
		 * if we don't find it, we'll use this one
		 */
		fdq = dq;
		goto relookup;
	}
	/*
	 * we've either freshly allocated a dq
	 * or we've atomically pulled it out of
	 * the hash and freelists... no one else
	 * can have a reference, which means no
	 * one else can be trying to use this dq
	 */
	dq_lock_internal(dq);
	if (dq_list_lock_changed(listlockval)) {
		dq_unlock_internal(dq);
		goto relookup;
	}

	/*
	 * Initialize the contents of the dquot structure.
	 */
	dq->dq_cnt = 1;
	dq->dq_flags = 0;
	dq->dq_id = id;
	dq->dq_qfile = qfp;
	dq->dq_type = type;
	/*
	 * once we insert it in the hash and
	 * drop the quota_list_lock, it can be
	 * 'found'... however, we're still holding
	 * the dq_lock which will keep us from doing
	 * anything with it until we've finished
	 * initializing it...
	 */
	LIST_INSERT_HEAD(dqh, dq, dq_hash);
	dq_list_unlock();

	if (ndq) {
	        /*
		 * we allocated this in the first pass through
		 * but we didn't need it, so free it after
		 * we've droped the quota list lock
		 */
	        _FREE(ndq, M_DQUOT);
	}

	error = dqlookup(qfp, id, &dq->dq_dqb, &dq->dq_index);

	/*
	 * I/O error in reading quota file, release
	 * quota structure and reflect problem to caller.
	 */
	if (error) {
	        dq_list_lock();

		dq->dq_id = 0;
		dq->dq_qfile = NULL;
		LIST_REMOVE(dq, dq_hash);

		dq_unlock_internal(dq);
		qf_rele(qfp);
	        dq_list_unlock();

		dqrele(dq);

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
		struct timeval tv;

		microtime(&tv);
		if (dq->dq_btime == 0)
			dq->dq_btime = tv.tv_sec + qfp->qf_btime;
		if (dq->dq_itime == 0)
			dq->dq_itime = tv.tv_sec + qfp->qf_itime;
	}
	dq_list_lock();
	dq_unlock_internal(dq);
	qf_rele(qfp);
	dq_list_unlock();

	*dqp = dq;
	return (0);
}

/*
 * Lookup a dqblk structure for the specified identifier and
 * quota file.  If there is no entry for this identifier then
 * one is inserted.  The actual hash table index is returned.
 */
static int
dqlookup(struct quotafile *qfp, u_long id, struct dqblk *dqb, uint32_t *index)
{
	struct vnode *dqvp;
	struct vfs_context context;
	uio_t auio;
	int i, skip, last;
	u_long mask;
	int error = 0;
	char uio_buf[ UIO_SIZEOF(1) ];


	qf_lock(qfp);

	dqvp = qfp->qf_vp;

	context.vc_thread = current_thread();
	context.vc_ucred = qfp->qf_cred;

	mask = qfp->qf_maxentries - 1;
	i = dqhash1(id, qfp->qf_shift, mask);
	skip = dqhash2(id, mask);

	for (last = (i + (qfp->qf_maxentries-1) * skip) & mask;
	     i != last;
	     i = (i + skip) & mask) {
		auio = uio_createwithbuffer(1, dqoffset(i), UIO_SYSSPACE, UIO_READ, 
									  &uio_buf[0], sizeof(uio_buf));
		uio_addiov(auio, CAST_USER_ADDR_T(dqb), sizeof (struct dqblk));
		error = VNOP_READ(dqvp, auio, 0, &context);
		if (error) {
			printf("dqlookup: error %d looking up id %lu at index %d\n", error, id, i);
			break;
		} else if (uio_resid(auio)) {
			error = EIO;
			printf("dqlookup: error looking up id %lu at index %d\n", id, i);
			break;
		}
		/*
		 * An empty entry means there is no entry
		 * with that id.  In this case a new dqb
		 * record will be inserted.
		 */
		if (dqb->dqb_id == 0) {
			bzero(dqb, sizeof(struct dqblk));
			dqb->dqb_id = OSSwapHostToBigInt32(id);
			/*
			 * Write back to reserve entry for this id
			 */
			uio_reset(auio, dqoffset(i), UIO_SYSSPACE, UIO_WRITE);
			uio_addiov(auio, CAST_USER_ADDR_T(dqb), sizeof (struct dqblk));
			error = VNOP_WRITE(dqvp, auio, 0, &context);
			if (uio_resid(auio) && error == 0)
				error = EIO;
			if (error == 0)
				++qfp->qf_entrycnt;
			dqb->dqb_id = id;
			break;
		}
		/* An id match means an entry was found. */
		if (OSSwapBigToHostInt32(dqb->dqb_id) == id) {
			dqb->dqb_bhardlimit = OSSwapBigToHostInt64(dqb->dqb_bhardlimit);
			dqb->dqb_bsoftlimit = OSSwapBigToHostInt64(dqb->dqb_bsoftlimit);
			dqb->dqb_curbytes   = OSSwapBigToHostInt64(dqb->dqb_curbytes);
			dqb->dqb_ihardlimit = OSSwapBigToHostInt32(dqb->dqb_ihardlimit);
			dqb->dqb_isoftlimit = OSSwapBigToHostInt32(dqb->dqb_isoftlimit);
			dqb->dqb_curinodes  = OSSwapBigToHostInt32(dqb->dqb_curinodes);
			dqb->dqb_btime      = OSSwapBigToHostInt32(dqb->dqb_btime);
			dqb->dqb_itime      = OSSwapBigToHostInt32(dqb->dqb_itime);
			dqb->dqb_id         = OSSwapBigToHostInt32(dqb->dqb_id);
			break;
		}
	}
	qf_unlock(qfp);

	*index = i;  /* remember index so we don't have to recompute it later */

	return (error);
}


/*
 * Release a reference to a dquot.
 */
void
dqrele(struct dquot *dq)
{

	if (dq == NODQUOT)
		return;
	dqlock(dq);

	if (dq->dq_cnt > 1) {
		dq->dq_cnt--;

		dqunlock(dq);
		return;
	}
	if (dq->dq_flags & DQ_MOD)
		(void) dqsync_locked(dq);
	dq->dq_cnt--;

	dq_list_lock();
	TAILQ_INSERT_TAIL(&dqfreelist, dq, dq_freelist);
        dq_unlock_internal(dq);
	dq_list_unlock();
}

/*
 * Release a reference to a dquot but don't do any I/O.
 */
void
dqreclaim(struct dquot *dq)
{

	if (dq == NODQUOT)
		return;

	dq_list_lock();
	dq_lock_internal(dq);

	if (--dq->dq_cnt > 0) {
	        dq_unlock_internal(dq);
		dq_list_unlock();
		return;
	}
	if (dq->dq_flags & DQ_MOD)
		TAILQ_INSERT_TAIL(&dqdirtylist, dq, dq_freelist);
	else
		TAILQ_INSERT_TAIL(&dqfreelist, dq, dq_freelist);

	dq_unlock_internal(dq);
	dq_list_unlock();
}

/*
 * Update a quota file's orphaned disk quotas.
 */
void
dqsync_orphans(struct quotafile *qfp)
{
	struct dquot *dq;
	
	dq_list_lock();
  loop:
	TAILQ_FOREACH(dq, &dqdirtylist, dq_freelist) {
		if (dq->dq_qfile != qfp)
		        continue;

		dq_lock_internal(dq);

		if (dq->dq_qfile != qfp) {
		        /*
			 * the identity of this dq changed while
			 * the quota_list_lock was dropped
			 * dq_lock_internal can drop it to msleep
			 */
		        dq_unlock_internal(dq);
			goto loop;
		}
		if ((dq->dq_flags & DQ_MOD) == 0) {
		        /*
			 * someone cleaned and removed this from
			 * the dq from the dirty list while the
			 * quota_list_lock was dropped
			 */
		        dq_unlock_internal(dq);
			goto loop;
		}
		if (dq->dq_cnt != 0)
			panic("dqsync_orphans: dquot in use");

		TAILQ_REMOVE(&dqdirtylist, dq, dq_freelist);

		dq_list_unlock();
		/*
		 * we're still holding the dqlock at this point
		 * with the reference count == 0
		 * we shouldn't be able
		 * to pick up another one since we hold dqlock
		 */
		(void) dqsync_locked(dq);
			
		dq_list_lock();

		TAILQ_INSERT_TAIL(&dqfreelist, dq, dq_freelist);

		dq_unlock_internal(dq);
		goto loop;
	}
	dq_list_unlock();
}

int
dqsync(struct dquot *dq)
{
        int error = 0;

	if (dq != NODQUOT) {
	        dqlock(dq);

		if ( (dq->dq_flags & DQ_MOD) )
	        error = dqsync_locked(dq);

		dqunlock(dq);
	}
	return (error);
}


/*
 * Update the disk quota in the quota file.
 */
int
dqsync_locked(struct dquot *dq)
{
	struct vfs_context context;
	struct vnode *dqvp;
	struct dqblk dqb, *dqblkp;
	uio_t auio;
	int error;
	char uio_buf[ UIO_SIZEOF(1) ];

	if (dq->dq_id == 0) {
	        dq->dq_flags &= ~DQ_MOD;
		return (0);
	}
	if (dq->dq_qfile == NULL)
		panic("dqsync: NULL dq_qfile");
	if ((dqvp = dq->dq_qfile->qf_vp) == NULLVP)
		panic("dqsync: NULL qf_vp");

	auio = uio_createwithbuffer(1, dqoffset(dq->dq_index), UIO_SYSSPACE, 
								  UIO_WRITE, &uio_buf[0], sizeof(uio_buf));
	uio_addiov(auio, CAST_USER_ADDR_T(&dqb), sizeof (struct dqblk));

	context.vc_thread = current_thread();	/* XXX */
	context.vc_ucred = dq->dq_qfile->qf_cred;

	dqblkp = &dq->dq_dqb;
	dqb.dqb_bhardlimit = OSSwapHostToBigInt64(dqblkp->dqb_bhardlimit);
	dqb.dqb_bsoftlimit = OSSwapHostToBigInt64(dqblkp->dqb_bsoftlimit);
	dqb.dqb_curbytes   = OSSwapHostToBigInt64(dqblkp->dqb_curbytes);
	dqb.dqb_ihardlimit = OSSwapHostToBigInt32(dqblkp->dqb_ihardlimit);
	dqb.dqb_isoftlimit = OSSwapHostToBigInt32(dqblkp->dqb_isoftlimit);
	dqb.dqb_curinodes  = OSSwapHostToBigInt32(dqblkp->dqb_curinodes);
	dqb.dqb_btime      = OSSwapHostToBigInt32(dqblkp->dqb_btime);
	dqb.dqb_itime      = OSSwapHostToBigInt32(dqblkp->dqb_itime);
	dqb.dqb_id         = OSSwapHostToBigInt32(dqblkp->dqb_id);
	dqb.dqb_spare[0]   = 0;
	dqb.dqb_spare[1]   = 0;
	dqb.dqb_spare[2]   = 0;
	dqb.dqb_spare[3]   = 0;

	error = VNOP_WRITE(dqvp, auio, 0, &context);
	if (uio_resid(auio) && error == 0)
		error = EIO;
	dq->dq_flags &= ~DQ_MOD;

	return (error);
}

/*
 * Flush all entries from the cache for a particular vnode.
 */
void
dqflush(struct vnode *vp)
{
	struct dquot *dq, *nextdq;
	struct dqhash *dqh;

	if (!dqisinitialized())
		return;

	/*
	 * Move all dquot's that used to refer to this quota
	 * file off their hash chains (they will eventually
	 * fall off the head of the free list and be re-used).
	 */
	dq_list_lock();

	for (dqh = &dqhashtbl[dqhash]; dqh >= dqhashtbl; dqh--) {
		for (dq = dqh->lh_first; dq; dq = nextdq) {
			nextdq = dq->dq_hash.le_next;
			if (dq->dq_qfile->qf_vp != vp)
				continue;
			if (dq->dq_cnt)
				panic("dqflush: stray dquot");
			LIST_REMOVE(dq, dq_hash);
			dq->dq_qfile = NULL;
		}
	}
	dq_list_unlock();
}

/*
 * LP64 support for munging dqblk structure.
 * XXX conversion of user_time_t to time_t loses precision; not an issue for 
 * XXX us now, since we are only ever setting 32 bits worth of time into it.
 */
__private_extern__ void 
munge_dqblk(struct dqblk *dqblkp, struct user_dqblk *user_dqblkp, boolean_t to64)
{
	if (to64) {
		/* munge kernel (32 bit) dqblk into user (64 bit) dqblk */
		bcopy((caddr_t)dqblkp, (caddr_t)user_dqblkp, offsetof(struct dqblk, dqb_btime));
		user_dqblkp->dqb_id = dqblkp->dqb_id;
		user_dqblkp->dqb_itime = dqblkp->dqb_itime;
		user_dqblkp->dqb_btime = dqblkp->dqb_btime;
	}
	else {
		/* munge user (64 bit) dqblk into kernel (32 bit) dqblk */
		bcopy((caddr_t)user_dqblkp, (caddr_t)dqblkp, offsetof(struct dqblk, dqb_btime));
		dqblkp->dqb_id = user_dqblkp->dqb_id;
		dqblkp->dqb_itime = user_dqblkp->dqb_itime;	/* XXX - lose precision */
		dqblkp->dqb_btime = user_dqblkp->dqb_btime;	/* XXX - lose precision */
	}
}
