/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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
 *	@(#)hfs_quota.c
 *	derived from @(#)ufs_quota.c	8.5 (Berkeley) 5/20/95
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/systm.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/vnode.h>
#include <sys/quota.h>

#include <hfs/hfs.h>
#include <hfs/hfs_cnode.h>
#include <hfs/hfs_quota.h>
#include <hfs/hfs_mount.h>

/*
 * Quota name to error message mapping.
 */
static char *quotatypes[] = INITQFNAMES;

/*
 * Set up the quotas for a cnode.
 *
 * This routine completely defines the semantics of quotas.
 * If other criterion want to be used to establish quotas, the
 * MAXQUOTAS value in quotas.h should be increased, and the
 * additional dquots set up here.
 */
int
hfs_getinoquota(cp)
	register struct cnode *cp;
{
	struct hfsmount *hfsmp;
	struct vnode *vp;
	int error;

	vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;
	hfsmp = VFSTOHFS(vp->v_mount);
	/*
	 * Set up the user quota based on file uid.
	 * EINVAL means that quotas are not enabled.
	 */
	if (cp->c_dquot[USRQUOTA] == NODQUOT &&
	    (error =
		dqget(vp, cp->c_uid, &hfsmp->hfs_qfiles[USRQUOTA], USRQUOTA, &cp->c_dquot[USRQUOTA])) &&
	    error != EINVAL)
		return (error);
	/*
	 * Set up the group quota based on file gid.
	 * EINVAL means that quotas are not enabled.
	 */
	if (cp->c_dquot[GRPQUOTA] == NODQUOT &&
	    (error =
		dqget(vp, cp->c_gid,  &hfsmp->hfs_qfiles[GRPQUOTA], GRPQUOTA, &cp->c_dquot[GRPQUOTA])) &&
	    error != EINVAL)
		return (error);
	return (0);
}

/*
 * Update disk usage, and take corrective action.
 */
int
hfs_chkdq(cp, change, cred, flags)
	register struct cnode *cp;
	int64_t change;
	struct ucred *cred;
	int flags;
{
	register struct dquot *dq;
	register int i;
	int64_t ncurbytes;
	int error=0;
	struct proc *p;

#if DIAGNOSTIC
	if ((flags & CHOWN) == 0)
		hfs_chkdquot(cp);
#endif
	if (change == 0)
		return (0);
	if (change < 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			while (dq->dq_flags & DQ_LOCK) {
				dq->dq_flags |= DQ_WANT;
				sleep((caddr_t)dq, PINOD+1);
			}
			ncurbytes = dq->dq_curbytes + change;
			if (ncurbytes >= 0)
				dq->dq_curbytes = ncurbytes;
			else
				dq->dq_curbytes = 0;
			dq->dq_flags &= ~DQ_BLKS;
			dq->dq_flags |= DQ_MOD;
		}
		return (0);
	}
	p = current_proc();
	if (cred == NOCRED)
		cred = kernproc->p_ucred;
	if ((cred->cr_uid != 0) || (p->p_flag & P_FORCEQUOTA)) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			error = hfs_chkdqchg(cp, change, cred, i);
			if (error) {
				break;
			}
		}
	}
	if ((flags & FORCE) || error == 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			while (dq->dq_flags & DQ_LOCK) {
				dq->dq_flags |= DQ_WANT;
				sleep((caddr_t)dq, PINOD+1);
			}
			dq->dq_curbytes += change;
			dq->dq_flags |= DQ_MOD;
		}
	}
	return (error);
}

/*
 * Check for a valid change to a users allocation.
 * Issue an error message if appropriate.
 */
int
hfs_chkdqchg(cp, change, cred, type)
	struct cnode *cp;
	int64_t change;
	struct ucred *cred;
	int type;
{
	register struct dquot *dq = cp->c_dquot[type];
	u_int64_t ncurbytes = dq->dq_curbytes + change;
	struct vnode *vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;

	/*
	 * If user would exceed their hard limit, disallow space allocation.
	 */
	if (ncurbytes >= dq->dq_bhardlimit && dq->dq_bhardlimit) {
		if ((dq->dq_flags & DQ_BLKS) == 0 &&
		    cp->c_uid == cred->cr_uid) {
#if 0	
			printf("\n%s: write failed, %s disk limit reached\n",
			    vp->v_mount->mnt_stat.f_mntonname,
			    quotatypes[type]);
#endif
			dq->dq_flags |= DQ_BLKS;
		}
		return (EDQUOT);
	}
	/*
	 * If user is over their soft limit for too long, disallow space
	 * allocation. Reset time limit as they cross their soft limit.
	 */
	if (ncurbytes >= dq->dq_bsoftlimit && dq->dq_bsoftlimit) {
		if (dq->dq_curbytes < dq->dq_bsoftlimit) {
			dq->dq_btime = time.tv_sec +
			    VFSTOHFS(vp->v_mount)->hfs_qfiles[type].qf_btime;
#if 0
			if (cp->c_uid == cred->cr_uid)
				printf("\n%s: warning, %s %s\n",
				    vp->v_mount->mnt_stat.f_mntonname,
				    quotatypes[type], "disk quota exceeded");
#endif
			return (0);
		}
		if (time.tv_sec > dq->dq_btime) {
			if ((dq->dq_flags & DQ_BLKS) == 0 &&
			    cp->c_uid == cred->cr_uid) {
#if 0
				printf("\n%s: write failed, %s %s\n",
				    vp->v_mount->mnt_stat.f_mntonname,
				    quotatypes[type],
				    "disk quota exceeded for too long");
#endif
				dq->dq_flags |= DQ_BLKS;
			}
			return (EDQUOT);
		}
	}
	return (0);
}

/*
 * Check the inode limit, applying corrective action.
 */
int
hfs_chkiq(cp, change, cred, flags)
	register struct cnode *cp;
	long change;
	struct ucred *cred;
	int flags;
{
	register struct dquot *dq;
	register int i;
	int ncurinodes, error=0;
	struct proc *p;

#if DIAGNOSTIC
	if ((flags & CHOWN) == 0)
		hfs_chkdquot(cp);
#endif
	if (change == 0)
		return (0);
	if (change < 0) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			while (dq->dq_flags & DQ_LOCK) {
				dq->dq_flags |= DQ_WANT;
				sleep((caddr_t)dq, PINOD+1);
			}
			ncurinodes = dq->dq_curinodes + change;
			if (ncurinodes >= 0)
				dq->dq_curinodes = ncurinodes;
			else
				dq->dq_curinodes = 0;
			dq->dq_flags &= ~DQ_INODS;
			dq->dq_flags |= DQ_MOD;
		}
		return (0);
	}
	p = current_proc();
	if (cred == NOCRED)
		cred = kernproc->p_ucred;
	if ((cred->cr_uid != 0) || (p->p_flag & P_FORCEQUOTA)) {
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			error = hfs_chkiqchg(cp, change, cred, i);
			if (error) {
				break;
			}
		}
	}
	if ((flags & FORCE) || error == 0) { 
		for (i = 0; i < MAXQUOTAS; i++) {
			if ((dq = cp->c_dquot[i]) == NODQUOT)
				continue;
			while (dq->dq_flags & DQ_LOCK) {
				dq->dq_flags |= DQ_WANT;
				sleep((caddr_t)dq, PINOD+1);
			}
			dq->dq_curinodes += change;
			dq->dq_flags |= DQ_MOD;
		}
	}
	return (error);
}

/*
 * Check for a valid change to a users allocation.
 * Issue an error message if appropriate.
 */
int
hfs_chkiqchg(cp, change, cred, type)
	struct cnode *cp;
	long change;
	struct ucred *cred;
	int type;
{
	register struct dquot *dq = cp->c_dquot[type];
	long ncurinodes = dq->dq_curinodes + change;
	struct vnode *vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;

	/*
	 * If user would exceed their hard limit, disallow cnode allocation.
	 */
	if (ncurinodes >= dq->dq_ihardlimit && dq->dq_ihardlimit) {
		if ((dq->dq_flags & DQ_INODS) == 0 &&
		    cp->c_uid == cred->cr_uid) {
#if 0
			printf("\n%s: write failed, %s cnode limit reached\n",
			    vp->v_mount->mnt_stat.f_mntonname,
			    quotatypes[type]);
#endif
			dq->dq_flags |= DQ_INODS;
		}
		return (EDQUOT);
	}
	/*
	 * If user is over their soft limit for too long, disallow cnode
	 * allocation. Reset time limit as they cross their soft limit.
	 */
	if (ncurinodes >= dq->dq_isoftlimit && dq->dq_isoftlimit) {
		if (dq->dq_curinodes < dq->dq_isoftlimit) {
			dq->dq_itime = time.tv_sec +
			    VFSTOHFS(vp->v_mount)->hfs_qfiles[type].qf_itime;
#if 0
			if (cp->c_uid == cred->cr_uid)
				printf("\n%s: warning, %s %s\n",
				    vp->v_mount->mnt_stat.f_mntonname,
				    quotatypes[type], "cnode quota exceeded");
#endif
			return (0);
		}
		if (time.tv_sec > dq->dq_itime) {
			if ((dq->dq_flags & DQ_INODS) == 0 &&
			    cp->c_uid == cred->cr_uid) {
#if 0
				printf("\n%s: write failed, %s %s\n",
				    vp->v_mount->mnt_stat.f_mntonname,
				    quotatypes[type],
				    "cnode quota exceeded for too long");
#endif
				dq->dq_flags |= DQ_INODS;
			}
			return (EDQUOT);
		}
	}
	return (0);
}

#if DIAGNOSTIC
/*
 * On filesystems with quotas enabled, it is an error for a file to change
 * size and not to have a dquot structure associated with it.
 */
void
hfs_chkdquot(cp)
	register struct cnode *cp;
{
	struct vnode *vp = cp->c_vp ? cp->c_vp : cp->c_rsrc_vp;
	struct hfsmount *hfsmp = VFSTOHFS(vp->v_mount);
	register int i;

	for (i = 0; i < MAXQUOTAS; i++) {
		if (hfsmp->hfs_qfiles[i].qf_vp == NULLVP ||
		    (hfsmp->hfs_qfiles[i].qf_qflags & (QTF_OPENING|QTF_CLOSING)))
			continue;
		if (cp->c_dquot[i] == NODQUOT) {
			vprint("chkdquot: missing dquot", vp);
			panic("missing dquot");
		}
	}
}
#endif

/*
 * Code to process quotactl commands.
 */

/*
 * Q_QUOTAON - set up a quota file for a particular file system.
 */
int
hfs_quotaon(p, mp, type, fname, segflg)
	struct proc *p;
	struct mount *mp;
	register int type;
	caddr_t fname;
	enum uio_seg segflg;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct vnode *vp, **vpp;
	struct vnode *nextvp;
	struct dquot *dq;
	int error;
	struct nameidata nd;

	vpp = &hfsmp->hfs_qfiles[type].qf_vp;
	NDINIT(&nd, LOOKUP, FOLLOW, segflg, fname, p);
	if (error = vn_open(&nd, FREAD|FWRITE, 0))
		return (error);
	vp = nd.ni_vp;
	VOP_UNLOCK(vp, 0, p);
	if (vp->v_type != VREG) {
		(void) vn_close(vp, FREAD|FWRITE, p->p_ucred, p);
		return (EACCES);
	}
	if (*vpp != vp)
		hfs_quotaoff(p, mp, type);
	hfsmp->hfs_qfiles[type].qf_qflags |= QTF_OPENING;
	mp->mnt_flag |= MNT_QUOTA;
	vp->v_flag |= VNOFLUSH;
	*vpp = vp;
	/*
	 * Save the credential of the process that turned on quotas.
	 */
	crhold(p->p_ucred);
	hfsmp->hfs_qfiles[type].qf_cred = p->p_ucred;
	/* Finish initializing the quota file */
	if (error = dqfileopen(&hfsmp->hfs_qfiles[type], type))
		goto exit;
	/*
	 * Search vnodes associated with this mount point,
	 * adding references to quota file being opened.
	 * NB: only need to add dquot's for cnodes being modified.
	 */
again:
	for (vp = mp->mnt_vnodelist.lh_first; vp != NULL; vp = nextvp) {
		nextvp = vp->v_mntvnodes.le_next;
		if (vp->v_writecount == 0)
			continue;
		if (vget(vp, LK_EXCLUSIVE, p))
			goto again;
		if (error = hfs_getinoquota(VTOC(vp))) {
			vput(vp);
			break;
		}
		vput(vp);
		if (vp->v_mntvnodes.le_next != nextvp || vp->v_mount != mp)
			goto again;
	}
exit:
	hfsmp->hfs_qfiles[type].qf_qflags &= ~QTF_OPENING;
	if (error)
		hfs_quotaoff(p, mp, type);
	return (error);
}

/*
 * Q_QUOTAOFF - turn off disk quotas for a filesystem.
 */
int
hfs_quotaoff(p, mp, type)
	struct proc *p;
	struct mount *mp;
	register int type;
{
	struct vnode *vp;
	struct vnode *qvp, *nextvp;
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct dquot *dq;
	struct cnode *cp;
	int error;
	struct ucred *cred;
	
	if ((qvp = hfsmp->hfs_qfiles[type].qf_vp) == NULLVP)
		return (0);
	hfsmp->hfs_qfiles[type].qf_qflags |= QTF_CLOSING;

	/*
	 * Sync out any orpaned dirty dquot entries.
	 */
	dqsync_orphans(&hfsmp->hfs_qfiles[type]);

	/*
	 * Search vnodes associated with this mount point,
	 * deleting any references to quota file being closed.
	 */
again:
	for (vp = mp->mnt_vnodelist.lh_first; vp != NULL; vp = nextvp) {
		nextvp = vp->v_mntvnodes.le_next;
		if (vget(vp, LK_EXCLUSIVE, p))
			goto again;
		cp = VTOC(vp);
		dq = cp->c_dquot[type];
		cp->c_dquot[type] = NODQUOT;
		dqrele(vp, dq);
		vput(vp);
		if (vp->v_mntvnodes.le_next != nextvp || vp->v_mount != mp)
			goto again;
	}
	dqflush(qvp);
	/* Finish tearing down the quota file */
	dqfileclose(&hfsmp->hfs_qfiles[type], type);
	qvp->v_flag &= ~VNOFLUSH;
	error = vn_close(qvp, FREAD|FWRITE, p->p_ucred, p);
	hfsmp->hfs_qfiles[type].qf_vp = NULLVP;
	cred = hfsmp->hfs_qfiles[type].qf_cred;
	if (cred != NOCRED) {
		hfsmp->hfs_qfiles[type].qf_cred = NOCRED;
		crfree(cred);
	}
	hfsmp->hfs_qfiles[type].qf_qflags &= ~QTF_CLOSING;
	for (type = 0; type < MAXQUOTAS; type++)
		if (hfsmp->hfs_qfiles[type].qf_vp != NULLVP)
			break;
	if (type == MAXQUOTAS)
		mp->mnt_flag &= ~MNT_QUOTA;
	return (error);
}

/*
 * Q_GETQUOTA - return current values in a dqblk structure.
 */
int
hfs_getquota(mp, id, type, addr)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t addr;
{
	struct dquot *dq;
	int error;

	if (error = dqget(NULLVP, id, &VFSTOHFS(mp)->hfs_qfiles[type], type, &dq))
		return (error);
	error = copyout((caddr_t)&dq->dq_dqb, addr, sizeof (struct dqblk));
	dqrele(NULLVP, dq);
	return (error);
}

/*
 * Q_SETQUOTA - assign an entire dqblk structure.
 */
int
hfs_setquota(mp, id, type, addr)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t addr;
{
	register struct dquot *dq;
	struct dquot *ndq;
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct dqblk newlim;
	int error;

	if (error = copyin(addr, (caddr_t)&newlim, sizeof (struct dqblk)))
		return (error);
	if (error = dqget(NULLVP, id, &hfsmp->hfs_qfiles[type], type, &ndq))
		return (error);
	dq = ndq;
	while (dq->dq_flags & DQ_LOCK) {
		dq->dq_flags |= DQ_WANT;
		sleep((caddr_t)dq, PINOD+1);
	}
	/*
	 * Copy all but the current values.
	 * Reset time limit if previously had no soft limit or were
	 * under it, but now have a soft limit and are over it.
	 */
	newlim.dqb_curbytes = dq->dq_curbytes;
	newlim.dqb_curinodes = dq->dq_curinodes;
	if (dq->dq_id != 0) {
		newlim.dqb_btime = dq->dq_btime;
		newlim.dqb_itime = dq->dq_itime;
	}
	if (newlim.dqb_bsoftlimit &&
	    dq->dq_curbytes >= newlim.dqb_bsoftlimit &&
	    (dq->dq_bsoftlimit == 0 || dq->dq_curbytes < dq->dq_bsoftlimit))
		newlim.dqb_btime = time.tv_sec + hfsmp->hfs_qfiles[type].qf_btime;
	if (newlim.dqb_isoftlimit &&
	    dq->dq_curinodes >= newlim.dqb_isoftlimit &&
	    (dq->dq_isoftlimit == 0 || dq->dq_curinodes < dq->dq_isoftlimit))
		newlim.dqb_itime = time.tv_sec + hfsmp->hfs_qfiles[type].qf_itime;
	dq->dq_dqb = newlim;
	if (dq->dq_curbytes < dq->dq_bsoftlimit)
		dq->dq_flags &= ~DQ_BLKS;
	if (dq->dq_curinodes < dq->dq_isoftlimit)
		dq->dq_flags &= ~DQ_INODS;
	if (dq->dq_isoftlimit == 0 && dq->dq_bsoftlimit == 0 &&
	    dq->dq_ihardlimit == 0 && dq->dq_bhardlimit == 0)
		dq->dq_flags |= DQ_FAKE;
	else
		dq->dq_flags &= ~DQ_FAKE;
	dq->dq_flags |= DQ_MOD;
	dqrele(NULLVP, dq);
	return (0);
}

/*
 * Q_SETUSE - set current cnode and byte usage.
 */
int
hfs_setuse(mp, id, type, addr)
	struct mount *mp;
	u_long id;
	int type;
	caddr_t addr;
{
	register struct dquot *dq;
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct dquot *ndq;
	struct dqblk usage;
	int error;

	if (error = copyin(addr, (caddr_t)&usage, sizeof (struct dqblk)))
		return (error);
	if (error = dqget(NULLVP, id, &hfsmp->hfs_qfiles[type], type, &ndq))
		return (error);
	dq = ndq;
	while (dq->dq_flags & DQ_LOCK) {
		dq->dq_flags |= DQ_WANT;
		sleep((caddr_t)dq, PINOD+1);
	}
	/*
	 * Reset time limit if have a soft limit and were
	 * previously under it, but are now over it.
	 */
	if (dq->dq_bsoftlimit && dq->dq_curbytes < dq->dq_bsoftlimit &&
	    usage.dqb_curbytes >= dq->dq_bsoftlimit)
		dq->dq_btime = time.tv_sec + hfsmp->hfs_qfiles[type].qf_btime;
	if (dq->dq_isoftlimit && dq->dq_curinodes < dq->dq_isoftlimit &&
	    usage.dqb_curinodes >= dq->dq_isoftlimit)
		dq->dq_itime = time.tv_sec + hfsmp->hfs_qfiles[type].qf_itime;
	dq->dq_curbytes = usage.dqb_curbytes;
	dq->dq_curinodes = usage.dqb_curinodes;
	if (dq->dq_curbytes < dq->dq_bsoftlimit)
		dq->dq_flags &= ~DQ_BLKS;
	if (dq->dq_curinodes < dq->dq_isoftlimit)
		dq->dq_flags &= ~DQ_INODS;
	dq->dq_flags |= DQ_MOD;
	dqrele(NULLVP, dq);
	return (0);
}

/*
 * Q_SYNC - sync quota files to disk.
 */
int
hfs_qsync(mp)
	struct mount *mp;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	struct proc *p = current_proc();		/* XXX */
	struct vnode *vp, *nextvp;
	struct dquot *dq;
	int i, error;

	/*
	 * Check if the mount point has any quotas.
	 * If not, simply return.
	 */
	for (i = 0; i < MAXQUOTAS; i++)
		if (hfsmp->hfs_qfiles[i].qf_vp != NULLVP)
			break;
	if (i == MAXQUOTAS)
		return (0);

	/*
	 * Sync out any orpaned dirty dquot entries.
	 */
	for (i = 0; i < MAXQUOTAS; i++)
		if (hfsmp->hfs_qfiles[i].qf_vp != NULLVP)
			dqsync_orphans(&hfsmp->hfs_qfiles[i]);

	/*
	 * Search vnodes associated with this mount point,
	 * synchronizing any modified dquot structures.
	 */
	simple_lock(&mntvnode_slock);
again:
	for (vp = mp->mnt_vnodelist.lh_first; vp != NULL; vp = nextvp) {
		if (vp->v_mount != mp)
			goto again;
		nextvp = vp->v_mntvnodes.le_next;
		simple_lock(&vp->v_interlock);
		simple_unlock(&mntvnode_slock);
		error = vget(vp, LK_EXCLUSIVE | LK_NOWAIT | LK_INTERLOCK, p);
		if (error) {
			simple_lock(&mntvnode_slock);
			if (error == ENOENT)
				goto again;
			continue;
		}

		/* Make sure that this is really an hfs vnode. */
		if (vp->v_mount != mp   ||
		    vp->v_type == VNON  ||
		    vp->v_tag != VT_HFS ||
		    VTOC(vp) == NULL) {
			vput(vp);
			simple_lock(&mntvnode_slock);
			goto again;
		}

		for (i = 0; i < MAXQUOTAS; i++) {
			dq = VTOC(vp)->c_dquot[i];
			if (dq != NODQUOT && (dq->dq_flags & DQ_MOD))
				dqsync(vp, dq);
		}
		vput(vp);
		simple_lock(&mntvnode_slock);
		if (vp->v_mntvnodes.le_next != nextvp)
			goto again;
	}
	simple_unlock(&mntvnode_slock);
	return (0);
}

/*
 * Q_QUOTASTAT - get quota on/off status 
 */
int
hfs_quotastat(mp, type, addr)
	struct mount *mp;
	register int type;
	caddr_t addr;
{
	struct hfsmount *hfsmp = VFSTOHFS(mp);
	int error = 0;
	int qstat;

	if ((mp->mnt_flag & MNT_QUOTA) && (hfsmp->hfs_qfiles[type].qf_vp != NULLVP))
	  qstat = 1;   /* quotas are on for this type */
	else
	  qstat = 0;   /* quotas are off for this type */
	
	error = copyout ((caddr_t)&qstat, addr, sizeof(qstat));
	return (error);
}

