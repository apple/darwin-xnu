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
/*	$NetBSD: umap_vnops.c,v 1.3 1994/08/19 11:25:42 mycroft Exp $	*/

/*
 * Copyright (c) 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software donated to Berkeley by
 * the UCLA Ficus project.
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
 *	@(#)umap_vnops.c	8.3 (Berkeley) 1/5/94
 */

/*
 * Umap Layer
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/malloc.h>
#include <sys/buf.h>
#include <miscfs/umapfs/umap.h>


int umap_bug_bypass = 0;   /* for debugging: enables bypass printf'ing */

/*
 * This is the 10-Apr-92 bypass routine.
 * See null_vnops.c:null_bypass for more details.
 */ 
int
umap_bypass(ap)
	struct vop_generic_args /* {
		struct vnodeop_desc *a_desc;
		<other random data follows, presumably>
	} */ *ap;
{
	extern int (**umap_vnodeop_p)(void *); /* not extern, really "forward" */
	struct ucred **credpp = 0, *credp = 0;
	struct ucred *savecredp, *savecompcredp = 0;
	struct ucred *compcredp = 0;
	struct vnode **this_vp_p;
	int error;
	struct vnode *old_vps[VDESC_MAX_VPS];
	struct vnode *vp1 = 0;
	struct vnode **vps_p[VDESC_MAX_VPS];
	struct vnode ***vppp;
	struct vnodeop_desc *descp = ap->a_desc;
	int reles, i;
	struct componentname **compnamepp = 0;

	if (umap_bug_bypass)
		printf ("umap_bypass: %s\n", descp->vdesc_name);

#ifdef SAFETY
	/*
	 * We require at least one vp.
	 */
	if (descp->vdesc_vp_offsets == NULL ||
	    descp->vdesc_vp_offsets[0] == VDESC_NO_OFFSET)
		panic ("umap_bypass: no vp's in map.\n");
#endif

	/*
	 * Map the vnodes going in.
	 * Later, we'll invoke the operation based on
	 * the first mapped vnode's operation vector.
	 */
	reles = descp->vdesc_flags;
	for (i = 0; i < VDESC_MAX_VPS; reles >>= 1, i++) {
		if (descp->vdesc_vp_offsets[i] == VDESC_NO_OFFSET)
			break;   /* bail out at end of list */
		vps_p[i] = this_vp_p = 
			VOPARG_OFFSETTO(struct vnode**, descp->vdesc_vp_offsets[i], ap);

		if (i == 0) {
			vp1 = *vps_p[0];
		}

		/*
		 * We're not guaranteed that any but the first vnode
		 * are of our type.  Check for and don't map any
		 * that aren't.  (Must map first vp or vclean fails.)
		 */

		if (i && (*this_vp_p)->v_op != umap_vnodeop_p) {
			old_vps[i] = NULL;
		} else {
			old_vps[i] = *this_vp_p;
			*(vps_p[i]) = UMAPVPTOLOWERVP(*this_vp_p);
			if (reles & 1)
				VREF(*this_vp_p);
		}
			
	}

	/*
	 * Fix the credentials.  (That's the purpose of this layer.)
	 */

	if (descp->vdesc_cred_offset != VDESC_NO_OFFSET) {

		credpp = VOPARG_OFFSETTO(struct ucred**, 
		    descp->vdesc_cred_offset, ap);

		/* Save old values */

		savecredp = *credpp;
		if (savecredp != NOCRED)
			*credpp = crdup(savecredp);
		credp = *credpp;

		if (umap_bug_bypass && credp->cr_uid != 0)
			printf("umap_bypass: user was %d, group %d\n", 
			    credp->cr_uid, credp->cr_gid);

		/* Map all ids in the credential structure. */

		umap_mapids(vp1->v_mount, credp);

		if (umap_bug_bypass && credp->cr_uid != 0)
			printf("umap_bypass: user now %d, group %d\n", 
			    credp->cr_uid, credp->cr_gid);
	}

	/* BSD often keeps a credential in the componentname structure
	 * for speed.  If there is one, it better get mapped, too. 
	 */

	if (descp->vdesc_componentname_offset != VDESC_NO_OFFSET) {

		compnamepp = VOPARG_OFFSETTO(struct componentname**, 
		    descp->vdesc_componentname_offset, ap);

		savecompcredp = (*compnamepp)->cn_cred;
		if (savecompcredp != NOCRED)
			(*compnamepp)->cn_cred = crdup(savecompcredp);
		compcredp = (*compnamepp)->cn_cred;

		if (umap_bug_bypass && compcredp->cr_uid != 0)
			printf("umap_bypass: component credit user was %d, group %d\n", 
			    compcredp->cr_uid, compcredp->cr_gid);

		/* Map all ids in the credential structure. */

		umap_mapids(vp1->v_mount, compcredp);

		if (umap_bug_bypass && compcredp->cr_uid != 0)
			printf("umap_bypass: component credit user now %d, group %d\n", 
			    compcredp->cr_uid, compcredp->cr_gid);
	}

	/*
	 * Call the operation on the lower layer
	 * with the modified argument structure.
	 */
	error = VCALL(*(vps_p[0]), descp->vdesc_offset, ap);

	/*
	 * Maintain the illusion of call-by-value
	 * by restoring vnodes in the argument structure
	 * to their original value.
	 */
	reles = descp->vdesc_flags;
	for (i = 0; i < VDESC_MAX_VPS; reles >>= 1, i++) {
		if (descp->vdesc_vp_offsets[i] == VDESC_NO_OFFSET)
			break;   /* bail out at end of list */
		if (old_vps[i]) {
			*(vps_p[i]) = old_vps[i];
			if (reles & 1)
				vrele(*(vps_p[i]));
		};
	};

	/*
	 * Map the possible out-going vpp
	 * (Assumes that the lower layer always returns
	 * a VREF'ed vpp unless it gets an error.)
	 */
	if (descp->vdesc_vpp_offset != VDESC_NO_OFFSET &&
	    !(descp->vdesc_flags & VDESC_NOMAP_VPP) &&
	    !error) {
		if (descp->vdesc_flags & VDESC_VPP_WILLRELE)
			goto out;
		vppp = VOPARG_OFFSETTO(struct vnode***,
				 descp->vdesc_vpp_offset, ap);
		error = umap_node_create(old_vps[0]->v_mount, **vppp, *vppp);
	};

 out:
	/* 
	 * Free duplicate cred structure and restore old one.
	 */
	if (descp->vdesc_cred_offset != VDESC_NO_OFFSET) {
		if (umap_bug_bypass && credp && credp->cr_uid != 0)
			printf("umap_bypass: returning-user was %d\n",
					credp->cr_uid);

		if (savecredp != NOCRED) {
			if (credp != NOCRED)
				crfree(credp);
			*credpp = savecredp;
			if (umap_bug_bypass && credpp && (*credpp)->cr_uid != 0)
			 	printf("umap_bypass: returning-user now %d\n\n", 
				    savecredp->cr_uid);
		}
	}

	if (descp->vdesc_componentname_offset != VDESC_NO_OFFSET) {
		if (umap_bug_bypass && compcredp && compcredp->cr_uid != 0)
			printf("umap_bypass: returning-component-user was %d\n", 
				compcredp->cr_uid);

		if (savecompcredp != NOCRED) {
			if (compcredp != NOCRED)
				crfree(compcredp);
			(*compnamepp)->cn_cred = savecompcredp;
			if (umap_bug_bypass && credpp && (*credpp)->cr_uid != 0)
			 	printf("umap_bypass: returning-component-user now %d\n", 
				    savecompcredp->cr_uid);
		}
	}

	return (error);
}


/*
 *  We handle getattr to change the fsid.
 */
int
umap_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	uid_t uid;
	gid_t gid;
	int error, tmpid, nentries, gnentries;
	uid_t (*mapdata)[2];
	gid_t (*gmapdata)[2];
	struct vnode **vp1p;
	struct vnodeop_desc *descp = ap->a_desc;

	if (error = umap_bypass(ap))
		return (error);
	/* Requires that arguments be restored. */
	ap->a_vap->va_fsid = ap->a_vp->v_mount->mnt_stat.f_fsid.val[0];

	/*
	 * Umap needs to map the uid and gid returned by a stat
	 * into the proper values for this site.  This involves
	 * finding the returned uid in the mapping information,
	 * translating it into the uid on the other end,
	 * and filling in the proper field in the vattr
	 * structure pointed to by ap->a_vap.  The group
	 * is easier, since currently all groups will be
	 * translate to the NULLGROUP.
	 */

	/* Find entry in map */

	uid = ap->a_vap->va_uid;
	gid = ap->a_vap->va_gid;
	if (umap_bug_bypass)
		printf("umap_getattr: mapped uid = %d, mapped gid = %d\n", uid, 
		    gid);

	vp1p = VOPARG_OFFSETTO(struct vnode**, descp->vdesc_vp_offsets[0], ap);
	nentries =  MOUNTTOUMAPMOUNT((*vp1p)->v_mount)->info_nentries;
	mapdata =  (MOUNTTOUMAPMOUNT((*vp1p)->v_mount)->info_mapdata);
	gnentries =  MOUNTTOUMAPMOUNT((*vp1p)->v_mount)->info_gnentries;
	gmapdata =  (MOUNTTOUMAPMOUNT((*vp1p)->v_mount)->info_gmapdata);

	/* Reverse map the uid for the vnode.  Since it's a reverse
		map, we can't use umap_mapids() to do it. */

	tmpid = umap_reverse_findid(uid, mapdata, nentries);

	if (tmpid != -1) {
		ap->a_vap->va_uid = (uid_t) tmpid;
		if (umap_bug_bypass)
			printf("umap_getattr: original uid = %d\n", uid);
	} else 
		ap->a_vap->va_uid = (uid_t) NOBODY;

	/* Reverse map the gid for the vnode. */

	tmpid = umap_reverse_findid(gid, gmapdata, gnentries);

	if (tmpid != -1) {
		ap->a_vap->va_gid = (gid_t) tmpid;
		if (umap_bug_bypass)
			printf("umap_getattr: original gid = %d\n", gid);
	} else
		ap->a_vap->va_gid = (gid_t) NULLGROUP;
	
	return (0);
}

int
umap_inactive(ap)
	struct vop_inactive_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	/*
	 * Do nothing (and _don't_ bypass).
	 * Wait to vrele lowervp until reclaim,
	 * so that until then our umap_node is in the
	 * cache and reusable.
	 *
	 */
	return (0);
}

int
umap_reclaim(ap)
	struct vop_reclaim_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct umap_node *xp = VTOUMAP(vp);
	struct vnode *lowervp = xp->umap_lowervp;
	
	/* After this assignment, this node will not be re-used. */
	xp->umap_lowervp = NULL;
	LIST_REMOVE(xp, umap_hash);
	FREE(vp->v_data, M_TEMP);
	vp->v_data = NULL;
	vrele(lowervp);
	return (0);
}

int
umap_strategy(ap)
	struct vop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{
	struct buf *bp = ap->a_bp;
	int error;
	struct vnode *savedvp;

	savedvp = bp->b_vp;
	bp->b_vp = UMAPVPTOLOWERVP(bp->b_vp);

	error = VOP_STRATEGY(ap->a_bp);

	bp->b_vp = savedvp;

	return (error);
}

int
umap_bwrite(ap)
	struct vop_bwrite_args /* {
		struct buf *a_bp;
	} */ *ap;
{
	struct buf *bp = ap->a_bp;
	int error;
	struct vnode *savedvp;

	savedvp = bp->b_vp;
	bp->b_vp = UMAPVPTOLOWERVP(bp->b_vp);

	error = VOP_BWRITE(ap->a_bp);

	bp->b_vp = savedvp;

	return (error);
}


int
umap_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	printf("\ttag VT_UMAPFS, vp=%x, lowervp=%x\n", vp, UMAPVPTOLOWERVP(vp));
	return (0);
}

int
umap_rename(ap)
	struct vop_rename_args  /* {
		struct vnode *a_fdvp;
		struct vnode *a_fvp;
		struct componentname *a_fcnp;
		struct vnode *a_tdvp;
		struct vnode *a_tvp;
		struct componentname *a_tcnp;
	} */ *ap;
{
	int error;
	struct componentname *compnamep;
	struct ucred *compcredp, *savecompcredp;
	struct vnode *vp;

	/*
	 * Rename is irregular, having two componentname structures.
	 * We need to map the cre in the second structure,
	 * and then bypass takes care of the rest.
	 */

	vp = ap->a_fdvp;
	compnamep = ap->a_tcnp;
	compcredp = compnamep->cn_cred;

	savecompcredp = compcredp;
	compcredp = compnamep->cn_cred = crdup(savecompcredp);

	if (umap_bug_bypass && compcredp->cr_uid != 0)
		printf("umap_rename: rename component credit user was %d, group %d\n", 
		    compcredp->cr_uid, compcredp->cr_gid);

	/* Map all ids in the credential structure. */

	umap_mapids(vp->v_mount, compcredp);

	if (umap_bug_bypass && compcredp->cr_uid != 0)
		printf("umap_rename: rename component credit user now %d, group %d\n", 
		    compcredp->cr_uid, compcredp->cr_gid);

	error = umap_bypass(ap);
	
	/* Restore the additional mapped componentname cred structure. */

	crfree(compcredp);
	compnamep->cn_cred = savecompcredp;

	return error;
}

/*
 * Global vfs data structures
 */
/*
 * XXX - strategy, bwrite are hand coded currently.  They should
 * go away with a merged buffer/block cache.
 *
 */

#define VOPFUNC int (*)(void *)

int (**umap_vnodeop_p)(void *);
struct vnodeopv_entry_desc umap_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)umap_bypass },
	{ &vop_getattr_desc, (VOPFUNC)umap_getattr },
	{ &vop_inactive_desc, (VOPFUNC)umap_inactive },
	{ &vop_reclaim_desc, (VOPFUNC)umap_reclaim },
	{ &vop_print_desc, (VOPFUNC)umap_print },
	{ &vop_rename_desc, (VOPFUNC)umap_rename },
	{ &vop_strategy_desc, (VOPFUNC)umap_strategy },
	{ &vop_bwrite_desc, (VOPFUNC)umap_bwrite },

	{ (struct vnodeop_desc*) NULL, (int(*)()) NULL }
};
struct vnodeopv_desc umap_vnodeop_opv_desc =
	{ &umap_vnodeop_p, umap_vnodeop_entries };
