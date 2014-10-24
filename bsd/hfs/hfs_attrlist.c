/*
 * Copyright (c) 2000-2014 Apple Inc. All rights reserved.
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
 * hfs_attrlist.c - HFS attribute list processing
 *
 * Copyright (c) 1998-2002, Apple Computer, Inc.  All Rights Reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/attr.h>
#include <sys/stat.h>
#include <sys/unistd.h>
#include <sys/mount_internal.h>
#include <sys/kauth.h>
#include <sys/fsctl.h>

#include <kern/locks.h>

#include "hfs.h"
#include "hfs_cnode.h"
#include "hfs_mount.h"
#include "hfs_dbg.h"
#include "hfs_attrlist.h"
#include "hfs_btreeio.h"

/* Packing routines: */

static void packnameattr(struct attrblock *abp, struct vnode *vp,
			const u_int8_t *name, int namelen);

static void packcommonattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct vnode *vp, struct cat_desc * cdp,
			struct cat_attr * cap, struct vfs_context *ctx);

static void packfileattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct cat_attr *cattrp, struct cat_fork *datafork,
			struct cat_fork *rsrcfork, struct vnode *vp);

static void packdirattr(struct attrblock *abp, struct hfsmount *hfsmp,
			struct vnode *vp, struct cat_desc * descp,
			struct cat_attr * cattrp);

static u_int32_t hfs_real_user_access(vnode_t vp, vfs_context_t ctx);

static void get_vattr_data_for_attrs(struct attrlist *, struct vnode_attr *,
    struct hfsmount *, struct vnode *, struct cat_desc *, struct cat_attr *,
    struct cat_fork *, struct cat_fork *, vfs_context_t);

static void vattr_data_for_common_attrs(struct attrlist *, struct vnode_attr *,
    struct hfsmount *, struct vnode *, struct cat_desc *, struct cat_attr *,
    vfs_context_t);

static void vattr_data_for_dir_attrs(struct attrlist *, struct vnode_attr *,
    struct hfsmount *, struct vnode *, struct cat_desc *, struct cat_attr *);

static void vattr_data_for_file_attrs(struct attrlist *, struct vnode_attr *,
    struct hfsmount *, struct cat_attr *, struct cat_fork *, struct cat_fork *,
    struct vnode *vp);

static int hfs_readdirattr_internal(struct vnode *, struct attrlist *,
    struct vnode_attr *, uio_t, uint64_t, int, uint32_t *, int *, int *,
    vfs_context_t);

/*
 * readdirattr operation will return attributes for the items in the
 * directory specified. 
 *
 * It does not do . and .. entries. The problem is if you are at the root of the
 * hfs directory and go to .. you could be crossing a mountpoint into a
 * different (ufs) file system. The attributes that apply for it may not 
 * apply for the file system you are doing the readdirattr on. To make life 
 * simpler, this call will only return entries in its directory, hfs like.
 */
int
hfs_vnop_readdirattr(ap)
	struct vnop_readdirattr_args /* {
		struct vnode *a_vp;
		struct attrlist *a_alist;
		struct uio *a_uio;
		u_long a_maxcount;
		u_long a_options;
		u_long *a_newstate;
		int *a_eofflag;
		u_long *a_actualcount;
		vfs_context_t a_context;
	} */ *ap;
{
	int error;
	struct attrlist *alist = ap->a_alist;

	/* Check for invalid options and buffer space. */
	if (((ap->a_options & ~(FSOPT_NOINMEMUPDATE | FSOPT_NOFOLLOW)) != 0) ||
	    (ap->a_maxcount <= 0)) {
		return (EINVAL);
	}
	/*
	 * Reject requests for unsupported attributes.
	 */
	if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
	    (alist->commonattr & ~HFS_ATTR_CMN_VALID) ||
	    (alist->volattr  != 0) ||
	    (alist->dirattr & ~HFS_ATTR_DIR_VALID) ||
	    (alist->fileattr & ~HFS_ATTR_FILE_VALID) ||
	    (alist->forkattr != 0)) {
		return (EINVAL);
	}

	error = hfs_readdirattr_internal(ap->a_vp, alist, NULL, ap->a_uio,
	    (uint64_t)ap->a_options, ap->a_maxcount, ap->a_newstate,
	    ap->a_eofflag, (int *)ap->a_actualcount, ap->a_context);

	return (error);
}


/*
 * getattrlistbulk, like readdirattr, will return attributes for the items in
 * the directory specified.
 *
 * It does not do . and .. entries. The problem is if you are at the root of the
 * hfs directory and go to .. you could be crossing a mountpoint into a
 * different (ufs) file system. The attributes that apply for it may not
 * apply for the file system you are doing the readdirattr on. To make life
 * simpler, this call will only return entries in its directory, hfs like.
 */
int
hfs_vnop_getattrlistbulk(ap)
	struct vnop_getattrlistbulk_args /* {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		struct attrlist *a_alist;
		struct vnode_attr *a_vap;
		struct uio *a_uio;
		void *a_private;
		uint64_t a_options;
		int32_t *a_eofflag;
		int32_t *a_actualcount;
		vfs_context_t a_context;
	} */ *ap;
{
	int error = 0;

	error = hfs_readdirattr_internal(ap->a_vp, ap->a_alist, ap->a_vap,
	    ap->a_uio, (uint64_t)ap->a_options, 0, NULL, ap->a_eofflag,
	    (int *)ap->a_actualcount, ap->a_context);

	return (error);
}

/*
 * Common function for both hfs_vnop_readdirattr and hfs_vnop_getattrlistbulk.
 * This either fills in a vnode_attr structure or fills in an attrbute buffer
 * Currently the difference in behaviour required for the two vnops is keyed
 * on whether the passed in vnode_attr pointer is null or not. If the pointer
 * is null we fill in buffer passed and if it is not null we fill in the fields
 * of the vnode_attr structure.
 */
int
hfs_readdirattr_internal(struct vnode *dvp, struct attrlist *alist,
    struct vnode_attr *vap, uio_t uio, uint64_t options, int maxcount,
    uint32_t *newstate, int *eofflag, int *actualcount, vfs_context_t ctx)
{
	struct cnode *dcp;
	struct hfsmount * hfsmp;
	u_int32_t fixedblocksize;
	u_int32_t maxattrblocksize;
	u_int32_t currattrbufsize;
	void *attrbufptr = NULL;
	void *attrptr = NULL;
	void *varptr = NULL;
	caddr_t namebuf = NULL;
	struct attrblock attrblk;
	int error = 0;
	int index = 0;
	int i = 0;
	struct cat_desc *lastdescp = NULL;
	struct cat_entrylist *ce_list = NULL;
	directoryhint_t *dirhint = NULL;
	unsigned int tag;
	int maxentries;
	int lockflags;
	u_int32_t dirchg = 0;
	int reachedeof = 0;

	*(actualcount) = 0;
	*(eofflag) = 0;

	if ((uio_resid(uio) <= 0) || (uio_iovcnt(uio) > 1))
		return (EINVAL);

	if (VTOC(dvp)->c_bsdflags & UF_COMPRESSED) {
		int compressed = hfs_file_is_compressed(VTOC(dvp), 0);  /* 0 == take the cnode lock */

		if (!compressed) {
			error = check_for_dataless_file(dvp, NAMESPACE_HANDLER_READ_OP);
			if (error) {
				return error;
			}
		}
	}

	/*
	 * Take an exclusive directory lock since we manipulate the directory hints
	 */
	if ((error = hfs_lock(VTOC(dvp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_DEFAULT))) {
		return (error);
	}
	dcp = VTOC(dvp);
	hfsmp = VTOHFS(dvp);

	dirchg = dcp->c_dirchangecnt;

	/* Extract directory index and tag (sequence number) from uio_offset */
	index = uio_offset(uio) & HFS_INDEX_MASK;
	tag = uio_offset(uio) & ~HFS_INDEX_MASK;

	/*
	 * We can't just use the valence as an optimization to avoid
	 * going to the catalog.  It might be wrong (== 0), and that would
	 * cause us to avoid iterating the directory when it might actually have
	 * contents.  Instead, use the catalog to tell us when we've hit EOF
	 * for this directory
	 */

	/* Get a buffer to hold packed attributes. */
	fixedblocksize = (sizeof(u_int32_t) + hfs_attrblksize(alist)); /* 4 bytes for length */

	if (!vap) {
		maxattrblocksize = fixedblocksize;
		if (alist->commonattr & ATTR_CMN_NAME)
			maxattrblocksize += kHFSPlusMaxFileNameBytes + 1;

		MALLOC(attrbufptr, void *, maxattrblocksize, M_TEMP, M_WAITOK);
		if (attrbufptr == NULL) {
			error = ENOMEM;
			goto exit2;
		}
		attrptr = attrbufptr;
		varptr = (char *)attrbufptr + fixedblocksize;  /* Point to variable-length storage */
	} else {
		if ((alist->commonattr & ATTR_CMN_NAME) && !vap->va_name) {
			MALLOC(namebuf, caddr_t, MAXPATHLEN, M_TEMP, M_WAITOK);
			if (!namebuf) {
				error = ENOMEM;
				goto exit2;
			}
			vap->va_name = namebuf;
		}
	}
	/* Get a detached directory hint (cnode must be locked exclusive) */	
	dirhint = hfs_getdirhint(dcp, ((index - 1) & HFS_INDEX_MASK) | tag, TRUE);

	/* Hide tag from catalog layer. */
	dirhint->dh_index &= HFS_INDEX_MASK;
	if (dirhint->dh_index == HFS_INDEX_MASK) {
		dirhint->dh_index = -1;
	}

	/*
	 * Obtain a list of catalog entries and pack their attributes until
	 * the output buffer is full or maxcount entries have been packed.
	 */

	/*
	 * Constrain our list size.
	 */
	maxentries = uio_resid(uio) / (fixedblocksize + HFS_AVERAGE_NAME_SIZE);
	/* There is maxcount for the bulk vnop */
	if (!vap)
		maxentries = min(maxentries, maxcount);
	maxentries = min(maxentries, MAXCATENTRIES);
	if (maxentries < 1) {
		error = EINVAL;
		goto exit2;
	}

	/* Initialize a catalog entry list. */
	MALLOC(ce_list, struct cat_entrylist *, CE_LIST_SIZE(maxentries), M_TEMP, M_WAITOK);
	if (ce_list == NULL) {
		error = ENOMEM;
		goto exit2;
	}
	bzero(ce_list, CE_LIST_SIZE(maxentries));
	ce_list->maxentries = maxentries;

	/*
	 * Populate the ce_list from the catalog file.
	 */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
	 
	error = cat_getentriesattr(hfsmp, dirhint, ce_list, &reachedeof);
	/* Don't forget to release the descriptors later! */

	hfs_systemfile_unlock(hfsmp, lockflags);

	if ((error == ENOENT) || (reachedeof != 0)) { 
		*(eofflag) = TRUE;
		error = 0;
	}
	if (error) {
		goto exit1;
	}

	/* 
	 * Check for a FS corruption in the valence. We're holding the cnode lock
	 * exclusive since we need to serialize the directory hints, so if we found
	 * that the valence reported 0, but we actually found some items here, then
	 * silently minimally self-heal and bump the valence to 1.
	 */
	if ((dcp->c_entries == 0) && (ce_list->realentries > 0)) {
		dcp->c_entries++;
		dcp->c_flag |= (C_MODIFIED | C_FORCEUPDATE);
		printf("hfs_vnop_readdirattr: repairing valence to non-zero! \n");
		/* force an update on dcp while we're still holding the lock. */
		hfs_update(dvp, 0);
	}

	/*
	 * Drop the directory lock so we don't deadlock when we:
	 *   - acquire a child cnode lock
	 *   - make calls to vnode_authorize()
	 *   - make calls to kauth_cred_ismember_gid()
	 */
	hfs_unlock(dcp);
	dcp = NULL;

	/* Process the catalog entries. */
	for (i = 0; i < (int)ce_list->realentries; ++i) {
		struct cnode *cp = NULL;
		struct vnode *vp = NULL;
		struct cat_desc * cdescp;
		struct cat_attr * cattrp;
		struct cat_fork c_datafork;
		struct cat_fork c_rsrcfork;

		bzero(&c_datafork, sizeof(c_datafork));
		bzero(&c_rsrcfork, sizeof(c_rsrcfork));
		cdescp = &ce_list->entry[i].ce_desc;
		cattrp = &ce_list->entry[i].ce_attr;
		c_datafork.cf_size   = ce_list->entry[i].ce_datasize;
		c_datafork.cf_blocks = ce_list->entry[i].ce_datablks;
		c_rsrcfork.cf_size   = ce_list->entry[i].ce_rsrcsize;
		c_rsrcfork.cf_blocks = ce_list->entry[i].ce_rsrcblks;

		if (((alist->commonattr & ATTR_CMN_USERACCESS) &&
		    (cattrp->ca_recflags & kHFSHasSecurityMask))
#if CONFIG_PROTECT
		    ||
		   ((alist->commonattr & ATTR_CMN_DATA_PROTECT_FLAGS) && (vap))
#endif
		    ) {
			/*
			 * Obtain vnode for our vnode_authorize() calls.
			 */
			if (hfs_vget(hfsmp, cattrp->ca_fileid, &vp, 0, 0) != 0) {
				vp = NULL;
			}
		} else if (vap || !(options & FSOPT_NOINMEMUPDATE)) {
			/* Get in-memory cnode data (if any). */
			vp = hfs_chash_getvnode(hfsmp, cattrp->ca_fileid, 0, 0, 0);
		}
		if (vp != NULL) {
			cp = VTOC(vp);
			/* Only use cnode's decriptor for non-hardlinks */
			if (!(cp->c_flag & C_HARDLINK))
				cdescp = &cp->c_desc;
			cattrp = &cp->c_attr;
			if (cp->c_datafork) {
				c_datafork.cf_size   = cp->c_datafork->ff_size;
				c_datafork.cf_blocks = cp->c_datafork->ff_blocks;
			}
			if (cp->c_rsrcfork) {
				c_rsrcfork.cf_size   = cp->c_rsrcfork->ff_size;
				c_rsrcfork.cf_blocks = cp->c_rsrcfork->ff_blocks;
			}
			/* All done with cnode. */
			hfs_unlock(cp);
			cp = NULL;
		}

		if (!vap) {
			*((u_int32_t *)attrptr) = 0;
			attrptr = ((u_int32_t *)attrptr) + 1;
			attrblk.ab_attrlist = alist;
			attrblk.ab_attrbufpp = &attrptr;
			attrblk.ab_varbufpp = &varptr;
			attrblk.ab_flags = 0;
			attrblk.ab_blocksize = maxattrblocksize;
			attrblk.ab_context = ctx;

			/* Pack catalog entries into attribute buffer. */
			hfs_packattrblk(&attrblk, hfsmp, vp, cdescp, cattrp, &c_datafork, &c_rsrcfork, ctx);
			currattrbufsize = ((char *)varptr - (char *)attrbufptr);

			/* All done with vnode. */
			if (vp != NULL) {
				vnode_put(vp);
				vp = NULL;
			}

			/* Make sure there's enough buffer space remaining. */
			// LP64todo - fix this!
			if (uio_resid(uio) < 0 ||
				currattrbufsize > (u_int32_t)uio_resid(uio)) {
				break;
			} else {
				*((u_int32_t *)attrbufptr) = currattrbufsize;
				error = uiomove((caddr_t)attrbufptr, currattrbufsize, uio);
				if (error != E_NONE) {
					break;
				}
				attrptr = attrbufptr;
				/* Point to variable-length storage */
				varptr = (char *)attrbufptr + fixedblocksize;
				/* Save the last valid catalog entry */
				lastdescp = &ce_list->entry[i].ce_desc;
				index++;
				*actualcount += 1;

				/* Termination checks */
				if ((--maxcount <= 0) ||
				    // LP64todo - fix this!
				    uio_resid(uio) < 0 ||
				    ((u_int32_t)uio_resid(uio) < (fixedblocksize + HFS_AVERAGE_NAME_SIZE))){
					break;
				}
			}
		} else {
			size_t orig_resid = (size_t)uio_resid(uio);
			size_t resid;

			get_vattr_data_for_attrs(alist, vap, hfsmp, vp, cdescp,
			    cattrp, &c_datafork, &c_rsrcfork, ctx);

#if CONFIG_PROTECT
			if ((alist->commonattr & ATTR_CMN_DATA_PROTECT_FLAGS) &&
			    vp) {
				int class;

				if (!cp_vnode_getclass(vp, &class)) {
					VATTR_RETURN(vap, va_dataprotect_class,
					    (uint32_t)class);
				}
			}
#endif
			error = vfs_attr_pack(vp, uio, alist, options, vap,
			    NULL, ctx);

			/* All done with vnode. */
			if (vp) {
				vnode_put(vp);
				vp = NULL;
			}

			resid = uio_resid(uio);

			/* Was this entry succesful ? */
			if (error || resid == orig_resid)
				break;

			/* Save the last valid catalog entry */
			lastdescp = &ce_list->entry[i].ce_desc;
			index++;
			*actualcount += 1;

			/* Do we have the bare minimum for the next entry ? */
			if (resid < sizeof(uint32_t))
				break;
		}
	} /* for each catalog entry */

	/* If we skipped catalog entries for reserved files that should
	 * not be listed in namespace, update the index accordingly.
	 */
	if (ce_list->skipentries) {
		index += ce_list->skipentries;
		ce_list->skipentries = 0;
	}

	/* 
	 * If there are more entries then save the last name. 
	 * Key this behavior based on whether or not we observed EOFFLAG. 
	 *
	 * Do not use the valence as a way to determine if we hit EOF, since
	 * it can be wrong.  Use the catalog's output only.
	 */
	if ((*(eofflag) == 0) &&  lastdescp != NULL) {

		/* Remember last entry */
		if ((dirhint->dh_desc.cd_flags & CD_HASBUF) &&
		    (dirhint->dh_desc.cd_nameptr != NULL)) {
			dirhint->dh_desc.cd_flags &= ~CD_HASBUF;
			vfs_removename((const char *)dirhint->dh_desc.cd_nameptr);
		}
		dirhint->dh_desc.cd_namelen = lastdescp->cd_namelen;
		dirhint->dh_desc.cd_nameptr = (const u_int8_t *)
		vfs_addname((const char *)lastdescp->cd_nameptr, lastdescp->cd_namelen, 0, 0);
		dirhint->dh_desc.cd_flags |= CD_HASBUF;
		dirhint->dh_index = index - 1;
		dirhint->dh_desc.cd_cnid = lastdescp->cd_cnid;
		dirhint->dh_desc.cd_hint = lastdescp->cd_hint;
		dirhint->dh_desc.cd_encoding = lastdescp->cd_encoding;
	} 

	/* All done with the catalog descriptors. */
	for (i = 0; i < (int)ce_list->realentries; ++i)
		cat_releasedesc(&ce_list->entry[i].ce_desc);
	ce_list->realentries = 0;

	(void) hfs_lock(VTOC(dvp), HFS_EXCLUSIVE_LOCK, HFS_LOCK_ALLOW_NOEXISTS);
	dcp = VTOC(dvp);

exit1:
	/* Pack directory index and tag into uio_offset. */
	while (tag == 0) tag = (++dcp->c_dirhinttag) << HFS_INDEX_BITS;	
	uio_setoffset(uio, index | tag);
	dirhint->dh_index |= tag;

exit2:
	if (newstate)
		*newstate = dirchg;

	/* 
	 * Drop directory hint on error or if there are no more entries,
	 * only if EOF was seen.
	 */
	if (dirhint) {
		if ((error != 0) || *(eofflag))
			hfs_reldirhint(dcp, dirhint);
		else
			hfs_insertdirhint(dcp, dirhint);
	}
	if (namebuf) {
		FREE(namebuf, M_TEMP);
		vap->va_name = NULL;
	}
	if (attrbufptr)
		FREE(attrbufptr, M_TEMP);
	if (ce_list)
		FREE(ce_list, M_TEMP);

	if (vap && *actualcount && error)
		error = 0;

	hfs_unlock(dcp);
	return (error);
}


/*==================== Attribute list support routines ====================*/

/*
 * Pack cnode attributes into an attribute block.
 */
__private_extern__
void
hfs_packattrblk(struct attrblock *abp,
		struct hfsmount *hfsmp,
		struct vnode *vp,
		struct cat_desc *descp,
		struct cat_attr *attrp,
		struct cat_fork *datafork,
		struct cat_fork *rsrcfork,
		struct vfs_context *ctx)
{
	struct attrlist *attrlistp = abp->ab_attrlist;

	if (attrlistp->commonattr)
		packcommonattr(abp, hfsmp, vp, descp, attrp, ctx);

	if (attrlistp->dirattr && S_ISDIR(attrp->ca_mode))
		packdirattr(abp, hfsmp, vp, descp,attrp);

	if (attrlistp->fileattr && !S_ISDIR(attrp->ca_mode))
		packfileattr(abp, hfsmp, attrp, datafork, rsrcfork, vp);
}


static char*
mountpointname(struct mount *mp)
{
	size_t namelength = strlen(mp->mnt_vfsstat.f_mntonname);
	int foundchars = 0;
	char *c;
	
	if (namelength == 0)
		return (NULL);
	
	/*
	 * Look backwards through the name string, looking for
	 * the first slash encountered (which must precede the
	 * last part of the pathname).
	 */
	for (c = mp->mnt_vfsstat.f_mntonname + namelength - 1;
	     namelength > 0; --c, --namelength) {
		if (*c != '/') {
			foundchars = 1;
		} else if (foundchars) {
			return (c + 1);
		}
	}
	
	return (mp->mnt_vfsstat.f_mntonname);
}


static void
packnameattr(
	struct attrblock *abp,
	struct vnode *vp,
	const u_int8_t *name,
	int namelen)
{
	void *varbufptr;
	struct attrreference * attr_refptr;
	char *mpname;
	size_t mpnamelen;
	u_int32_t attrlength;
	u_int8_t empty = 0;
	
	/* A cnode's name may be incorrect for the root of a mounted
	 * filesystem (it can be mounted on a different directory name
	 * than the name of the volume, such as "blah-1").  So for the
	 * root directory, it's best to return the last element of the
	 location where the volume's mounted:
	 */
	if ((vp != NULL) && vnode_isvroot(vp) &&
	    (mpname = mountpointname(vnode_mount(vp)))) {
		mpnamelen = strlen(mpname);
		
		/* Trim off any trailing slashes: */
		while ((mpnamelen > 0) && (mpname[mpnamelen-1] == '/'))
			--mpnamelen;

		/* If there's anything left, use it instead of the volume's name */
		if (mpnamelen > 0) {
			name = (u_int8_t *)mpname;
			namelen = mpnamelen;
		}
	}
	if (name == NULL) {
		name = &empty;
		namelen = 0;
	}

	varbufptr = *abp->ab_varbufpp;
	attr_refptr = (struct attrreference *)(*abp->ab_attrbufpp);

	attrlength = namelen + 1;
	attr_refptr->attr_dataoffset = (char *)varbufptr - (char *)attr_refptr;
	attr_refptr->attr_length = attrlength;
	(void) strncpy((char *)varbufptr, (const char *) name, attrlength);
	/*
	 * Advance beyond the space just allocated and
	 * round up to the next 4-byte boundary:
	 */
	varbufptr = ((char *)varbufptr) + attrlength + ((4 - (attrlength & 3)) & 3);
	++attr_refptr;

	*abp->ab_attrbufpp = attr_refptr;
	*abp->ab_varbufpp = varbufptr;
}

static void
packcommonattr(
	struct attrblock *abp,
	struct hfsmount *hfsmp,
	struct vnode *vp,
	struct cat_desc * cdp,
	struct cat_attr * cap,
	struct vfs_context * ctx)
{
	attrgroup_t attr = abp->ab_attrlist->commonattr;
	struct mount *mp = HFSTOVFS(hfsmp);
	void *attrbufptr = *abp->ab_attrbufpp;
	void *varbufptr = *abp->ab_varbufpp;
	boolean_t is_64_bit = proc_is64bit(vfs_context_proc(ctx));
	uid_t cuid = 1;
	int isroot = 0;

	if (attr & (ATTR_CMN_OWNERID | ATTR_CMN_GRPID)) {
		cuid = kauth_cred_getuid(vfs_context_ucred(ctx));
		isroot = cuid == 0;
	}
	
	if (ATTR_CMN_NAME & attr) {
		packnameattr(abp, vp, cdp->cd_nameptr, cdp->cd_namelen);
		attrbufptr = *abp->ab_attrbufpp;
		varbufptr = *abp->ab_varbufpp;
	}
	if (ATTR_CMN_DEVID & attr) {
		*((dev_t *)attrbufptr) = hfsmp->hfs_raw_dev;
		attrbufptr = ((dev_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_FSID & attr) {
		fsid_t fsid;
		
		fsid.val[0] = hfsmp->hfs_raw_dev;
		fsid.val[1] = vfs_typenum(mp);
		*((fsid_t *)attrbufptr) = fsid;
		attrbufptr = ((fsid_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_OBJTYPE & attr) {
		*((fsobj_type_t *)attrbufptr) = IFTOVT(cap->ca_mode);
		attrbufptr = ((fsobj_type_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_OBJTAG & attr) {
		*((fsobj_tag_t *)attrbufptr) = VT_HFS;
		attrbufptr = ((fsobj_tag_t *)attrbufptr) + 1;
	}
	/*
	 * Exporting file IDs from HFS Plus:
	 *
	 * For "normal" files the c_fileid is the same value as the
	 * c_cnid.  But for hard link files, they are different - the
	 * c_cnid belongs to the active directory entry (ie the link)
	 * and the c_fileid is for the actual inode (ie the data file).
	 *
	 * The stat call (getattr) will always return the c_fileid
	 * and Carbon APIs, which are hardlink-ignorant, will always
	 * receive the c_cnid (from getattrlist).
	 */
	if (ATTR_CMN_OBJID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = cdp->cd_cnid;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		attrbufptr = ((fsobj_id_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_OBJPERMANENTID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = cdp->cd_cnid;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		attrbufptr = ((fsobj_id_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_PAROBJID & attr) {
		((fsobj_id_t *)attrbufptr)->fid_objno = cdp->cd_parentcnid;
		((fsobj_id_t *)attrbufptr)->fid_generation = 0;
		attrbufptr = ((fsobj_id_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_SCRIPT & attr) {
		*((text_encoding_t *)attrbufptr) = cdp->cd_encoding;
		attrbufptr = ((text_encoding_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_CRTIME & attr) {
	    if (is_64_bit) {
            ((struct user64_timespec *)attrbufptr)->tv_sec = cap->ca_itime;
            ((struct user64_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user64_timespec *)attrbufptr) + 1;
	    }
	    else {
            ((struct user32_timespec *)attrbufptr)->tv_sec = cap->ca_itime;
            ((struct user32_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user32_timespec *)attrbufptr) + 1;
	    }
	}
	if (ATTR_CMN_MODTIME & attr) {
	    if (is_64_bit) {
             ((struct user64_timespec *)attrbufptr)->tv_sec = cap->ca_mtime;
             ((struct user64_timespec *)attrbufptr)->tv_nsec = 0;
			 attrbufptr = ((struct user64_timespec *)attrbufptr) + 1;
	    }
	    else {
            ((struct user32_timespec *)attrbufptr)->tv_sec = cap->ca_mtime;
            ((struct user32_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user32_timespec *)attrbufptr) + 1;
	    }
	}
	if (ATTR_CMN_CHGTIME & attr) {
	    if (is_64_bit) {
            ((struct user64_timespec *)attrbufptr)->tv_sec = cap->ca_ctime;
            ((struct user64_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user64_timespec *)attrbufptr) + 1;
	    }
	    else {
            ((struct user32_timespec *)attrbufptr)->tv_sec = cap->ca_ctime;
            ((struct user32_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user32_timespec *)attrbufptr) + 1;
	    }
	}
	if (ATTR_CMN_ACCTIME & attr) {
	    if (is_64_bit) {
            ((struct user64_timespec *)attrbufptr)->tv_sec = cap->ca_atime;
            ((struct user64_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user64_timespec *)attrbufptr) + 1;
	    }
	    else {
            ((struct user32_timespec *)attrbufptr)->tv_sec = cap->ca_atime;
            ((struct user32_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user32_timespec *)attrbufptr) + 1;
	    }
	}
	if (ATTR_CMN_BKUPTIME & attr) {
	    if (is_64_bit) {
            ((struct user64_timespec *)attrbufptr)->tv_sec = cap->ca_btime;
            ((struct user64_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user64_timespec *)attrbufptr) + 1;
	    }
	    else {
            ((struct user32_timespec *)attrbufptr)->tv_sec = cap->ca_btime;
            ((struct user32_timespec *)attrbufptr)->tv_nsec = 0;
			attrbufptr = ((struct user32_timespec *)attrbufptr) + 1;
	    }
	}
	if (ATTR_CMN_FNDRINFO & attr) {
		u_int8_t *finfo = NULL;
		bcopy(&cap->ca_finderinfo, attrbufptr, sizeof(u_int8_t) * 32);
		finfo = (u_int8_t*)attrbufptr;

		/* Don't expose a symlink's private type/creator. */
		if (S_ISLNK(cap->ca_mode)) {
			struct FndrFileInfo *fip;

			fip = (struct FndrFileInfo *)attrbufptr;
			fip->fdType = 0;
			fip->fdCreator = 0;
		}

		/* advance 16 bytes into the attrbuf */
		finfo = finfo + 16;

		/* also don't expose the date_added or write_gen_counter fields */
		if (S_ISREG(cap->ca_mode) || S_ISLNK(cap->ca_mode)) {
			struct FndrExtendedFileInfo *extinfo = (struct FndrExtendedFileInfo *)finfo;
			extinfo->document_id = 0;
			extinfo->date_added = 0;
			extinfo->write_gen_counter = 0;
		}
		else if (S_ISDIR(cap->ca_mode)) {
			struct FndrExtendedDirInfo *extinfo = (struct FndrExtendedDirInfo *)finfo;
			extinfo->document_id = 0;
			extinfo->date_added = 0;
			extinfo->write_gen_counter = 0;
		}

		attrbufptr = (char *)attrbufptr + sizeof(u_int8_t) * 32;
	}
	if (ATTR_CMN_OWNERID & attr) {
		uid_t nuid = cap->ca_uid;

		if (!isroot) {
			if (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS)
				nuid = cuid;
			else if (nuid == UNKNOWNUID)
				nuid = cuid;
		}

		*((uid_t *)attrbufptr) = nuid;
		attrbufptr = ((uid_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_GRPID & attr) {
		gid_t ngid = cap->ca_gid;

		if (!isroot) {
			gid_t cgid = kauth_cred_getgid(vfs_context_ucred(ctx));
			if (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS)
				ngid = cgid;
			else if (ngid == UNKNOWNUID)
				ngid = cgid;
		}

		*((gid_t *)attrbufptr) = ngid;
		attrbufptr = ((gid_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_ACCESSMASK & attr) {
		/*
		 * [2856576]  Since we are dynamically changing the owner, also
		 * effectively turn off the set-user-id and set-group-id bits,
		 * just like chmod(2) would when changing ownership.  This prevents
		 * a security hole where set-user-id programs run as whoever is
		 * logged on (or root if nobody is logged in yet!)
		 */
		*((u_int32_t *)attrbufptr) = (cap->ca_uid == UNKNOWNUID) ?
			cap->ca_mode & ~(S_ISUID | S_ISGID) : cap->ca_mode;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_FLAGS & attr) {
		*((u_int32_t *)attrbufptr) = cap->ca_flags;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_USERACCESS & attr) {
		u_int32_t user_access;

		/* Take the long path when we have an ACL */
		if ((vp != NULLVP) && (cap->ca_recflags & kHFSHasSecurityMask)) {
			user_access = hfs_real_user_access(vp, abp->ab_context);
		} else {
			user_access = DerivePermissionSummary(cap->ca_uid, cap->ca_gid,
			                  cap->ca_mode, mp, vfs_context_ucred(ctx), 0);
		}
		/* Also consider READ-ONLY file system. */
		if (vfs_flags(mp) & MNT_RDONLY) {
			user_access &= ~W_OK;
		}
		/* Locked objects are not writable either */
		if ((cap->ca_flags & UF_IMMUTABLE) && (vfs_context_suser(abp->ab_context) != 0))
			user_access &= ~W_OK;
		if ((cap->ca_flags & SF_IMMUTABLE) && (vfs_context_suser(abp->ab_context) == 0))
			user_access &= ~W_OK;

		*((u_int32_t *)attrbufptr) = user_access;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_FILEID & attr) {
		*((u_int64_t *)attrbufptr) = cap->ca_fileid;
		attrbufptr = ((u_int64_t *)attrbufptr) + 1;
	}
	if (ATTR_CMN_PARENTID & attr) {
		*((u_int64_t *)attrbufptr) = cdp->cd_parentcnid;
		attrbufptr = ((u_int64_t *)attrbufptr) + 1;
	}
	
	*abp->ab_attrbufpp = attrbufptr;
	*abp->ab_varbufpp = varbufptr;
}

static void
packdirattr(
	struct attrblock *abp,
	struct hfsmount *hfsmp,
	struct vnode *vp,
	struct cat_desc * descp,
	struct cat_attr * cattrp)
{
	attrgroup_t attr = abp->ab_attrlist->dirattr;
	void *attrbufptr = *abp->ab_attrbufpp;
	u_int32_t entries;

	/*
	 * The DIR_LINKCOUNT is the count of real directory hard links.
	 * (i.e. its not the sum of the implied "." and ".." references
	 *  typically used in stat's st_nlink field)
	 */
	if (ATTR_DIR_LINKCOUNT & attr) {
		*((u_int32_t *)attrbufptr) = cattrp->ca_linkcount;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_DIR_ENTRYCOUNT & attr) {
		entries = cattrp->ca_entries;

		if (descp->cd_parentcnid == kHFSRootParentID) {
			if (hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid != 0)
				--entries;	    /* hide private dir */
			if (hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid != 0)
				--entries;	    /* hide private dir */
			if (hfsmp->jnl ||
			    ((hfsmp->vcbAtrb & kHFSVolumeJournaledMask) &&
			     (hfsmp->hfs_flags & HFS_READ_ONLY)))
				entries -= 2;	/* hide the journal files */
		}

		*((u_int32_t *)attrbufptr) = entries;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_DIR_MOUNTSTATUS & attr) {
		if (vp != NULL && vnode_mountedhere(vp) != NULL)
			*((u_int32_t *)attrbufptr) = DIR_MNTSTATUS_MNTPOINT;
		else
			*((u_int32_t *)attrbufptr) = 0;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	*abp->ab_attrbufpp = attrbufptr;
}

static void
packfileattr(
	struct attrblock *abp,
	struct hfsmount *hfsmp,
	struct cat_attr *cattrp,
	struct cat_fork *datafork,
	struct cat_fork *rsrcfork,
	struct vnode *vp)
{
#if !HFS_COMPRESSION
#pragma unused(vp)
#endif
	attrgroup_t attr = abp->ab_attrlist->fileattr;
	void *attrbufptr = *abp->ab_attrbufpp;
	void *varbufptr = *abp->ab_varbufpp;
	u_int32_t allocblksize;

	allocblksize = HFSTOVCB(hfsmp)->blockSize;

	off_t datasize = datafork->cf_size;
	off_t totalsize = datasize + rsrcfork->cf_size;
#if HFS_COMPRESSION
	int handle_compressed;
	handle_compressed =  (cattrp->ca_flags & UF_COMPRESSED);// && hfs_file_is_compressed(VTOC(vp), 1);
	
	if (handle_compressed) {
		if (attr & (ATTR_FILE_DATALENGTH|ATTR_FILE_TOTALSIZE)) {
			if ( 0 == hfs_uncompressed_size_of_compressed_file(hfsmp, vp, cattrp->ca_fileid, &datasize, 1) ) { /* 1 == don't take the cnode lock */
				/* total size of a compressed file is just the data size */
				totalsize = datasize;
			}
		}
	}
#endif

	if (ATTR_FILE_LINKCOUNT & attr) {
		*((u_int32_t *)attrbufptr) = cattrp->ca_linkcount;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_TOTALSIZE & attr) {
		*((off_t *)attrbufptr) = totalsize;
		attrbufptr = ((off_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_ALLOCSIZE & attr) {
		*((off_t *)attrbufptr) =
			(off_t)cattrp->ca_blocks * (off_t)allocblksize;
		attrbufptr = ((off_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_IOBLOCKSIZE & attr) {
		*((u_int32_t *)attrbufptr) = hfsmp->hfs_logBlockSize;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_CLUMPSIZE & attr) {
		*((u_int32_t *)attrbufptr) = hfsmp->vcbClpSiz;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	if (ATTR_FILE_DEVTYPE & attr) {
		if (S_ISBLK(cattrp->ca_mode) || S_ISCHR(cattrp->ca_mode))
			*((u_int32_t *)attrbufptr) = (u_int32_t)cattrp->ca_rdev;
		else
			*((u_int32_t *)attrbufptr) = 0;
		attrbufptr = ((u_int32_t *)attrbufptr) + 1;
	}
	
	if (ATTR_FILE_DATALENGTH & attr) {
		*((off_t *)attrbufptr) = datasize;
		attrbufptr = ((off_t *)attrbufptr) + 1;
	}
	
#if HFS_COMPRESSION
	/* fake the data fork size on a decmpfs compressed file to reflect the 
	 * uncompressed size. This ensures proper reading and copying of these files.
	 * NOTE: we may need to get the vnode here because the vnode parameter
	 * passed by hfs_vnop_readdirattr() may be null. 
	 */
	
	if ( handle_compressed ) {
		if (attr & ATTR_FILE_DATAALLOCSIZE) {
			*((off_t *)attrbufptr) = (off_t)rsrcfork->cf_blocks * (off_t)allocblksize;
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
		if (attr & ATTR_FILE_RSRCLENGTH) {
			*((off_t *)attrbufptr) = 0;
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
		if (attr & ATTR_FILE_RSRCALLOCSIZE) {
			*((off_t *)attrbufptr) = 0;
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
	}
	else
#endif
	{
		if (ATTR_FILE_DATAALLOCSIZE & attr) {
			*((off_t *)attrbufptr) = (off_t)datafork->cf_blocks * (off_t)allocblksize;
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
		if (ATTR_FILE_RSRCLENGTH & attr) {
			*((off_t *)attrbufptr) = rsrcfork->cf_size;
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
		if (ATTR_FILE_RSRCALLOCSIZE & attr) {
			*((off_t *)attrbufptr) = (off_t)rsrcfork->cf_blocks * (off_t)allocblksize;
			attrbufptr = ((off_t *)attrbufptr) + 1;
		}
	}
	*abp->ab_attrbufpp = attrbufptr;
	*abp->ab_varbufpp = varbufptr;
}

/*
 * Calculate the total size of an attribute block.
 */
__private_extern__
int
hfs_attrblksize(struct attrlist *attrlist)
{
	int size;
	attrgroup_t a;
	int sizeof_timespec;
	boolean_t is_64_bit = proc_is64bit(current_proc());
	
    if (is_64_bit) 
        sizeof_timespec = sizeof(struct user64_timespec);
    else
        sizeof_timespec = sizeof(struct user32_timespec);

	DBG_ASSERT((attrlist->commonattr & ~ATTR_CMN_VALIDMASK) == 0);

	DBG_ASSERT((attrlist->volattr & ~ATTR_VOL_VALIDMASK) == 0);

	DBG_ASSERT((attrlist->dirattr & ~ATTR_DIR_VALIDMASK) == 0);

	DBG_ASSERT((attrlist->fileattr & ~ATTR_FILE_VALIDMASK) == 0);

	DBG_ASSERT((attrlist->forkattr & ~ATTR_FORK_VALIDMASK) == 0);

	size = 0;
	
	if ((a = attrlist->commonattr) != 0) {
		if (a & ATTR_CMN_NAME) size += sizeof(struct attrreference);
		if (a & ATTR_CMN_DEVID) size += sizeof(dev_t);
		if (a & ATTR_CMN_FSID) size += sizeof(fsid_t);
		if (a & ATTR_CMN_OBJTYPE) size += sizeof(fsobj_type_t);
		if (a & ATTR_CMN_OBJTAG) size += sizeof(fsobj_tag_t);
		if (a & ATTR_CMN_OBJID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_OBJPERMANENTID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_PAROBJID) size += sizeof(fsobj_id_t);
		if (a & ATTR_CMN_SCRIPT) size += sizeof(text_encoding_t);
		if (a & ATTR_CMN_CRTIME) size += sizeof_timespec;
		if (a & ATTR_CMN_MODTIME) size += sizeof_timespec;
		if (a & ATTR_CMN_CHGTIME) size += sizeof_timespec;
		if (a & ATTR_CMN_ACCTIME) size += sizeof_timespec;
		if (a & ATTR_CMN_BKUPTIME) size += sizeof_timespec;
		if (a & ATTR_CMN_FNDRINFO) size += 32 * sizeof(u_int8_t);
		if (a & ATTR_CMN_OWNERID) size += sizeof(uid_t);
		if (a & ATTR_CMN_GRPID) size += sizeof(gid_t);
		if (a & ATTR_CMN_ACCESSMASK) size += sizeof(u_int32_t);
		if (a & ATTR_CMN_FLAGS) size += sizeof(u_int32_t);
		if (a & ATTR_CMN_USERACCESS) size += sizeof(u_int32_t);
		if (a & ATTR_CMN_FILEID) size += sizeof(u_int64_t);
		if (a & ATTR_CMN_PARENTID) size += sizeof(u_int64_t);
	}
	if ((a = attrlist->dirattr) != 0) {
		if (a & ATTR_DIR_LINKCOUNT) size += sizeof(u_int32_t);
		if (a & ATTR_DIR_ENTRYCOUNT) size += sizeof(u_int32_t);
		if (a & ATTR_DIR_MOUNTSTATUS) size += sizeof(u_int32_t);
	}
	if ((a = attrlist->fileattr) != 0) {
		if (a & ATTR_FILE_LINKCOUNT) size += sizeof(u_int32_t);
		if (a & ATTR_FILE_TOTALSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_ALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_IOBLOCKSIZE) size += sizeof(u_int32_t);
		if (a & ATTR_FILE_CLUMPSIZE) size += sizeof(u_int32_t);
		if (a & ATTR_FILE_DEVTYPE) size += sizeof(u_int32_t);
		if (a & ATTR_FILE_DATALENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_DATAALLOCSIZE) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCLENGTH) size += sizeof(off_t);
		if (a & ATTR_FILE_RSRCALLOCSIZE) size += sizeof(off_t);
	}

	return (size);
}

#define KAUTH_DIR_WRITE_RIGHTS		(KAUTH_VNODE_ACCESS | KAUTH_VNODE_ADD_FILE | \
                                	 KAUTH_VNODE_ADD_SUBDIRECTORY | \
                                	 KAUTH_VNODE_DELETE_CHILD)

#define KAUTH_DIR_READ_RIGHTS		(KAUTH_VNODE_ACCESS | KAUTH_VNODE_LIST_DIRECTORY)

#define KAUTH_DIR_EXECUTE_RIGHTS	(KAUTH_VNODE_ACCESS | KAUTH_VNODE_SEARCH)

#define KAUTH_FILE_WRITE_RIGHTS		(KAUTH_VNODE_ACCESS | KAUTH_VNODE_WRITE_DATA)

#define KAUTH_FILE_READRIGHTS		(KAUTH_VNODE_ACCESS | KAUTH_VNODE_READ_DATA)

#define KAUTH_FILE_EXECUTE_RIGHTS	(KAUTH_VNODE_ACCESS | KAUTH_VNODE_EXECUTE)


/*
 * Compute the same [expensive] user_access value as getattrlist does
 */
static u_int32_t
hfs_real_user_access(vnode_t vp, vfs_context_t ctx)
{
	u_int32_t user_access = 0;

	if (vnode_isdir(vp)) {
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_WRITE_RIGHTS, ctx) == 0)
			user_access |= W_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_READ_RIGHTS, ctx) == 0)
			user_access |= R_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_DIR_EXECUTE_RIGHTS, ctx) == 0)
			user_access |= X_OK;
	} else {
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_WRITE_RIGHTS, ctx) == 0)
			user_access |= W_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_READRIGHTS, ctx) == 0)
			user_access |= R_OK;
		if (vnode_authorize(vp, NULLVP, KAUTH_FILE_EXECUTE_RIGHTS, ctx) == 0)
			user_access |= X_OK;
	}
	return (user_access);
}
		

u_int32_t
DerivePermissionSummary(uid_t obj_uid, gid_t obj_gid, mode_t obj_mode,
		struct mount *mp, kauth_cred_t cred, __unused struct proc *p)
{
	u_int32_t permissions;

	if (obj_uid == UNKNOWNUID)
		obj_uid = kauth_cred_getuid(cred);

	/* User id 0 (root) always gets access. */
	if (!suser(cred, NULL)) {
		permissions = R_OK | W_OK | X_OK;
		goto Exit;
	};

	/* Otherwise, check the owner. */
	if (hfs_owner_rights(VFSTOHFS(mp), obj_uid, cred, NULL, false) == 0) {
		permissions = ((u_int32_t)obj_mode & S_IRWXU) >> 6;
		goto Exit;
	}

	/* Otherwise, check the groups. */
	if (! (((unsigned int)vfs_flags(mp)) & MNT_UNKNOWNPERMISSIONS)) {
		int is_member;

		if (kauth_cred_ismember_gid(cred, obj_gid, &is_member) == 0 && is_member) {
			permissions = ((u_int32_t)obj_mode & S_IRWXG) >> 3;
			goto Exit;
		}
	}

	/* Otherwise, settle for 'others' access. */
	permissions = (u_int32_t)obj_mode & S_IRWXO;

Exit:
	return (permissions);    
}


/*
 * ===========================================================================
 * Support functions for filling up a vnode_attr structure based on attributes
 * requested.
 * ===========================================================================
 */
void
get_vattr_data_for_attrs(struct attrlist *alp, struct vnode_attr *vap,
    struct hfsmount *hfsmp, struct vnode *vp, struct cat_desc *descp,
    struct cat_attr *atrp, struct cat_fork *datafork, struct cat_fork *rsrcfork,
    vfs_context_t ctx)
{
	if (alp->commonattr)
		vattr_data_for_common_attrs(alp, vap, hfsmp, vp, descp, atrp,
		ctx);

	if (alp->dirattr && S_ISDIR(atrp->ca_mode))
		vattr_data_for_dir_attrs(alp, vap, hfsmp, vp, descp, atrp);

	if (alp->fileattr && !S_ISDIR(atrp->ca_mode)) {
		vattr_data_for_file_attrs(alp, vap, hfsmp, atrp, datafork,
		    rsrcfork, vp);
	}
}

static void
copy_name_attr(struct vnode_attr *vap, struct vnode *vp, const u_int8_t *name,
    int namelen)
{
	char *mpname;
	size_t mpnamelen;
	u_int32_t attrlength;
	u_int8_t empty = 0;

	/* A cnode's name may be incorrect for the root of a mounted
	 * filesystem (it can be mounted on a different directory name
	 * than the name of the volume, such as "blah-1").  So for the
	 * root directory, it's best to return the last element of the
	 location where the volume's mounted:
	 */
	if ((vp != NULL) && vnode_isvroot(vp) &&
	    (mpname = mountpointname(vnode_mount(vp)))) {
		mpnamelen = strlen(mpname);

		/* Trim off any trailing slashes: */
		while ((mpnamelen > 0) && (mpname[mpnamelen-1] == '/'))
			--mpnamelen;

		/* If there's anything left, use it instead of the volume's name */
		if (mpnamelen > 0) {
			name = (u_int8_t *)mpname;
			namelen = mpnamelen;
		}
	}

	if (name == NULL) {
		name = &empty;
		namelen = 0;
	}

	attrlength = namelen + 1;
	(void) strncpy((char *)vap->va_name, (const char *) name, attrlength);
	/*
	 * round upto 8 and zero out the rounded up bytes.
	 */
	attrlength = min(kHFSPlusMaxFileNameBytes, ((attrlength + 7) & ~0x07));
	bzero(vap->va_name + attrlength, kHFSPlusMaxFileNameBytes - attrlength);
}

static void
vattr_data_for_common_attrs( struct attrlist *alp, struct vnode_attr *vap,
    struct hfsmount *hfsmp, struct vnode *vp, struct cat_desc *cdp,
    struct cat_attr *cap, vfs_context_t ctx)
{
	attrgroup_t attr = alp->commonattr;
	struct mount *mp = HFSTOVFS(hfsmp);
	uid_t cuid = 1;
	int isroot = 0;

	if (attr & (ATTR_CMN_OWNERID | ATTR_CMN_GRPID)) {
		cuid = kauth_cred_getuid(vfs_context_ucred(ctx));
		isroot = cuid == 0;
	}

	if (ATTR_CMN_NAME & attr) {
		if (vap->va_name) {
			copy_name_attr(vap, vp, cdp->cd_nameptr,
			    cdp->cd_namelen);
			VATTR_SET_SUPPORTED(vap, va_name);
		} else {
			VATTR_CLEAR_SUPPORTED(vap, va_name);
		}
	}

	if (ATTR_CMN_DEVID & attr) {
		vap->va_devid = hfsmp->hfs_raw_dev;
		VATTR_SET_SUPPORTED(vap, va_devid);
	}

	if (ATTR_CMN_FSID & attr) {
		vap->va_fsid64.val[0] = hfsmp->hfs_raw_dev;
		vap->va_fsid64.val[1] = vfs_typenum(mp);
		VATTR_SET_SUPPORTED(vap, va_fsid64);
	}
	/*
	 * We always provide the objtype even if not asked because VFS helper
	 * functions depend on knowing the object's type.
	 */
	vap->va_objtype = IFTOVT(cap->ca_mode);
	VATTR_SET_SUPPORTED(vap, va_objtype);

	if (ATTR_CMN_OBJTAG & attr) {
		vap->va_objtag = VT_HFS;
		VATTR_SET_SUPPORTED(vap, va_objtag);
	}
	/*
	 * Exporting file IDs from HFS Plus:
	 *
	 * For "normal" files the c_fileid is the same value as the
	 * c_cnid.  But for hard link files, they are different - the
	 * c_cnid belongs to the active directory entry (ie the link)
	 * and the c_fileid is for the actual inode (ie the data file).
	 *
	 * The stat call (getattr) will always return the c_fileid
	 * and Carbon APIs, which are hardlink-ignorant, will always
	 * receive the c_cnid (from getattrlist).
	 */
	if ((ATTR_CMN_OBJID & attr) ||
	    (ATTR_CMN_OBJPERMANENTID & attr)) {
		vap->va_linkid = cdp->cd_cnid;
		VATTR_SET_SUPPORTED(vap, va_linkid);
	}

	if (ATTR_CMN_PAROBJID & attr) {
		vap->va_parentid = cdp->cd_parentcnid;
		VATTR_SET_SUPPORTED(vap, va_parentid);
	}

	if (ATTR_CMN_SCRIPT & attr) {
		vap->va_encoding = cdp->cd_encoding;
		VATTR_SET_SUPPORTED(vap, va_encoding);
	}

	if (ATTR_CMN_CRTIME & attr) {
		vap->va_create_time.tv_sec = cap->ca_itime;
		vap->va_create_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_create_time);
	}

	if (ATTR_CMN_MODTIME & attr) {
		vap->va_modify_time.tv_sec = cap->ca_mtime;
		vap->va_modify_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_modify_time);
	}

	if (ATTR_CMN_CHGTIME & attr) {
		vap->va_change_time.tv_sec = cap->ca_ctime;
		vap->va_change_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_change_time);
	}

	if (ATTR_CMN_ACCTIME & attr) {
		vap->va_access_time.tv_sec = cap->ca_atime;
		vap->va_access_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_access_time);
	}

	if (ATTR_CMN_BKUPTIME & attr) {
		vap->va_backup_time.tv_sec = cap->ca_btime;
		vap->va_backup_time.tv_nsec = 0;
		VATTR_SET_SUPPORTED(vap, va_backup_time);
	}

	if (ATTR_CMN_FNDRINFO & attr) {
		u_int8_t *finfo = NULL;

		bcopy(&cap->ca_finderinfo, &vap->va_finderinfo[0],
		    sizeof(u_int8_t) * 32);
		finfo = (u_int8_t*)(&vap->va_finderinfo[0]);

		/* Don't expose a symlink's private type/creator. */
		if (S_ISLNK(cap->ca_mode)) {
			struct FndrFileInfo *fip;

			fip = (struct FndrFileInfo *)finfo;
			fip->fdType = 0;
			fip->fdCreator = 0;
		}

		/* advance 16 bytes into the attrbuf */
		finfo = finfo + 16;

		/* also don't expose the date_added or write_gen_counter fields */
		if (S_ISREG(cap->ca_mode) || S_ISLNK(cap->ca_mode)) {
			struct FndrExtendedFileInfo *extinfo =
			    (struct FndrExtendedFileInfo *)finfo;
			extinfo->document_id = 0;
			extinfo->date_added = 0;
			extinfo->write_gen_counter = 0;
		} else if (S_ISDIR(cap->ca_mode)) {
			struct FndrExtendedDirInfo *extinfo =
			    (struct FndrExtendedDirInfo *)finfo;
			extinfo->document_id = 0;
			extinfo->date_added = 0;
			extinfo->write_gen_counter = 0;
		}

		VATTR_SET_SUPPORTED(vap, va_finderinfo);
	}

	if (ATTR_CMN_OWNERID & attr) {
		uid_t nuid = cap->ca_uid;

		if (!isroot) {
			if (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS)
				nuid = cuid;
			else if (nuid == UNKNOWNUID)
				nuid = cuid;
		}

		vap->va_uid = nuid;
		VATTR_SET_SUPPORTED(vap, va_uid);
	}

	if (ATTR_CMN_GRPID & attr) {
		gid_t ngid = cap->ca_gid;

		if (!isroot) {
			gid_t cgid = kauth_cred_getgid(vfs_context_ucred(ctx));
			if (((unsigned int)vfs_flags(HFSTOVFS(hfsmp))) & MNT_UNKNOWNPERMISSIONS)
				ngid = cgid;
			else if (ngid == UNKNOWNUID)
				ngid = cgid;
		}

		vap->va_gid = ngid;
		VATTR_SET_SUPPORTED(vap, va_gid);
	}

	if (ATTR_CMN_ACCESSMASK & attr) {
		uint32_t nmode;
		/*
		 * [2856576]  Since we are dynamically changing the owner, also
		 * effectively turn off the set-user-id and set-group-id bits,
		 * just like chmod(2) would when changing ownership.  This prevents
		 * a security hole where set-user-id programs run as whoever is
		 * logged on (or root if nobody is logged in yet!)
		 */
		nmode = (cap->ca_uid == UNKNOWNUID) ?
		    cap->ca_mode & ~(S_ISUID | S_ISGID) : cap->ca_mode;

		vap->va_mode = nmode;
		VATTR_SET_SUPPORTED(vap, va_mode);
	}

	if (ATTR_CMN_FLAGS & attr) {
		vap->va_flags = cap->ca_flags;
		VATTR_SET_SUPPORTED(vap, va_flags);
	}

	if (ATTR_CMN_GEN_COUNT & attr) {
		vap->va_write_gencount = hfs_get_gencount_from_blob(
		    (const uint8_t *)cap->ca_finderinfo, cap->ca_mode);
		VATTR_SET_SUPPORTED(vap, va_write_gencount);
	}

	if (ATTR_CMN_DOCUMENT_ID & attr) {
		vap->va_document_id = hfs_get_document_id_from_blob(
		    (const uint8_t *)cap->ca_finderinfo, cap->ca_mode);
		VATTR_SET_SUPPORTED(vap, va_document_id);
	}

	if (ATTR_CMN_USERACCESS & attr) {
		u_int32_t user_access;

		/* Take the long path when we have an ACL */
		if ((vp != NULLVP) && (cap->ca_recflags & kHFSHasSecurityMask)) {
			user_access = hfs_real_user_access(vp, ctx);
		} else {
			user_access = DerivePermissionSummary(cap->ca_uid, cap->ca_gid,
			                  cap->ca_mode, mp, vfs_context_ucred(ctx), 0);
		}
		/* Also consider READ-ONLY file system. */
		if (vfs_flags(mp) & MNT_RDONLY) {
			user_access &= ~W_OK;
		}
		/* Locked objects are not writable either */
		if ((cap->ca_flags & UF_IMMUTABLE) && (vfs_context_suser(ctx) != 0))
			user_access &= ~W_OK;
		if ((cap->ca_flags & SF_IMMUTABLE) && (vfs_context_suser(ctx) == 0))
			user_access &= ~W_OK;

		vap->va_user_access = user_access;
		VATTR_SET_SUPPORTED(vap, va_user_access);
	}

	/*
	 * Right now the best we can do is tell if we *don't* have extended
	 * security (like hfs_vnop_getattr).
	 */
	if (ATTR_CMN_EXTENDED_SECURITY & attr) {
		if (!(cap->ca_recflags & kHFSHasSecurityMask)) {
			vap->va_acl = (kauth_acl_t) KAUTH_FILESEC_NONE;
			VATTR_SET_SUPPORTED(vap, va_acl);
		}
	}

	if (ATTR_CMN_FILEID & attr) {
		vap->va_fileid = cap->ca_fileid;
		VATTR_SET_SUPPORTED(vap, va_fileid);
	}

	if (ATTR_CMN_PARENTID & attr) {
		vap->va_parentid = cdp->cd_parentcnid;
		VATTR_SET_SUPPORTED(vap, va_parentid);
	}

	if (ATTR_CMN_ADDEDTIME & attr) {
		if (cap->ca_recflags & kHFSHasDateAddedMask) {
			vap->va_addedtime.tv_sec = hfs_get_dateadded_from_blob(
			    (const uint8_t *)cap->ca_finderinfo, cap->ca_mode);
			vap->va_addedtime.tv_nsec = 0;
			VATTR_SET_SUPPORTED(vap, va_addedtime);
		}
	}
}

static void
vattr_data_for_dir_attrs(struct attrlist *alp, struct vnode_attr *vap,
    struct hfsmount *hfsmp, struct vnode *vp, struct cat_desc * descp,
    struct cat_attr * cattrp)
{
	attrgroup_t attr = alp->dirattr;
	u_int32_t entries;

	/*
	 * The DIR_LINKCOUNT is the count of real directory hard links.
	 * (i.e. its not the sum of the implied "." and ".." references
	 *  typically used in stat's st_nlink field)
	 */
	if (ATTR_DIR_LINKCOUNT & attr) {
			vap->va_dirlinkcount = cattrp->ca_linkcount;
			VATTR_SET_SUPPORTED(vap, va_dirlinkcount);
	}
	if (ATTR_DIR_ENTRYCOUNT & attr) {
		entries = cattrp->ca_entries;

		if (descp->cd_parentcnid == kHFSRootParentID) {
			if (hfsmp->hfs_private_desc[FILE_HARDLINKS].cd_cnid != 0)
				--entries;	    /* hide private dir */
			if (hfsmp->hfs_private_desc[DIR_HARDLINKS].cd_cnid != 0)
				--entries;	    /* hide private dir */
			if (hfsmp->jnl ||
			    ((hfsmp->vcbAtrb & kHFSVolumeJournaledMask) &&
			     (hfsmp->hfs_flags & HFS_READ_ONLY)))
				entries -= 2;	/* hide the journal files */
		}

		vap->va_nchildren = entries;
		VATTR_SET_SUPPORTED(vap, va_nchildren);
	}

	if (ATTR_DIR_MOUNTSTATUS & attr) {
		/*
		 * There is not vnode_attr for mount point status.
		 * XXX. Should there be ?
		 */
		u_int32_t mstatus = 0;

		if (vp != NULL && vnode_mountedhere(vp) != NULL)
			mstatus = DIR_MNTSTATUS_MNTPOINT;
	}
}

static void
vattr_data_for_file_attrs(struct attrlist *alp, struct vnode_attr *vap,
    struct hfsmount *hfsmp, struct cat_attr *cattrp, struct cat_fork *datafork,
    struct cat_fork *rsrcfork, struct vnode *vp)
{
#if !HFS_COMPRESSION
#pragma unused(vp)
#endif
	attrgroup_t attr = alp->fileattr;
	off_t da_size, rsrc_len, rsrc_alloc;
	u_int32_t allocblksize;

	allocblksize = HFSTOVCB(hfsmp)->blockSize;

	off_t datasize = datafork->cf_size;
	off_t totalsize = datasize + rsrcfork->cf_size;
#if HFS_COMPRESSION
	int handle_compressed;
	handle_compressed =  (cattrp->ca_flags & UF_COMPRESSED);// && hfs_file_is_compressed(VTOC(vp), 1);

	if (handle_compressed) {
		if (attr & (ATTR_FILE_DATALENGTH|ATTR_FILE_TOTALSIZE)) {
			if ( 0 == hfs_uncompressed_size_of_compressed_file(hfsmp, vp, cattrp->ca_fileid, &datasize, 1) ) { /* 1 == don't take the cnode lock */
				/* total size of a compressed file is just the data size */
				totalsize = datasize;
			}
		}
	}
#endif

	if (ATTR_FILE_LINKCOUNT & attr) {
		vap->va_nlink = cattrp->ca_linkcount;
		VATTR_SET_SUPPORTED(vap, va_nlink);
	}
	if (ATTR_FILE_TOTALSIZE & attr) {
		VATTR_RETURN(vap, va_total_size, totalsize);
	}
	if (ATTR_FILE_ALLOCSIZE & attr) {
		 VATTR_RETURN(vap, va_total_alloc,
			    (off_t)cattrp->ca_blocks * (off_t)allocblksize );
	}
	if (ATTR_FILE_IOBLOCKSIZE & attr) {
		VATTR_RETURN(vap, va_iosize,  hfsmp->hfs_logBlockSize);
	}

	/* ATTR_FILE_CLUMPSIZE is obsolete */

	if (ATTR_FILE_DEVTYPE & attr) {
		dev_t dev = 0;

		if (S_ISBLK(cattrp->ca_mode) || S_ISCHR(cattrp->ca_mode))
			dev = (u_int32_t)cattrp->ca_rdev;

		VATTR_RETURN(vap, va_rdev, dev);
	}

	if (ATTR_FILE_DATALENGTH & attr) {
		VATTR_RETURN(vap, va_data_size, datasize);
	}
#if HFS_COMPRESSION
	/* fake the data fork size on a decmpfs compressed file to reflect the
	 * uncompressed size. This ensures proper reading and copying of these
	 * files.
	 * NOTE: we may need to get the vnode here because the vnode parameter
	 * passed by hfs_vnop_readdirattr() may be null.
	 */

	if (handle_compressed) {
		da_size = (off_t)rsrcfork->cf_blocks * (off_t)allocblksize;
		rsrc_len = 0;
		rsrc_alloc = 0;
	}
	else
#endif
	{
		da_size = (off_t)datafork->cf_blocks * (off_t)allocblksize;
		rsrc_len = rsrcfork->cf_size;
		rsrc_alloc = (off_t)rsrcfork->cf_blocks * (off_t)allocblksize;
	}

	if (ATTR_FILE_DATAALLOCSIZE & attr) {
		VATTR_RETURN(vap, va_data_alloc, da_size);
	}

	if (ATTR_FILE_RSRCLENGTH & attr) {
		VATTR_RETURN(vap, va_rsrc_length, rsrc_len);
	}

	if (ATTR_FILE_RSRCALLOCSIZE & attr) {
		VATTR_RETURN(vap, va_rsrc_alloc, rsrc_alloc);
	}
}
