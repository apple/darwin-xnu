/*
 * Copyright (c) 2004-2005 Apple Computer, Inc. All rights reserved.
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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/utfconv.h>
#include <sys/vnode.h>
#include <sys/xattr.h>

#include "hfs.h"
#include "hfs_cnode.h"
#include "hfs_mount.h"
#include "hfs_format.h"
#include "hfs_endian.h"

#include "hfscommon/headers/BTreesInternal.h"


#define  ATTRIBUTE_FILE_NODE_SIZE   8192


/* State information for the listattr_callback callback function. */
struct listattr_callback_state {
	u_int32_t   fileID;
	int         result;
	uio_t       uio;
	size_t      size;
};

#define HFS_MAXATTRIBUTESIZE    (1024*1024)

/* HFS Internal Names */
#define	XATTR_EXTENDEDSECURITY_NAME   "system.extendedsecurity"


#define RESOURCE_FORK_EXISTS(VP)   \
	((VTOC((VP))->c_blocks - VTOF((VP))->ff_blocks) > 0)

static u_int32_t emptyfinfo[8] = {0};


extern int  hfs_create_attr_btree(struct hfsmount *hfsmp, uint32_t nodesize, uint32_t nodecnt);


int  hfs_vnop_getxattr(struct vnop_getxattr_args *ap);
int  hfs_vnop_setxattr(struct vnop_setxattr_args *ap);
int  hfs_vnop_removexattr(struct vnop_removexattr_args *ap);
int  hfs_vnop_listxattr(struct vnop_listxattr_args *ap);
int  hfs_attrkeycompare(HFSPlusAttrKey *searchKey, HFSPlusAttrKey *trialKey);



static int  listattr_callback(const HFSPlusAttrKey *key, const HFSPlusAttrData *data,
                       struct listattr_callback_state *state);

static int  buildkey(u_int32_t fileID, const char *attrname, HFSPlusAttrKey *key);

static int  getnodecount(struct hfsmount *hfsmp, size_t nodesize);

static size_t  getmaxinlineattrsize(struct vnode * attrvp);

/*
 * Retrieve the data of an extended attribute.
 */
__private_extern__
int
hfs_vnop_getxattr(struct vnop_getxattr_args *ap)
/*
	struct vnop_getxattr_args {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		char * a_name;
		uio_t a_uio;
		size_t *a_size;
		int a_options;
		vfs_context_t a_context;
	};
*/
{
	struct vnode *vp = ap->a_vp;
	struct hfsmount *hfsmp;
	uio_t uio = ap->a_uio;
	struct BTreeIterator * iterator = NULL;
	struct filefork *btfile;
	FSBufferDescriptor btdata;
	HFSPlusAttrData * datap = NULL;
	size_t bufsize;
	UInt16 datasize;
	int lockflags;
	int result;

	if (ap->a_name == NULL || ap->a_name[0] == '\0') {
		return (EINVAL);  /* invalid name */
	}
	hfsmp = VTOHFS(vp);

	if (!VNODE_IS_RSRC(vp)) {
		/* Get the Finder Info. */
		if (bcmp(ap->a_name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
			bufsize = 32;

			/* If Finder Info is empty then it doesn't exist. */
			if (bcmp(VTOC(vp)->c_finderinfo, emptyfinfo, sizeof(emptyfinfo)) == 0) {
				return (ENOATTR);
			}
			if (uio == NULL) {
				*ap->a_size = bufsize;
				return (0);
			}
			if (uio_resid(uio) < bufsize)
				return (ERANGE);

			result = uiomove((caddr_t) &VTOC(vp)->c_finderinfo , bufsize, uio);

			return (result);
		}
		/* Read the Resource Fork. */
		if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) == 0) {
			struct vnode *rvp = NULL;

			if ( !vnode_isreg(vp) ) {
				return (EPERM);
			}
			if ( !RESOURCE_FORK_EXISTS(vp)) {
				return (ENOATTR);
			}
			if ((result = hfs_vgetrsrc(hfsmp, vp, &rvp, vfs_context_proc(ap->a_context)))) {
				return (result);
			}
			if (uio == NULL) {
				*ap->a_size = (size_t)VTOF(rvp)->ff_size;
			} else {
				result = VNOP_READ(rvp, uio, 0, ap->a_context);
			}
			vnode_put(rvp);
			return (result);
		}
	}
	/*
	 * Standard HFS only supports native FinderInfo and Resource Forks.
	 */
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return (EPERM);
	}
	/* Bail if we don't have any extended attributes. */
	if ((hfsmp->hfs_attribute_vp == NULL) ||
	    (VTOC(vp)->c_attr.ca_recflags & kHFSHasAttributesMask) == 0) {
		return (ENOATTR);
	}
	btfile = VTOF(hfsmp->hfs_attribute_vp);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	bufsize = sizeof(HFSPlusAttrData) - 2;
	if (uio)
		bufsize += uio_resid(uio);
	MALLOC(datap, HFSPlusAttrData *, bufsize, M_TEMP, M_WAITOK);
	btdata.bufferAddress = datap;
	btdata.itemSize = bufsize;
	btdata.itemCount = 1;

	result = buildkey(VTOC(vp)->c_fileid, ap->a_name, (HFSPlusAttrKey *)&iterator->key);
	if (result)
		goto exit;	

	/* Lookup the attribute. */
	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_SHARED_LOCK);
	result = BTSearchRecord(btfile, iterator, &btdata, &datasize, NULL);
	hfs_systemfile_unlock(hfsmp, lockflags);

	if (result) {
		if (result == btNotFound)
			result = ENOATTR;
		goto exit;
	}

	*ap->a_size = datap->attrSize;

	/* Copy out the attribute data. */
	if (uio) {
		if (datap->attrSize > uio_resid(uio))
			result = ERANGE;
		else
			result = uiomove((caddr_t) &datap->attrData , datap->attrSize, uio);
	}
exit:
	FREE(datap, M_TEMP);
	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}

/*
 * Set the data of an extended attribute.
 */
__private_extern__
int
hfs_vnop_setxattr(struct vnop_setxattr_args *ap)
/*
	struct vnop_setxattr_args {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		char * a_name;
		uio_t a_uio;
		int a_options;
		vfs_context_t a_context;
	};
*/
{
	struct vnode *vp = ap->a_vp;
	struct hfsmount *hfsmp;
	uio_t uio = ap->a_uio;
	struct BTreeIterator * iterator = NULL;
	struct filefork *btfile;
	size_t attrsize;
	FSBufferDescriptor btdata;
	HFSPlusAttrData * datap = NULL;
	UInt16 datasize;
	int lockflags;
	int result;

	if (ap->a_name == NULL || ap->a_name[0] == '\0') {
		return (EINVAL);  /* invalid name */
	}
	hfsmp = VTOHFS(vp);
	if (VNODE_IS_RSRC(vp)) {
		return (EPERM);
	}
	/* Set the Finder Info. */
	if (bcmp(ap->a_name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		attrsize = 32;

		if (bcmp(VTOC(vp)->c_finderinfo, emptyfinfo, sizeof(emptyfinfo))) {
			/* attr exists and "create" was specified. */
			if (ap->a_options & XATTR_CREATE) {
				return (EEXIST);
			}
		} else {
			/* attr doesn't exists and "replace" was specified. */
			if (ap->a_options & XATTR_REPLACE) {
				return (ENOATTR);
			}
		}
		if (uio_resid(uio) != attrsize)
			return (ERANGE);

		result = uiomove((caddr_t) &VTOC(vp)->c_finderinfo , attrsize, uio);
		if (result == 0) {
			VTOC(vp)->c_touch_chgtime = TRUE;
			VTOC(vp)->c_flag |= C_MODIFIED;
			result = hfs_update(vp, FALSE);
		}
		return (result);
	}
	/* Write the Resource Fork. */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) == 0) {
		struct vnode *rvp = NULL;

		if (!vnode_isreg(vp)) {
			return (EPERM);
		}
		if (RESOURCE_FORK_EXISTS(vp)) {
			/* attr exists and "create" was specified. */
			if (ap->a_options & XATTR_CREATE) {
				return (EEXIST);
			}
		} else {
			/* attr doesn't exists and "replace" was specified. */
			if (ap->a_options & XATTR_REPLACE) {
				return (ENOATTR);
			}
		}
		if ((result = hfs_vgetrsrc(hfsmp, vp, &rvp, vfs_context_proc(ap->a_context)))) {
			return (result);
		}
		result = VNOP_WRITE(rvp, uio, 0, ap->a_context);
		vnode_put(rvp);
		return (result);
	}
	/*
	 * Standard HFS only supports native FinderInfo and Resource Forks.
	 */
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return (EPERM);
	}
	if (hfsmp->hfs_max_inline_attrsize == 0) {
		hfsmp->hfs_max_inline_attrsize = getmaxinlineattrsize(hfsmp->hfs_attribute_vp);
	}
	attrsize = uio_resid(uio);
	if (attrsize > hfsmp->hfs_max_inline_attrsize) {
		/*
		 * XXX Need to support extent-based attributes XXX
		 */
		return (E2BIG);
	}
	/* Calculate size of record rounded up to multiple of 2 bytes. */
	datasize = sizeof(HFSPlusAttrData) - 2 + attrsize + ((attrsize & 1) ? 1 : 0);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	MALLOC(datap, HFSPlusAttrData *, datasize, M_TEMP, M_WAITOK);
	btdata.bufferAddress = datap;
	btdata.itemSize = datasize;
	btdata.itemCount = 1;
	datap->recordType = kHFSPlusAttrInlineData;
	datap->reserved[0] = 0;
	datap->reserved[1] = 0;
	datap->attrSize = attrsize;

	/* Copy in the attribute data. */
	result = uiomove((caddr_t) &datap->attrData , attrsize, uio);
	if (result) {
		goto exit2;
	}
	/* Build a b-tree key. */
	result = buildkey(VTOC(vp)->c_fileid, ap->a_name, (HFSPlusAttrKey *)&iterator->key);
	if (result) {
		goto exit2;
	}
	/* Start a transaction for our changes. */
	if (hfs_start_transaction(hfsmp) != 0) {
	    result = EINVAL;
	    goto exit2;
	}

	/* once we started the transaction, nobody can compete with us, so make sure this file is still there */
	struct cnode *cp;
	cp = VTOC(vp);
	if (cp->c_flag & C_NOEXISTS) {				 /* this file has already been removed */
		result = ENOENT;
		goto exit1;
	}

	/*
	 * If there isn't an attributes b-tree then create one.
	 */
	if (hfsmp->hfs_attribute_vp == NULL) {
		lockflags = hfs_systemfile_lock(hfsmp, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);
		result = hfs_create_attr_btree(hfsmp, ATTRIBUTE_FILE_NODE_SIZE,
		                               getnodecount(hfsmp, ATTRIBUTE_FILE_NODE_SIZE));
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (result) {
			goto exit1;
		}
	}
	btfile = VTOF(hfsmp->hfs_attribute_vp);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	if (ap->a_options & XATTR_REPLACE) {
		result = BTReplaceRecord(btfile, iterator, &btdata, datasize);
		if (result)
			goto exit0;
		else
			goto exit;
	}

	/* Insert the attribute. */
	result = BTInsertRecord(btfile, iterator, &btdata, datasize);
	if (result) {
		if (result != btExists) {
			goto exit0;
		}

		// if it exists and XATTR_CREATE was specified,
		// the spec says to return EEXIST
		if (ap->a_options & XATTR_CREATE) {
			result = EEXIST;
			goto exit0;
		}
		/* XXX need to account for old size in c_attrblks */
		result = BTReplaceRecord(btfile, iterator, &btdata, datasize);
	}
exit:
	(void) BTFlushPath(btfile);
exit0:
	hfs_systemfile_unlock(hfsmp, lockflags);
	if (result == 0) {
		struct cnode * cp;

		cp = VTOC(vp);
		cp->c_touch_chgtime = TRUE;
		if ((cp->c_attr.ca_recflags & kHFSHasAttributesMask) == 0) {
			cp->c_attr.ca_recflags |= kHFSHasAttributesMask;
			(void) hfs_update(vp, 0);
		}
		HFS_KNOTE(vp, NOTE_ATTRIB);
	}
exit1:
	/* Finish the transaction of our changes. */
	hfs_end_transaction(hfsmp);
exit2:
	FREE(datap, M_TEMP);
	FREE(iterator, M_TEMP);

	if (result == btNotFound)
		result = ENOATTR;
	else
		result = MacToVFSError(result);

	return (result);
}

/*
 * Remove an extended attribute.
 */
__private_extern__
int
hfs_vnop_removexattr(struct vnop_removexattr_args *ap)
/*
	struct vnop_removexattr_args {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		char * a_name;
		int a_options;
		vfs_context_t a_context;
	};
*/
{
	struct vnode *vp = ap->a_vp;
	struct hfsmount *hfsmp;
	struct BTreeIterator * iterator = NULL;
	struct filefork *btfile;
	struct proc *p = vfs_context_proc(ap->a_context);
	FSBufferDescriptor btdata;
	HFSPlusAttrData attrdata;
	int lockflags;
	int result;

	if (ap->a_name == NULL || ap->a_name[0] == '\0') {
		return (EINVAL);  /* invalid name */
	}
	hfsmp = VTOHFS(vp);
	if (VNODE_IS_RSRC(vp)) {
		return (EPERM);
	}

	/* If Resource Fork is non-empty then truncate it. */
	if (bcmp(ap->a_name, XATTR_RESOURCEFORK_NAME, sizeof(XATTR_RESOURCEFORK_NAME)) == 0) {
		struct vnode *rvp = NULL;

		if ( !vnode_isreg(vp) ) {
			return (EPERM);
		}
		if ( !RESOURCE_FORK_EXISTS(vp) ) {
			return (ENOATTR);
		}
		if ((result = hfs_vgetrsrc(hfsmp, vp, &rvp, p))) {
			return (result);
		}
		hfs_lock_truncate(VTOC(rvp), TRUE);
		if ((result = hfs_lock(VTOC(rvp), HFS_EXCLUSIVE_LOCK))) {
			hfs_unlock_truncate(VTOC(vp));
			vnode_put(rvp);
			return (result);
		}
		result = hfs_truncate(rvp, (off_t)0, IO_NDELAY, 0, ap->a_context);

		hfs_unlock_truncate(VTOC(rvp));
		hfs_unlock(VTOC(rvp));

		vnode_put(rvp);
		return (result);
	}
	/* Clear out the Finder Info. */
	if (bcmp(ap->a_name, XATTR_FINDERINFO_NAME, sizeof(XATTR_FINDERINFO_NAME)) == 0) {
		if (bcmp(VTOC(vp)->c_finderinfo, emptyfinfo, sizeof(emptyfinfo)) == 0) {
			return (ENOATTR);
		}
		bzero(VTOC(vp)->c_finderinfo, sizeof(emptyfinfo));
		return (0);
	}
	/*
	 * Standard HFS only supports native FinderInfo and Resource Forks.
	 */
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return (EPERM);
	}
	if (hfsmp->hfs_attribute_vp == NULL) {
		return (ENOATTR);
	}
	btfile = VTOF(hfsmp->hfs_attribute_vp);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	if (hfs_start_transaction(hfsmp) != 0) {
	    result = EINVAL;
	    goto exit2;
	}

	result = buildkey(VTOC(vp)->c_fileid, ap->a_name, (HFSPlusAttrKey *)&iterator->key);
	if (result)
		goto exit2;	

	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	btdata.bufferAddress = &attrdata;
	btdata.itemSize = sizeof(attrdata);
	btdata.itemCount = 1;
	result = BTSearchRecord(btfile, iterator, &btdata, NULL, NULL);
	if (result)
		goto exit1;	

	result = BTDeleteRecord(btfile, iterator);
	(void) BTFlushPath(btfile);
exit1:
	hfs_systemfile_unlock(hfsmp, lockflags);
	if (result == 0) {
		VTOC(vp)->c_touch_chgtime = TRUE;
		HFS_KNOTE(vp, NOTE_ATTRIB);
	}
exit2:
	if (result == btNotFound) {
		result = ENOATTR;
	}
	hfs_end_transaction(hfsmp);

	FREE(iterator, M_TEMP);

	return MacToVFSError(result);
}


/*
 * Retrieve the list of extended attribute names.
 */
__private_extern__
int
hfs_vnop_listxattr(struct vnop_listxattr_args *ap)
/*
	struct vnop_listxattr_args {
		struct vnodeop_desc *a_desc;
		vnode_t a_vp;
		uio_t a_uio;
		size_t *a_size;
		int a_options;
		vfs_context_t a_context;
*/
{
	struct vnode *vp = ap->a_vp;
	struct hfsmount *hfsmp;
	uio_t uio = ap->a_uio;
	struct BTreeIterator * iterator = NULL;
	struct filefork *btfile;
	struct listattr_callback_state state;
	int lockflags;
	int result;

	if (VNODE_IS_RSRC(vp)) {
		return (EPERM);
	}
	hfsmp = VTOHFS(vp);
	*ap->a_size = 0;

	/* If Finder Info is non-empty then export it. */
	if (bcmp(VTOC(vp)->c_finderinfo, emptyfinfo, sizeof(emptyfinfo)) != 0) {
		if (uio == NULL) {
			*ap->a_size += sizeof(XATTR_FINDERINFO_NAME);
		} else if (uio_resid(uio) < sizeof(XATTR_FINDERINFO_NAME)) {
			return (ERANGE);
		} else {
			result = uiomove((caddr_t)XATTR_FINDERINFO_NAME,
			                  sizeof(XATTR_FINDERINFO_NAME), uio);
			if (result)
				return (result);
		}
	}
	/* If Resource Fork is non-empty then export it. */
	if (vnode_isreg(vp) && RESOURCE_FORK_EXISTS(vp)) {
		if (uio == NULL) {
			*ap->a_size += sizeof(XATTR_RESOURCEFORK_NAME);
		} else if (uio_resid(uio) < sizeof(XATTR_RESOURCEFORK_NAME)) {
			return (ERANGE);
		} else {
			result = uiomove((caddr_t)XATTR_RESOURCEFORK_NAME,
			                 sizeof(XATTR_RESOURCEFORK_NAME), uio);
			if (result)
				return (result);
		}
	}
	/*
	 * Standard HFS only supports native FinderInfo and Resource Forks.
	 * Return at this point.
	 */
	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return (0);
	}
	/* Bail if we don't have any extended attributes. */
	if ((hfsmp->hfs_attribute_vp == NULL) ||
	    (VTOC(vp)->c_attr.ca_recflags & kHFSHasAttributesMask) == 0) {
		return (0);
	}
	btfile = VTOF(hfsmp->hfs_attribute_vp);

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));
	result = buildkey(VTOC(vp)->c_fileid, NULL, (HFSPlusAttrKey *)&iterator->key);
	if (result)
		goto exit;	

	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_SHARED_LOCK);

	result = BTSearchRecord(btfile, iterator, NULL, NULL, NULL);
	if (result && result != btNotFound) {
		hfs_systemfile_unlock(hfsmp, lockflags);
		goto exit;
	}

	state.fileID = VTOC(vp)->c_fileid;
	state.result = 0;
	state.uio = uio;
	state.size = 0;

	/*
	 * Process entries starting just after iterator->key.
	 */
	result = BTIterateRecords(btfile, kBTreeNextRecord, iterator,
	                          (IterateCallBackProcPtr)listattr_callback, &state);
	hfs_systemfile_unlock(hfsmp, lockflags);
	if (uio == NULL) {
		*ap->a_size += state.size;
	}
exit:
	FREE(iterator, M_TEMP);
	
	if (state.result || result == btNotFound)
		result = state.result;

	return MacToVFSError(result);
}


/*
 * Callback - called for each attribute
 */
static int
listattr_callback(const HFSPlusAttrKey *key, __unused const HFSPlusAttrData *data, struct listattr_callback_state *state)
{
	char attrname[XATTR_MAXNAMELEN + 1];
	size_t bytecount;
	int result;

	if (state->fileID != key->fileID) {
		state->result = 0;
		return (0);	/* stop */
	}
	/*
	 * Skip over non-primary keys
	 */
	if (key->startBlock != 0) {
		return (1);	/* continue */
	}

	result = utf8_encodestr(key->attrName, key->attrNameLen * sizeof(UniChar),
				attrname, &bytecount, sizeof(attrname), 0, 0);
	if (result) {
		state->result = result;
		return (0);	/* stop */
	}
	bytecount++; /* account for null termination char */

	if (xattr_protected(attrname))
		return (1);     /* continue */

	if (state->uio == NULL) {
		state->size += bytecount;
	} else {
		if (bytecount > uio_resid(state->uio)) {
			state->result = ERANGE;
			return (0);	/* stop */
		}
		result = uiomove((caddr_t) attrname, bytecount, state->uio);
		if (result) {
			state->result = result;
			return (0);	/* stop */
		}
	}
	return (1); /* continue */
}


/*
 * Remove all the attributes from a cnode.
 *
 * A jornal transaction must be already started.
 * Attributes b-Tree must have exclusive lock held.
 */
__private_extern__
int
hfs_removeallattr(struct hfsmount *hfsmp, u_int32_t fileid)
{
	BTreeIterator *next_iterator, *del_iterator;
	HFSPlusAttrKey *next_key;
	struct filefork *btfile;
	int result, iter_result;

	if (hfsmp->hfs_attribute_vp == NULL) {
		return (0);
	}
	btfile = VTOF(hfsmp->hfs_attribute_vp);

	MALLOC(next_iterator, BTreeIterator *, sizeof(BTreeIterator) * 2, M_TEMP, M_WAITOK);
	bzero(next_iterator, sizeof(BTreeIterator) * 2);
	del_iterator = &next_iterator[1];
	next_key = (HFSPlusAttrKey *)&next_iterator->key;

	/*
	 * Go to first possible attribute key/record pair
	 */
	(void) buildkey(fileid, NULL, next_key);
	result = BTIterateRecord(btfile, kBTreeNextRecord, next_iterator, NULL, NULL);
	if (result || next_key->fileID != fileid) {
		goto exit;
	}
	/* Remember iterator of attribute to delete */
	bcopy(next_iterator, del_iterator, sizeof(BTreeIterator));

	/* Loop until there are no more attributes for this file id */
	for(;;) {
		iter_result = BTIterateRecord(btfile, kBTreeNextRecord, next_iterator, NULL, NULL);

		/* XXX need to free and extents for record types 0x20 and 0x30 */
		result = BTDeleteRecord(btfile, del_iterator);
		if (result) {
			goto exit;
		}
		if (iter_result) {
			result = iter_result;
			break;
		}
		if (iter_result || next_key->fileID != fileid) {
			break;  /* end of attributes for this file id */
		}
		bcopy(next_iterator, del_iterator, sizeof(BTreeIterator));
	}
exit:
	(void) BTFlushPath(btfile);

	if (result == btNotFound) {
		result = 0;
	}
	FREE(next_iterator, M_TEMP);
	return (result);
}

/*
 * Enable/Disable extended security (ACLs).
 */
__private_extern__
int
hfs_setextendedsecurity(struct hfsmount *hfsmp, int state)
{
	struct BTreeIterator * iterator = NULL;
	struct filefork *btfile;
	int lockflags;
	int result;

	if (hfsmp->hfs_flags & HFS_STANDARD) {
		return (ENOTSUP);
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	/*
	 * Build a b-tree key.
	 * We use the root's parent id (1) to hold this volume attribute.
	 */
	(void) buildkey(kHFSRootParentID, XATTR_EXTENDEDSECURITY_NAME,
	                  (HFSPlusAttrKey *)&iterator->key);

	/* Start a transaction for our changes. */
	if (hfs_start_transaction(hfsmp) != 0) {
		result = EINVAL;
		goto exit2;
	}
	/*
	 * If there isn't an attributes b-tree then create one.
	 */
	if (hfsmp->hfs_attribute_vp == NULL) {
		lockflags = hfs_systemfile_lock(hfsmp, SFL_EXTENTS, HFS_EXCLUSIVE_LOCK);
		result = hfs_create_attr_btree(hfsmp, ATTRIBUTE_FILE_NODE_SIZE,
		                               getnodecount(hfsmp, ATTRIBUTE_FILE_NODE_SIZE));
		hfs_systemfile_unlock(hfsmp, lockflags);
		if (result) {
			goto exit1;
		}
	}
	btfile = VTOF(hfsmp->hfs_attribute_vp);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	if (state == 0) {
		/* Remove the attribute. */
		result = BTDeleteRecord(btfile, iterator);
		if (result == btNotFound)
			result = 0;
	} else {
		FSBufferDescriptor btdata;
		HFSPlusAttrData attrdata;
		UInt16 datasize;

		datasize = sizeof(attrdata);
		btdata.bufferAddress = &attrdata;
		btdata.itemSize = datasize;
		btdata.itemCount = 1;
		attrdata.recordType = kHFSPlusAttrInlineData;
		attrdata.reserved[0] = 0;
		attrdata.reserved[1] = 0;
		attrdata.attrSize    = 2;
		attrdata.attrData[0] = 0;
		attrdata.attrData[1] = 0;

		/* Insert the attribute. */
		result = BTInsertRecord(btfile, iterator, &btdata, datasize);
		if (result == btExists)
			result = 0;
	}
	(void) BTFlushPath(btfile);

	hfs_systemfile_unlock(hfsmp, lockflags);
exit1:
	/* Finish the transaction of our changes. */
	hfs_end_transaction(hfsmp);
exit2:
	FREE(iterator, M_TEMP);

	if (result == 0) {
		if (state == 0)
			vfs_clearextendedsecurity(HFSTOVFS(hfsmp));
		else
			vfs_setextendedsecurity(HFSTOVFS(hfsmp));
		printf("hfs: %s extended security on %s\n",
		       state == 0 ? "disabling" : "enabling", hfsmp->vcbVN);
	}

	return MacToVFSError(result);
}

/*
 * Check for extended security (ACLs).
 */
__private_extern__
void
hfs_checkextendedsecurity(struct hfsmount *hfsmp)
{
	struct BTreeIterator * iterator;
	struct filefork *btfile;
	int lockflags;
	int result;

	if (hfsmp->hfs_flags & HFS_STANDARD ||
	    hfsmp->hfs_attribute_vp == NULL) {
		return;
	}

	MALLOC(iterator, BTreeIterator *, sizeof(*iterator), M_TEMP, M_WAITOK);
	bzero(iterator, sizeof(*iterator));

	/*
	 * Build a b-tree key.
	 * We use the root's parent id (1) to hold this volume attribute.
	 */
	(void) buildkey(kHFSRootParentID, XATTR_EXTENDEDSECURITY_NAME,
	                  (HFSPlusAttrKey *)&iterator->key);

	btfile = VTOF(hfsmp->hfs_attribute_vp);

	lockflags = hfs_systemfile_lock(hfsmp, SFL_ATTRIBUTE, HFS_EXCLUSIVE_LOCK);

	/* Check for our attribute. */
	result = BTSearchRecord(btfile, iterator, NULL, NULL, NULL);

	hfs_systemfile_unlock(hfsmp, lockflags);
	FREE(iterator, M_TEMP);

	if (result == 0) {
		vfs_setextendedsecurity(HFSTOVFS(hfsmp));
		printf("hfs mount: enabling extended security on %s\n", hfsmp->vcbVN);
	}
}


/*
 * hfs_attrkeycompare - compare two attribute b-tree keys.
 *
 * The name portion of the key is compared using a 16-bit binary comparison. 
 * This is called from the b-tree code.
 */
__private_extern__
int
hfs_attrkeycompare(HFSPlusAttrKey *searchKey, HFSPlusAttrKey *trialKey)
{
	u_int32_t searchFileID, trialFileID;
	int result;

	searchFileID = searchKey->fileID;
	trialFileID = trialKey->fileID;
	result = 0;
	
	if (searchFileID > trialFileID) {
		++result;
	} else if (searchFileID < trialFileID) {
		--result;
	} else {
		u_int16_t * str1 = &searchKey->attrName[0];
		u_int16_t * str2 = &trialKey->attrName[0];
		int length1 = searchKey->attrNameLen;
		int length2 = trialKey->attrNameLen;
		u_int16_t c1, c2;
		int length;
	
		if (length1 < length2) {
			length = length1;
			--result;
		} else if (length1 > length2) {
			length = length2;
			++result;
		} else {
			length = length1;
		}
	
		while (length--) {
			c1 = *(str1++);
			c2 = *(str2++);
	
			if (c1 > c2) {
				result = 1;
				break;
			}
			if (c1 < c2) {
				result = -1;
				break;
			}
		}
		if (result)
			return (result);
		/*
		 * Names are equal; compare startBlock
		 */
		if (searchKey->startBlock == trialKey->startBlock)
			return (0);
		else
			return (searchKey->startBlock < trialKey->startBlock ? -1 : 1);
		}

	return result;
}


/*
 * buildkey - build an Attribute b-tree key
 */
static int
buildkey(u_int32_t fileID, const char *attrname, HFSPlusAttrKey *key)
{
	int result = 0;
	size_t unicodeBytes = 0;

	if (attrname != NULL) {
		/*
		 * Convert filename from UTF-8 into Unicode
		 */	
		result = utf8_decodestr(attrname, strlen(attrname), key->attrName,
					&unicodeBytes, sizeof(key->attrName), 0, 0);
		if (result) {
			if (result != ENAMETOOLONG)
				result = EINVAL;  /* name has invalid characters */
			return (result);
		}
		key->attrNameLen = unicodeBytes / sizeof(UniChar);
		key->keyLength = kHFSPlusAttrKeyMinimumLength + unicodeBytes;
	} else {
		key->attrNameLen = 0;
		key->keyLength = kHFSPlusAttrKeyMinimumLength;
	}
	key->pad = 0;
	key->fileID = fileID;
	key->startBlock = 0;

	return (0);
 }

/*
 * getnodecount - calculate starting node count for attributes b-tree.
 */
static int
getnodecount(struct hfsmount *hfsmp, size_t nodesize)
{
	int avedatasize;
	int recpernode;
	int count;

	avedatasize = sizeof(u_int16_t);  /* index slot */
	avedatasize += kHFSPlusAttrKeyMinimumLength + HFS_AVERAGE_NAME_SIZE * sizeof(u_int16_t);
	avedatasize += sizeof(HFSPlusAttrData) + 32;

	recpernode = (nodesize - sizeof(BTNodeDescriptor)) / avedatasize;

	count = (hfsmp->hfs_filecount + hfsmp->hfs_dircount) / 8;
	count /= recpernode;

	/* XXX should also consider volume size XXX */

	return (MAX(count, (int)(1024 * 1024) / (int)nodesize));
}


/*
 * getmaxinlineattrsize - calculate maximum inline attribute size.
 *
 * This yields 3,802 bytes for an 8K node size.
 */
static size_t
getmaxinlineattrsize(struct vnode * attrvp)
{
	struct BTreeInfoRec btinfo;
	size_t nodesize = ATTRIBUTE_FILE_NODE_SIZE;
	size_t maxsize;

	if (attrvp != NULL) {
		(void) hfs_lock(VTOC(attrvp), HFS_SHARED_LOCK);
		if (BTGetInformation(VTOF(attrvp), 0, &btinfo) == 0)
			nodesize = btinfo.nodeSize;
		hfs_unlock(VTOC(attrvp));
	}
	maxsize = nodesize;
	maxsize -= sizeof(BTNodeDescriptor);     /* minus node descriptor */
	maxsize -= 3 * sizeof(UInt16);           /* minus 3 index slots */
	maxsize /= 2;                            /* 2 key/rec pairs minumum */
	maxsize -= sizeof(HFSPlusAttrKey);       /* minus maximum key size */
	maxsize -= sizeof(HFSPlusAttrData) - 2;  /* minus data header */
	maxsize &= 0xFFFFFFFE;                   /* multiple of 2 bytes */
	
	return (maxsize);
}


