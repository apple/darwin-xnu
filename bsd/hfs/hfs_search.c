/*
 * Copyright (c) 1997-2004 Apple Computer, Inc. All rights reserved.
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
 *
 *	@(#)hfs_search.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <mach/machine/vm_types.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/signalvar.h>
#include <sys/attr.h>
#include <sys/utfconv.h>
#include <sys/kauth.h>
#include <sys/vnode_internal.h>

#include "hfs.h"
#include "hfs_dbg.h"
#include "hfs_catalog.h"
#include "hfs_attrlist.h"
#include "hfs_endian.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"
#include "hfscommon/headers/BTreesPrivate.h"
#include "hfscommon/headers/BTreeScanner.h"
#include "hfscommon/headers/CatalogPrivate.h"

/* Search criterea. */
struct directoryInfoSpec
{
	u_int32_t   numFiles;
};

struct fileInfoSpec
{
	off_t		dataLogicalLength;
	off_t		dataPhysicalLength;
	off_t		resourceLogicalLength;
	off_t		resourcePhysicalLength;
};

struct searchinfospec
{
	u_char			name[kHFSPlusMaxFileNameBytes];
	u_long			nameLength;
	char			attributes;		// see IM:Files 2-100
	u_long			nodeID;
	u_long			parentDirID;
	struct timespec		creationDate;		
	struct timespec		modificationDate;		
	struct timespec		changeDate;	
	struct timespec		accessDate;		
	struct timespec		lastBackupDate;	
	uint8_t			finderInfo[32];
	uid_t			uid;	
	gid_t			gid;
	mode_t			mask;
	struct fileInfoSpec	f;
	struct directoryInfoSpec d;
};
typedef struct searchinfospec searchinfospec_t;

static void ResolveHardlink(ExtendedVCB *vcb, HFSPlusCatalogFile *recp);


static int UnpackSearchAttributeBlock(struct hfsmount *hfsmp, struct attrlist *alist,
		searchinfospec_t *searchInfo, void *attributeBuffer);

static int CheckCriteria(	ExtendedVCB *vcb, 
							u_long searchBits,
							struct attrlist *attrList, 
							CatalogRecord *rec,
							CatalogKey *key, 
							searchinfospec_t *searchInfo1,
							searchinfospec_t *searchInfo2,
							Boolean lookForDup );

static int CheckAccess(ExtendedVCB *vcb, u_long searchBits, CatalogKey *key, struct proc *p);

static int InsertMatch(struct hfsmount *hfsmp, uio_t a_uio, CatalogRecord *rec,
			CatalogKey *key, struct attrlist *returnAttrList,
			void *attributesBuffer, void *variableBuffer,
			u_long * nummatches );

static Boolean CompareRange(u_long val, u_long low, u_long high);
static Boolean CompareWideRange(u_int64_t val, u_int64_t low, u_int64_t high);

static Boolean CompareRange( u_long val, u_long low, u_long high )
{
	return( (val >= low) && (val <= high) );
}

static Boolean CompareWideRange( u_int64_t val, u_int64_t low, u_int64_t high )
{
	return( (val >= low) && (val <= high) );
}
//#define CompareRange(val, low, high)	((val >= low) && (val <= high))
			
#if 1 // Installer workaround (2940423)
static Boolean IsTargetName( searchinfospec_t * searchInfoPtr, Boolean isHFSPlus );
#endif // Installer workaround

__private_extern__ int hfs_vnop_search(struct vnop_searchfs_args *ap);


/************************************************************************/
/* Entry for searchfs()                                                 */
/************************************************************************/

#define	errSearchBufferFull	101	/* Internal search errors */
/*
#
#% searchfs	vp	L L L
#
vnop_searchfs {
    IN struct vnode *vp;
    IN off_t length;
    IN int flags;
    IN kauth_cred_t cred;
    IN struct proc *p;
};
*/

__private_extern__
int
hfs_vnop_search(ap)
	struct vnop_searchfs_args *ap; /*
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		void *a_searchparams1;
		void *a_searchparams2;
		struct attrlist *a_searchattrs;
		u_long a_maxmatches;
		struct timeval *a_timelimit;
		struct attrlist *a_returnattrs;
		u_long *a_nummatches;
		u_long a_scriptcode;
		u_long a_options;
		struct uio *a_uio;
		struct searchstate *a_searchstate;
		vfs_context_t a_context;
	*/
{
	ExtendedVCB *vcb = VTOVCB(ap->a_vp);
	struct hfsmount *hfsmp;
	FCB * catalogFCB;
	searchinfospec_t searchInfo1;
	searchinfospec_t searchInfo2;
	void *attributesBuffer;
	void *variableBuffer;
	u_long fixedBlockSize;
	u_long eachReturnBufferSize;
	struct proc *p = proc_self();
	int err = E_NONE;
	int isHFSPlus;
	int timerExpired = false;
	int doQuickExit = false;
	CatalogKey * myCurrentKeyPtr;
	CatalogRecord * myCurrentDataPtr;
	CatPosition * myCatPositionPtr;
	BTScanState myBTScanState;
	user_addr_t user_start = 0;
	user_size_t user_len = 0;
	int32_t searchTime;
	int lockflags;

	/* XXX Parameter check a_searchattrs? */

	*(ap->a_nummatches) = 0;

	if (ap->a_options & ~SRCHFS_VALIDOPTIONSMASK)
		return (EINVAL);

	/* SRCHFS_SKIPLINKS requires root access.
	 * This option cannot be used with either
	 * the ATTR_CMN_NAME or ATTR_CMN_PAROBJID
	 * attributes.
	 */
	if (ap->a_options & SRCHFS_SKIPLINKS) {
		attrgroup_t attrs;

		attrs = ap->a_searchattrs->commonattr | ap->a_returnattrs->commonattr;
		if (attrs & (ATTR_CMN_NAME | ATTR_CMN_PAROBJID))
			return (EINVAL);
		if ((err = suser(kauth_cred_get(), 0)))
			return (err);
	}

	if (uio_resid(ap->a_uio) <= 0)
		return (EINVAL);

	isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);
	hfsmp = VTOHFS(ap->a_vp);
	
	searchTime = kMaxMicroSecsInKernel;
	if (ap->a_timelimit->tv_sec == 0 &&
	    ap->a_timelimit->tv_usec > 0 &&
	    ap->a_timelimit->tv_usec < kMaxMicroSecsInKernel) {
		searchTime = ap->a_timelimit->tv_usec;
	}

	/* UnPack the search boundries, searchInfo1, searchInfo2 */
	err = UnpackSearchAttributeBlock(hfsmp, ap->a_searchattrs,
				&searchInfo1, ap->a_searchparams1);
	if (err) return err;
	err = UnpackSearchAttributeBlock(hfsmp, ap->a_searchattrs,
				&searchInfo2, ap->a_searchparams2);
	if (err) return err;

    fixedBlockSize = sizeof(uint32_t) + hfs_attrblksize(ap->a_returnattrs);	/* uint32_t for length word */

	eachReturnBufferSize = fixedBlockSize;

	if ( ap->a_returnattrs->commonattr & ATTR_CMN_NAME )	/* XXX should be more robust! */
		eachReturnBufferSize += kHFSPlusMaxFileNameBytes + 1;

	MALLOC( attributesBuffer, void *, eachReturnBufferSize, M_TEMP, M_WAITOK );
	variableBuffer = (void*)((char*) attributesBuffer + fixedBlockSize);

	// XXXdbg - have to lock the user's buffer so we don't fault
	// while holding the shared catalog file lock.  see the comment
	// in hfs_readdir() for more details.
	//
	if (hfsmp->jnl && uio_isuserspace(ap->a_uio)) {
		user_start = uio_curriovbase(ap->a_uio);
		user_len = uio_curriovlen(ap->a_uio);

		if ((err = vslock(user_start, user_len)) != 0) {
			user_start = 0;
			goto ExitThisRoutine;
		}
	}

	lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);

	catalogFCB = GetFileControlBlock(vcb->catalogRefNum);
	myCurrentKeyPtr = NULL;
	myCurrentDataPtr = NULL;
	myCatPositionPtr = (CatPosition *)ap->a_searchstate;

	if (ap->a_options & SRCHFS_START) {
		/* Starting a new search. */
		/* Make sure the on-disk Catalog file is current */
		(void) hfs_fsync(vcb->catalogRefNum, MNT_WAIT, 0, p);
		if (hfsmp->jnl) {
		    hfs_systemfile_unlock(hfsmp, lockflags);
		    journal_flush(hfsmp->jnl);
		    lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
		}

		ap->a_options &= ~SRCHFS_START;
		bzero( (caddr_t)myCatPositionPtr, sizeof( *myCatPositionPtr ) );
		err = BTScanInitialize(catalogFCB, 0, 0, 0, kCatSearchBufferSize, &myBTScanState);
		
#if 1 // Installer workaround (2940423)
		// hack to get around installer problems when the installer expects search results 
		// to be in key order.  At this point the problem appears to be limited to 
		// searches for "Library".  The idea here is to go get the "Library" at root
		// and return it first to the caller then continue the search as normal with
		// the exception of taking care not to return a duplicate hit (see CheckCriteria) 
		if ( err == E_NONE &&
			 (ap->a_searchattrs->commonattr & ATTR_CMN_NAME) != 0 &&
			 IsTargetName( &searchInfo1, isHFSPlus )  )
		{
			CatalogRecord		rec;
			BTreeIterator       iterator;
			FSBufferDescriptor  btrec;
			CatalogKey *		keyp;
			UInt16              reclen;
			OSErr				result;
		
			bzero( (caddr_t)&iterator, sizeof( iterator ) );
			keyp = (CatalogKey *) &iterator.key;
			(void) BuildCatalogKeyUTF8(vcb, kRootDirID, "Library", kUndefinedStrLen, keyp, NULL);

			btrec.bufferAddress = &rec;
			btrec.itemCount = 1;
			btrec.itemSize = sizeof( rec );

			result = BTSearchRecord( catalogFCB, &iterator, &btrec, &reclen, &iterator );
			if ( result == E_NONE ) {
				// need to unlock since CheckAccess assumes no lock held
				hfs_systemfile_unlock(hfsmp, lockflags);
				if (CheckCriteria(vcb, ap->a_options, ap->a_searchattrs, &rec,
								  keyp, &searchInfo1, &searchInfo2, false) &&
					CheckAccess(vcb, ap->a_options, keyp, p)) {
		
					result = InsertMatch(hfsmp, ap->a_uio, &rec, 
									  keyp, ap->a_returnattrs,
									  attributesBuffer, variableBuffer,
									  ap->a_nummatches);
					if (result == E_NONE && *(ap->a_nummatches) >= ap->a_maxmatches)
						doQuickExit = true;
				}
				lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
			}
		}
#endif // Installer workaround
	} else {
		/* Resuming a search. */
		err = BTScanInitialize(catalogFCB, myCatPositionPtr->nextNode, 
					myCatPositionPtr->nextRecord, 
					myCatPositionPtr->recordsFound,
					kCatSearchBufferSize, 
					&myBTScanState);
		/* Make sure Catalog hasn't changed. */
		if (err == 0
		&&  myCatPositionPtr->writeCount != myBTScanState.btcb->writeCount) {
			myCatPositionPtr->writeCount = myBTScanState.btcb->writeCount;
			err = EBUSY; /* catChangedErr */
		}
	}
	hfs_systemfile_unlock(hfsmp, lockflags);

	if (err)
		goto ExitThisRoutine;
#if 1 // Installer workaround (2940423)
	if ( doQuickExit )
		goto QuickExit;
#endif // Installer workaround

	/*
	 * Check all the catalog btree records...
	 *   return the attributes for matching items
	 */
	for (;;) {
		struct timeval myCurrentTime;
		struct timeval myElapsedTime;
		
		err = BTScanNextRecord(&myBTScanState, timerExpired, 
			(void **)&myCurrentKeyPtr, (void **)&myCurrentDataPtr, 
			NULL);
		if (err)
			break;

		/* Resolve any hardlinks */
		if (isHFSPlus && (ap->a_options & SRCHFS_SKIPLINKS) == 0) {
			lockflags = hfs_systemfile_lock(hfsmp, SFL_CATALOG, HFS_SHARED_LOCK);
			ResolveHardlink(vcb, (HFSPlusCatalogFile *) myCurrentDataPtr);
			hfs_systemfile_unlock(hfsmp, lockflags);
		}
		if (CheckCriteria( vcb, ap->a_options, ap->a_searchattrs, myCurrentDataPtr,
				myCurrentKeyPtr, &searchInfo1, &searchInfo2, true )
		&&  CheckAccess(vcb, ap->a_options, myCurrentKeyPtr, p)) {
			err = InsertMatch(hfsmp, ap->a_uio, myCurrentDataPtr, 
					myCurrentKeyPtr, ap->a_returnattrs,
					attributesBuffer, variableBuffer, ap->a_nummatches);
			if (err) {
				/*
				 * The last match didn't fit so come back
				 * to this record on the next trip.
				 */
				--myBTScanState.recordsFound;
				--myBTScanState.recordNum;
				break;
			}

			if (*(ap->a_nummatches) >= ap->a_maxmatches)
				break;
		}

		/*
		 * Check our elapsed time and bail if we've hit the max.
		 * The idea here is to throttle the amount of time we
		 * spend in the kernel.
		 */
		microuptime(&myCurrentTime);
		timersub(&myCurrentTime, &myBTScanState.startTime, &myElapsedTime);
		/* Note: assumes kMaxMicroSecsInKernel is less than 1,000,000 */
		if (myElapsedTime.tv_sec > 0
		||  myElapsedTime.tv_usec >= searchTime) {
			timerExpired = true;
		}
	}

QuickExit:
	/* Update catalog position */
	myCatPositionPtr->writeCount = myBTScanState.btcb->writeCount;

	BTScanTerminate(&myBTScanState, &myCatPositionPtr->nextNode, 
			&myCatPositionPtr->nextRecord, 
			&myCatPositionPtr->recordsFound);

	if ( err == E_NONE ) {
		err = EAGAIN;	/* signal to the user to call searchfs again */
	} else if ( err == errSearchBufferFull ) {
		if ( *(ap->a_nummatches) > 0 )
			err = EAGAIN;
 		else
			err = ENOBUFS;
	} else if ( err == btNotFound ) {
		err = E_NONE;	/* the entire disk has been searched */
	} else if ( err == fsBTTimeOutErr ) {
		err = EAGAIN;
	}

ExitThisRoutine:
    FREE( attributesBuffer, M_TEMP );

	if (hfsmp->jnl && user_start) {
		vsunlock(user_start, user_len, TRUE);
	}

	return (MacToVFSError(err));
}


static void
ResolveHardlink(ExtendedVCB *vcb, HFSPlusCatalogFile *recp)
{
	if ((recp->recordType == kHFSPlusFileRecord)
	&&  (SWAP_BE32(recp->userInfo.fdType) == kHardLinkFileType)
	&&  (SWAP_BE32(recp->userInfo.fdCreator) == kHFSPlusCreator)
	&&  ((to_bsd_time(recp->createDate) == vcb->vcbCrDate) ||
	     (to_bsd_time(recp->createDate) == VCBTOHFS(vcb)->hfs_metadata_createdate))) {
		cnid_t saved_cnid;

		/* Export link's cnid (a unique value) instead of inode's cnid */
		saved_cnid = recp->fileID;
		(void) resolvelink(VCBTOHFS(vcb), recp->bsdInfo.special.iNodeNum, recp);
		recp->fileID = saved_cnid;
	}
}


static Boolean
CompareMasked(const UInt32 *thisValue, const UInt32 *compareData,
		const UInt32 *compareMask, UInt32 count)
{
	Boolean	matched;
	UInt32	i;
	
	matched = true;		/* Assume it will all match */
	
	for (i=0; i<count; i++) {
		if (((*thisValue++ ^ *compareData++) & *compareMask++) != 0) {
			matched = false;
			break;
		}
	}
	
	return matched;
}


static Boolean
ComparePartialUnicodeName (register ConstUniCharArrayPtr str, register ItemCount s_len,
			   register ConstUniCharArrayPtr find, register ItemCount f_len )
{
	if (f_len == 0 || s_len == 0)
		return FALSE;

	do {
		if (s_len-- < f_len)
			return FALSE;
	} while (FastUnicodeCompare(str++, f_len, find, f_len) != 0);

	return TRUE;
}


static Boolean
ComparePartialPascalName ( register ConstStr31Param str, register ConstStr31Param find )
{
	register u_char s_len = str[0];
	register u_char f_len = find[0];
	register u_char *tsp;
	Str31 tmpstr;

	if (f_len == 0 || s_len == 0)
		return FALSE;

	bcopy(str, tmpstr, s_len + 1);
	tsp = &tmpstr[0];

	while (s_len-- >= f_len) {
		*tsp = f_len;

		if (FastRelString(tsp++, find) == 0)
			return TRUE;
	}

	return FALSE;
}


//
// Determine if a name is "inappropriate" where the definition
// of "inappropriate" is up to higher level execs.  Currently
// that's limited to /System.
//
static int
is_inappropriate_name(char *name, int len)
{
    const char *bad_names[] = { "System" };
    int   bad_len[]   = {        6 };
    int  i;
    
    for(i=0; i < (int) (sizeof(bad_names) / sizeof(bad_names[0])); i++) {
	if (len == bad_len[i] && strcmp(name, bad_names[i]) == 0) {
	    return 1;
	}
    }

    // if we get here, no name matched
    return 0;
}



/*
 * Check to see if caller has access rights to this item
 */

static int
CheckAccess(ExtendedVCB *theVCBPtr, u_long searchBits, CatalogKey *theKeyPtr, struct proc *theProcPtr)
{
	Boolean				isHFSPlus;
	int					myErr;
	int					myResult; 	
	HFSCatalogNodeID 	myNodeID;
	hfsmount_t *		hfsmp;
	struct FndrDirInfo	*finfop;
	struct vnode * 		vp = NULL;
	struct vfs_context 	my_context;

	myResult = 0;	/* default to "no access" */
	my_context.vc_proc = theProcPtr;
	my_context.vc_ucred = kauth_cred_get();
		
	if (!proc_suser(theProcPtr)) {
		myResult = 1;	/* allow access */
		goto ExitThisRoutine; /* root always has access */
	}

	hfsmp = VCBTOHFS( theVCBPtr );
	isHFSPlus = ( theVCBPtr->vcbSigWord == kHFSPlusSigWord );
	if ( isHFSPlus )
		myNodeID = theKeyPtr->hfsPlus.parentID;
	else
		myNodeID = theKeyPtr->hfs.parentID;
	
	while ( myNodeID >= kRootDirID ) {
		cnode_t *	cp;
		
		/* now go get catalog data for this directory */
		myErr = hfs_vget(hfsmp, myNodeID, &vp, 0);
		if ( myErr ) {
			goto ExitThisRoutine;	/* no access */
		}

		cp = VTOC(vp);
		finfop = (struct FndrDirInfo *)&cp->c_attr.ca_finderinfo[0];

		if ( searchBits & SRCHFS_SKIPPACKAGES ) {
		    if (   (SWAP_BE16(finfop->frFlags) & kHasBundle)
			|| (cp->c_desc.cd_nameptr != NULL
			    && is_package_name(cp->c_desc.cd_nameptr, cp->c_desc.cd_namelen)) ) {
				myResult = 0;
				goto ExitThisRoutine;
		    }
		}

		if ( searchBits & SRCHFS_SKIPINAPPROPRIATE ) {
		    if ( cp->c_parentcnid == kRootDirID && cp->c_desc.cd_nameptr != NULL &&
			     is_inappropriate_name(cp->c_desc.cd_nameptr, cp->c_desc.cd_namelen) ) {
				myResult = 0;
				goto ExitThisRoutine;
		    }
		}

		if ( (searchBits & SRCHFS_SKIPINVISIBLE) && 
			 (SWAP_BE16(finfop->frFlags) & kIsInvisible) ) {
		    myResult = 0;
		    goto ExitThisRoutine;
		}

		myNodeID = cp->c_parentcnid;	/* move up the hierarchy */
		hfs_unlock(VTOC(vp));
		if (vp->v_type == VDIR) {
		    myErr = vnode_authorize(vp, NULL, (KAUTH_VNODE_SEARCH | KAUTH_VNODE_LIST_DIRECTORY), &my_context);
		} else {
		    myErr = vnode_authorize(vp, NULL, (KAUTH_VNODE_SEARCH), &my_context);
		}
		vnode_put(vp);
		vp = NULL;
		if ( myErr ) {
			goto ExitThisRoutine;	/* no access */
		}
	}
	myResult = 1;	/* allow access */

ExitThisRoutine:
	if ( vp != NULL ) {
		hfs_unlock(VTOC(vp));
		vnode_put(vp);
	}
	return ( myResult );
	
}

static int
CheckCriteria(	ExtendedVCB *vcb, 
				u_long searchBits,
				struct attrlist *attrList, 
				CatalogRecord *rec, 
				CatalogKey *key,
				searchinfospec_t  *searchInfo1, 
				searchinfospec_t *searchInfo2,
				Boolean lookForDup )
{
	Boolean matched, atleastone;
	Boolean isHFSPlus;
	attrgroup_t searchAttributes;
	struct cat_attr c_attr;
	struct cat_fork datafork;
	struct cat_fork rsrcfork;
	
	bzero(&c_attr, sizeof(c_attr));
	isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);

	switch (rec->recordType) {
	case kHFSFolderRecord:
	case kHFSPlusFolderRecord:
		if ( (searchBits & SRCHFS_MATCHDIRS) == 0 ) {	/* If we are NOT searching folders */
			matched = false;
			goto TestDone;
		}
		break;
			
	case kHFSFileRecord:
		if ( (searchBits & SRCHFS_MATCHFILES) == 0 ) {	/* If we are NOT searching files */
			matched = false;
			goto TestDone;
		}
		break;

	case kHFSPlusFileRecord:
		/* Check if hardlink links should be skipped. */
		if (searchBits & SRCHFS_SKIPLINKS) {
			cnid_t parid = key->hfsPlus.parentID;
			HFSPlusCatalogFile *filep = (HFSPlusCatalogFile *)rec;

			if ((SWAP_BE32(filep->userInfo.fdType) == kHardLinkFileType) &&
			    (SWAP_BE32(filep->userInfo.fdCreator) == kHFSPlusCreator)) {
				return (false);	/* skip over link records */
			} else if ((parid == VCBTOHFS(vcb)->hfs_privdir_desc.cd_cnid) &&
			           (filep->bsdInfo.special.linkCount == 0)) {
				return (false);	/* skip over unlinked files */
			}
		} else if (key->hfsPlus.parentID == VCBTOHFS(vcb)->hfs_privdir_desc.cd_cnid) {
			return (false);	/* skip over private files */
		}

		if ( (searchBits & SRCHFS_MATCHFILES) == 0 ) {	/* If we are NOT searching files */
			matched = false;
			goto TestDone;
		}
		break;

	default:	/* Never match a thread record or any other type. */
		return( false );	/* Not a file or folder record, so can't search it */
	}
	
	matched = true;		/* Assume we got a match */
	atleastone = false;	/* Dont insert unless we match at least one criteria */
	
	/* First, attempt to match the name -- either partial or complete */
	if ( attrList->commonattr & ATTR_CMN_NAME ) {
		if (isHFSPlus) {
			/* Check for partial/full HFS Plus name match */

			if ( searchBits & SRCHFS_MATCHPARTIALNAMES ) {
				matched = ComparePartialUnicodeName(key->hfsPlus.nodeName.unicode,
								    key->hfsPlus.nodeName.length,
								    (UniChar*)searchInfo1->name,
								    searchInfo1->nameLength );
			} else /* full HFS Plus name match */ { 
				matched = (FastUnicodeCompare(key->hfsPlus.nodeName.unicode,
							      key->hfsPlus.nodeName.length,
							      (UniChar*)searchInfo1->name,
							      searchInfo1->nameLength ) == 0);
			}
		} else {
			/* Check for partial/full HFS name match */

			if ( searchBits & SRCHFS_MATCHPARTIALNAMES )
				matched = ComparePartialPascalName(key->hfs.nodeName, (u_char*)searchInfo1->name);
			else /* full HFS name match */
				matched = (FastRelString(key->hfs.nodeName, (u_char*)searchInfo1->name) == 0);
		}

#if 1 // Installer workaround (2940423)
		if ( lookForDup ) {
			HFSCatalogNodeID parentID;
			if (isHFSPlus)
				parentID = key->hfsPlus.parentID;
			else
				parentID = key->hfs.parentID;
	
			if ( matched && parentID == kRootDirID && 
				 IsTargetName( searchInfo1, isHFSPlus )  )
				matched = false;
		}
#endif // Installer workaround

		if ( matched == false || (searchBits & ~SRCHFS_MATCHPARTIALNAMES) == 0 )
			goto TestDone;	/* no match, or nothing more to compare */

		atleastone = true;
	}

	/* Convert catalog record into cat_attr format. */
	cat_convertattr(VCBTOHFS(vcb), rec, &c_attr, &datafork, &rsrcfork);
	
	if (searchBits & SRCHFS_SKIPINVISIBLE) {
	    int flags;
	    
	    switch (rec->recordType) {
		case kHFSFolderRecord:
		case kHFSPlusFolderRecord: {
		    struct FndrDirInfo *finder_info;
		    
		    finder_info = (struct FndrDirInfo *)&c_attr.ca_finderinfo[0];
		    flags = SWAP_BE16(finder_info->frFlags);
		    break;
		}
			
		case kHFSFileRecord:
		case kHFSPlusFileRecord: {
		    struct FndrFileInfo *finder_info;
		    
		    finder_info = (struct FndrFileInfo *)&c_attr.ca_finderinfo[0];
		    flags = SWAP_BE16(finder_info->fdFlags);
		    break;
		}

		default: {
		    flags = kIsInvisible;
		    break;
		}
	    }
		    
	    if (flags & kIsInvisible) {
		matched = false;
		goto TestDone;
	    }
	}
	
		    

	/* Now that we have a record worth searching, see if it matches the search attributes */
	if (rec->recordType == kHFSFileRecord ||
	    rec->recordType == kHFSPlusFileRecord) {
		if ((attrList->fileattr & ~ATTR_FILE_VALIDMASK) != 0) {	/* attr we do know about  */
			matched = false;
			goto TestDone;
		}
		else if ((attrList->fileattr & ATTR_FILE_VALIDMASK) != 0) {
		searchAttributes = attrList->fileattr;
	
		/* File logical length (data fork) */
		if ( searchAttributes & ATTR_FILE_DATALENGTH ) {
			matched = CompareWideRange(
			    datafork.cf_size,
			    searchInfo1->f.dataLogicalLength,
			    searchInfo2->f.dataLogicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
		}
	
		/* File physical length (data fork) */
		if ( searchAttributes & ATTR_FILE_DATAALLOCSIZE ) {
			matched = CompareWideRange(
			    (u_int64_t)datafork.cf_blocks * (u_int64_t)vcb->blockSize,
			    searchInfo1->f.dataPhysicalLength,
			    searchInfo2->f.dataPhysicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
		}

		/* File logical length (resource fork) */
		if ( searchAttributes & ATTR_FILE_RSRCLENGTH ) {
			matched = CompareWideRange(
			    rsrcfork.cf_size,
			    searchInfo1->f.resourceLogicalLength,
			    searchInfo2->f.resourceLogicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
		}
		
		/* File physical length (resource fork) */
		if ( searchAttributes & ATTR_FILE_RSRCALLOCSIZE ) {
			matched = CompareWideRange(
			    (u_int64_t)rsrcfork.cf_blocks * (u_int64_t)vcb->blockSize,
			    searchInfo1->f.resourcePhysicalLength,
			    searchInfo2->f.resourcePhysicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
			}
		}
		else {
			atleastone = true;	/* to match SRCHFS_MATCHFILES */
		}
	}
	/*
	 * Check the directory attributes
	 */
	else if (rec->recordType == kHFSFolderRecord ||
	         rec->recordType == kHFSPlusFolderRecord) {
		if ((attrList->dirattr & ~ATTR_DIR_VALIDMASK) != 0) {	/* attr we do know about  */
			matched = false;
			goto TestDone;
		}
		else if ((attrList->dirattr & ATTR_DIR_VALIDMASK) != 0) {
		searchAttributes = attrList->dirattr;
		
		/* Directory valence */
		if ( searchAttributes & ATTR_DIR_ENTRYCOUNT ) {
			matched = CompareRange(c_attr.ca_entries,
					searchInfo1->d.numFiles,
					searchInfo2->d.numFiles );
			if (matched == false) goto TestDone;
				atleastone = true;
			}
		}
		else {
			atleastone = true;		/* to match SRCHFS_MATCHDIRS */
		}
	}
	
	/*
	 * Check the common attributes
	 */
	searchAttributes = attrList->commonattr;
	if ( (searchAttributes & ATTR_CMN_VALIDMASK) != 0 ) {
		/* node ID */
		if ( searchAttributes & ATTR_CMN_OBJID ) {
			matched = CompareRange(c_attr.ca_fileid,
					searchInfo1->nodeID,
					searchInfo2->nodeID );
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Parent ID */
		if ( searchAttributes & ATTR_CMN_PAROBJID ) {
			HFSCatalogNodeID parentID;
			
			if (isHFSPlus)
				parentID = key->hfsPlus.parentID;
			else
				parentID = key->hfs.parentID;
				
			matched = CompareRange(parentID, searchInfo1->parentDirID,
					searchInfo2->parentDirID );
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Finder Info & Extended Finder Info where extFinderInfo is last 32 bytes */
		if ( searchAttributes & ATTR_CMN_FNDRINFO ) {
			UInt32 *thisValue;
			thisValue = (UInt32 *) &c_attr.ca_finderinfo;

			/* 
			 * Note: ioFlFndrInfo and ioDrUsrWds have the same offset in search info, so
			 * no need to test the object type here.
			 */
			matched = CompareMasked(thisValue,
					(UInt32 *)&searchInfo1->finderInfo,
					(UInt32 *) &searchInfo2->finderInfo, 8);
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Create date */
		if ( searchAttributes & ATTR_CMN_CRTIME ) {
			matched = CompareRange(c_attr.ca_itime,
					searchInfo1->creationDate.tv_sec,
					searchInfo2->creationDate.tv_sec);
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* Mod date */
		if ( searchAttributes & ATTR_CMN_MODTIME ) {
			matched = CompareRange(c_attr.ca_mtime,
					searchInfo1->modificationDate.tv_sec,
					searchInfo2->modificationDate.tv_sec);
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* Change Time */
		if ( searchAttributes & ATTR_CMN_CHGTIME ) {
			matched = CompareRange(c_attr.ca_ctime,
					searchInfo1->changeDate.tv_sec,
					searchInfo2->changeDate.tv_sec);
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* Access date */
		if ( searchAttributes & ATTR_CMN_ACCTIME ) {
			matched = CompareRange(c_attr.ca_atime,
					searchInfo1->accessDate.tv_sec,
					searchInfo2->accessDate.tv_sec);
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Backup date */
		if ( searchAttributes & ATTR_CMN_BKUPTIME ) {
			matched = CompareRange(c_attr.ca_btime,
					searchInfo1->lastBackupDate.tv_sec,
					searchInfo2->lastBackupDate.tv_sec);
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* User ID */
		if ( searchAttributes & ATTR_CMN_OWNERID ) {
			matched = CompareRange(c_attr.ca_uid,
					searchInfo1->uid, searchInfo2->uid);
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Group ID */
		if ( searchAttributes & ATTR_CMN_GRPID ) {
			matched = CompareRange(c_attr.ca_gid,
					searchInfo1->gid, searchInfo2->gid);
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* mode */
		if ( searchAttributes & ATTR_CMN_ACCESSMASK ) {
			matched = CompareRange((uint32_t)c_attr.ca_mode, 
					(uint32_t)searchInfo1->mask,
					(uint32_t)searchInfo2->mask);
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	}

	/* If we got here w/o matching any, then set to false */
	if (! atleastone)
		matched = false;
	
TestDone:
	/*
	 * Finally, determine whether we need to negate the sense of the match
	 * (i.e. find all objects that DON'T match).
	 */
	if ( searchBits & SRCHFS_NEGATEPARAMS )
		matched = !matched;
	
	return( matched );
}


/*
 * Adds another record to the packed array for output
 */
static int
InsertMatch(struct hfsmount *hfsmp, uio_t a_uio, CatalogRecord *rec,
            CatalogKey *key, struct attrlist *returnAttrList,
            void *attributesBuffer, void *variableBuffer, u_long * nummatches)
{
	int err;
	void *rovingAttributesBuffer;
	void *rovingVariableBuffer;
	u_long packedBufferSize;
	u_long privateDir = hfsmp->hfs_privdir_desc.cd_cnid;
	struct attrblock attrblk;
	struct cat_desc c_desc;
	struct cat_attr c_attr;
	struct cat_fork datafork;
	struct cat_fork rsrcfork;

	bzero(&c_desc, sizeof(c_desc));
	bzero(&c_attr, sizeof(c_attr));
	rovingAttributesBuffer = (char*)attributesBuffer + sizeof(u_long); /* Reserve space for length field */
	rovingVariableBuffer = variableBuffer;

	/* Convert catalog record into cat_attr format. */
	cat_convertattr(hfsmp, rec, &c_attr, &datafork, &rsrcfork);

	/* hide our private meta data directory */
	if ((privateDir != 0) && (c_attr.ca_fileid == privateDir)) {
		err = 0;
		goto exit;
	}

	/* Hide the private journal files */
	if (hfsmp->jnl &&
	    ((c_attr.ca_fileid == hfsmp->hfs_jnlfileid) ||
	     (c_attr.ca_fileid == hfsmp->hfs_jnlinfoblkid))) {
		err = 0;
		goto exit;
	}

	if (returnAttrList->commonattr & ATTR_CMN_NAME) {
		cat_convertkey(hfsmp, key, rec, &c_desc);
	} else {
		c_desc.cd_cnid = c_attr.ca_fileid;
		if (hfsmp->hfs_flags & HFS_STANDARD)
			c_desc.cd_parentcnid = key->hfs.parentID;
		else
			c_desc.cd_parentcnid = key->hfsPlus.parentID;
	}

	attrblk.ab_attrlist = returnAttrList;
	attrblk.ab_attrbufpp = &rovingAttributesBuffer;
	attrblk.ab_varbufpp = &rovingVariableBuffer;
	attrblk.ab_flags = 0;
	attrblk.ab_blocksize = 0;

	hfs_packattrblk(&attrblk, hfsmp, NULL, &c_desc, &c_attr, &datafork, &rsrcfork, current_proc());

	packedBufferSize = (char*)rovingVariableBuffer - (char*)attributesBuffer;

	if ( packedBufferSize > uio_resid(a_uio) )
		return( errSearchBufferFull );

   	(* nummatches)++;
	
	*((u_long *)attributesBuffer) = packedBufferSize;	/* Store length of fixed + var block */
	
	err = uiomove( (caddr_t)attributesBuffer, packedBufferSize, a_uio );	/* XXX should be packedBufferSize */
exit:
	cat_releasedesc(&c_desc);
	
	return( err );
}


static int
UnpackSearchAttributeBlock( struct hfsmount *hfsmp, struct attrlist	*alist, searchinfospec_t *searchInfo, void *attributeBuffer )
{
	attrgroup_t		a;
	u_long			bufferSize;
	boolean_t       is_64_bit;

    DBG_ASSERT(searchInfo != NULL);
    
    is_64_bit = proc_is64bit(current_proc());

    bufferSize = *((uint32_t *)attributeBuffer);
	if (bufferSize == 0)
		return (EINVAL);	/* XXX -DJB is a buffer size of zero ever valid for searchfs? */

    ++((uint32_t *)attributeBuffer);	/* advance past the size */
	
	/* 
	 * UnPack common attributes
	 */
	a = alist->commonattr;
	if ( a != 0 ) {
		if ( a & ATTR_CMN_NAME ) {
			char *s;
			u_int32_t len;

            s = (char*) attributeBuffer + ((attrreference_t *) attributeBuffer)->attr_dataoffset;
            len = ((attrreference_t *) attributeBuffer)->attr_length;

			if (len > sizeof(searchInfo->name))
				return (EINVAL);

			if (hfsmp->hfs_flags & HFS_STANDARD) {
				/* Convert name to pascal string to match HFS B-Tree names */

				if (len > 0) {
					if (utf8_to_hfs(HFSTOVCB(hfsmp), len-1, s, (u_char*)searchInfo->name) != 0)
						return (EINVAL);

					searchInfo->nameLength = searchInfo->name[0];
				} else {
					searchInfo->name[0] = searchInfo->nameLength = 0;
				}
                ++((attrreference_t *)attributeBuffer);
			} else {
				size_t ucslen;
				/* Convert name to Unicode to match HFS Plus B-Tree names */

				if (len > 0) {
					if (utf8_decodestr(s, len-1, (UniChar*)searchInfo->name, &ucslen,
					    sizeof(searchInfo->name), ':', UTF_DECOMPOSED))
						return (EINVAL);

					searchInfo->nameLength = ucslen / sizeof(UniChar);
				} else {
					searchInfo->nameLength = 0;
				}
                ++((attrreference_t *)attributeBuffer);
			}
		}
		if ( a & ATTR_CMN_OBJID ) {
			searchInfo->nodeID = ((fsobj_id_t *) attributeBuffer)->fid_objno;	/* ignore fid_generation */
			++((fsobj_id_t *)attributeBuffer);
		}
		if ( a & ATTR_CMN_PAROBJID ) {
			searchInfo->parentDirID = ((fsobj_id_t *) attributeBuffer)->fid_objno;	/* ignore fid_generation */
			++((fsobj_id_t *)attributeBuffer);
		}
		if ( a & ATTR_CMN_CRTIME ) {
            if (is_64_bit) {
                struct user_timespec tmp;
                tmp = *((struct user_timespec *)attributeBuffer);
                searchInfo->creationDate.tv_sec = (time_t)tmp.tv_sec;
                searchInfo->creationDate.tv_nsec = tmp.tv_nsec;
                ++((struct user_timespec *)attributeBuffer);
            }
            else {
                searchInfo->creationDate = *((struct timespec *)attributeBuffer);
                ++((struct timespec *)attributeBuffer);
            }
		}
		if ( a & ATTR_CMN_MODTIME ) {
            if (is_64_bit) {
                struct user_timespec tmp;
                tmp = *((struct user_timespec *)attributeBuffer);
                searchInfo->modificationDate.tv_sec = (time_t)tmp.tv_sec;
                searchInfo->modificationDate.tv_nsec = tmp.tv_nsec;
                ++((struct user_timespec *)attributeBuffer);
            }
            else {
                searchInfo->modificationDate = *((struct timespec *)attributeBuffer);
                ++((struct timespec *)attributeBuffer);
            }
		}
		if ( a & ATTR_CMN_CHGTIME ) {
            if (is_64_bit) {
                struct user_timespec tmp;
                tmp = *((struct user_timespec *)attributeBuffer);
                searchInfo->changeDate.tv_sec = (time_t)tmp.tv_sec;
                searchInfo->changeDate.tv_nsec = tmp.tv_nsec;
                ++((struct user_timespec *)attributeBuffer);
            }
            else {
                searchInfo->changeDate = *((struct timespec *)attributeBuffer);
                ++((struct timespec *)attributeBuffer);
            }
		}
		if ( a & ATTR_CMN_ACCTIME ) {
            if (is_64_bit) {
                struct user_timespec tmp;
                tmp = *((struct user_timespec *)attributeBuffer);
                searchInfo->accessDate.tv_sec = (time_t)tmp.tv_sec;
                searchInfo->accessDate.tv_nsec = tmp.tv_nsec;
                ++((struct user_timespec *)attributeBuffer);
            }
            else {
                searchInfo->accessDate = *((struct timespec *)attributeBuffer);
                ++((struct timespec *)attributeBuffer);
            }
		}
		if ( a & ATTR_CMN_BKUPTIME ) {
            if (is_64_bit) {
                struct user_timespec tmp;
                tmp = *((struct user_timespec *)attributeBuffer);
                searchInfo->lastBackupDate.tv_sec = (time_t)tmp.tv_sec;
                searchInfo->lastBackupDate.tv_nsec = tmp.tv_nsec;
                ++((struct user_timespec *)attributeBuffer);
            }
            else {
                searchInfo->lastBackupDate = *((struct timespec *)attributeBuffer);
                ++((struct timespec *)attributeBuffer);
            }
		}
		if ( a & ATTR_CMN_FNDRINFO ) {
			bcopy( attributeBuffer, searchInfo->finderInfo, sizeof(searchInfo->finderInfo) );
			(uint8_t *)attributeBuffer += 32;
		}
		if ( a & ATTR_CMN_OWNERID ) {
			searchInfo->uid = *((uid_t *)attributeBuffer);
			++((uid_t *)attributeBuffer);
		}
		if ( a & ATTR_CMN_GRPID ) {
			searchInfo->gid = *((gid_t *)attributeBuffer);
			++((gid_t *)attributeBuffer);
		}
		if ( a & ATTR_CMN_ACCESSMASK ) {
			searchInfo->mask = *((mode_t *)attributeBuffer);
			++((mode_t *)attributeBuffer);
		}
	}

	a = alist->dirattr;
	if ( a != 0 ) {
		if ( a & ATTR_DIR_ENTRYCOUNT ) {
			searchInfo->d.numFiles = *((u_int32_t *)attributeBuffer);
			++((u_int32_t *)attributeBuffer);
		}
	}

	a = alist->fileattr;
	if ( a != 0 ) {
		if ( a & ATTR_FILE_DATALENGTH ) {
			searchInfo->f.dataLogicalLength = *((off_t *)attributeBuffer);
			++((off_t *)attributeBuffer);
		}
		if ( a & ATTR_FILE_DATAALLOCSIZE ) {
			searchInfo->f.dataPhysicalLength = *((off_t *)attributeBuffer);
			++((off_t *)attributeBuffer);
		}
		if ( a & ATTR_FILE_RSRCLENGTH ) {
			searchInfo->f.resourceLogicalLength = *((off_t *)attributeBuffer);
			++((off_t *)attributeBuffer);
		}
		if ( a & ATTR_FILE_RSRCALLOCSIZE ) {
			searchInfo->f.resourcePhysicalLength = *((off_t *)attributeBuffer);
			++((off_t *)attributeBuffer);
		}
	}

	return (0);
}


#if 1 // Installer workaround (2940423)
/* this routine was added as part of the work around where some installers would fail */
/* because they incorrectly assumed search results were in some kind of order.  */
/* This routine is used to indentify the problematic target.  At this point we */
/* only know of one.  This routine could be modified for more (I hope not). */
static Boolean IsTargetName( searchinfospec_t * searchInfoPtr, Boolean isHFSPlus )
{
	if ( searchInfoPtr->name == NULL )
		return( false );
		
	if (isHFSPlus) {
		HFSUniStr255 myName = {
			7, 	/* number of unicode characters */
			{
				'L','i','b','r','a','r','y'
			}
		};		
		if ( FastUnicodeCompare( myName.unicode, myName.length,
								 (UniChar*)searchInfoPtr->name,
								 searchInfoPtr->nameLength ) == 0 )  {
			return( true );
		}
						  
	} else {
		u_char		myName[32] = {
			0x07,'L','i','b','r','a','r','y'
		};
		if ( FastRelString(myName, (u_char*)searchInfoPtr->name) == 0 )  {
			return( true );
		}
	}
	return( false );
	
} /* IsTargetName */
#endif // Installer workaround

