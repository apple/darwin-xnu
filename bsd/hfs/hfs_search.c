/*
 * Copyright (c) 1997-2002 Apple Computer, Inc. All rights reserved.
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
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/conf.h>
#include <mach/machine/vm_types.h>
#include <sys/vnode.h>
#include <sys/malloc.h>
#include <sys/signalvar.h>
#include <sys/attr.h>
#include <sys/utfconv.h>

#include "hfs.h"
#include "hfs_dbg.h"
#include "hfs_catalog.h"
#include "hfs_attrlist.h"
#include "hfs_endian.h"

#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/CatalogPrivate.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"
#include "hfscommon/headers/BTreesPrivate.h"
#include "hfscommon/headers/BTreeScanner.h"


/* Search criterea. */
struct directoryInfoSpec
{
	u_long		numFiles;
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
	u_long			finderInfo[8];
	uid_t			uid;	
	gid_t			gid;
	mode_t			mask;
	struct fileInfoSpec	f;
	struct directoryInfoSpec d;
};
typedef struct searchinfospec searchinfospec_t;

static void ResolveHardlink(ExtendedVCB *vcb, HFSPlusCatalogFile *recp);


static int UnpackSearchAttributeBlock(struct vnode *vp, struct attrlist	*alist,
		searchinfospec_t *searchInfo, void *attributeBuffer);

static int CheckCriteria(	ExtendedVCB *vcb, 
							u_long searchBits,
							struct attrlist *attrList, 
							CatalogRecord *rec,
							CatalogKey *key, 
							searchinfospec_t *searchInfo1,
							searchinfospec_t *searchInfo2,
							Boolean lookForDup );

static int CheckAccess(ExtendedVCB *vcb, CatalogKey *key, struct proc *p);

static int InsertMatch(struct vnode *vp, struct uio *a_uio, CatalogRecord *rec,
			CatalogKey *key, struct attrlist *returnAttrList,
			void *attributesBuffer, void *variableBuffer,
			u_long bufferSize, u_long * nummatches );

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

extern int cat_convertkey(
			struct hfsmount *hfsmp,
			CatalogKey *key,
			CatalogRecord * recp,
			struct cat_desc *descp);

extern void cat_convertattr(
			struct hfsmount *hfsmp,
			CatalogRecord * recp,
			struct cat_attr *attrp,
			struct cat_fork *datafp,
			struct cat_fork *rsrcfp);

extern int resolvelink(struct hfsmount *hfsmp, u_long linkref,
			struct HFSPlusCatalogFile *recp);

/************************************************************************/
/* Entry for searchfs()                                                 */
/************************************************************************/

#define	errSearchBufferFull	101	/* Internal search errors */
/*
#
#% searchfs	vp	L L L
#
vop_searchfs {
    IN struct vnode *vp;
    IN off_t length;
    IN int flags;
    IN struct ucred *cred;
    IN struct proc *p;
};
*/

int
hfs_search( ap )
	struct vop_searchfs_args *ap; /*
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
	*/
{
	ExtendedVCB *vcb = VTOVCB(ap->a_vp);
	FCB * catalogFCB;
	searchinfospec_t searchInfo1;
	searchinfospec_t searchInfo2;
	void *attributesBuffer;
	void *variableBuffer;
	u_long fixedBlockSize;
	u_long eachReturnBufferSize;
	struct proc *p = current_proc();
	int err = E_NONE;
	int isHFSPlus;
	int timerExpired = false;
	int doQuickExit = false;
	CatalogKey * myCurrentKeyPtr;
	CatalogRecord * myCurrentDataPtr;
	CatPosition * myCatPositionPtr;
	BTScanState myBTScanState;
	void *user_start = NULL;
	int   user_len;

	/* XXX Parameter check a_searchattrs? */

	*(ap->a_nummatches) = 0;

	if (ap->a_options & ~SRCHFS_VALIDOPTIONSMASK)
		return (EINVAL);

	if (ap->a_uio->uio_resid <= 0)
		return (EINVAL);

	isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);

	/* UnPack the search boundries, searchInfo1, searchInfo2 */
	err = UnpackSearchAttributeBlock(ap->a_vp, ap->a_searchattrs,
				&searchInfo1, ap->a_searchparams1);
	if (err) return err;
	err = UnpackSearchAttributeBlock(ap->a_vp, ap->a_searchattrs,
				&searchInfo2, ap->a_searchparams2);
	if (err) return err;

	fixedBlockSize = sizeof(u_long) + hfs_attrblksize(ap->a_returnattrs);	/* u_long for length longword */
	eachReturnBufferSize = fixedBlockSize;

	if ( ap->a_returnattrs->commonattr & ATTR_CMN_NAME )	/* XXX should be more robust! */
		eachReturnBufferSize += kHFSPlusMaxFileNameBytes + 1;

	MALLOC( attributesBuffer, void *, eachReturnBufferSize, M_TEMP, M_WAITOK );
	variableBuffer = (void*)((char*) attributesBuffer + fixedBlockSize);

	// XXXdbg - have to lock the user's buffer so we don't fault
	// while holding the shared catalog file lock.  see the comment
	// in hfs_readdir() for more details.
	//
	if (VTOHFS(ap->a_vp)->jnl && ap->a_uio->uio_segflg == UIO_USERSPACE) {
		user_start = ap->a_uio->uio_iov->iov_base;
		user_len   = ap->a_uio->uio_iov->iov_len;

		if ((err = vslock(user_start, user_len)) != 0) {
			user_start = NULL;
			goto ExitThisRoutine;
		}
	}

	/* Lock catalog b-tree */
	err = hfs_metafilelocking(VTOHFS(ap->a_vp), kHFSCatalogFileID, LK_SHARED, p);
	if (err)
		goto ExitThisRoutine;

	catalogFCB = GetFileControlBlock(vcb->catalogRefNum);
	myCurrentKeyPtr = NULL;
	myCurrentDataPtr = NULL;
	myCatPositionPtr = (CatPosition *)ap->a_searchstate;

	if (ap->a_options & SRCHFS_START) {
		/* Starting a new search. */
		/* Make sure the on-disk Catalog file is current */
		(void) VOP_FSYNC(vcb->catalogRefNum, NOCRED, MNT_WAIT, p);
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
				if (CheckCriteria(vcb, ap->a_options, ap->a_searchattrs, &rec,
								  keyp, &searchInfo1, &searchInfo2, false) &&
					CheckAccess(vcb, keyp, ap->a_uio->uio_procp)) {
		
					result = InsertMatch(ap->a_vp, ap->a_uio, &rec, 
									  keyp, ap->a_returnattrs,
									  attributesBuffer, variableBuffer,
									  eachReturnBufferSize, ap->a_nummatches);
					if (result == E_NONE && *(ap->a_nummatches) >= ap->a_maxmatches)
						doQuickExit = true;
				}
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

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking(VTOHFS(ap->a_vp), kHFSCatalogFileID, LK_RELEASE, p);
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
		if (isHFSPlus)
			ResolveHardlink(vcb, (HFSPlusCatalogFile *) myCurrentDataPtr);

		if (CheckCriteria( vcb, ap->a_options, ap->a_searchattrs, myCurrentDataPtr,
				myCurrentKeyPtr, &searchInfo1, &searchInfo2, true )
		&&  CheckAccess(vcb, myCurrentKeyPtr, ap->a_uio->uio_procp)) {
			err = InsertMatch(ap->a_vp, ap->a_uio, myCurrentDataPtr, 
					myCurrentKeyPtr, ap->a_returnattrs,
					attributesBuffer, variableBuffer,
					eachReturnBufferSize, ap->a_nummatches);
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
		myCurrentTime = time;
		timersub(&myCurrentTime, &myBTScanState.startTime, &myElapsedTime);
		/* Note: assumes kMaxMicroSecsInKernel is less than 1,000,000 */
		if (myElapsedTime.tv_sec > 0
		||  myElapsedTime.tv_usec >= kMaxMicroSecsInKernel) {
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

	if (VTOHFS(ap->a_vp)->jnl && user_start) {
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
		(void) resolvelink(VCBTOHFS(vcb), recp->bsdInfo.special.iNodeNum, recp);
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


/*
 * Check to see if caller has access rights to this item
 */

static int
CheckAccess(ExtendedVCB *theVCBPtr, CatalogKey *theKeyPtr, struct proc *theProcPtr)
{
	Boolean			isHFSPlus;
	int			myErr;
	int			myResult; 	
	HFSCatalogNodeID 	myNodeID;
	unsigned long		myPerms;
	hfsmount_t *		my_hfsmountPtr;
	struct cat_desc 	my_cat_desc;
	struct cat_attr 	my_cat_attr;
	
	myResult = 0;	/* default to "no access" */
	my_cat_desc.cd_nameptr = NULL;
	my_cat_desc.cd_namelen = 0;
		
	if ( theProcPtr->p_ucred->cr_uid == 0 ) {
		myResult = 1;	/* allow access */
		goto ExitThisRoutine; /* root always has access */
	}

	my_hfsmountPtr = VCBTOHFS( theVCBPtr );
	isHFSPlus = ( theVCBPtr->vcbSigWord == kHFSPlusSigWord );
	if ( isHFSPlus )
		myNodeID = theKeyPtr->hfsPlus.parentID;
	else
		myNodeID = theKeyPtr->hfs.parentID;
	
	while ( myNodeID >= kRootDirID ) {
		/* now go get catalog data for this directory */
		myErr = hfs_metafilelocking( my_hfsmountPtr, kHFSCatalogFileID, LK_SHARED, theProcPtr );
		if ( myErr )
			goto ExitThisRoutine;	/* no access */
	
		myErr = cat_idlookup( my_hfsmountPtr, myNodeID, &my_cat_desc, &my_cat_attr, NULL );
		(void) hfs_metafilelocking( my_hfsmountPtr, kHFSCatalogFileID, LK_RELEASE, theProcPtr );
		if ( myErr )
			goto ExitThisRoutine;	/* no access */

		myNodeID = my_cat_desc.cd_parentcnid;	/* move up the hierarchy */
		myPerms = DerivePermissionSummary(my_cat_attr.ca_uid, my_cat_attr.ca_gid, 
						my_cat_attr.ca_mode, my_hfsmountPtr->hfs_mp,
						theProcPtr->p_ucred, theProcPtr  );
		cat_releasedesc( &my_cat_desc );
		
		if ( (myPerms & X_OK) == 0 )
			goto ExitThisRoutine;	/* no access */
	}
	
	myResult = 1;	/* allow access */

ExitThisRoutine:
	cat_releasedesc( &my_cat_desc );
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
	struct cat_attr c_attr = {0};
	struct cat_fork datafork;
	struct cat_fork rsrcfork;
	
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
	case kHFSPlusFileRecord:
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
			matched = CompareRange((u_long)c_attr.ca_mode, 
					(u_long)searchInfo1->mask,
					(u_long)searchInfo2->mask);
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
InsertMatch( struct vnode *root_vp, struct uio *a_uio, CatalogRecord *rec,
		CatalogKey *key, struct attrlist *returnAttrList, void *attributesBuffer,
		void *variableBuffer, u_long bufferSize, u_long * nummatches )
{
	int err;
	void *rovingAttributesBuffer;
	void *rovingVariableBuffer;
	u_long packedBufferSize;
	ExtendedVCB *vcb = VTOVCB(root_vp);
	Boolean isHFSPlus = vcb->vcbSigWord == kHFSPlusSigWord;
	u_long privateDir = VTOHFS(root_vp)->hfs_private_metadata_dir;
	struct attrblock attrblk;
	struct cat_desc c_desc = {0};
	struct cat_attr c_attr = {0};
	struct cat_fork datafork;
	struct cat_fork rsrcfork;

	rovingAttributesBuffer = (char*)attributesBuffer + sizeof(u_long); /* Reserve space for length field */
	rovingVariableBuffer = variableBuffer;

	/* Convert catalog record into cat_attr format. */
	cat_convertattr(VTOHFS(root_vp), rec, &c_attr, &datafork, &rsrcfork);

	/* hide our private meta data directory */
	if ((privateDir != 0) && (c_attr.ca_fileid == privateDir)) {
		err = 0;
		goto exit;
	}

	/* Hide the private journal files */
	if (VTOHFS(root_vp)->jnl &&
	    ((c_attr.ca_fileid == VTOHFS(root_vp)->hfs_jnlfileid) ||
	     (c_attr.ca_fileid == VTOHFS(root_vp)->hfs_jnlinfoblkid))) {
		err = 0;
		goto exit;
	}

	if (returnAttrList->commonattr & ATTR_CMN_NAME) {
		cat_convertkey(VTOHFS(root_vp), key, rec, &c_desc);
	} else {
		c_desc.cd_cnid = c_attr.ca_fileid;
		if (isHFSPlus)
			c_desc.cd_parentcnid = key->hfsPlus.parentID;
		else
			c_desc.cd_parentcnid = key->hfs.parentID;
	}

	/* hide open files that have been deleted */
	if ((privateDir != 0) && (c_desc.cd_parentcnid == privateDir)) {
		err = 0;
		goto exit;
	}

	attrblk.ab_attrlist = returnAttrList;
	attrblk.ab_attrbufpp = &rovingAttributesBuffer;
	attrblk.ab_varbufpp = &rovingVariableBuffer;
	attrblk.ab_flags = 0;
	attrblk.ab_blocksize = 0;

	hfs_packattrblk(&attrblk, VTOHFS(root_vp), NULL, &c_desc, &c_attr, &datafork, &rsrcfork);

	packedBufferSize = (char*)rovingVariableBuffer - (char*)attributesBuffer;

	if ( packedBufferSize > a_uio->uio_resid )
		return( errSearchBufferFull );

   	(* nummatches)++;
	
	*((u_long *)attributesBuffer) = packedBufferSize;	/* Store length of fixed + var block */
	
	err = uiomove( (caddr_t)attributesBuffer, packedBufferSize, a_uio );	/* XXX should be packedBufferSize */
exit:
	cat_releasedesc(&c_desc);
	
	return( err );
}


static int
UnpackSearchAttributeBlock( struct vnode *vp, struct attrlist	*alist, searchinfospec_t *searchInfo, void *attributeBuffer )
{
	attrgroup_t		a;
	u_long			bufferSize;

    DBG_ASSERT(searchInfo != NULL);

	bufferSize = *((u_long *)attributeBuffer);
	if (bufferSize == 0)
		return (EINVAL);	/* XXX -DJB is a buffer size of zero ever valid for searchfs? */

	++((u_long *)attributeBuffer);	/* advance past the size */
	
	/* 
	 * UnPack common attributes
	 */
	a = alist->commonattr;
	if ( a != 0 ) {
		if ( a & ATTR_CMN_NAME ) {
			char *s = (char*) attributeBuffer + ((attrreference_t *) attributeBuffer)->attr_dataoffset;
			size_t len = ((attrreference_t *) attributeBuffer)->attr_length;

			if (len > sizeof(searchInfo->name))
				return (EINVAL);

			if (VTOVCB(vp)->vcbSigWord == kHFSPlusSigWord) {
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

			} else {
				/* Convert name to pascal string to match HFS B-Tree names */

				if (len > 0) {
					if (utf8_to_hfs(VTOVCB(vp), len-1, s, (u_char*)searchInfo->name) != 0)
						return (EINVAL);

					searchInfo->nameLength = searchInfo->name[0];
				} else {
					searchInfo->name[0] = searchInfo->nameLength = 0;
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
			searchInfo->creationDate = *((struct timespec *)attributeBuffer);
			++((struct timespec *)attributeBuffer);
		}
		if ( a & ATTR_CMN_MODTIME ) {
			searchInfo->modificationDate = *((struct timespec *)attributeBuffer);
			++((struct timespec *)attributeBuffer);
		}
		if ( a & ATTR_CMN_CHGTIME ) {
			searchInfo->changeDate = *((struct timespec *)attributeBuffer);
			++((struct timespec *)attributeBuffer);
		}
		if ( a & ATTR_CMN_ACCTIME ) {
			searchInfo->accessDate = *((struct timespec *)attributeBuffer);
			++((struct timespec *)attributeBuffer);
		}
		if ( a & ATTR_CMN_BKUPTIME ) {
			searchInfo->lastBackupDate = *((struct timespec *)attributeBuffer);
			++((struct timespec *)attributeBuffer);
		}
		if ( a & ATTR_CMN_FNDRINFO ) {
		   bcopy( attributeBuffer, searchInfo->finderInfo, sizeof(u_long) * 8 );
		   (u_long *)attributeBuffer += 8;
		}
		if ( a & ATTR_CMN_BKUPTIME ) {
			searchInfo->lastBackupDate = *((struct timespec *)attributeBuffer);
			++((struct timespec *)attributeBuffer);
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
			searchInfo->d.numFiles = *((u_long *)attributeBuffer);
			++((u_long *)attributeBuffer);
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

