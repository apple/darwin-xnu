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
/*	@(#)hfs_search.c
 *
 *	(c) 1997-2000	Apple Computer, Inc.  All Rights Reserved
 *	
 *
 *	MODIFICATION HISTORY:
 *      04-May-1999	Don Brady		Split off from hfs_vnodeops.c.
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
#include "hfscommon/headers/FileMgrInternal.h"
#include "hfscommon/headers/CatalogPrivate.h"
#include "hfscommon/headers/HFSUnicodeWrappers.h"


/* Private description used in hfs_search */
/*
 * ============ W A R N I N G ! ============
 * DO NOT INCREASE THE SIZE OF THIS STRUCT!
 * It must match the size of the opaque
 * searchstate struct (in sys/attr.h).
 */
struct SearchState {
	long		searchBits;
	BTreeIterator	btreeIterator;
};
typedef struct SearchState SearchState;


static int UnpackSearchAttributeBlock(struct vnode *vp, struct attrlist	*alist, searchinfospec_t *searchInfo, void *attributeBuffer);

Boolean CheckCriteria(ExtendedVCB *vcb, const SearchState *searchState,
			u_long searchBits, struct attrlist *attrList,
			CatalogNodeData *cnp, CatalogKey *key,
			searchinfospec_t *searchInfo1, searchinfospec_t *searchInfo2);

static int CheckAccess(CatalogNodeData *cnp, CatalogKey *key, struct proc *p);

static int InsertMatch(struct vnode *vp, struct uio *a_uio, CatalogNodeData *cnp,
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



/************************************************************************/
/*	Entry for searchfs() 		  										*/
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
	CatalogNodeData		cnode;
	BTreeKey			*key;
	FSBufferDescriptor	btRecord;
	FCB*				catalogFCB;
	SearchState			*searchState;
	searchinfospec_t	searchInfo1;
	searchinfospec_t	searchInfo2;
	void				*attributesBuffer;
	void				*variableBuffer;
	short				recordSize;
	short				operation;
	u_long				fixedBlockSize;
	u_long				eachReturnBufferSize;
	struct proc			*p = current_proc();
	u_long				nodesToCheck = 30;	/* After we search 30 nodes we must give up time */
	u_long				lastNodeNum = 0XFFFFFFFF;
	ExtendedVCB			*vcb = VTOVCB(ap->a_vp);
	int					err = E_NONE;
	int					isHFSPlus;

	/* XXX Parameter check a_searchattrs? */

	*(ap->a_nummatches) = 0;

	if ( ap->a_options & ~SRCHFS_VALIDOPTIONSMASK )
		return( EINVAL );

	if (ap->a_uio->uio_resid <= 0)
		return (EINVAL);

	isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);
	searchState = (SearchState *)ap->a_searchstate;

	/*
	 * Check if this is the first time we are being called.
	 * If it is, allocate SearchState and we'll move it to the users space on exit
	 */
	if ( ap->a_options & SRCHFS_START ) {
		bzero( (caddr_t)searchState, sizeof(SearchState) );
		operation = kBTreeFirstRecord;
		ap->a_options &= ~SRCHFS_START;
	} else {
		operation = kBTreeCurrentRecord;
	}

	/* UnPack the search boundries, searchInfo1, searchInfo2 */
	err = UnpackSearchAttributeBlock( ap->a_vp, ap->a_searchattrs, &searchInfo1, ap->a_searchparams1 );
	if (err) return err;
	err = UnpackSearchAttributeBlock( ap->a_vp, ap->a_searchattrs, &searchInfo2, ap->a_searchparams2 );
	if (err) return err;

	btRecord.itemCount = 1;
	if (isHFSPlus) {
		btRecord.itemSize = sizeof(cnode);
		btRecord.bufferAddress = &cnode;
	} else {
		btRecord.itemSize = sizeof(HFSCatalogFile);
		btRecord.bufferAddress = &cnode.cnd_extra;
	}
	catalogFCB = VTOFCB( vcb->catalogRefNum );
	key = (BTreeKey*) &(searchState->btreeIterator.key);
	fixedBlockSize = sizeof(u_long) + AttributeBlockSize( ap->a_returnattrs );	/* u_long for length longword */
	eachReturnBufferSize = fixedBlockSize;
	
	if ( ap->a_returnattrs->commonattr & ATTR_CMN_NAME )	/* XXX should be more robust! */
		eachReturnBufferSize += kHFSPlusMaxFileNameBytes + 1;

	MALLOC( attributesBuffer, void *, eachReturnBufferSize, M_TEMP, M_WAITOK );
	variableBuffer = (void*)((char*) attributesBuffer + fixedBlockSize);

	/* Lock catalog b-tree */
	err = hfs_metafilelocking( VTOHFS(ap->a_vp), kHFSCatalogFileID, LK_SHARED, p );
	if ( err != E_NONE ) {
		goto ExitThisRoutine;
	};

	/*
	 * Iterate over all the catalog btree records
	 */
	
	err = BTIterateRecord( catalogFCB, operation, &(searchState->btreeIterator), &btRecord, &recordSize );

	while( err == E_NONE ) {
		if (!isHFSPlus)
			CopyCatalogNodeData(vcb, (CatalogRecord*)&cnode.cnd_extra, &cnode);
	
		if ( CheckCriteria( vcb, searchState, ap->a_options, ap->a_searchattrs, &cnode,
							(CatalogKey *)key, &searchInfo1, &searchInfo2 ) &&
			 CheckAccess(&cnode, (CatalogKey *)key, ap->a_uio->uio_procp)) {
			err = InsertMatch(ap->a_vp, ap->a_uio, &cnode, (CatalogKey *)key,
					  ap->a_returnattrs, attributesBuffer, variableBuffer,
					  eachReturnBufferSize, ap->a_nummatches);
			if ( err != E_NONE )
				break;
		}

		err = BTIterateRecord( catalogFCB, kBTreeNextRecord, &(searchState->btreeIterator), &btRecord, &recordSize );
		
			if  ( *(ap->a_nummatches) >= ap->a_maxmatches )
				break;

  		if ( searchState->btreeIterator.hint.nodeNum != lastNodeNum ) {
			lastNodeNum = searchState->btreeIterator.hint.nodeNum;
			if ( --nodesToCheck == 0 )
				break;	/* We must leave the kernel to give up time */
		}
	}

	/* Unlock catalog b-tree */
	(void) hfs_metafilelocking( VTOHFS(ap->a_vp), kHFSCatalogFileID, LK_RELEASE, p );


	if ( err == E_NONE ) {
		err = EAGAIN;	/* signal to the user to call searchfs again */
	} else if ( err == errSearchBufferFull ) {
		if ( *(ap->a_nummatches) > 0 )
			err = EAGAIN;
 		else
			err = ENOBUFS;
	} else if ( err == btNotFound ) {
		err = E_NONE;	/* the entire disk has been searched */
	}

ExitThisRoutine:
        FREE( attributesBuffer, M_TEMP );

	return( err );
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
CheckAccess(CatalogNodeData *cnp, CatalogKey *key, struct proc *p)
{
	return (1);
}

Boolean
CheckCriteria( ExtendedVCB *vcb, const SearchState *searchState, u_long searchBits,
		struct attrlist *attrList, CatalogNodeData *cnp, CatalogKey *key,
		searchinfospec_t  *searchInfo1, searchinfospec_t *searchInfo2 )
{
	Boolean matched, atleastone;
	Boolean isHFSPlus;
	attrgroup_t searchAttributes;
	
	isHFSPlus = (vcb->vcbSigWord == kHFSPlusSigWord);

	switch (cnp->cnd_type) {
	case kCatalogFolderNode:
		if ( (searchBits & SRCHFS_MATCHDIRS) == 0 ) {	/* If we are NOT searching folders */
			matched = false;
			goto TestDone;
		}
		break;
			
	case kCatalogFileNode:
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
		
		if ( matched == false || (searchBits & ~SRCHFS_MATCHPARTIALNAMES) == 0 )
			goto TestDone;	/* no match, or nothing more to compare */

		atleastone = true;
	}
	
	/* Now that we have a record worth searching, see if it matches the search attributes */
	if (cnp->cnd_type == kCatalogFileNode) {
		if ((attrList->dirattr & ~ATTR_FILE_VALIDMASK) != 0) {	/* attr we do know about  */
			matched = false;
			goto TestDone;
		}
		else if ((attrList->dirattr & ATTR_FILE_VALIDMASK) != 0) {
		searchAttributes = attrList->fileattr;
	
		/* File logical length (data fork) */
		if ( searchAttributes & ATTR_FILE_DATALENGTH ) {
			matched = CompareWideRange(
			    cnp->cnd_datafork.logicalSize,
			    searchInfo1->f.dataLogicalLength,
			    searchInfo2->f.dataLogicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
		}
	
		/* File physical length (data fork) */
		if ( searchAttributes & ATTR_FILE_DATAALLOCSIZE ) {
			matched = CompareWideRange(
			    cnp->cnd_datafork.totalBlocks * vcb->blockSize,
			    searchInfo1->f.dataPhysicalLength,
			    searchInfo2->f.dataPhysicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
		}

		/* File logical length (resource fork) */
		if ( searchAttributes & ATTR_FILE_RSRCLENGTH ) {
			matched = CompareWideRange(
			    cnp->cnd_rsrcfork.logicalSize,
			    searchInfo1->f.resourceLogicalLength,
			    searchInfo2->f.resourceLogicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
		}
		
		/* File physical length (resource fork) */
		if ( searchAttributes & ATTR_FILE_RSRCALLOCSIZE ) {
			matched = CompareWideRange(
			    cnp->cnd_rsrcfork.totalBlocks * vcb->blockSize,
			    searchInfo1->f.resourcePhysicalLength,
			    searchInfo2->f.resourcePhysicalLength);
			if (matched == false) goto TestDone;
				atleastone = true;
			}
		}
		else {
			atleastone = true;		/* to match SRCHFS_MATCHDIRS */
		}
	}
	/*
	 * Check the directory attributes
	 */
	else if (cnp->cnd_type == kCatalogFolderNode) {
		if ((attrList->dirattr & ~ATTR_DIR_VALIDMASK) != 0) {	/* attr we do know about  */
			matched = false;
			goto TestDone;
		}
		else if ((attrList->dirattr & ATTR_DIR_VALIDMASK) != 0) {
		searchAttributes = attrList->dirattr;
		
		/* Directory valence */
		if ( searchAttributes & ATTR_DIR_ENTRYCOUNT ) {
			matched = CompareRange(cnp->cnd_valence, searchInfo1->d.numFiles, searchInfo2->d.numFiles );
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
			matched = CompareRange( cnp->cnd_nodeID, searchInfo1->nodeID, searchInfo2->nodeID );
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
				
			matched = CompareRange( parentID, searchInfo1->parentDirID, searchInfo2->parentDirID );
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Finder Info & Extended Finder Info where extFinderInfo is last 32 bytes */
		if ( searchAttributes & ATTR_CMN_FNDRINFO ) {
			UInt32 *thisValue;
			thisValue = (UInt32 *) &cnp->cnd_finderInfo;

			/* 
			 * Note: ioFlFndrInfo and ioDrUsrWds have the same offset in search info, so
			 * no need to test the object type here.
			 */
			matched = CompareMasked( thisValue, (UInt32 *) &searchInfo1->finderInfo,
				(UInt32 *) &searchInfo2->finderInfo, 8 ); /* 8 * UInt32 */
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Create date */
		if ( searchAttributes & ATTR_CMN_CRTIME ) {
			matched = CompareRange(to_bsd_time(cnp->cnd_createDate),
			    searchInfo1->creationDate.tv_sec,  searchInfo2->creationDate.tv_sec );
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* Mod date */
		if ( searchAttributes & ATTR_CMN_MODTIME ) {
			matched = CompareRange(to_bsd_time(cnp->cnd_contentModDate),
			    searchInfo1->modificationDate.tv_sec, searchInfo2->modificationDate.tv_sec );
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* Change Time */
		if ( searchAttributes & ATTR_CMN_CHGTIME ) {
			matched = CompareRange(to_bsd_time(cnp->cnd_attributeModDate),
			    searchInfo1->changeDate.tv_sec, searchInfo2->changeDate.tv_sec );
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* Backup date */
		if ( searchAttributes & ATTR_CMN_BKUPTIME ) {
			matched = CompareRange(to_bsd_time(cnp->cnd_backupDate),
			    searchInfo1->lastBackupDate.tv_sec, searchInfo2->lastBackupDate.tv_sec );
			if (matched == false) goto TestDone;
			atleastone = true;
		}
	
		/* User ID */
		if ( searchAttributes & ATTR_CMN_OWNERID ) {
			matched = CompareRange( cnp->cnd_ownerID, searchInfo1->uid, searchInfo2->uid );
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* Group ID */
		if ( searchAttributes & ATTR_CMN_GRPID ) {
			matched = CompareRange( cnp->cnd_groupID, searchInfo1->gid, searchInfo2->gid );
			if (matched == false) goto TestDone;
			atleastone = true;
		}

		/* mode */
		if ( searchAttributes & ATTR_CMN_ACCESSMASK ) {
			matched = CompareRange( (u_long)cnp->cnd_mode, 
				(u_long)searchInfo1->mask, (u_long)searchInfo2->mask );
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
InsertMatch( struct vnode *root_vp, struct uio *a_uio, CatalogNodeData *cnp,
		CatalogKey *key, struct attrlist *returnAttrList, void *attributesBuffer,
		void *variableBuffer, u_long bufferSize, u_long * nummatches )
{
	int err;
	void *rovingAttributesBuffer;
	void *rovingVariableBuffer;
	struct hfsCatalogInfo catalogInfo;
	u_long packedBufferSize;
	ExtendedVCB *vcb = VTOVCB(root_vp);
	Boolean isHFSPlus = vcb->vcbSigWord == kHFSPlusSigWord;
	u_long privateDir = VTOHFS(root_vp)->hfs_private_metadata_dir;

	rovingAttributesBuffer = (char*)attributesBuffer + sizeof(u_long); /* Reserve space for length field */
	rovingVariableBuffer = variableBuffer;
	
	INIT_CATALOGDATA(&catalogInfo.nodeData, 0);

	/* The packing call below expects a struct hfsCatalogInfo */
	bcopy(cnp, &catalogInfo.nodeData, (cnp->cnd_type == kCatalogFileNode) ?
	      sizeof(HFSPlusCatalogFile) : sizeof(HFSPlusCatalogFolder));

	catalogInfo.nodeData.cnm_parID = isHFSPlus ? key->hfsPlus.parentID : key->hfs.parentID;

	/* hide open files that have been deleted */
	if ((privateDir != 0) && (catalogInfo.nodeData.cnm_parID == privateDir))
		return (0);

	/* hide our private meta data directory */
	if ((privateDir != 0) && (catalogInfo.nodeData.cnd_nodeID == privateDir))
		return (0);

	if ( returnAttrList->commonattr & ATTR_CMN_NAME ) {
		size_t utf8len = 0;

		catalogInfo.nodeData.cnm_nameptr = catalogInfo.nodeData.cnm_namespace;

		/* Return result in UTF-8 */
		if ( isHFSPlus ) {
			err = utf8_encodestr(key->hfsPlus.nodeName.unicode,
					key->hfsPlus.nodeName.length * sizeof(UniChar),
					catalogInfo.nodeData.cnm_namespace,
					&utf8len,
					MAXHFSVNODELEN + 1, ':', 0);
			if (err == ENAMETOOLONG) {
				utf8len = utf8_encodelen(key->hfsPlus.nodeName.unicode,
						key->hfsPlus.nodeName.length * sizeof(UniChar), ':', 0);
				MALLOC(catalogInfo.nodeData.cnm_nameptr, char *, utf8len+1, M_TEMP, M_WAITOK);
				catalogInfo.nodeData.cnm_flags |= kCatNameIsAllocated;
				err = utf8_encodestr(key->hfsPlus.nodeName.unicode,
						key->hfsPlus.nodeName.length * sizeof(UniChar),
						catalogInfo.nodeData.cnm_nameptr,
						&utf8len,
						utf8len + 1, ':', 0);
			}
		 } else {
			err = hfs_to_utf8(vcb, 
					key->hfs.nodeName,
					MAXHFSVNODELEN + 1,
					(ByteCount*) &utf8len, 
					catalogInfo.nodeData.cnm_namespace);
			if (err == ENAMETOOLONG) {
				MALLOC(catalogInfo.nodeData.cnm_nameptr, char *, utf8len+1, M_TEMP, M_WAITOK);
				catalogInfo.nodeData.cnm_flags |= kCatNameIsAllocated;
				err = hfs_to_utf8(vcb, 
						key->hfs.nodeName, 
						utf8len + 1, 
						(ByteCount*) &utf8len, 
						catalogInfo.nodeData.cnm_nameptr);
			} else if (err) {
				/*
				 * When an HFS name cannot be encoded with the current
				 * volume encoding we use MacRoman as a fallback.
				 */
				err = mac_roman_to_utf8(key->hfs.nodeName, MAXHFSVNODELEN + 1,
				                        (ByteCount*) &utf8len,
				                         catalogInfo.nodeData.cnm_namespace);
			}
		}
		catalogInfo.nodeData.cnm_length = utf8len;
		if (err && (catalogInfo.nodeData.cnm_flags & kCatNameIsAllocated))
		{
			DisposePtr(catalogInfo.nodeData.cnm_nameptr);
			catalogInfo.nodeData.cnm_flags &= ~kCatNameIsAllocated;
                        catalogInfo.nodeData.cnm_nameptr = catalogInfo.nodeData.cnm_namespace;
                        catalogInfo.nodeData.cnm_namespace[0] = 0;
		}
	}

	PackCatalogInfoAttributeBlock( returnAttrList,root_vp, &catalogInfo, &rovingAttributesBuffer, &rovingVariableBuffer );

	CLEAN_CATALOGDATA(&catalogInfo.nodeData);

	packedBufferSize = (char*)rovingVariableBuffer - (char*)attributesBuffer;

	if ( packedBufferSize > a_uio->uio_resid )
		return( errSearchBufferFull );

   	(* nummatches)++;
	
	*((u_long *)attributesBuffer) = packedBufferSize;	/* Store length of fixed + var block */
	
	err = uiomove( (caddr_t)attributesBuffer, packedBufferSize, a_uio );	/* XXX should be packedBufferSize */
	
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


