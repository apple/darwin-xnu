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
/*	@(#)MacOSStubs.c	4.0
*
*	(c) 1997-1999 Apple Computer, Inc.  All Rights Reserved
*
*	MacOSStubs.c -- Contains routines called by MacOS code, that is not defined.
*
*	HISTORY
*	 9-9-99		Don Brady	Don't use MNT_WAIT in C_FlushMDB.
*	 9-Mar-1999	Don Brady		Remove more obsolete routines, add ClearMemory(bzero).
*	20-Nov-1998	Don Brady		Remove UFSToHFSStr and HFSToUFSStr routines (obsolete).
*	31-Aug-1998	Don Brady		Move DST adjustments to GetTimeLocal (radar #2265075).
*	28-Jul-1998	Don Brady		Add GetDiskBlocks routine (radar #2258148).
*	23-Jul-1998	Don Brady		Use bdwrite instead of bwrite for default in RelBlock_glue (radar #2257225).
*	 7-Jul-1998	Don Brady		Remove character mappings from/to hfs (ufs_hfs and hfs_ufs tables).
*	22-Jun-1998	Pat Dirks		Added the vice versa mappings in ufs_hfs and hfs_ufs to more
*								thoroughly interchange ":" and "/" in name strings.
*	 4-Jun-1998	Pat Dirks		Changed to do all B*-Tree writes synchronously (FORCESYNCBTREEWRITES = 1)
*	 4-jun-1998	Don Brady		Use VPUT macro instead of vput.
*	 6-may-1998	Don Brady		Bump h_devvp refcount in GetInitializedVNode (radar #2232480).
*	27-apr-1998	Don Brady		Change printf to kprintf.
*	23-Apr-1998	Pat Dirks		Cleaned up GetBlock_glue to add brelse on I/O errors from bread.
*	23-apr-1998	Don Brady		Add '/' to ':' mapping and vice versa to mapping tables.
*	21-apr-1998	Don Brady		Clean up time/date conversion routines.
*	11-apr-1998	Don Brady		Add RequireFileLock routine.
*	 8-apr-1998	Don Brady		C_FlushMDB now calls hfs_flushvolumeheader and hfs_flushMDB.
*	12-nov-1997	Scott Roberts
*		Initially created file.
*
*/
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <sys/malloc.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/ubc.h>
#include <sys/vm.h>
#include <dev/disk.h>
#include "hfs.h"
#include "hfs_dbg.h"


#include "hfscommon/headers/FileMgrInternal.h"

extern int (**hfs_vnodeop_p)(void *);


/* 
 * gTimeZone should only be used for HFS volumes!
 * It is initialized when an HFS volume is mounted.
 */
struct timezone gTimeZone = {8*60,1};


/*************************************************************************************/

/*************************************************************************************/
/*
 * The following two routines work in tandem: StoreBufferMapping stores
 * successive buffer address -> buffer pointer mappings in a circular
 * match list, advancing the list index forward each time, while LookupBufferMapping
 * looks backwards through the list to look up a particular mapping (which is
 * typically the entry currently pointed to by gBufferAddress).
 *
 */
static void StoreBufferMapping(caddr_t bufferAddress, struct buf *bp)
{
	int i;
	
    DBG_ASSERT(gBufferListIndex >= 0);
    DBG_ASSERT(gBufferListIndex < BUFFERPTRLISTSIZE);

	simple_lock(&gBufferPtrListLock);
	
	/* We've got at most BUFFERPTRLISTSIZE tries at this... */
	for (i = BUFFERPTRLISTSIZE; i > 0; --i) {
		if (gBufferAddress[gBufferListIndex] == NULL) {
			gBufferAddress[gBufferListIndex] = bufferAddress;
			gBufferHeaderPtr[gBufferListIndex] = bp;
			break;
		}
		gBufferListIndex = (gBufferListIndex + 1) % BUFFERPTRLISTSIZE;
	};
	
	if (i == 0) {
		panic("StoreBufferMapping: couldn't find an empty slot in buffer list.");
	};
	
    DBG_ASSERT(gBufferListIndex >= 0);
    DBG_ASSERT(gBufferListIndex < BUFFERPTRLISTSIZE);

    simple_unlock(&gBufferPtrListLock);
}


/*static*/ OSErr LookupBufferMapping(caddr_t bufferAddress, struct buf **bpp, int *mappingIndexPtr)
{
	OSErr err = E_NONE;
	int i;
	int listIndex = gBufferListIndex;
	struct buf *bp = NULL;
	
    DBG_ASSERT(gBufferListIndex >= 0);
    DBG_ASSERT(gBufferListIndex < BUFFERPTRLISTSIZE);

    simple_lock(&gBufferPtrListLock);
	
	/* We've got at most BUFFERPTRLISTSIZE tries at this... */
	for (i = BUFFERPTRLISTSIZE; i > 0; --i) {
		if (gBufferAddress[listIndex] == bufferAddress) {
            *mappingIndexPtr = listIndex;
			bp = gBufferHeaderPtr[listIndex];
			break;
		};
		
		listIndex = (listIndex - 1);
		if (listIndex < 0) {
			listIndex = BUFFERPTRLISTSIZE - 1;
		};
	};
	
	if (bp == NULL) {
		DEBUG_BREAK_MSG(("LookupBufferMapping: couldn't find buffer header for buffer in list.\n"));
		err = -1;
	};
	
    DBG_ASSERT(gBufferListIndex >= 0);
    DBG_ASSERT(gBufferListIndex < BUFFERPTRLISTSIZE);

    simple_unlock(&gBufferPtrListLock);
	
	*bpp = bp;
	return err;
}


static void ReleaseMappingEntry(int entryIndex) {

    DBG_ASSERT(gBufferListIndex >= 0);
    DBG_ASSERT(gBufferListIndex < BUFFERPTRLISTSIZE);

    simple_lock(&gBufferPtrListLock);
    gBufferAddress[entryIndex] = NULL;
    simple_unlock(&gBufferPtrListLock);
};
#if HFS_DIAGNOSTIC
#define DBG_GETBLOCK 0
#else
#define DBG_GETBLOCK 0
#endif

OSErr GetBlock_glue (UInt16 options,  UInt32 blockNum, Ptr *baddress, FileReference fileRefNum, ExtendedVCB * vcb)
{
	int			status;
    struct buf *bp = NULL;
    int			readcount = 0;

#if DBG_GETBLOCK
    DBG_IO(("Getting block %ld with options %d and a refnum of %x\n", blockNum, options, fileRefNum ));
#endif

	if ((options & ~(gbReadMask | gbNoReadMask)) != 0) {
		DEBUG_BREAK_MSG(("GetBlock_glue: options = 0x%04X.\n", options));
	};
	
    *baddress = NULL;

	if (options & gbNoReadMask) {
	    if (fileRefNum == NULL) {
		    bp = getblk (VCBTOHFS(vcb)->hfs_devvp,
   	                     IOBLKNOFORBLK(blockNum, VCBTOHFS(vcb)->hfs_phys_block_size),
   	                     IOBYTECCNTFORBLK(blockNum, kHFSBlockSize, VCBTOHFS(vcb)->hfs_phys_block_size),
	                     0,
	                     0,
	                     BLK_META);
	    } else {
		    bp = getblk (fileRefNum,
		   	             IOBLKNOFORBLK(blockNum, VCBTOHFS(vcb)->hfs_phys_block_size),
		   	             IOBYTECCNTFORBLK(blockNum, kHFSBlockSize, VCBTOHFS(vcb)->hfs_phys_block_size),
		   	    		 0,
		   	    		 0,
		   	    		 BLK_META);
	    };
	    status = E_NONE;
	} else {
		do {
		    if (fileRefNum == NULL) {
			    status = meta_bread (VCBTOHFS(vcb)->hfs_devvp,
		                            IOBLKNOFORBLK(blockNum, VCBTOHFS(vcb)->hfs_phys_block_size),
		                            IOBYTECCNTFORBLK(blockNum, kHFSBlockSize, VCBTOHFS(vcb)->hfs_phys_block_size),
		                            NOCRED,
		                            &bp);
		    } else {
			    status = meta_bread (fileRefNum,
			   	                     IOBLKNOFORBLK(blockNum, VCBTOHFS(vcb)->hfs_phys_block_size),
			   	                     IOBYTECCNTFORBLK(blockNum, kHFSBlockSize, VCBTOHFS(vcb)->hfs_phys_block_size),
			   	    				 NOCRED,
			   	    				 &bp);
		    };
		    if (status != E_NONE) {
		    	if (bp) brelse(bp);
		    	goto Error_Exit;
		    };
	
		    if (bp == NULL) {
		        status = -1;
		        goto Error_Exit;
		    };
		    
		    ++readcount;
		    
		    if ((options & gbReadMask) && (bp->b_flags & B_CACHE)) {
		    	/* Rats!  The block was found in the cache just when we really wanted a
		    	   fresh copy off disk...
		    	 */
		    	if (bp->b_flags & B_DIRTY) {
		    		DEBUG_BREAK_MSG(("GetBlock_glue: forced read for dirty block!\n"))
		    	};
		    	bp->b_flags |= B_INVAL;
		    	brelse(bp);
		    	
		    	/* Fall through and try again until we get a fresh copy from the disk... */
		    };
		} while (((options & gbReadMask) != 0) && (readcount <= 1));
	};
	
    *baddress = bp->b_data + IOBYTEOFFSETFORBLK(bp->b_blkno, VCBTOHFS(vcb)->hfs_phys_block_size);
    StoreBufferMapping(*baddress, bp);
	
Error_Exit: ;
    return status;
}

void MarkBlock_glue (Ptr address)
{
    int		err;
    struct buf *bp = NULL;
    int mappingEntry;

    if ((err = LookupBufferMapping(address, &bp, &mappingEntry))) {
        panic("Failed to find buffer pointer for buffer in MarkBlock_glue.");
    } else {
        bp->b_flags |= B_DIRTY;
    };
}

OSErr RelBlock_glue (Ptr address, UInt16 options )
{
    int		err;
    struct buf	*bp;
    int mappingEntry;

	if (options & ~(rbTrashMask | rbDirtyMask | rbWriteMask) == 0) {
		DEBUG_BREAK_MSG(("RelBlock_glue: options = 0x%04X.\n", options));
	};
	
    if ((err = LookupBufferMapping(address, &bp, &mappingEntry))) {
        DEBUG_BREAK_MSG(("Failed to find buffer pointer for buffer in RelBlock_glue.\n"));
    } else {
    	if (bp->b_flags & B_DIRTY) {
    		/* The buffer was previously marked dirty (using MarkBlock_glue):
    		   now's the time to write it. */
    		options |= rbDirtyMask;
    	};
        ReleaseMappingEntry(mappingEntry);
        if (options & rbTrashMask) {
            bp->b_flags |= B_INVAL;
            brelse(bp);
        } else {
            if (options & (rbDirtyMask | rbWriteMask)) {
                bp->b_flags |= B_DIRTY;
                if (options & rbWriteMask) {
                    bwrite(bp);
                } else {
                    bdwrite(bp);
                }
            } else {
            	brelse(bp);
            };
        };
	err = E_NONE;
    };
    return err;
}

/*										*/
/*	Creates a new vnode to hold a psuedo file like an extents tree file	*/
/*										*/

OSStatus  GetInitializedVNode(struct hfsmount *hfsmp, struct vnode **tmpvnode, int init_ubc)
{

    struct hfsnode	*hp;
    struct vnode 	*vp = NULL;
    int				rtn;

    DBG_ASSERT(hfsmp != NULL);
    DBG_ASSERT(tmpvnode != NULL);

    /* Allocate a new hfsnode. */
    /*
	 * Must do malloc() before getnewvnode(), since malloc() can block
	 * and could cause other part of the system to access v_data
	 * which has not been initialized yet
	 */
    MALLOC_ZONE(hp, struct hfsnode *, sizeof(struct hfsnode), M_HFSNODE, M_WAITOK);
    if(hp == NULL) {
        rtn = ENOMEM;
        goto Err_Exit;
    }
    bzero((caddr_t)hp, sizeof(struct hfsnode));
    lockinit(&hp->h_lock, PINOD, "hfsnode", 0, 0);

    MALLOC_ZONE(hp->h_meta, struct hfsfilemeta *, 
		sizeof(struct hfsfilemeta), M_HFSFMETA, M_WAITOK);
    /* Allocate a new vnode. */
    if ((rtn = getnewvnode(VT_HFS, HFSTOVFS(hfsmp), hfs_vnodeop_p, &vp))) {
		FREE_ZONE(hp->h_meta, sizeof(struct hfsfilemeta), M_HFSFMETA);
		FREE_ZONE(hp, sizeof(struct hfsnode), M_HFSNODE);
        goto Err_Exit;
    }

    /* Init the structure */
    bzero(hp->h_meta, sizeof(struct hfsfilemeta));

    hp->h_vp = vp;									/* Make HFSTOV work */
    hp->h_meta->h_devvp = hfsmp->hfs_devvp;
    hp->h_meta->h_dev = hfsmp->hfs_raw_dev;
    hp->h_meta->h_usecount++;
    hp->h_nodeflags |= IN_ACCESS | IN_CHANGE | IN_UPDATE;
#if HFS_DIAGNOSTIC
    hp->h_valid = HFS_VNODE_MAGIC;
#endif
    vp->v_data = hp;								/* Make VTOH work */
    vp->v_type = VREG;
	/*
	 * Metadata files are VREG but not available for IO
	 * through mapped IO as will as POSIX IO APIs.
	 * Hence we do not initialize UBC for those files
	 */
    if (init_ubc) 
		ubc_info_init(vp);
    else
		vp->v_ubcinfo = UBC_NOINFO;

    *tmpvnode = vp;
    
    VREF(hp->h_meta->h_devvp);

    return noErr;

Err_Exit:
    
    *tmpvnode = NULL;

    return rtn;
}

OSErr GetNewFCB(ExtendedVCB *vcb, FileReference* fRefPtr)
{
    OSErr    err;

    err = GetInitializedVNode( VCBTOHFS(vcb), fRefPtr, 0 );
    panic("This node is not completely initialized in GetNewFCB!");		/* XXX SER */

	return( err );    
}


OSErr	CheckVolumeOffLine( ExtendedVCB *vcb )
{

    return( 0 );
}


OSErr	C_FlushMDB( ExtendedVCB *volume)
{
	short	err;

	if (volume->vcbSigWord == kHFSPlusSigWord)
		err = hfs_flushvolumeheader(VCBTOHFS(volume), 0);
	else
		err = hfs_flushMDB(VCBTOHFS(volume), 0);

	return err;
}


/*
 * GetTimeUTC - get the GMT Mac OS time (in seconds since 1/1/1904)
 *
 * called by the Catalog Manager when creating/updating HFS Plus records
 */
UInt32 GetTimeUTC(void)
{
    return (time.tv_sec + MAC_GMT_FACTOR);
}

/*
 * GetTimeLocal - get the local Mac OS time (in seconds since 1/1/1904)
 *
 * called by the Catalog Manager when creating/updating HFS records
 */
UInt32 GetTimeLocal(Boolean forHFS)
{
	UInt32 localTime;

	localTime = UTCToLocal(GetTimeUTC());

	if (forHFS && gTimeZone.tz_dsttime)
		localTime += 3600;

	return localTime;
}

/*
 * LocalToUTC - convert from Mac OS local time to Mac OS GMT time.
 * This should only be called for HFS volumes (not for HFS Plus).
 */
UInt32 LocalToUTC(UInt32 localTime)
{
	UInt32 gtime = localTime;
	
	if (gtime != 0) {
		gtime += (gTimeZone.tz_minuteswest * 60);
	/*
	 * We no longer do DST adjustments here since we don't
	 * know if time supplied needs adjustment!
	 *
	 * if (gTimeZone.tz_dsttime)
	 *     gtime -= 3600;
	 */
	}
    return (gtime);
}

/*
 * UTCToLocal - convert from Mac OS GMT time to Mac OS local time.
 * This should only be called for HFS volumes (not for HFS Plus).
 */
UInt32 UTCToLocal(UInt32 utcTime)
{
	UInt32 ltime = utcTime;
	
	if (ltime != 0) {
		ltime -= (gTimeZone.tz_minuteswest * 60);
	/*
	 * We no longer do DST adjustments here since we don't
	 * know if time supplied needs adjustment!
	 *
	 * if (gTimeZone.tz_dsttime)
	 *     ltime += 3600;
	 */
	}
    return (ltime);
}

/*
 * to_bsd_time - convert from Mac OS time (seconds since 1/1/1904)
 *		 to BSD time (seconds since 1/1/1970)
 */
u_int32_t to_bsd_time(u_int32_t hfs_time)
{
	u_int32_t gmt = hfs_time;

	if (gmt > MAC_GMT_FACTOR)
		gmt -= MAC_GMT_FACTOR;
	else
		gmt = 0;	/* don't let date go negative! */

	return gmt;
}

/*
 * to_hfs_time - convert from BSD time (seconds since 1/1/1970)
 *		 to Mac OS time (seconds since 1/1/1904)
 */
u_int32_t to_hfs_time(u_int32_t bsd_time)
{
	u_int32_t hfs_time = bsd_time;

	/* don't adjust zero - treat as uninitialzed */
	if (hfs_time != 0)
		hfs_time += MAC_GMT_FACTOR;

	return (hfs_time);
}


void BlockMoveData (const void *srcPtr, void *destPtr, Size byteCount)
{
    bcopy(srcPtr, destPtr, byteCount);
}


Ptr  NewPtrSysClear (Size byteCount)
{
    Ptr		tmptr;
    MALLOC (tmptr, Ptr, byteCount, M_TEMP, M_WAITOK);
    if (tmptr)
        bzero(tmptr, byteCount);
    return tmptr;
}



Ptr  NewPtr (Size byteCount)
{
    Ptr		tmptr;
    MALLOC (tmptr, Ptr, byteCount, M_TEMP, M_WAITOK);
    return tmptr;
}


void DisposePtr (Ptr p)
{
    FREE (p, M_TEMP);
}


void DebugStr (ConstStr255Param  debuggerMsg)
{
    kprintf ("*** Mac OS Debugging Message: %s\n", &debuggerMsg[1]);
	DEBUG_BREAK;
}

OSErr MemError (void)
{
	return 0;
}


void ClearMemory( void* start, UInt32 length )
{
	bzero(start, (size_t)length);
}


/*
 * RequireFileLock
 *
 * Check to see if a vnode is locked in the current context
 * This is to be used for debugging purposes only!!
 */
#if HFS_DIAGNOSTIC
void RequireFileLock(FileReference vp, int shareable)
{
	struct lock__bsd__ *lkp;
	int locked = false;
	pid_t pid;
	void * self;

	pid = current_proc()->p_pid;
    self = (void *) current_thread();
	lkp = &VTOH(vp)->h_lock;

return;

	simple_lock(&lkp->lk_interlock);
	
	if (shareable && (lkp->lk_sharecount > 0) && (lkp->lk_lockholder == LK_NOPROC))
		locked = true;
	else if ((lkp->lk_exclusivecount > 0) && (lkp->lk_lockholder == pid) && (lkp->lk_lockthread == self))
		locked = true;

	simple_unlock(&lkp->lk_interlock);
	
	if (!locked) {
		DBG_VFS((" # context...  self=0x%0X, pid=0x%0X, proc=0x%0X\n", (int)self, pid, (int)current_proc()));
		DBG_VFS((" # lock state...  thread=0x%0X, holder=0x%0X, ex=%d, sh=%d\n", (int)lkp->lk_lockthread, lkp->lk_lockholder, lkp->lk_exclusivecount, lkp->lk_sharecount));

		switch (H_FILEID(VTOH(vp))) {
			case 3:
				DEBUG_BREAK_MSG((" #\n # RequireFileLock: extent btree vnode not locked! v: 0x%08X\n #\n", (u_int)vp));
				break;

			case 4:
				DEBUG_BREAK_MSG((" #\n # RequireFileLock: catalog btree vnode not locked! v: 0x%08X\n #\n", (u_int)vp));
				break;

			default:
				DEBUG_BREAK_MSG((" #\n # RequireFileLock: file (%d) not locked! v: 0x%08X\n #\n", H_FILEID(VTOH(vp)), (u_int)vp));
				break;
		}
	}
}
#endif

