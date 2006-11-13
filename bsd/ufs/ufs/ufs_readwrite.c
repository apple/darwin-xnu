/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*-
 * Copyright (c) 1993
 *	The Regents of the University of California.  All rights reserved.
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
 *	@(#)ufs_readwrite.c	8.11 (Berkeley) 5/8/95
 */

#include <sys/buf_internal.h>
#include <sys/uio_internal.h>


#define	BLKSIZE(a, b, c)	blksize(a, b, c)
#define	FS			struct fs
#define	I_FS			i_fs



/*
 * Vnode op for reading.
 */
/* ARGSUSED */
ffs_read(ap)
	struct vnop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
        return(ffs_read_internal(ap->a_vp, ap->a_uio, ap->a_ioflag));
}


int
ffs_read_internal(vnode_t vp, struct uio *uio, int ioflag)
{
	struct	inode *ip;
	FS	*fs;
	buf_t	bp = (struct buf *)0;
	ufs_daddr_t lbn, nextlbn;
	off_t bytesinfile;
	long size, xfersize, blkoffset;
	int error;
	u_short mode;
#if REV_ENDIAN_FS
	int rev_endian=0;
#endif /* REV_ENDIAN_FS */

	ip = VTOI(vp);
	mode = ip->i_mode;

#if REV_ENDIAN_FS
	rev_endian=(vp->v_mount->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_READ)
		panic("ffs_read: invalid uio_rw = %x", uio->uio_rw);

	if (vp->v_type == VLNK) {
		if ((int)ip->i_size < vp->v_mount->mnt_maxsymlinklen)
			panic("ffs_read: short symlink = %d", ip->i_size);
	} else if (vp->v_type != VREG && vp->v_type != VDIR)
		panic("ffs_read: invalid v_type = %x", vp->v_type);
#endif
	fs = ip->I_FS;
	if (uio->uio_offset < 0)
		return (EINVAL);
	if (uio->uio_offset > fs->fs_maxfilesize)
		return (EFBIG);

	if (UBCINFOEXISTS(vp)) {
		error = cluster_read(vp, uio, (off_t)ip->i_size, 0);
	} else {
	for (error = 0, bp = NULL; uio_resid(uio) > 0; 
	    bp = NULL) {
	        char *buf_data;

		if ((bytesinfile = ip->i_size - uio->uio_offset) <= 0)
			break;
		lbn = lblkno(fs, uio->uio_offset);
		nextlbn = lbn + 1;
		size = BLKSIZE(fs, ip, lbn);
		blkoffset = blkoff(fs, uio->uio_offset);
		xfersize = fs->fs_bsize - blkoffset;
		// LP64todo - fix this
		if (uio_resid(uio) < xfersize)
			xfersize = uio_resid(uio);
		if (bytesinfile < xfersize)
			xfersize = bytesinfile;

		if (lblktosize(fs, nextlbn) >= ip->i_size)
			error = (int)buf_bread(vp, (daddr64_t)((unsigned)lbn), size, NOCRED, &bp);
		else if (lbn - 1 == ip->i_lastr && !(vp->v_flag & VRAOFF)) {
			int nextsize = BLKSIZE(fs, ip, nextlbn);
			error = (int)buf_breadn(vp, (daddr64_t)((unsigned)lbn),
						size, &nextlbn, &nextsize, 1, NOCRED, &bp);
		} else
			error = (int)buf_bread(vp, lbn, size, NOCRED, &bp);
		if (error)
			break;
		ip->i_lastr = lbn;

		/*
		 * We should only get non-zero buffer resid when an I/O error
		 * has occurred, which should cause us to break above.
		 * However, if the short read did not cause an error,
		 * then we want to ensure that we do not uiomove bad
		 * or uninitialized data.
		 */
		size -= buf_resid(bp);
		if (size < xfersize) {
			if (size == 0)
				break;
			xfersize = size;
		}
		buf_data = (char *)buf_dataptr(bp);
#if REV_ENDIAN_FS
		if (rev_endian && S_ISDIR(mode)) {
			byte_swap_dir_block_in(buf_data + blkoffset, xfersize);
		}
#endif /* REV_ENDIAN_FS */
		if (error =
		    uiomove(buf_data + blkoffset, (int)xfersize, uio)) {
#if REV_ENDIAN_FS
			if (rev_endian && S_ISDIR(mode)) {
			byte_swap_dir_block_in(buf_data + blkoffset, xfersize);
			}
#endif /* REV_ENDIAN_FS */
			break;
	}

#if REV_ENDIAN_FS
		if (rev_endian && S_ISDIR(mode)) {
			byte_swap_dir_out(buf_data + blkoffset, xfersize);
		}
#endif /* REV_ENDIAN_FS */
		if (S_ISREG(mode) && (xfersize + blkoffset == fs->fs_bsize ||
		    uio->uio_offset == ip->i_size))
			buf_markaged(bp);
		buf_brelse(bp);
	}
	}
	if (bp != NULL)
		buf_brelse(bp);
	ip->i_flag |= IN_ACCESS;
	return (error);
}

/*
 * Vnode op for writing.
 */
ffs_write(ap)
	struct vnop_write_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		vfs_context_t a_context;
	} */ *ap;
{
        return(ffs_write_internal(ap->a_vp, ap->a_uio, ap->a_ioflag, vfs_context_ucred(ap->a_context)));
}


ffs_write_internal(vnode_t vp, struct uio *uio, int ioflag, ucred_t cred)
{
	buf_t	bp;
	proc_t	p;
	struct	inode *ip;
	FS	*fs;
	ufs_daddr_t lbn;
	off_t osize;
	int blkoffset, flags, resid, rsd,  size, xfersize;
	int save_error=0, save_size=0;
	int blkalloc = 0;
	int error = 0;
	int file_extended = 0;
	int doingdirectory = 0;

#if REV_ENDIAN_FS
	int rev_endian=0;
#endif /* REV_ENDIAN_FS */

	ip = VTOI(vp);
#if REV_ENDIAN_FS
	rev_endian=(vp->v_mount->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

#if DIAGNOSTIC
	if (uio->uio_rw != UIO_WRITE)
		panic("ffs_write: uio_rw = %x\n", uio->uio_rw);
#endif

	switch (vp->v_type) {
	case VREG:
		if (ioflag & IO_APPEND)
			uio->uio_offset = ip->i_size;
		if ((ip->i_flags & APPEND) && uio->uio_offset != ip->i_size)
			return (EPERM);
		/* FALLTHROUGH */
	case VLNK:
		break;
	case VDIR:
		doingdirectory = 1;
		if ((ioflag & IO_SYNC) == 0)
			panic("ffs_write: nonsync dir write");
		break;
	default:
		panic("ffs_write: invalid v_type=%x", vp->v_type);
	}

	fs = ip->I_FS;
	if (uio->uio_offset < 0 ||
	    (u_int64_t)uio->uio_offset + uio_resid(uio) > fs->fs_maxfilesize)
		return (EFBIG);
	if (uio_resid(uio) == 0)
	        return (0);

	// LP64todo - fix this
	resid = uio_resid(uio);
	osize = ip->i_size;
	flags = 0;
	if ((ioflag & IO_SYNC) && !((vp)->v_mount->mnt_flag & MNT_ASYNC))
		flags = B_SYNC;

    if (UBCINFOEXISTS(vp)) {
	off_t filesize;
	off_t endofwrite;
	off_t local_offset;
	off_t head_offset;
	int local_flags;
	int first_block;
	int fboff;
	int fblk;
	int loopcount;

	// LP64todo - fix this
	endofwrite = uio->uio_offset + uio_resid(uio);

	if (endofwrite > ip->i_size) {
		filesize = endofwrite;
                file_extended = 1;
	} else 
		filesize = ip->i_size;

	head_offset = ip->i_size;

	/* Go ahead and allocate the block that are going to be written */
	// LP64todo - fix this
	rsd = uio_resid(uio);
	local_offset = uio->uio_offset;
	local_flags = 0;
	if ((ioflag & IO_SYNC) && !((vp)->v_mount->mnt_flag & MNT_ASYNC))
		local_flags = B_SYNC;
	local_flags |= B_NOBUFF;
	
	first_block = 1;
	fboff = 0;
	fblk = 0;
	loopcount = 0;

	for (error = 0; rsd > 0;) {
		blkalloc = 0;
		lbn = lblkno(fs, local_offset);
		blkoffset = blkoff(fs, local_offset);
		xfersize = fs->fs_bsize - blkoffset;
		if (first_block)
			fboff = blkoffset;
		if (rsd < xfersize)
			xfersize = rsd;
		if (fs->fs_bsize > xfersize)
			local_flags |= B_CLRBUF;
		else
			local_flags &= ~B_CLRBUF;

		/* Allocate block without reading into a buf */
		error = ffs_balloc(ip,
			lbn, blkoffset + xfersize, cred, 
			&bp, local_flags, &blkalloc);
		if (error)
			break;
		if (first_block) {
			fblk = blkalloc;
			first_block = 0;
		}
		loopcount++;

		rsd -= xfersize;
		local_offset += (off_t)xfersize;
		if (local_offset > ip->i_size)
			ip->i_size = local_offset;
	}

	if(error) {
		save_error = error;
		save_size = rsd;
		uio_setresid(uio, (uio_resid(uio) - rsd));
		if (file_extended)
			filesize -= rsd;
	}

	flags = ioflag & IO_SYNC ? IO_SYNC : 0;
	/* flags |= IO_NOZEROVALID; */

	if((error == 0) && fblk && fboff) {
		if( fblk > fs->fs_bsize) 
			panic("ffs_balloc : allocated more than bsize(head)");
		/* We need to zero out the head */
		head_offset = uio->uio_offset - (off_t)fboff ;
		flags |= IO_HEADZEROFILL;
		/* flags &= ~IO_NOZEROVALID; */
	}

	if((error == 0) && blkalloc && ((blkalloc - xfersize) > 0)) {
		/* We need to zero out the tail */
		if( blkalloc > fs->fs_bsize) 
			panic("ffs_balloc : allocated more than bsize(tail)");
		local_offset += (blkalloc - xfersize);
		if (loopcount == 1) {
		/* blkalloc is same as fblk; so no need to check again*/
			local_offset -= fboff;
		}
		flags |= IO_TAILZEROFILL;
		/*  Freshly allocated block; bzero even if 
		 * find a page 
		 */
		/* flags &= ~IO_NOZEROVALID; */
	}
	  /*
	   * if the write starts beyond the current EOF then
	   * we we'll zero fill from the current EOF to where the write begins
	   */

          error = cluster_write(vp, uio, osize, filesize, head_offset, local_offset, flags);
	
	if (uio->uio_offset > osize) {
		if (error && ((ioflag & IO_UNIT)==0))
			(void)ffs_truncate_internal(vp, uio->uio_offset, ioflag & IO_SYNC, cred);
		ip->i_size = uio->uio_offset; 
		ubc_setsize(vp, (off_t)ip->i_size);
	}
	 if(save_error) {
		uio_setresid(uio, (uio_resid(uio) + save_size));
		if(!error)
			error = save_error;	
	}
	 ip->i_flag |= IN_CHANGE | IN_UPDATE;
    } else {
	flags = 0;
	if ((ioflag & IO_SYNC) && !((vp)->v_mount->mnt_flag & MNT_ASYNC))
		flags = B_SYNC;

	for (error = 0; uio_resid(uio) > 0;) {
	        char *buf_data;

		lbn = lblkno(fs, uio->uio_offset);
		blkoffset = blkoff(fs, uio->uio_offset);
		xfersize = fs->fs_bsize - blkoffset;
		if (uio_resid(uio) < xfersize)
			// LP64todo - fix this
			xfersize = uio_resid(uio);

		if (fs->fs_bsize > xfersize)
			flags |= B_CLRBUF;
		else
			flags &= ~B_CLRBUF;

		error = ffs_balloc(ip, lbn, blkoffset + xfersize, cred, &bp, flags, 0);
		if (error)
			break;
		if (uio->uio_offset + xfersize > ip->i_size) {
			ip->i_size = uio->uio_offset + xfersize;
			ubc_setsize(vp, (u_long)ip->i_size);
		}

		size = BLKSIZE(fs, ip, lbn) - buf_resid(bp);
		if (size < xfersize)
			xfersize = size;

		buf_data = (char *)buf_dataptr(bp);

		error = uiomove(buf_data + blkoffset, (int)xfersize, uio);
#if REV_ENDIAN_FS
		if (rev_endian && S_ISDIR(ip->i_mode)) {
			byte_swap_dir_out(buf_data + blkoffset, xfersize);
		}
#endif /* REV_ENDIAN_FS */
		if (doingdirectory == 0 && (ioflag & IO_SYNC))
			(void)buf_bwrite(bp);
		else if (xfersize + blkoffset == fs->fs_bsize) {
		        buf_markaged(bp);
			buf_bdwrite(bp);
		}
		else
			buf_bdwrite(bp);
		if (error || xfersize == 0)
			break;
		ip->i_flag |= IN_CHANGE | IN_UPDATE;
	}
    }
	/*
	 * If we successfully wrote any data, and we are not the superuser
	 * we clear the setuid and setgid bits as a precaution against
	 * tampering.
	 */
	if (resid > uio_resid(uio) && cred && suser(cred, NULL))
		ip->i_mode &= ~(ISUID | ISGID);
	if (resid > uio_resid(uio))
		VN_KNOTE(vp, NOTE_WRITE | (file_extended ? NOTE_EXTEND : 0));
	if (error) {
		if (ioflag & IO_UNIT) {
			(void)ffs_truncate_internal(vp, osize, ioflag & IO_SYNC, cred);
			// LP64todo - fix this
			uio->uio_offset -= resid - uio_resid(uio);
			uio_setresid(uio, resid);
		}
	} else if (resid > uio_resid(uio) && (ioflag & IO_SYNC)) {
		struct timeval tv;

		microtime(&tv);		
		error = ffs_update(vp, &tv, &tv, 1);
	}
	return (error);
}

/*
 * Vnode op for pagein.
 * Similar to ffs_read()
 */
/* ARGSUSED */
ffs_pagein(ap)
	struct vnop_pagein_args /* {
	   	struct vnode *a_vp,
	   	upl_t 	a_pl,
		vm_offset_t   a_pl_offset,
		off_t         a_f_offset,
		size_t        a_size,
		int           a_flags
		vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size= ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	register struct inode *ip;
	int error;

	ip = VTOI(vp);

	/* check pageins for reg file only  and ubc info is present*/
	if  (UBCINVALID(vp))
		panic("ffs_pagein: Not a  VREG: vp=%x", vp);
	if (UBCINFOMISSING(vp))
		panic("ffs_pagein: No mapping: vp=%x", vp);

#if DIAGNOSTIC
	if (vp->v_type == VLNK) {
		if ((int)ip->i_size < vp->v_mount->mnt_maxsymlinklen)
			panic("%s: short symlink", "ffs_pagein");
	} else if (vp->v_type != VREG && vp->v_type != VDIR)
		panic("%s: type %d", "ffs_pagein", vp->v_type);
#endif

  	error = cluster_pagein(vp, pl, pl_offset, f_offset, size, (off_t)ip->i_size, flags);

	/* ip->i_flag |= IN_ACCESS; */
	return (error);
}

/*
 * Vnode op for pageout.
 * Similar to ffs_write()
 * make sure the buf is not in hash queue when you return
 */
ffs_pageout(ap)
	struct vnop_pageout_args /* {
	   struct vnode *a_vp,
	   upl_t        a_pl,
	   vm_offset_t   a_pl_offset,
	   off_t         a_f_offset,
	   size_t        a_size,
	   int           a_flags
	   vfs_context_t a_context;
	} */ *ap;
{
	register struct vnode *vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size= ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	register struct inode *ip;
	register FS *fs;
	int error ;
	size_t xfer_size = 0;
	int local_flags=0;
	off_t local_offset;
	int resid, blkoffset;
	size_t xsize, lsize;
	daddr_t lbn;
	int save_error =0, save_size=0;
	vm_offset_t lupl_offset;
	int nocommit = flags & UPL_NOCOMMIT;
	int devBlockSize = 0;
	struct buf *bp;

	ip = VTOI(vp);

	/* check pageouts for reg file only  and ubc info is present*/
	if  (UBCINVALID(vp))
		panic("ffs_pageout: Not a  VREG: vp=%x", vp);
	if (UBCINFOMISSING(vp))
		panic("ffs_pageout: No mapping: vp=%x", vp);

        if (vp->v_mount->mnt_flag & MNT_RDONLY) {
		if (!nocommit)
  			ubc_upl_abort_range(pl, pl_offset, size, 
				UPL_ABORT_FREE_ON_EMPTY);
		return (EROFS);
	}
	fs = ip->I_FS;

	if (f_offset < 0 || f_offset >= ip->i_size) {
	        if (!nocommit)
		        ubc_upl_abort_range(pl, pl_offset, size, 
				UPL_ABORT_FREE_ON_EMPTY);
		return (EINVAL);
	}

	/*
	 * once we enable multi-page pageouts we will
	 * need to make sure we abort any pages in the upl
	 * that we don't issue an I/O for
	 */
	if (f_offset + size > ip->i_size)
	        xfer_size = ip->i_size - f_offset;
	else
	        xfer_size = size;

	devBlockSize = vfs_devblocksize(vnode_mount(vp));

	if (xfer_size & (PAGE_SIZE - 1)) {
	        /* if not a multiple of page size
		 * then round up to be a multiple
		 * the physical disk block size
		 */
		xfer_size = (xfer_size + (devBlockSize - 1)) & ~(devBlockSize - 1);
	}

	/*
	 * once the block allocation is moved to ufs_blockmap
	 * we can remove all the size and offset checks above
	 * cluster_pageout does all of this now
	 * we need to continue to do it here so as not to
	 * allocate blocks that aren't going to be used because
	 * of a bogus parameter being passed in
	 */
	local_flags = 0;
	resid = xfer_size;
	local_offset = f_offset;
	for (error = 0; resid > 0;) {
		lbn = lblkno(fs, local_offset);
		blkoffset = blkoff(fs, local_offset);
		xsize = fs->fs_bsize - blkoffset;
		if (resid < xsize)
			xsize = resid;
		/* Allocate block without reading into a buf */
		error = ffs_blkalloc(ip,
			lbn, blkoffset + xsize, vfs_context_ucred(ap->a_context), 
			local_flags);
		if (error)
			break;
		resid -= xsize;
		local_offset += (off_t)xsize;
	}

	if (error) {
		save_size = resid;
		save_error = error;
		xfer_size -= save_size;
	}
        

	error = cluster_pageout(vp, pl, pl_offset, f_offset, round_page_32(xfer_size), ip->i_size, flags);

	if(save_error) {
		lupl_offset = size - save_size;
		resid = round_page_32(save_size);
		if (!nocommit)
			ubc_upl_abort_range(pl, lupl_offset, resid,
				UPL_ABORT_FREE_ON_EMPTY);
		if(!error)
			error= save_error;
	}
	return (error);
}
