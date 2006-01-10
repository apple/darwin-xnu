/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
/*	$NetBSD: cd9660_vnops.c,v 1.22 1994/12/27 19:05:12 mycroft Exp $	*/

/*-
 * Copyright (c) 1994
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley
 * by Pace Willisson (pace@blitz.com).  The Rock Ridge Extension
 * Support code is derived from software contributed to Berkeley
 * by Atsushi Murai (amurai@spec.co.jp).
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
 *	@(#)cd9660_vnops.c	8.15 (Berkeley) 12/5/94
 *
 * HISTORY
 * 02-Feb-00	chw		Add cd9660_copyfile to return error
 * 29-Sep-98	djb		Add cd9660_getattrlist VOP for VDI support.
 * 15-sep-98	added cd9660_rmdir to do proper unlocking - chw
 * 12-aug-98	added cd9660_remove which will do proper unlocking - chw
 * 17-Feb-98	radar 1669467 - changed lock protocols to use the lock manager - chw
 * 22-Jan-98	radar 1669467 - ISO 9660 CD support - jwc
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/resourcevar.h>
#include <sys/kernel.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/buf.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/conf.h>
#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>
#include <sys/malloc.h>
#include <sys/dir.h>
#include <sys/attr.h>
#include <vfs/vfs_support.h>
#include <vm/vm_kern.h>
#include <sys/ubc.h>
#include <sys/lock.h>
#include <sys/ubc_internal.h>
#include <sys/uio_internal.h>
#include <architecture/byte_order.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>		/* kmem_alloc, kmem_free */

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/cd9660_node.h>
#include <isofs/cd9660/iso_rrip.h>

/*
 * Open called.
 *
 * Nothing to do.
 */
int
cd9660_open(__unused struct vnop_open_args *ap)
{
	return (0);
}

/*
 * Close called
 *
 * Update the times on the inode on writeable file systems.
 */
int
cd9660_close(__unused struct vnop_close_args *ap)
{
	return (0);
}

int
cd9660_getattr(struct vnop_getattr_args *ap)
{
	struct vnode *vp = ap->a_vp;
	register struct vnode_attr *vap = ap->a_vap;
	register struct iso_node *ip = VTOI(vp);

	VATTR_RETURN(vap, va_fsid,	ip->i_dev);
	VATTR_RETURN(vap, va_fileid,	ip->i_number);

	VATTR_RETURN(vap, va_mode,	ip->inode.iso_mode);
	VATTR_RETURN(vap, va_nlink,	ip->inode.iso_links);
	VATTR_RETURN(vap, va_uid,	ip->inode.iso_uid);
	VATTR_RETURN(vap, va_gid,	ip->inode.iso_gid);
	VATTR_RETURN(vap, va_access_time, ip->inode.iso_atime);
	VATTR_RETURN(vap, va_modify_time, ip->inode.iso_mtime);
	VATTR_RETURN(vap, va_change_time, ip->inode.iso_ctime);
	VATTR_RETURN(vap, va_rdev,	ip->inode.iso_rdev);

	VATTR_RETURN(vap, va_data_size,	(off_t)ip->i_size);
	if (ip->i_size == 0 && (vap->va_mode & S_IFMT) == S_IFLNK) {
		struct vnop_readlink_args rdlnk;
		uio_t auio;
		char uio_buf[ UIO_SIZEOF(1) ];
		char *cp;

		MALLOC(cp, char *, MAXPATHLEN, M_TEMP, M_WAITOK);
		auio = uio_createwithbuffer(1, 0, UIO_SYSSPACE, UIO_READ, 
								  &uio_buf[0], sizeof(uio_buf));
		uio_addiov(auio, CAST_USER_ADDR_T(cp), MAXPATHLEN);
		
		rdlnk.a_uio = auio;
		rdlnk.a_vp = ap->a_vp;
		rdlnk.a_context = ap->a_context;
		if (cd9660_readlink(&rdlnk) == 0)
			// LP64todo - fix this!
			VATTR_RETURN(vap, va_data_size, MAXPATHLEN - uio_resid(auio));
		FREE(cp, M_TEMP);
	}
	VATTR_RETURN(vap, va_flags, 0);
	VATTR_RETURN(vap, va_gen, 1);
	VATTR_RETURN(vap, va_iosize, ip->i_mnt->logical_block_size);
	VATTR_RETURN(vap, va_total_size, ip->i_size + ip->i_rsrcsize);

	return (0);
}


/*
 * Vnode op for reading.
 */
int
cd9660_read(struct vnop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
	register struct iso_node *ip = VTOI(vp);
	register struct iso_mnt *imp;
	struct buf *bp;
	daddr_t lbn;
	daddr64_t rablock;
	off_t diff;
	int rasize, error = 0;
	int32_t size, n, on;

	if (uio_resid(uio) == 0)
		return (0);
	if (uio->uio_offset < 0)
		return (EINVAL);

	imp = ip->i_mnt;

	if (UBCINFOEXISTS(vp)) {
		/*
		 * Copy any part of the Apple Double header.
		 */
		if ((ip->i_flag & ISO_ASSOCIATED) && (uio->uio_offset < ADH_SIZE)) {
			apple_double_header_t  header;
			int bytes;

			if (uio->uio_offset < sizeof(apple_double_header_t)) {
				header.magic = APPLEDOUBLE_MAGIC;
				header.version = APPLEDOUBLE_VERSION;
				header.count = 2;
				header.entries[0].entryID = APPLEDOUBLE_FINDERINFO;
				header.entries[0].offset = offsetof(apple_double_header_t, finfo);
				header.entries[0].length = 32;
				header.entries[1].entryID = APPLEDOUBLE_RESFORK;
				header.entries[1].offset = ADH_SIZE;
				header.entries[1].length = ip->i_size - ADH_SIZE;
				header.finfo.fdType = ip->i_FileType;
				header.finfo.fdCreator = ip->i_Creator;
				header.finfo.fdFlags = ip->i_FinderFlags;
				header.finfo.fdLocation.v = -1;
				header.finfo.fdLocation.h = -1;
				header.finfo.fdReserved = 0;

				bytes = min(uio_resid(uio), sizeof(apple_double_header_t) - uio->uio_offset);
				error = uiomove(((char *) &header) + uio->uio_offset, bytes, uio);
				if (error)
					return error;
			}
			if (uio_resid(uio) && uio->uio_offset < ADH_SIZE) {
				caddr_t  buffer;

				if (kmem_alloc(kernel_map, (vm_offset_t *)&buffer, ADH_SIZE)) {
					return (ENOMEM);
				}	
				bytes = min(uio_resid(uio), ADH_SIZE - uio->uio_offset);
				error = uiomove(((char *) buffer) + uio->uio_offset, bytes, uio);
				kmem_free(kernel_map, (vm_offset_t)buffer, ADH_SIZE);
				if (error)
					return error;
			}
		}
		if (uio_resid(uio) > 0)
			error = cluster_read(vp, uio, (off_t)ip->i_size, 0);
	} else {

	do {
		lbn = lblkno(imp, uio->uio_offset);
		on = blkoff(imp, uio->uio_offset);
		n = min((u_int)(imp->logical_block_size - on),
			uio_resid(uio));
		diff = (off_t)ip->i_size - uio->uio_offset;
		if (diff <= 0)
			return (0);
		if (diff < n)
			n = diff;
		size = blksize(imp, ip, lbn);
		rablock = (daddr64_t)lbn + 1;

		if (ip->i_lastr + 1 == lbn &&
		    lblktosize(imp, rablock) < ip->i_size) {
		        rasize = blksize(imp, ip, (daddr_t)rablock);
			error = (int)buf_breadn(vp, (daddr64_t)((unsigned)lbn), size, &rablock,
				       &rasize, 1, NOCRED, &bp);
		} else
		        error = (int)buf_bread(vp, (daddr64_t)((unsigned)lbn), size, NOCRED, &bp);

		ip->i_lastr = lbn;
		n = min(n, size - buf_resid(bp));
		if (error) {
			buf_brelse(bp);
			return (error);
		}

		error = uiomove((caddr_t)(buf_dataptr(bp) + on), (int)n, uio);
		if (n + on == imp->logical_block_size ||
		    uio->uio_offset == (off_t)ip->i_size)
		        buf_markaged(bp);
		buf_brelse(bp);
	} while (error == 0 && uio_resid(uio) > 0 && n != 0);
	}

	return (error);
}

int
cd9660_ioctl(__unused struct vnop_ioctl_args *ap)
{
	return (ENOTTY);
}

int
cd9660_select(__unused struct vnop_select_args *ap)
{
	/*
	 * We should really check to see if I/O is possible.
	 */
	return (1);
}

/*
 * Mmap a file
 *
 * NB Currently unsupported.
 */
int
cd9660_mmap(__unused struct vnop_mmap_args *ap)
{

	return (EINVAL);
}

/*
 * Structure for reading directories
 */
struct isoreaddir {
	struct dirent saveent;
	struct dirent current;
	off_t saveoff;
	off_t curroff;
	struct uio *uio;
	off_t uio_off;
	int eofflag;
//	u_long **cookies;
//	int *ncookies;
};

static int
iso_uiodir(struct isoreaddir *idp, struct dirent *dp, off_t off)
{
	int error;

	dp->d_name[dp->d_namlen] = 0;
	dp->d_reclen = DIRSIZ(dp);

	if (uio_resid(idp->uio) < dp->d_reclen) {
		idp->eofflag = 0;
		return (-1);
	}

#if 0
	if (idp->cookies) {
		if (*idp->ncookies <= 0) {
			idp->eofflag = 0;
			return (-1);
		}

		**idp->cookies++ = off;
		--*idp->ncookies;
	}
#endif

	if ( (error = uiomove( (caddr_t)dp, dp->d_reclen, idp->uio )) )
		return (error);
	idp->uio_off = off;
	return (0);
}

static int
iso_shipdir(struct isoreaddir *idp)
{
	struct dirent *dp;
	int cl, sl;
	int error;
	char *cname, *sname;

	cl = idp->current.d_namlen;
	cname = idp->current.d_name;

	dp = &idp->saveent;
	sname = dp->d_name;
	sl = dp->d_namlen;
	if (sl > 0) {
		if (sl != cl
		    || bcmp(sname,cname,sl)) {
			if (idp->saveent.d_namlen) {
				if ( (error = iso_uiodir(idp,&idp->saveent,idp->saveoff)) )
					return (error);
				idp->saveent.d_namlen = 0;
			}
		}
	}
	idp->current.d_reclen = DIRSIZ(&idp->current);
	idp->saveoff = idp->curroff;
	bcopy(&idp->current,&idp->saveent,idp->current.d_reclen);
	return (0);
}

/*
 * Vnode op for readdir
 *
 * Note that directories are sector aligned (2K) and
 * that an entry can cross a logical block but not
 * a sector.
 */
int
cd9660_readdir(struct vnop_readdir_args *ap)
{
	register struct uio *uio = ap->a_uio;
	off_t startingOffset = uio->uio_offset;
	size_t lost = 0;
	struct isoreaddir *idp;
	struct vnode *vdp = ap->a_vp;
	struct iso_node *dp;
	struct iso_mnt *imp;
	struct buf *bp = NULL;
	struct iso_directory_record *ep;
	int entryoffsetinblock;
	doff_t endsearch;
	uint32_t bmask;
	int error = 0;
	int reclen;
	u_short namelen;

	if (ap->a_flags & (VNODE_READDIR_EXTENDED | VNODE_READDIR_REQSEEKOFF))
		return (EINVAL);

	dp = VTOI(vdp);
	imp = dp->i_mnt;
	bmask = imp->im_sector_size - 1;

	MALLOC(idp, struct isoreaddir *, sizeof(*idp), M_TEMP, M_WAITOK);
	idp->saveent.d_namlen = 0;
	/*
	 * XXX
	 * Is it worth trying to figure out the type?
	 */
	idp->saveent.d_type = idp->current.d_type = DT_UNKNOWN;
	idp->uio = uio;
	idp->eofflag = 1;
	idp->curroff = uio->uio_offset;

	if ((entryoffsetinblock = idp->curroff & bmask) &&
	    (error = cd9660_blkatoff(vdp, SECTOFF(imp, idp->curroff), NULL, &bp))) {
		FREE(idp, M_TEMP);
		return (error);
	}
	endsearch = dp->i_size;

	while (idp->curroff < endsearch) {
		/*
		 * If offset is on a block boundary,
		 * read the next directory block.
		 * Release previous if it exists.
		 */
		if ((idp->curroff & bmask) == 0) {
			if (bp != NULL)
				buf_brelse(bp);
			if ((error = cd9660_blkatoff(vdp, SECTOFF(imp, idp->curroff), NULL, &bp)))
				break;
			entryoffsetinblock = 0;
		}
		/*
		 * Get pointer to next entry.
		 */
		ep = (struct iso_directory_record *)
			(buf_dataptr(bp) + entryoffsetinblock);

		reclen = isonum_711(ep->length);
		if (reclen == 0) {
			/* skip to next block, if any */
			idp->curroff =
			    (idp->curroff & ~bmask) + imp->im_sector_size;
			continue;
		}

		if (reclen < ISO_DIRECTORY_RECORD_SIZE) {
			error = EINVAL;
			/* illegal entry, stop */
			break;
		}

		if (entryoffsetinblock + reclen > imp->im_sector_size) {
			error = EINVAL;
			/* illegal directory, so stop looking */
			break;
		}

		idp->current.d_namlen = isonum_711(ep->name_len);

		if (reclen < ISO_DIRECTORY_RECORD_SIZE + idp->current.d_namlen) {
			error = EINVAL;
			/* illegal entry, stop */
			break;
		}

		/*
		 * Some poorly mastered discs have an incorrect directory
		 * file size.  If the '.' entry has a better size (bigger)
		 * then use that instead.
		 */
		if ((uio->uio_offset == 0) && (isonum_733(ep->size) > endsearch)) {
			dp->i_size = endsearch = isonum_733(ep->size);
		}

		if ( isonum_711(ep->flags) & directoryBit )
			idp->current.d_fileno = isodirino(ep, imp);
		else {
			idp->current.d_fileno = ((daddr_t)buf_blkno(bp) << imp->im_bshift) +
			                        entryoffsetinblock;
		}

		idp->curroff += reclen;

		switch (imp->iso_ftype) {
		case ISO_FTYPE_RRIP:
			cd9660_rrip_getname(ep,idp->current.d_name, &namelen,
					   &idp->current.d_fileno,imp);
			idp->current.d_namlen = (u_char)namelen;
			if (idp->current.d_namlen)
				error = iso_uiodir(idp,&idp->current,idp->curroff);
			break;

		case ISO_FTYPE_JOLIET:
			ucsfntrans((u_int16_t *)ep->name, idp->current.d_namlen,
				   idp->current.d_name, &namelen,
				   isonum_711(ep->flags) & directoryBit,
				   isonum_711(ep->flags) & associatedBit);
			idp->current.d_namlen = (u_char)namelen;
			if (idp->current.d_namlen)
				error = iso_uiodir(idp,&idp->current,idp->curroff);
			break;

		default:	/* ISO_FTYPE_DEFAULT || ISO_FTYPE_9660 */
			strcpy(idp->current.d_name,"..");
			switch (ep->name[0]) {
			case 0:
				idp->current.d_namlen = 1;
				error = iso_uiodir(idp,&idp->current,idp->curroff);
				break;
			case 1:
				idp->current.d_namlen = 2;
				error = iso_uiodir(idp,&idp->current,idp->curroff);
				break;
			default:
				isofntrans(ep->name,idp->current.d_namlen,
					   idp->current.d_name, &namelen,
					   imp->iso_ftype == ISO_FTYPE_9660,
					   isonum_711(ep->flags) & associatedBit);
				idp->current.d_namlen = (u_char)namelen;
				if (imp->iso_ftype == ISO_FTYPE_DEFAULT)
					error = iso_shipdir(idp);
				else
					error = iso_uiodir(idp,&idp->current,idp->curroff);
				break;
			}
		}
		if (error)
			break;

		entryoffsetinblock += reclen;
	}

	if (!error && imp->iso_ftype == ISO_FTYPE_DEFAULT) {
		idp->current.d_namlen = 0;
		error = iso_shipdir(idp);
	}
#if 0
	if (!error && ap->a_ncookies) {
		struct dirent *dirp, *dpstart;
		off_t bufferOffset;
		u_long *cookies;
		int ncookies;

		/*
		 * Only the NFS server uses cookies, and it loads the
		 * directory block into system space, so we can just look at
		 * it directly.
		 *
		 * We assume the entire transfer is done to a single contiguous buffer.
		 */
		if (UIO_SEG_IS_USER_SPACE(uio->uio_segflg) || uio->uio_iovcnt != 1)
			panic("ufs_readdir: lost in space");
		
		/*
		 * Make a first pass over the buffer just generated,
		 * counting the number of entries:
		 */
		// LP64todo - fix this!
		dpstart = (struct dirent *) 
			CAST_DOWN(caddr_t, (uio_iov_base(uio) - (uio->uio_offset - startingOffset)));
		for (dirp = dpstart, bufferOffset = startingOffset, ncookies = 0;
		     bufferOffset < uio->uio_offset; ) {
			if (dirp->d_reclen == 0)
				break;
			bufferOffset += dirp->d_reclen;
			ncookies++;
			dirp = (struct dirent *)((caddr_t)dirp + dirp->d_reclen);
		}
		lost += uio->uio_offset - bufferOffset;
		uio->uio_offset = bufferOffset;
		
		/*
		 * Allocate a buffer to hold the cookies requested:
		 */
		MALLOC(cookies, u_long *, ncookies * sizeof(u_long), M_TEMP, M_WAITOK);
		*ap->a_ncookies = ncookies;
		*ap->a_cookies = cookies;

		/*
		 * Fill in the offsets for each entry in the buffer just allocated:
		 */
		for (bufferOffset = startingOffset, dirp = dpstart; bufferOffset < uio->uio_offset; ) {
			*(cookies++) = bufferOffset;
			bufferOffset += dirp->d_reclen;
			dirp = (struct dirent *)((caddr_t)dirp + dirp->d_reclen);
		}
	}
#endif
	if (error < 0)
		error = 0;

	if (bp)
		buf_brelse (bp);

	uio->uio_offset = idp->uio_off;
	*ap->a_eofflag = idp->eofflag;

	FREE(idp, M_TEMP);

	return (error);
}

/*
 * Return target name of a symbolic link
 * Shouldn't we get the parent vnode and read the data from there?
 * This could eventually result in deadlocks in cd9660_lookup.
 * But otherwise the block read here is in the block buffer two times.
 */
typedef struct iso_directory_record ISODIR;
typedef struct iso_node             ISONODE;
typedef struct iso_mnt              ISOMNT;
int
cd9660_readlink(struct vnop_readlink_args *ap)
{
	ISONODE	*ip;
	ISODIR	*dirp;
	ISOMNT	*imp;
	struct	buf *bp;
	struct	uio *uio;
	u_short	symlen;
	int	error;
	char	*symname;

	ip  = VTOI(ap->a_vp);
	imp = ip->i_mnt;
	uio = ap->a_uio;

	if (imp->iso_ftype != ISO_FTYPE_RRIP)
		return (EINVAL);

	/*
	 * Get parents directory record block that this inode included.
	 */
	error = (int)buf_bread(imp->im_devvp,
			       (daddr64_t)((unsigned)(ip->i_number >> imp->im_bshift)),
		      imp->logical_block_size, NOCRED, &bp);
	if (error) {
		buf_brelse(bp);
		return (EINVAL);
	}

	/*
	 * Setup the directory pointer for this inode
	 */
	dirp = (ISODIR *)(buf_dataptr(bp) + (ip->i_number & imp->im_bmask));

	/*
	 * Just make sure, we have a right one....
	 *   1: Check not cross boundary on block
	 */
	if ((ip->i_number & imp->im_bmask) + isonum_711(dirp->length)
	    > imp->logical_block_size) {
		buf_brelse(bp);
		return (EINVAL);
	}

	/*
	 * Now get a buffer
	 * Abuse a namei buffer for now.
	 */
	if (UIO_SEG_IS_USER_SPACE(uio->uio_segflg))
		MALLOC_ZONE(symname, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	else
		// LP64todo - fix this!
		symname = CAST_DOWN(caddr_t, uio_iov_base(uio));
	
	/*
	 * Ok, we just gathering a symbolic name in SL record.
	 */
	if (cd9660_rrip_getsymname(dirp, symname, &symlen, imp) == 0) {
		if (UIO_SEG_IS_USER_SPACE(uio->uio_segflg))
			FREE_ZONE(symname, MAXPATHLEN, M_NAMEI);
		buf_brelse(bp);
		return (EINVAL);
	}
	/*
	 * Don't forget before you leave from home ;-)
	 */
	buf_brelse(bp);

	/*
	 * return with the symbolic name to caller's.
	 */
	if (UIO_SEG_IS_USER_SPACE(uio->uio_segflg)) {
		error = uiomove(symname, symlen, uio);
		FREE_ZONE(symname, MAXPATHLEN, M_NAMEI);
		return (error);
	}
#if LP64KERN
	uio_setresid(uio, (uio_resid(uio) - symlen));
	uio_iov_len_add(uio, -((int64_t)symlen));
#else
	uio_setresid(uio, (uio_resid(uio) - symlen));
	uio_iov_len_add(uio, -((int)symlen));
#endif
	uio_iov_base_add(uio, symlen);
	return (0);
}


/*
 * prepare and issue the I/O
 */
int
cd9660_strategy(struct vnop_strategy_args *ap)
{
	buf_t	bp = ap->a_bp;
	vnode_t	vp = buf_vnode(bp);
	struct iso_node *ip = VTOI(vp);

	return (buf_strategy(ip->i_devvp, ap));
}


/*
 * Return POSIX pathconf information applicable to cd9660 filesystems.
 */
int
cd9660_pathconf(struct vnop_pathconf_args *ap)
{

	switch (ap->a_name) {
	case _PC_LINK_MAX:
		*ap->a_retval = 1;
		return (0);
	case _PC_NAME_MAX:
		switch (VTOI(ap->a_vp)->i_mnt->iso_ftype) {
		case ISO_FTYPE_RRIP:
			*ap->a_retval = ISO_RRIP_NAMEMAX;
			break;
		case ISO_FTYPE_JOLIET:
			*ap->a_retval = ISO_JOLIET_NAMEMAX;
			break;
		default:
			*ap->a_retval = ISO_NAMEMAX;
		}
		return (0);
	case _PC_PATH_MAX:
		*ap->a_retval = PATH_MAX;
		return (0);
	case _PC_PIPE_BUF:
		*ap->a_retval = PIPE_BUF;
		return (0);
	case _PC_CHOWN_RESTRICTED:
		*ap->a_retval = 1;
		return (0);
	case _PC_NO_TRUNC:
		*ap->a_retval = 1;
		return (0);
	default:
		return (EINVAL);
	}
	/* NOTREACHED */
}

/*
 * Unsupported operation
 */
int
cd9660_enotsupp(void)
{
	return (ENOTSUP);
}
/* Pagein. similar to read */
int
cd9660_pagein(struct vnop_pagein_args *ap)
{
	struct vnode *vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size = ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	register struct iso_node *ip = VTOI(vp);
	int error = 0;

	/*
	 * Copy the Apple Double header.
	 */
	if ((ip->i_flag & ISO_ASSOCIATED) && (f_offset == 0) && (size == ADH_SIZE)) {
		apple_double_header_t  header;
		kern_return_t  kret;
		vm_offset_t  ioaddr;

		kret = ubc_upl_map(pl, &ioaddr);
		if (kret != KERN_SUCCESS)
			panic("cd9660_xa_pagein: ubc_upl_map error = %d", kret);
		ioaddr += pl_offset;
		bzero((caddr_t)ioaddr, ADH_SIZE);

		header.magic = APPLEDOUBLE_MAGIC;
		header.version = APPLEDOUBLE_VERSION;
		header.count = 2;
		header.entries[0].entryID = APPLEDOUBLE_FINDERINFO;
		header.entries[0].offset = offsetof(apple_double_header_t, finfo);
		header.entries[0].length = 32;
		header.entries[1].entryID = APPLEDOUBLE_RESFORK;
		header.entries[1].offset = ADH_SIZE;
		header.entries[1].length = ip->i_size - ADH_SIZE;
		header.finfo.fdType = ip->i_FileType;
		header.finfo.fdCreator = ip->i_Creator;
		header.finfo.fdFlags = ip->i_FinderFlags;
		header.finfo.fdLocation.v = -1;
		header.finfo.fdLocation.h = -1;
		header.finfo.fdReserved = 0;

		bcopy((caddr_t)&header, (caddr_t)ioaddr, sizeof(apple_double_header_t));

		kret = ubc_upl_unmap(pl);
		if (kret != KERN_SUCCESS)
			panic("cd9660_xa_pagein: ubc_upl_unmap error = %d", kret);

		if ((flags & UPL_NOCOMMIT) == 0) {
			ubc_upl_commit_range(pl, pl_offset, size, UPL_COMMIT_FREE_ON_EMPTY);
		}
	} else {
		/* check pageouts are for reg file only  and ubc info is present*/
		if  (UBCINVALID(vp))
			panic("cd9660_pagein: Not a  VREG");
		UBCINFOCHECK("cd9660_pagein", vp);
	
		error = cluster_pagein(vp, pl, pl_offset, f_offset, size,
				       (off_t)ip->i_size, flags);
	}
	return (error);
}

/*  
 * cd9660_remove - not possible to remove a file from iso cds
 *  
 * Locking policy: a_dvp and vp locked on entry, unlocked on exit
 */ 
int 
cd9660_remove(__unused struct vnop_remove_args *ap)
{   
    return (EROFS);
}   


/*  
 * cd9660_rmdir - not possible to remove a directory from iso cds
 *  
 * Locking policy: a_dvp and vp locked on entry, unlocked on exit
 */ 
int 
cd9660_rmdir(struct vnop_rmdir_args *ap)
{   
    (void) nop_rmdir(ap);
    return (EROFS);
}   

/*

#
#% getattrlist	vp	= = =
#
 vnop_getattrlist {
     IN struct vnode *vp;
     IN struct attrlist *alist;
     INOUT struct uio *uio;
     IN vfs_context_t context;
 };

 */
int
cd9660_getattrlist(struct vnop_getattrlist_args *ap)
{
    struct attrlist *alist = ap->a_alist;
    int fixedblocksize;
    int attrblocksize;
    int attrbufsize;
    void *attrbufptr;
    void *attrptr;
    void *varptr;
    int error = 0;

	if ((alist->bitmapcount != ATTR_BIT_MAP_COUNT) ||
        ((alist->commonattr & ~ATTR_CMN_VALIDMASK) != 0) ||
        ((alist->volattr & ~ATTR_VOL_VALIDMASK) != 0) ||
        ((alist->dirattr & ~ATTR_DIR_VALIDMASK) != 0) ||
        ((alist->fileattr & ~ATTR_FILE_VALIDMASK) != 0) ||
        ((alist->forkattr & ~ATTR_FORK_VALIDMASK) != 0)) {
		return EINVAL;
	};

	/* 
	 * Requesting volume information requires setting the ATTR_VOL_INFO bit and
	 * volume info requests are mutually exclusive with all other info requests:
	 */
	if ((alist->volattr != 0) &&
		(((alist->volattr & ATTR_VOL_INFO) == 0) ||
		(alist->dirattr != 0) || 
		(alist->fileattr != 0) || 
		(alist->forkattr != 0) )) {
        return EINVAL;
	};

	/*
	 * Reject requests for unsupported options for now:
	 */
	if (alist->volattr & ATTR_VOL_MOUNTPOINT) return EINVAL;
	if (alist->commonattr & (ATTR_CMN_NAMEDATTRCOUNT | ATTR_CMN_NAMEDATTRLIST)) return EINVAL;
	if (alist->fileattr &
		(ATTR_FILE_FILETYPE |
		 ATTR_FILE_FORKCOUNT |
		 ATTR_FILE_FORKLIST |
		 ATTR_FILE_DATAEXTENTS |
		 ATTR_FILE_RSRCEXTENTS)) {
		return EINVAL;
	};


    fixedblocksize = attrcalcsize(alist);
    attrblocksize = fixedblocksize + (sizeof(uint32_t));                    /* uint32_t for length word */
    if (alist->commonattr & ATTR_CMN_NAME) attrblocksize += NAME_MAX;
    if (alist->commonattr & ATTR_CMN_NAMEDATTRLIST) attrblocksize += 0;			/* XXX PPD */
    if (alist->volattr & ATTR_VOL_MOUNTPOINT) attrblocksize += PATH_MAX;
    if (alist->volattr & ATTR_VOL_NAME) attrblocksize += NAME_MAX;
    if (alist->fileattr & ATTR_FILE_FORKLIST) attrblocksize += 0;				/* XXX PPD */

    attrbufsize = MIN(uio_resid(ap->a_uio), attrblocksize);
    MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);
    attrptr = attrbufptr;
    *((uint32_t *)attrptr) = 0;									/* Set buffer length in case of errors */
    ++((uint32_t *)attrptr);										/* Reserve space for length field */
    varptr = ((char *)attrptr) + fixedblocksize;				/* Point to variable-length storage */

	packattrblk(alist, ap->a_vp, &attrptr, &varptr);

    /* Store length of fixed + var block */
    *((uint32_t *)attrbufptr) = ((char*)varptr - (char*)attrbufptr);
    /* Don't copy out more data than was generated */
    attrbufsize = MIN(attrbufsize, (char*)varptr - (char*)attrbufptr);

    error = uiomove((caddr_t)attrbufptr, attrbufsize, ap->a_uio);

    FREE(attrbufptr, M_TEMP);

    return error;
}

/*
 * Make a RIFF file header for a CD-ROM XA media file.
 */
__private_extern__ void
cd9660_xa_init(struct iso_node *ip, struct iso_directory_record *isodir)
{
	uint32_t sectors;
	struct riff_header *header;
	u_char name_len;
	char *cdxa;
	
	MALLOC(header, struct riff_header *, sizeof(struct riff_header), M_TEMP, M_WAITOK);

	sectors = ip->i_size / 2048;

	strncpy(header->riff, "RIFF", 4);
	header->fileSize = NXSwapHostLongToLittle(sectors * CDXA_SECTOR_SIZE + sizeof(struct riff_header) - 8);
	strncpy(header->cdxa, "CDXA", 4);
	strncpy(header->fmt, "fmt ", 4);
	header->fmtSize = NXSwapHostLongToLittle(16);
	strncpy(header->data, "data", 4);
	header->dataSize = NXSwapHostLongToLittle(sectors * CDXA_SECTOR_SIZE);

	/*
	 * Copy the CD-ROM XA extended directory information into the header.  As far as
	 * I can tell, it's always 14 bytes in the directory record, but allocated 16 bytes
	 * in the header (the last two being zeroed pad bytes).
	 */
	name_len = isonum_711(isodir->name_len);
	cdxa = &isodir->name[name_len];
	if ((name_len & 0x01) == 0)
		++cdxa;		/* Skip pad byte */
	bcopy(cdxa, header->fmtData, 14);
	header->fmtData[14] = 0;
	header->fmtData[15] = 0;

	/*
	 * Point this i-node to the "whole sector" device instead of the normal
	 * device.  This allows cd9660_strategy to be ignorant of the block
	 * (sector) size.
	 */
	ip->i_devvp = ip->i_mnt->phys_devvp;

	ip->i_size = sectors * CDXA_SECTOR_SIZE + sizeof(struct riff_header);
	ip->i_riff = header;
}

/*
 * Helper routine for vnop_read and vnop_pagein of CD-ROM XA multimedia files.
 * This routine determines the physical location of the file, then reads
 * sectors directly from the device into a buffer.  It also handles inserting
 * the RIFF header at the beginning of the file.
 *
 * Exactly one of buffer or uio must be non-zero.  It will either bcopy to
 * buffer, or uiomove via uio.
 *
 * XXX Should this code be using buf_breadn and ip->i_lastr to support single-block
 * read-ahead?  Should we try more aggressive read-ahead like cluster_io does?
 *
 * XXX This could be made to do larger I/O to the device (reading all the
 * whole sectors directly into the buffer).  That would make the code more
 * complex, and the current code only adds 2.5% overhead compared to reading
 * from the device directly (at least on my test machine).
 */
static int
cd9660_xa_read_common(
	struct vnode *vp,
	off_t offset,
	size_t amount,
	caddr_t buffer,
	struct uio *uio)
{
	struct iso_node *ip = VTOI(vp);
	struct buf *bp;
	off_t diff;		/* number of bytes from offset to file's EOF */
	daddr_t block;	/* physical disk block containing offset */
	off_t sect_off;	/* starting offset into current sector */
	u_int count;	/* number of bytes to transfer in current block */
	int error=0;

	/*
	 * Copy any part of the RIFF header.
	 */
	if (offset < sizeof(struct riff_header)) {
		char *p;
		
		p = ((char *) ip->i_riff) + offset;
		count = min(amount, sizeof(struct riff_header) - offset);
		if (buffer) {
			bcopy(p, buffer, count);
			buffer += count;
		} else {
			error = uiomove(p, count, uio);
		}
		amount -= count;
		offset += count;
	}
	if (error)
		return error;

	/*
	 * Loop over (possibly partial) blocks to transfer.
	 */
	while (error == 0 && amount > 0) {
		/*
		 * Determine number of bytes until EOF.  If we've hit
		 * EOF then return.
		 */
		diff = ip->i_size - offset;
		if (diff <= 0)
			return 0;

		/* Get a block from the underlying device */
		block = ip->iso_start + (offset - sizeof(struct riff_header))/CDXA_SECTOR_SIZE;
		error = (int)buf_bread(ip->i_devvp, (daddr64_t)((unsigned)block), CDXA_SECTOR_SIZE, NOCRED, &bp);
		if (error) {
			buf_brelse(bp);
			return error;
		}
		if (buf_resid(bp)) {
			printf("isofs: cd9660_xa_read_common: buf_bread didn't read full sector\n");
			return EIO;
		}
		
		/* Figure out which part of the block to copy, and copy it */
		sect_off = (offset - sizeof(struct riff_header)) % CDXA_SECTOR_SIZE;
		count = min(CDXA_SECTOR_SIZE-sect_off, amount);
		if (diff < count)	/* Pin transfer amount to EOF */
			count = diff;
		
		if (buffer) {
			bcopy(CAST_DOWN(caddr_t, (buf_dataptr(bp)+sect_off)), buffer, count);
			buffer += count;
		} else {
			error = uiomove(CAST_DOWN(caddr_t, (buf_dataptr(bp)+sect_off)), count, uio);
		}
		amount -= count;
		offset += count;
		
		/*
		 * If we copied through the end of the block, or the end of file, then
		 * age the device block.  This is optimized for sequential access.
		 */
		if (sect_off+count == CDXA_SECTOR_SIZE || offset == (off_t)ip->i_size)
			buf_markaged(bp);
		buf_brelse(bp);
	}

	return error;
}

/*
 * Read from a CD-ROM XA multimedia file.
 *
 * This uses the same common routine as pagein for doing the actual read
 * from the device.
 *
 * This routine doesn't do any caching beyond what the block device does.
 * Even then, cd9660_xa_read_common ages the blocks once we read up to
 * the end.
 *
 * We don't even take advantage if the file has been memory mapped and has
 * valid pages already (in which case we could just uiomove from the page
 * to the caller).  Since we're a read-only filesystem, there can't be
 * any cache coherency problems.  Multimedia files are expected to be
 * large and streamed anyway, so caching file contents probably isn't
 * important.
 */
int
cd9660_xa_read(struct vnop_read_args *ap)
{
	struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
	register struct iso_node *ip = VTOI(vp);
	off_t offset = uio->uio_offset;
	// LP64todo - fix this!
	size_t size = uio_resid(uio);

	/* Check for some obvious parameter problems */
	if (offset < 0)
		return EINVAL;
	if (size == 0)
		return 0;
	if (offset >= ip->i_size)
		return 0;

	/* Pin the size of the read to the file's EOF */
	if (offset + size > ip->i_size)
		size = ip->i_size - offset;

	return cd9660_xa_read_common(vp, offset, size, NULL, uio);
}

/*
 * Page in from a CD-ROM XA media file.
 *
 * Since our device block size isn't a power of two, we can't use
 * cluster_pagein.  Instead, we have to map the page and read into it.
 */
static int
cd9660_xa_pagein(struct vnop_pagein_args *ap)
{
	struct vnode *vp = ap->a_vp;
	upl_t pl = ap->a_pl;
	size_t size= ap->a_size;
	off_t f_offset = ap->a_f_offset;
	vm_offset_t pl_offset = ap->a_pl_offset;
	int flags  = ap->a_flags;
	register struct iso_node *ip = VTOI(vp);
	int error;
    kern_return_t kret;
    vm_offset_t ioaddr;

	/* check pageins are for reg file only  and ubc info is present*/
	if  (UBCINVALID(vp))
		panic("cd9660_xa_pagein: Not a  VREG");
	UBCINFOCHECK("cd9660_xa_pagein", vp);

	if (size <= 0)
		panic("cd9660_xa_pagein: size = %d", size);

	kret = ubc_upl_map(pl, &ioaddr);
	if (kret != KERN_SUCCESS)
		panic("cd9660_xa_pagein: ubc_upl_map error = %d", kret);

	ioaddr += pl_offset;

	/* Make sure pagein doesn't extend past EOF */
	if (f_offset + size > ip->i_size)
		size = ip->i_size - f_offset;	/* pin size to EOF */

	/* Read the data in using the underlying device */
	error = cd9660_xa_read_common(vp, f_offset, size, (caddr_t)ioaddr, NULL);
	
	/* Zero fill part of page past EOF */
	if (ap->a_size > size)
		bzero((caddr_t)ioaddr+size, ap->a_size-size);

	kret = ubc_upl_unmap(pl);
	if (kret != KERN_SUCCESS)
		panic("cd9660_xa_pagein: ubc_upl_unmap error = %d", kret);

	if ((flags & UPL_NOCOMMIT) == 0)
	{
		if (error)
			ubc_upl_abort_range(pl, pl_offset, ap->a_size, UPL_ABORT_FREE_ON_EMPTY);
		else
			ubc_upl_commit_range(pl, pl_offset, ap->a_size, UPL_COMMIT_FREE_ON_EMPTY);
	}
	
	return error;
}

/*
 * Global vfs data structures for isofs
 */
#define cd9660_create \
	((int (*)(struct  vnop_create_args *))err_create)
#define cd9660_mknod ((int (*)(struct  vnop_mknod_args *))err_mknod)
#define cd9660_write ((int (*)(struct  vnop_write_args *))cd9660_enotsupp)
#define cd9660_fsync ((int (*)(struct  vnop_fsync_args *))nullop)
#define cd9660_rename \
	((int (*)(struct  vnop_rename_args *))err_rename)
#define cd9660_copyfile \
	((int (*)(struct  vnop_copyfile_args *))err_copyfile)
#define cd9660_link ((int (*)(struct  vnop_link_args *))err_link)
#define cd9660_mkdir ((int (*)(struct  vnop_mkdir_args *))err_mkdir)
#define cd9660_symlink \
	((int (*)(struct vnop_symlink_args *))err_symlink)
#define cd9660_advlock \
	((int (*)(struct vnop_advlock_args *))cd9660_enotsupp)
#define cd9660_bwrite \
	((int (*)(struct  vnop_bwrite_args *))cd9660_enotsupp)
#define cd9660_pageout \
	((int (*)(struct  vnop_pageout_args *))cd9660_enotsupp)
int cd9660_blktooff(struct vnop_blktooff_args *ap);
int cd9660_offtoblk(struct vnop_offtoblk_args *ap);
int cd9660_blockmap(struct vnop_blockmap_args *ap);

#define VOPFUNC int (*)(void *)
/*
 * Global vfs data structures for cd9660
 */
int (**cd9660_vnodeop_p)(void *);
struct vnodeopv_entry_desc cd9660_vnodeop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)cd9660_lookup },	/* lookup */
	{ &vnop_create_desc, (VOPFUNC)cd9660_create },	/* create */
	{ &vnop_mknod_desc, (VOPFUNC)cd9660_mknod },	/* mknod */
	{ &vnop_open_desc, (VOPFUNC)cd9660_open },	/* open */
	{ &vnop_close_desc, (VOPFUNC)cd9660_close },	/* close */
	{ &vnop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vnop_read_desc, (VOPFUNC)cd9660_read },	/* read */
	{ &vnop_write_desc, (VOPFUNC)cd9660_write },	/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)cd9660_ioctl },	/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)cd9660_select },	/* select */
	{ &vnop_mmap_desc, (VOPFUNC)cd9660_mmap },	/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)cd9660_fsync },	/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)cd9660_remove },	/* remove */
	{ &vnop_link_desc, (VOPFUNC)cd9660_link },	/* link */
	{ &vnop_rename_desc, (VOPFUNC)cd9660_rename },	/* rename */
	{ &vnop_copyfile_desc, (VOPFUNC)cd9660_copyfile },/* copyfile */
	{ &vnop_mkdir_desc, (VOPFUNC)cd9660_mkdir },	/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)cd9660_rmdir },	/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)cd9660_symlink },	/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)cd9660_readdir },	/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)cd9660_readlink },/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)cd9660_strategy },/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)cd9660_pathconf },/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)cd9660_advlock },	/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)cd9660_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vnop_getattrlist_desc, (VOPFUNC)cd9660_getattrlist },	/* getattrlist */
	{ &vnop_blktooff_desc, (VOPFUNC)cd9660_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)cd9660_offtoblk },	/* offtoblk */
  	{ &vnop_blockmap_desc, (VOPFUNC)cd9660_blockmap },		/* blockmap */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_vnodeop_opv_desc =
	{ &cd9660_vnodeop_p, cd9660_vnodeop_entries };

/*
 * The VOP table for CD-ROM XA (media) files is almost the same
 * as for ordinary files, except for read, and pagein.
 * Note that cd9660_xa_read doesn't use cluster I/O, so blockmap
 * isn't needed, and isn't implemented.  Similarly, it doesn't
 * do buf_bread() on CD XA vnodes, so bmap, blktooff, offtoblk
 * aren't needed.
 */
int (**cd9660_cdxaop_p)(void *);
struct vnodeopv_entry_desc cd9660_cdxaop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)cd9660_lookup },	/* lookup */
	{ &vnop_create_desc, (VOPFUNC)cd9660_create },	/* create */
	{ &vnop_mknod_desc, (VOPFUNC)cd9660_mknod },	/* mknod */
	{ &vnop_open_desc, (VOPFUNC)cd9660_open },	/* open */
	{ &vnop_close_desc, (VOPFUNC)cd9660_close },	/* close */
	{ &vnop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vnop_read_desc, (VOPFUNC)cd9660_xa_read },	/* read */
	{ &vnop_write_desc, (VOPFUNC)cd9660_write },	/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)cd9660_ioctl },	/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)cd9660_select },	/* select */
	{ &vnop_mmap_desc, (VOPFUNC)cd9660_mmap },	/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)cd9660_fsync },	/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)cd9660_remove },	/* remove */
	{ &vnop_link_desc, (VOPFUNC)cd9660_link },	/* link */
	{ &vnop_rename_desc, (VOPFUNC)cd9660_rename },	/* rename */
	{ &vnop_copyfile_desc, (VOPFUNC)cd9660_copyfile },/* copyfile */
	{ &vnop_mkdir_desc, (VOPFUNC)cd9660_mkdir },	/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)cd9660_rmdir },	/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)cd9660_symlink },	/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)cd9660_readdir },	/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)cd9660_readlink },/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)cd9660_strategy },/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)cd9660_pathconf },/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)cd9660_advlock },	/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)cd9660_xa_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vnop_getattrlist_desc, (VOPFUNC)cd9660_getattrlist },	/* getattrlist */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_cdxaop_opv_desc =
	{ &cd9660_cdxaop_p, cd9660_cdxaop_entries };

/*
 * Special device vnode ops
 */
int (**cd9660_specop_p)(void *);
struct vnodeopv_entry_desc cd9660_specop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)spec_lookup },	/* lookup */
	{ &vnop_create_desc, (VOPFUNC)spec_create },	/* create */
	{ &vnop_mknod_desc, (VOPFUNC)spec_mknod },	/* mknod */
	{ &vnop_open_desc, (VOPFUNC)spec_open },		/* open */
	{ &vnop_close_desc, (VOPFUNC)spec_close },	/* close */
	{ &vnop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vnop_read_desc, (VOPFUNC)spec_read },		/* read */
	{ &vnop_write_desc, (VOPFUNC)spec_write },	/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)spec_ioctl },	/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)spec_select },	/* select */
	{ &vnop_mmap_desc, (VOPFUNC)spec_mmap },		/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)spec_fsync },	/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)spec_remove },	/* remove */
	{ &vnop_link_desc, (VOPFUNC)spec_link },		/* link */
	{ &vnop_rename_desc, (VOPFUNC)spec_rename },	/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)spec_mkdir },	/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)spec_rmdir },	/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)spec_symlink },	/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)spec_readdir },	/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)spec_readlink },	/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)spec_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)spec_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)spec_advlock },	/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_devblocksize_desc, (VOPFUNC)spec_devblocksize }, /* devblocksize */
	{ &vnop_pagein_desc, (VOPFUNC)cd9660_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vnop_blktooff_desc, (VOPFUNC)cd9660_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)cd9660_offtoblk },	/* offtoblk */
  	{ &vnop_blockmap_desc, (VOPFUNC)cd9660_blockmap },		/* blockmap */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_specop_opv_desc =
	{ &cd9660_specop_p, cd9660_specop_entries };

#if FIFO
int (**cd9660_fifoop_p)(void *);
struct vnodeopv_entry_desc cd9660_fifoop_entries[] = {
	{ &vnop_default_desc, (VOPFUNC)vn_default_error },
	{ &vnop_lookup_desc, (VOPFUNC)fifo_lookup },	/* lookup */
	{ &vnop_create_desc, (VOPFUNC)fifo_create },	/* create */
	{ &vnop_mknod_desc, (VOPFUNC)fifo_mknod },	/* mknod */
	{ &vnop_open_desc, (VOPFUNC)fifo_open },		/* open */
	{ &vnop_close_desc, (VOPFUNC)fifo_close },	/* close */
	{ &vnop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vnop_read_desc, (VOPFUNC)fifo_read },		/* read */
	{ &vnop_write_desc, (VOPFUNC)fifo_write },	/* write */
	{ &vnop_ioctl_desc, (VOPFUNC)fifo_ioctl },	/* ioctl */
	{ &vnop_select_desc, (VOPFUNC)fifo_select },	/* select */
	{ &vnop_mmap_desc, (VOPFUNC)fifo_mmap },		/* mmap */
	{ &vnop_fsync_desc, (VOPFUNC)fifo_fsync },	/* fsync */
	{ &vnop_remove_desc, (VOPFUNC)fifo_remove },	/* remove */
	{ &vnop_link_desc, (VOPFUNC)fifo_link }	,	/* link */
	{ &vnop_rename_desc, (VOPFUNC)fifo_rename },	/* rename */
	{ &vnop_mkdir_desc, (VOPFUNC)fifo_mkdir },	/* mkdir */
	{ &vnop_rmdir_desc, (VOPFUNC)fifo_rmdir },	/* rmdir */
	{ &vnop_symlink_desc, (VOPFUNC)fifo_symlink },	/* symlink */
	{ &vnop_readdir_desc, (VOPFUNC)fifo_readdir },	/* readdir */
	{ &vnop_readlink_desc, (VOPFUNC)fifo_readlink },	/* readlink */
	{ &vnop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vnop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vnop_strategy_desc, (VOPFUNC)fifo_strategy },	/* strategy */
	{ &vnop_pathconf_desc, (VOPFUNC)fifo_pathconf },	/* pathconf */
	{ &vnop_advlock_desc, (VOPFUNC)fifo_advlock },	/* advlock */
	{ &vnop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vnop_pagein_desc, (VOPFUNC)cd9660_pagein },		/* Pagein */
	{ &vnop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vnop_blktooff_desc, (VOPFUNC)cd9660_blktooff },	/* blktooff */
	{ &vnop_offtoblk_desc, (VOPFUNC)cd9660_offtoblk },	/* offtoblk */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_fifoop_opv_desc =
	{ &cd9660_fifoop_p, cd9660_fifoop_entries };
#endif /* FIFO */
