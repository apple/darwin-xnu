/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
#include <sys/conf.h>
#include <miscfs/specfs/specdev.h>
#include <miscfs/fifofs/fifo.h>
#include <sys/malloc.h>
#include <sys/dir.h>
#include <sys/attr.h>
#include <vfs/vfs_support.h>
#include <sys/ubc.h>
#include <sys/lock.h>
#include <architecture/byte_order.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/cd9660_node.h>
#include <isofs/cd9660/iso_rrip.h>

/*
 * Open called.
 *
 * Nothing to do.
 */
/* ARGSUSED */
int
cd9660_open(ap)
	struct vop_open_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	return (0);
}

/*
 * Close called
 *
 * Update the times on the inode on writeable file systems.
 */
/* ARGSUSED */
int
cd9660_close(ap)
	struct vop_close_args /* {
		struct vnode *a_vp;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	return (0);
}

/*
 * Check mode permission on inode pointer. Mode is READ, WRITE or EXEC.
 * The mode is shifted to select the owner/group/other fields. The
 * super user is granted all permissions.
 */
/* ARGSUSED */
int
cd9660_access(ap)
	struct vop_access_args /* {
		struct vnode *a_vp;
		int  a_mode;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	struct iso_node *ip = VTOI(vp);
	struct ucred *cred = ap->a_cred;
	mode_t mask, mode = ap->a_mode;
	register gid_t *gp;
	int i, error;

	/*
	 * Disallow write attempts on read-only file systems;
	 * unless the file is a socket, fifo, or a block or
	 * character device resident on the file system.
	 */
	if (mode & VWRITE) {
		switch (vp->v_type) {
		case VDIR:
		case VLNK:
		case VREG:
			return (EROFS);
			/* NOT REACHED */
		default:
			break;
		}
	}

	/* If immutable bit set, nobody gets to write it. */
#if 0
	if ((mode & VWRITE) && (ip->i_flag & IMMUTABLE))
		return (EPERM);
#endif
	/* Otherwise, user id 0 always gets access. */
	if (cred->cr_uid == 0)
		return (0);

	mask = 0;

	/* Otherwise, check the owner. */
	if (cred->cr_uid == ip->inode.iso_uid) {
		if (mode & VEXEC)
			mask |= S_IXUSR;
		if (mode & VREAD)
			mask |= S_IRUSR;
		if (mode & VWRITE)
			mask |= S_IWUSR;
		return ((ip->inode.iso_mode & mask) == mask ? 0 : EACCES);
	}

	/* Otherwise, check the groups. */
	for (i = 0, gp = cred->cr_groups; i < cred->cr_ngroups; i++, gp++)
		if (ip->inode.iso_gid == *gp) {
			if (mode & VEXEC)
				mask |= S_IXGRP;
			if (mode & VREAD)
				mask |= S_IRGRP;
			if (mode & VWRITE)
				mask |= S_IWGRP;
			return ((ip->inode.iso_mode & mask) == mask ? 0 : EACCES);
		}

	/* Otherwise, check everyone else. */
	if (mode & VEXEC)
		mask |= S_IXOTH;
	if (mode & VREAD)
		mask |= S_IROTH;
	if (mode & VWRITE)
		mask |= S_IWOTH;
	return ((ip->inode.iso_mode & mask) == mask ? 0 : EACCES);
}

int
cd9660_getattr(ap)
	struct vop_getattr_args /* {
		struct vnode *a_vp;
		struct vattr *a_vap;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;

{
	struct vnode *vp = ap->a_vp;
	register struct vattr *vap = ap->a_vap;
	register struct iso_node *ip = VTOI(vp);

	vap->va_fsid	= ip->i_dev;
	vap->va_fileid	= ip->i_number;

	vap->va_mode	= ip->inode.iso_mode;
	vap->va_nlink	= ip->inode.iso_links;
	vap->va_uid	= ip->inode.iso_uid;
	vap->va_gid	= ip->inode.iso_gid;
	vap->va_atime	= ip->inode.iso_atime;
	vap->va_mtime	= ip->inode.iso_mtime;
	vap->va_ctime	= ip->inode.iso_ctime;
	vap->va_rdev	= ip->inode.iso_rdev;

	vap->va_size	= (u_quad_t) ip->i_size;
	if (ip->i_size == 0 && (vap->va_mode & S_IFMT) == S_IFLNK) {
		struct vop_readlink_args rdlnk;
		struct iovec aiov;
		struct uio auio;
		char *cp;

		MALLOC(cp, char *, MAXPATHLEN, M_TEMP, M_WAITOK);
		aiov.iov_base = cp;
		aiov.iov_len = MAXPATHLEN;
		auio.uio_iov = &aiov;
		auio.uio_iovcnt = 1;
		auio.uio_offset = 0;
		auio.uio_rw = UIO_READ;
		auio.uio_segflg = UIO_SYSSPACE;
		auio.uio_procp = ap->a_p;
		auio.uio_resid = MAXPATHLEN;
		rdlnk.a_uio = &auio;
		rdlnk.a_vp = ap->a_vp;
		rdlnk.a_cred = ap->a_cred;
		if (cd9660_readlink(&rdlnk) == 0)
			vap->va_size = MAXPATHLEN - auio.uio_resid;
		FREE(cp, M_TEMP);
	}
	vap->va_flags = 0;
	vap->va_gen = 1;
	vap->va_blocksize = ip->i_mnt->logical_block_size;
	vap->va_bytes = (u_quad_t) (ip->i_size + ip->i_rsrcsize);
	vap->va_type = vp->v_type;

	return (0);
}


/*
 * Vnode op for reading.
 */
int
cd9660_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
	register struct iso_node *ip = VTOI(vp);
	register struct iso_mnt *imp;
	struct buf *bp;
	daddr_t lbn, rablock;
	off_t diff;
	int rasize, error = 0;
	long size, n, on;
	int devBlockSize = 0;

	if (uio->uio_resid == 0)
		return (0);
	if (uio->uio_offset < 0)
		return (EINVAL);

	imp = ip->i_mnt;
	VOP_DEVBLOCKSIZE(ip->i_devvp, &devBlockSize);

	if (UBCISVALID(vp)) {
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

				bytes = min(uio->uio_resid, sizeof(apple_double_header_t) - uio->uio_offset);
				error = uiomove(((char *) &header) + uio->uio_offset, bytes, uio);
				if (error)
					return error;
			}
			if (uio->uio_resid && uio->uio_offset < ADH_SIZE) {
				caddr_t  buffer;

				if (kmem_alloc(kernel_map, (vm_offset_t *)&buffer, ADH_SIZE)) {
					return (ENOMEM);
				}	
				bytes = min(uio->uio_resid, ADH_SIZE - uio->uio_offset);
				error = uiomove(((char *) buffer) + uio->uio_offset, bytes, uio);
				kmem_free(kernel_map, (vm_offset_t)buffer, ADH_SIZE);
				if (error)
					return error;
			}
		}
		if (uio->uio_resid > 0)
			error = cluster_read(vp, uio, (off_t)ip->i_size, devBlockSize, 0);
	} else {

	do {
		lbn = lblkno(imp, uio->uio_offset);
		on = blkoff(imp, uio->uio_offset);
		n = min((u_int)(imp->logical_block_size - on),
			uio->uio_resid);
		diff = (off_t)ip->i_size - uio->uio_offset;
		if (diff <= 0)
			return (0);
		if (diff < n)
			n = diff;
		size = blksize(imp, ip, lbn);
		rablock = lbn + 1;

		if (vp->v_lastr + 1 == lbn &&
		    lblktosize(imp, rablock) < ip->i_size) {
		        rasize = blksize(imp, ip, rablock);
			error = breadn(vp, lbn, size, &rablock,
				       &rasize, 1, NOCRED, &bp);
		} else
		        error = bread(vp, lbn, size, NOCRED, &bp);

		vp->v_lastr = lbn;
		n = min(n, size - bp->b_resid);
		if (error) {
			brelse(bp);
			return (error);
		}

		error = uiomove(bp->b_data + on, (int)n, uio);
		if (n + on == imp->logical_block_size ||
		    uio->uio_offset == (off_t)ip->i_size)
			bp->b_flags |= B_AGE;
		brelse(bp);
	} while (error == 0 && uio->uio_resid > 0 && n != 0);
	}

	return (error);
}

/* ARGSUSED */
int
cd9660_ioctl(ap)
	struct vop_ioctl_args /* {
		struct vnode *a_vp;
		u_long a_command;
		caddr_t  a_data;
		int  a_fflag;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{
	return (ENOTTY);
}

/* ARGSUSED */
int
cd9660_select(ap)
	struct vop_select_args /* {
		struct vnode *a_vp;
		int  a_which;
		int  a_fflags;
		struct ucred *a_cred;
		void *a_wql;
		struct proc *a_p;
	} */ *ap;
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
/* ARGSUSED */
int
cd9660_mmap(ap)
	struct vop_mmap_args /* {
		struct vnode *a_vp;
		int  a_fflags;
		struct ucred *a_cred;
		struct proc *a_p;
	} */ *ap;
{

	return (EINVAL);
}

/*
 * Seek on a file
 *
 * Nothing to do, so just return.
 */
/* ARGSUSED */
int
cd9660_seek(ap)
	struct vop_seek_args /* {
		struct vnode *a_vp;
		off_t  a_oldoff;
		off_t  a_newoff;
		struct ucred *a_cred;
	} */ *ap;
{

	return (0);
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
iso_uiodir(idp,dp,off)
	struct isoreaddir *idp;
	struct dirent *dp;
	off_t off;
{
	int error;

	dp->d_name[dp->d_namlen] = 0;
	dp->d_reclen = DIRSIZ(dp);

	if (idp->uio->uio_resid < dp->d_reclen) {
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
iso_shipdir(idp)
	struct isoreaddir *idp;
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
cd9660_readdir(ap)
	struct vop_readdir_args /* {
		struct vnodeop_desc *a_desc;
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
		int *a_eofflag;
		int *a_ncookies;
		u_long **a_cookies;
	} */ *ap;
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
	u_long bmask;
	int error = 0;
	int reclen;
	u_short namelen;

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
	    (error = VOP_BLKATOFF(vdp, SECTOFF(imp, idp->curroff), NULL, &bp))) {
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
				brelse(bp);
			if ((error = VOP_BLKATOFF(vdp, SECTOFF(imp, idp->curroff), NULL, &bp)))
				break;
			entryoffsetinblock = 0;
		}
		/*
		 * Get pointer to next entry.
		 */
		ep = (struct iso_directory_record *)
			((char *)bp->b_data + entryoffsetinblock);

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
			idp->current.d_fileno = (bp->b_blkno << imp->im_bshift) +
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

	if (!error && ap->a_ncookies) {
		struct dirent *dp, *dpstart;
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
		if (uio->uio_segflg != UIO_SYSSPACE || uio->uio_iovcnt != 1)
			panic("ufs_readdir: lost in space");
		
		/*
		 * Make a first pass over the buffer just generated,
		 * counting the number of entries:
		 */
		dpstart = (struct dirent *) (uio->uio_iov->iov_base - (uio->uio_offset - startingOffset));
		for (dp = dpstart, bufferOffset = startingOffset, ncookies = 0;
		     bufferOffset < uio->uio_offset; ) {
			if (dp->d_reclen == 0)
				break;
			bufferOffset += dp->d_reclen;
			ncookies++;
			dp = (struct dirent *)((caddr_t)dp + dp->d_reclen);
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
		for (bufferOffset = startingOffset, dp = dpstart; bufferOffset < uio->uio_offset; ) {
			*(cookies++) = bufferOffset;
			bufferOffset += dp->d_reclen;
			dp = (struct dirent *)((caddr_t)dp + dp->d_reclen);
		}
	}

	if (error < 0)
		error = 0;

	if (bp)
		brelse (bp);

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
cd9660_readlink(ap)
	struct vop_readlink_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		struct ucred *a_cred;
	} */ *ap;
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
	error = bread(imp->im_devvp,
			  (ip->i_number >> imp->im_bshift),
		      imp->logical_block_size, NOCRED, &bp);
	if (error) {
		brelse(bp);
		return (EINVAL);
	}

	/*
	 * Setup the directory pointer for this inode
	 */
	dirp = (ISODIR *)(bp->b_data + (ip->i_number & imp->im_bmask));

	/*
	 * Just make sure, we have a right one....
	 *   1: Check not cross boundary on block
	 */
	if ((ip->i_number & imp->im_bmask) + isonum_711(dirp->length)
	    > imp->logical_block_size) {
		brelse(bp);
		return (EINVAL);
	}

	/*
	 * Now get a buffer
	 * Abuse a namei buffer for now.
	 */
	if (uio->uio_segflg == UIO_SYSSPACE)
		symname = uio->uio_iov->iov_base;
	else
		MALLOC_ZONE(symname, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	
	/*
	 * Ok, we just gathering a symbolic name in SL record.
	 */
	if (cd9660_rrip_getsymname(dirp, symname, &symlen, imp) == 0) {
		if (uio->uio_segflg != UIO_SYSSPACE)
			FREE_ZONE(symname, MAXPATHLEN, M_NAMEI);
		brelse(bp);
		return (EINVAL);
	}
	/*
	 * Don't forget before you leave from home ;-)
	 */
	brelse(bp);

	/*
	 * return with the symbolic name to caller's.
	 */
	if (uio->uio_segflg != UIO_SYSSPACE) {
		error = uiomove(symname, symlen, uio);
		FREE_ZONE(symname, MAXPATHLEN, M_NAMEI);
		return (error);
	}
	uio->uio_resid -= symlen;
	uio->uio_iov->iov_base += symlen;
	uio->uio_iov->iov_len -= symlen;
	return (0);
}

/*
 * Lock an inode.
 */
 
int
cd9660_lock(ap)
	struct vop_lock_args /* {
		struct vnode *a_vp;
		int a_flags;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	if (VTOI(vp) == (struct iso_node *) NULL)
		panic ("cd9660_lock: null inode");
	return (lockmgr(&VTOI(vp)->i_lock, ap->a_flags, &vp->v_interlock,ap->a_p));
}

/*
 * Unlock an inode.
 */

int
cd9660_unlock(ap)
	struct vop_unlock_args /* {
		struct vnode *a_vp;
		int a_flags;
		struct proc *a_p;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;

	return (lockmgr(&VTOI(vp)->i_lock, ap->a_flags | LK_RELEASE, &vp->v_interlock,ap->a_p));

}

/*
 * Calculate the logical to physical mapping if not done already,
 * then call the device strategy routine.
 */
int
cd9660_strategy(ap)
	struct vop_strategy_args /* {
		struct buf *a_bp;
	} */ *ap;
{
	register struct buf *bp = ap->a_bp;
	register struct vnode *vp = bp->b_vp;
	register struct iso_node *ip;
	int error;

	ip = VTOI(vp);
	if (vp->v_type == VBLK || vp->v_type == VCHR)
		panic("cd9660_strategy: spec");
	if (bp->b_blkno == bp->b_lblkno) {
		if ( (error = VOP_BMAP(vp, bp->b_lblkno, NULL, &bp->b_blkno, NULL)) ) {
			bp->b_error = error;
			bp->b_flags |= B_ERROR;
			biodone(bp);
			return (error);
		}
		if ((long)bp->b_blkno == -1)
			clrbuf(bp);
	}
	if ((long)bp->b_blkno == -1) {
		biodone(bp);
		return (0);
	}
	vp = ip->i_devvp;
	bp->b_dev = vp->v_rdev;
	VOCALL (vp->v_op, VOFFSET(vop_strategy), ap);
	return (0);
}

/*
 * Print out the contents of an inode.
 */
int
cd9660_print(ap)
	struct vop_print_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	printf("tag VT_ISOFS, isofs vnode\n");
	return (0);
}

/*
 * Check for a locked inode.
 */
int
cd9660_islocked(ap)
	struct vop_islocked_args /* {
		struct vnode *a_vp;
	} */ *ap;
{

	return (lockstatus(&VTOI(ap->a_vp)->i_lock));
}

/*
 * Return POSIX pathconf information applicable to cd9660 filesystems.
 */
int
cd9660_pathconf(ap)
	struct vop_pathconf_args /* {
		struct vnode *a_vp;
		int a_name;
		register_t *a_retval;
	} */ *ap;
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
cd9660_enotsupp()
{

	return (EOPNOTSUPP);
}
/* Pagein. similar to read */
int
cd9660_pagein(ap)
	struct vop_pagein_args /* {
	   	struct vnode 	*a_vp,
	   	upl_t		a_pl,
		vm_offset_t	a_pl_offset,
		off_t		a_f_offset,
		size_t		a_size,
		struct ucred	*a_cred,
		int		a_flags
	} */ *ap;
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
		int devBlockSize = 0;

		/* check pageouts are for reg file only  and ubc info is present*/
		if  (UBCINVALID(vp))
			panic("cd9660_pagein: Not a  VREG");
		UBCINFOCHECK("cd9660_pagein", vp);
	
		VOP_DEVBLOCKSIZE(ip->i_devvp, &devBlockSize);

		error = cluster_pagein(vp, pl, pl_offset, f_offset, size,
			    (off_t)ip->i_size, devBlockSize, flags);
	}
	return (error);
}

/*  
 * cd9660_remove - not possible to remove a file from iso cds
 *  
 * Locking policy: a_dvp and vp locked on entry, unlocked on exit
 */ 
int 
cd9660_remove(ap)
    struct vop_remove_args      /* { struct vnode *a_dvp; struct vnode *a_vp;
        struct componentname *a_cnp; } */ *ap;  
{   
    if (ap->a_dvp == ap->a_vp)
                vrele(ap->a_vp);
        else
                vput(ap->a_vp);
	vput(ap->a_dvp);

    return (EROFS);
}   


/*  
 * cd9660_rmdir - not possible to remove a directory from iso cds
 *  
 * Locking policy: a_dvp and vp locked on entry, unlocked on exit
 */ 
int 
cd9660_rmdir(ap)
    struct vop_rmdir_args      /* { struct vnode *a_dvp; struct vnode *a_vp;
        struct componentname *a_cnp; } */ *ap;  
{   
    (void) nop_rmdir(ap);
    return (EROFS);
}   

/*

#
#% getattrlist	vp	= = =
#
 vop_getattrlist {
     IN struct vnode *vp;
     IN struct attrlist *alist;
     INOUT struct uio *uio;
     IN struct ucred *cred;
     IN struct proc *p;
 };

 */
int
cd9660_getattrlist(ap)
	struct vop_getattrlist_args /* {
	struct vnode *a_vp;
	struct attrlist *a_alist
	struct uio *a_uio;
	struct ucred *a_cred;
	struct proc *a_p;
	} */ *ap;
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
    attrblocksize = fixedblocksize + (sizeof(u_long));							/* u_long for length longword */
    if (alist->commonattr & ATTR_CMN_NAME) attrblocksize += NAME_MAX;
    if (alist->commonattr & ATTR_CMN_NAMEDATTRLIST) attrblocksize += 0;			/* XXX PPD */
    if (alist->volattr & ATTR_VOL_MOUNTPOINT) attrblocksize += PATH_MAX;
    if (alist->volattr & ATTR_VOL_NAME) attrblocksize += NAME_MAX;
    if (alist->fileattr & ATTR_FILE_FORKLIST) attrblocksize += 0;				/* XXX PPD */

    attrbufsize = MIN(ap->a_uio->uio_resid, attrblocksize);
    MALLOC(attrbufptr, void *, attrblocksize, M_TEMP, M_WAITOK);
    attrptr = attrbufptr;
    *((u_long *)attrptr) = 0;									/* Set buffer length in case of errors */
    ++((u_long *)attrptr);										/* Reserve space for length field */
    varptr = ((char *)attrptr) + fixedblocksize;				/* Point to variable-length storage */

	packattrblk(alist, ap->a_vp, &attrptr, &varptr);

    /* Store length of fixed + var block */
    *((u_long *)attrbufptr) = ((char*)varptr - (char*)attrbufptr);
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
cd9660_xa_init(struct vnode *vp, struct iso_directory_record *isodir)
{
	u_long sectors;
	struct iso_node *ip = VTOI(vp);
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
	vrele(ip->i_devvp);
	ip->i_devvp = ip->i_mnt->phys_devvp;
	VREF(ip->i_devvp);

	ip->i_size = sectors * CDXA_SECTOR_SIZE + sizeof(struct riff_header);
	ip->i_riff = header;
	vp->v_op = cd9660_cdxaop_p;
}

/*
 * Helper routine for VOP_READ and VOP_PAGEIN of CD-ROM XA multimedia files.
 * This routine determines the physical location of the file, then reads
 * sectors directly from the device into a buffer.  It also handles inserting
 * the RIFF header at the beginning of the file.
 *
 * Exactly one of buffer or uio must be non-zero.  It will either bcopy to
 * buffer, or uiomove via uio.
 *
 * XXX Should this code be using breadn and vp->v_lastr to support single-block
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
		error = bread(ip->i_devvp, block, CDXA_SECTOR_SIZE, NOCRED, &bp);
		if (error) {
			brelse(bp);
			return error;
		}
		if (bp->b_resid) {
			printf("isofs: cd9660_xa_read_common: bread didn't read full sector\n");
			return EIO;
		}
		
		/* Figure out which part of the block to copy, and copy it */
		sect_off = (offset - sizeof(struct riff_header)) % CDXA_SECTOR_SIZE;
		count = min(CDXA_SECTOR_SIZE-sect_off, amount);
		if (diff < count)	/* Pin transfer amount to EOF */
			count = diff;
		
		if (buffer) {
			bcopy(bp->b_data+sect_off, buffer, count);
			buffer += count;
		} else {
			error = uiomove(bp->b_data+sect_off, count, uio);
		}
		amount -= count;
		offset += count;
		
		/*
		 * If we copied through the end of the block, or the end of file, then
		 * age the device block.  This is optimized for sequential access.
		 */
		if (sect_off+count == CDXA_SECTOR_SIZE || offset == (off_t)ip->i_size)
			bp->b_flags |= B_AGE;
		brelse(bp);
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
cd9660_xa_read(ap)
	struct vop_read_args /* {
		struct vnode *a_vp;
		struct uio *a_uio;
		int a_ioflag;
		struct ucred *a_cred;
	} */ *ap;
{
	struct vnode *vp = ap->a_vp;
	register struct uio *uio = ap->a_uio;
	register struct iso_node *ip = VTOI(vp);
	off_t offset = uio->uio_offset;
	size_t size = uio->uio_resid;

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
cd9660_xa_pagein(ap)
	struct vop_pagein_args /* {
	   	struct vnode 	*a_vp,
	   	upl_t		a_pl,
		vm_offset_t	a_pl_offset,
		off_t		a_f_offset,
		size_t		a_size,
		struct ucred	*a_cred,
		int		a_flags
	} */ *ap;
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
	((int (*) __P((struct  vop_create_args *)))err_create)
#define cd9660_mknod ((int (*) __P((struct  vop_mknod_args *)))err_mknod)
#define cd9660_setattr \
	((int (*) __P((struct  vop_setattr_args *)))cd9660_enotsupp)
#define cd9660_write ((int (*) __P((struct  vop_write_args *)))cd9660_enotsupp)
#if NFSSERVER
int	lease_check __P((struct vop_lease_args *));
#define	cd9660_lease_check lease_check
#else
#define	cd9660_lease_check ((int (*) __P((struct vop_lease_args *)))nullop)
#endif
#define cd9660_fsync ((int (*) __P((struct  vop_fsync_args *)))nullop)
#define cd9660_rename \
	((int (*) __P((struct  vop_rename_args *)))err_rename)
#define cd9660_copyfile \
	((int (*) __P((struct  vop_copyfile_args *)))err_copyfile)
#define cd9660_link ((int (*) __P((struct  vop_link_args *)))err_link)
#define cd9660_mkdir ((int (*) __P((struct  vop_mkdir_args *)))err_mkdir)
#define cd9660_symlink \
	((int (*) __P((struct vop_symlink_args *)))err_symlink)
#define cd9660_advlock \
	((int (*) __P((struct vop_advlock_args *)))cd9660_enotsupp)
#define cd9660_valloc ((int(*) __P(( \
		struct vnode *pvp, \
		int mode, \
		struct ucred *cred, \
		struct vnode **vpp))) cd9660_enotsupp)
#define cd9660_vfree ((int (*) __P((struct  vop_vfree_args *)))cd9660_enotsupp)
#define cd9660_truncate \
	((int (*) __P((struct  vop_truncate_args *)))cd9660_enotsupp)
#define cd9660_update \
	((int (*) __P((struct  vop_update_args *)))cd9660_enotsupp)
#define cd9660_bwrite \
	((int (*) __P((struct  vop_bwrite_args *)))cd9660_enotsupp)
#define cd9660_pageout \
	((int (*) __P((struct  vop_pageout_args *)))cd9660_enotsupp)
int cd9660_blktooff(struct vop_blktooff_args *ap);
int cd9660_offtoblk(struct vop_offtoblk_args *ap);
int cd9660_cmap(struct vop_cmap_args *ap);

#define VOPFUNC int (*)(void *)
/*
 * Global vfs data structures for cd9660
 */
int (**cd9660_vnodeop_p)(void *);
struct vnodeopv_entry_desc cd9660_vnodeop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)cd9660_lookup },	/* lookup */
	{ &vop_create_desc, (VOPFUNC)cd9660_create },	/* create */
	{ &vop_mknod_desc, (VOPFUNC)cd9660_mknod },	/* mknod */
	{ &vop_open_desc, (VOPFUNC)cd9660_open },	/* open */
	{ &vop_close_desc, (VOPFUNC)cd9660_close },	/* close */
	{ &vop_access_desc, (VOPFUNC)cd9660_access },	/* access */
	{ &vop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)cd9660_setattr },	/* setattr */
	{ &vop_read_desc, (VOPFUNC)cd9660_read },	/* read */
	{ &vop_write_desc, (VOPFUNC)cd9660_write },	/* write */
	{ &vop_lease_desc, (VOPFUNC)cd9660_lease_check },/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)cd9660_ioctl },	/* ioctl */
	{ &vop_select_desc, (VOPFUNC)cd9660_select },	/* select */
	{ &vop_mmap_desc, (VOPFUNC)cd9660_mmap },	/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)cd9660_fsync },	/* fsync */
	{ &vop_seek_desc, (VOPFUNC)cd9660_seek },	/* seek */
	{ &vop_remove_desc, (VOPFUNC)cd9660_remove },	/* remove */
	{ &vop_link_desc, (VOPFUNC)cd9660_link },	/* link */
	{ &vop_rename_desc, (VOPFUNC)cd9660_rename },	/* rename */
	{ &vop_copyfile_desc, (VOPFUNC)cd9660_copyfile },/* copyfile */
	{ &vop_mkdir_desc, (VOPFUNC)cd9660_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)cd9660_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)cd9660_symlink },	/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)cd9660_readdir },	/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)cd9660_readlink },/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)nop_abortop },	/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)cd9660_lock },	/* lock */
	{ &vop_unlock_desc, (VOPFUNC)cd9660_unlock },	/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)cd9660_bmap },	/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)cd9660_strategy },/* strategy */
	{ &vop_print_desc, (VOPFUNC)cd9660_print },	/* print */
	{ &vop_islocked_desc, (VOPFUNC)cd9660_islocked },/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)cd9660_pathconf },/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)cd9660_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)cd9660_blkatoff },/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)cd9660_valloc },	/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)cd9660_vfree },	/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)cd9660_truncate },/* truncate */
	{ &vop_update_desc, (VOPFUNC)cd9660_update },	/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)cd9660_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vop_getattrlist_desc, (VOPFUNC)cd9660_getattrlist },	/* getattrlist */
	{ &vop_blktooff_desc, (VOPFUNC)cd9660_blktooff },	/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)cd9660_offtoblk },	/* offtoblk */
  	{ &vop_cmap_desc, (VOPFUNC)cd9660_cmap },		/* cmap */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_vnodeop_opv_desc =
	{ &cd9660_vnodeop_p, cd9660_vnodeop_entries };

/*
 * The VOP table for CD-ROM XA (media) files is almost the same
 * as for ordinary files, except for read, and pagein.
 * Note that cd9660_xa_read doesn't use cluster I/O, so cmap
 * isn't needed, and isn't implemented.  Similarly, it doesn't
 * do bread() on CD XA vnodes, so bmap, blktooff, offtoblk
 * aren't needed.
 */
int (**cd9660_cdxaop_p)(void *);
struct vnodeopv_entry_desc cd9660_cdxaop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)cd9660_lookup },	/* lookup */
	{ &vop_create_desc, (VOPFUNC)cd9660_create },	/* create */
	{ &vop_mknod_desc, (VOPFUNC)cd9660_mknod },	/* mknod */
	{ &vop_open_desc, (VOPFUNC)cd9660_open },	/* open */
	{ &vop_close_desc, (VOPFUNC)cd9660_close },	/* close */
	{ &vop_access_desc, (VOPFUNC)cd9660_access },	/* access */
	{ &vop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)cd9660_setattr },	/* setattr */
	{ &vop_read_desc, (VOPFUNC)cd9660_xa_read },	/* read */
	{ &vop_write_desc, (VOPFUNC)cd9660_write },	/* write */
	{ &vop_lease_desc, (VOPFUNC)cd9660_lease_check },/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)cd9660_ioctl },	/* ioctl */
	{ &vop_select_desc, (VOPFUNC)cd9660_select },	/* select */
	{ &vop_mmap_desc, (VOPFUNC)cd9660_mmap },	/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)cd9660_fsync },	/* fsync */
	{ &vop_seek_desc, (VOPFUNC)cd9660_seek },	/* seek */
	{ &vop_remove_desc, (VOPFUNC)cd9660_remove },	/* remove */
	{ &vop_link_desc, (VOPFUNC)cd9660_link },	/* link */
	{ &vop_rename_desc, (VOPFUNC)cd9660_rename },	/* rename */
	{ &vop_copyfile_desc, (VOPFUNC)cd9660_copyfile },/* copyfile */
	{ &vop_mkdir_desc, (VOPFUNC)cd9660_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)cd9660_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)cd9660_symlink },	/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)cd9660_readdir },	/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)cd9660_readlink },/* readlink */
	{ &vop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)cd9660_lock },	/* lock */
	{ &vop_unlock_desc, (VOPFUNC)cd9660_unlock },	/* unlock */
	{ &vop_strategy_desc, (VOPFUNC)cd9660_strategy },/* strategy */
	{ &vop_print_desc, (VOPFUNC)cd9660_print },	/* print */
	{ &vop_islocked_desc, (VOPFUNC)cd9660_islocked },/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)cd9660_pathconf },/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)cd9660_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)cd9660_blkatoff },/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)cd9660_valloc },	/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)cd9660_vfree },	/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)cd9660_truncate },/* truncate */
	{ &vop_update_desc, (VOPFUNC)cd9660_update },	/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)cd9660_xa_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vop_getattrlist_desc, (VOPFUNC)cd9660_getattrlist },	/* getattrlist */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_cdxaop_opv_desc =
	{ &cd9660_cdxaop_p, cd9660_cdxaop_entries };

/*
 * Special device vnode ops
 */
int (**cd9660_specop_p)(void *);
struct vnodeopv_entry_desc cd9660_specop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)spec_lookup },	/* lookup */
	{ &vop_create_desc, (VOPFUNC)spec_create },	/* create */
	{ &vop_mknod_desc, (VOPFUNC)spec_mknod },	/* mknod */
	{ &vop_open_desc, (VOPFUNC)spec_open },		/* open */
	{ &vop_close_desc, (VOPFUNC)spec_close },	/* close */
	{ &vop_access_desc, (VOPFUNC)cd9660_access },	/* access */
	{ &vop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)cd9660_setattr },	/* setattr */
	{ &vop_read_desc, (VOPFUNC)spec_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)spec_write },	/* write */
	{ &vop_lease_desc, (VOPFUNC)spec_lease_check },	/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)spec_ioctl },	/* ioctl */
	{ &vop_select_desc, (VOPFUNC)spec_select },	/* select */
	{ &vop_mmap_desc, (VOPFUNC)spec_mmap },		/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)spec_fsync },	/* fsync */
	{ &vop_seek_desc, (VOPFUNC)spec_seek },		/* seek */
	{ &vop_remove_desc, (VOPFUNC)spec_remove },	/* remove */
	{ &vop_link_desc, (VOPFUNC)spec_link },		/* link */
	{ &vop_rename_desc, (VOPFUNC)spec_rename },	/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)spec_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)spec_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)spec_symlink },	/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)spec_readdir },	/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)spec_readlink },	/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)spec_abortop },	/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)cd9660_lock },	/* lock */
	{ &vop_unlock_desc, (VOPFUNC)cd9660_unlock },	/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)spec_bmap },		/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)spec_strategy },	/* strategy */
	{ &vop_print_desc, (VOPFUNC)cd9660_print },	/* print */
	{ &vop_islocked_desc, (VOPFUNC)cd9660_islocked },/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)spec_pathconf },	/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)spec_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)spec_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)spec_valloc },	/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)spec_vfree },	/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)spec_truncate },	/* truncate */
	{ &vop_update_desc, (VOPFUNC)cd9660_update },	/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_devblocksize_desc, (VOPFUNC)spec_devblocksize }, /* devblocksize */
	{ &vop_pagein_desc, (VOPFUNC)cd9660_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vop_blktooff_desc, (VOPFUNC)cd9660_blktooff },	/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)cd9660_offtoblk },	/* offtoblk */
  	{ &vop_cmap_desc, (VOPFUNC)cd9660_cmap },		/* cmap */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_specop_opv_desc =
	{ &cd9660_specop_p, cd9660_specop_entries };

#if FIFO
int (**cd9660_fifoop_p)(void *);
struct vnodeopv_entry_desc cd9660_fifoop_entries[] = {
	{ &vop_default_desc, (VOPFUNC)vn_default_error },
	{ &vop_lookup_desc, (VOPFUNC)fifo_lookup },	/* lookup */
	{ &vop_create_desc, (VOPFUNC)fifo_create },	/* create */
	{ &vop_mknod_desc, (VOPFUNC)fifo_mknod },	/* mknod */
	{ &vop_open_desc, (VOPFUNC)fifo_open },		/* open */
	{ &vop_close_desc, (VOPFUNC)fifo_close },	/* close */
	{ &vop_access_desc, (VOPFUNC)cd9660_access },	/* access */
	{ &vop_getattr_desc, (VOPFUNC)cd9660_getattr },	/* getattr */
	{ &vop_setattr_desc, (VOPFUNC)cd9660_setattr },	/* setattr */
	{ &vop_read_desc, (VOPFUNC)fifo_read },		/* read */
	{ &vop_write_desc, (VOPFUNC)fifo_write },	/* write */
	{ &vop_lease_desc, (VOPFUNC)fifo_lease_check },	/* lease */
	{ &vop_ioctl_desc, (VOPFUNC)fifo_ioctl },	/* ioctl */
	{ &vop_select_desc, (VOPFUNC)fifo_select },	/* select */
	{ &vop_mmap_desc, (VOPFUNC)fifo_mmap },		/* mmap */
	{ &vop_fsync_desc, (VOPFUNC)fifo_fsync },	/* fsync */
	{ &vop_seek_desc, (VOPFUNC)fifo_seek },		/* seek */
	{ &vop_remove_desc, (VOPFUNC)fifo_remove },	/* remove */
	{ &vop_link_desc, (VOPFUNC)fifo_link }	,	/* link */
	{ &vop_rename_desc, (VOPFUNC)fifo_rename },	/* rename */
	{ &vop_mkdir_desc, (VOPFUNC)fifo_mkdir },	/* mkdir */
	{ &vop_rmdir_desc, (VOPFUNC)fifo_rmdir },	/* rmdir */
	{ &vop_symlink_desc, (VOPFUNC)fifo_symlink },	/* symlink */
	{ &vop_readdir_desc, (VOPFUNC)fifo_readdir },	/* readdir */
	{ &vop_readlink_desc, (VOPFUNC)fifo_readlink },	/* readlink */
	{ &vop_abortop_desc, (VOPFUNC)fifo_abortop },	/* abortop */
	{ &vop_inactive_desc, (VOPFUNC)cd9660_inactive },/* inactive */
	{ &vop_reclaim_desc, (VOPFUNC)cd9660_reclaim },	/* reclaim */
	{ &vop_lock_desc, (VOPFUNC)cd9660_lock },	/* lock */
	{ &vop_unlock_desc, (VOPFUNC)cd9660_unlock },	/* unlock */
	{ &vop_bmap_desc, (VOPFUNC)fifo_bmap },		/* bmap */
	{ &vop_strategy_desc, (VOPFUNC)fifo_strategy },	/* strategy */
	{ &vop_print_desc, (VOPFUNC)cd9660_print },	/* print */
	{ &vop_islocked_desc, (VOPFUNC)cd9660_islocked },/* islocked */
	{ &vop_pathconf_desc, (VOPFUNC)fifo_pathconf },	/* pathconf */
	{ &vop_advlock_desc, (VOPFUNC)fifo_advlock },	/* advlock */
	{ &vop_blkatoff_desc, (VOPFUNC)fifo_blkatoff },	/* blkatoff */
	{ &vop_valloc_desc, (VOPFUNC)fifo_valloc },	/* valloc */
	{ &vop_vfree_desc, (VOPFUNC)fifo_vfree },	/* vfree */
	{ &vop_truncate_desc, (VOPFUNC)fifo_truncate },	/* truncate */
	{ &vop_update_desc, (VOPFUNC)cd9660_update },	/* update */
	{ &vop_bwrite_desc, (VOPFUNC)vn_bwrite },
	{ &vop_pagein_desc, (VOPFUNC)cd9660_pagein },		/* Pagein */
	{ &vop_pageout_desc, (VOPFUNC)cd9660_pageout },		/* Pageout */
	{ &vop_blktooff_desc, (VOPFUNC)cd9660_blktooff },	/* blktooff */
	{ &vop_offtoblk_desc, (VOPFUNC)cd9660_offtoblk },	/* offtoblk */
	{ (struct vnodeop_desc*)NULL, (VOPFUNC)NULL }
};
struct vnodeopv_desc cd9660_fifoop_opv_desc =
	{ &cd9660_fifoop_p, cd9660_fifoop_entries };
#endif /* FIFO */
