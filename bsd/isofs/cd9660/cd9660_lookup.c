/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
/*	$NetBSD: cd9660_lookup.c,v 1.13 1994/12/24 15:30:03 cgd Exp $	*/

/*-
 * Copyright (c) 1989, 1993, 1994
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
 *	from: @(#)ufs_lookup.c	7.33 (Berkeley) 5/19/91
 *
 *	@(#)cd9660_lookup.c	8.5 (Berkeley) 12/5/94
 *
 */

#include <sys/param.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/utfconv.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/cd9660_node.h>
#include <isofs/cd9660/iso_rrip.h>
#include <isofs/cd9660/cd9660_rrip.h>

struct	nchstats iso_nchstats;

/*
 * Convert a component of a pathname into a pointer to a locked inode.
 * This is a very central and rather complicated routine.
 * If the file system is not maintained in a strict tree hierarchy,
 * this can result in a deadlock situation (see comments in code below).
 *
 * The flag argument is LOOKUP, CREATE, RENAME, or DELETE depending on
 * whether the name is to be looked up, created, renamed, or deleted.
 * When CREATE, RENAME, or DELETE is specified, information usable in
 * creating, renaming, or deleting a directory entry may be calculated.
 * If flag has LOCKPARENT or'ed into it and the target of the pathname
 * exists, lookup returns both the target and its parent directory locked.
 * When creating or renaming and LOCKPARENT is specified, the target may
 * not be ".".  When deleting and LOCKPARENT is specified, the target may
 * be "."., but the caller must check to ensure it does an vrele and iput
 * instead of two iputs.
 *
 * Overall outline of ufs_lookup:
 *
 *	check accessibility of directory
 *	look for name in cache, if found, then if at end of path
 *	  and deleting or creating, drop it, else return name
 *	search for name in directory, to found or notfound
 * notfound:
 *	if creating, return locked directory, leaving info on available slots
 *	else return error
 * found:
 *	if at end of path and deleting, return information to allow delete
 *	if at end of path and rewriting (RENAME and LOCKPARENT), lock target
 *	  inode and return info to allow rewrite
 *	if not at end, add name to cache; if at end and neither creating
 *	  nor deleting, add name to cache
 *
 * NOTE: (LOOKUP | LOCKPARENT) currently returns the parent inode unlocked.
 */
int
cd9660_lookup(struct vnop_lookup_args *ap)
{
	register struct vnode *vdp;	/* vnode for directory being searched */
	register struct iso_node *dp;	/* inode for directory being searched */
	register struct iso_mnt *imp;	/* file system that directory is in */
	struct buf *bp;			/* a buffer of directory entries */
	struct iso_directory_record *ep = NULL;/* the current directory entry */
	int entryoffsetinblock;		/* offset of ep in bp's buffer */
	int saveoffset = 0;		/* offset of last directory entry in dir */
	int numdirpasses;		/* strategy for directory search */
	doff_t endsearch;		/* offset to end directory search */
	struct vnode *pdp;		/* saved dp during symlink work */
	struct vnode *tdp;		/* returned by cd9660_vget_internal */
	u_long bmask;			/* block offset mask */
	int lockparent;			/* 1 => lockparent flag is set */
	int wantparent;			/* 1 => wantparent or lockparent flag */
	int wantassoc;
	int error;
	ino_t ino = 0;
	int reclen;
	u_short namelen;
	int isoflags;
	char altname[ISO_RRIP_NAMEMAX];
	int res;
	int len;
	char *name;
	struct vnode **vpp = ap->a_vpp;
	struct componentname *cnp = ap->a_cnp;
	int flags = cnp->cn_flags;
	int nameiop = cnp->cn_nameiop;
	vfs_context_t ctx = cnp->cn_context;
	struct proc *p = vfs_context_proc(ctx);
	size_t altlen;
	
	bp = NULL;
	*vpp = NULL;
	vdp = ap->a_dvp;
	dp = VTOI(vdp);
	imp = dp->i_mnt;
	lockparent = flags & LOCKPARENT;
	wantparent = flags & (LOCKPARENT|WANTPARENT);
	wantassoc = 0;

	
	/*
	 * We now have a segment name to search for, and a directory to search.
	 *
	 * Before tediously performing a linear scan of the directory,
	 * check the name cache to see if the directory/name pair
	 * we are looking for is known already.
	 */
	if ((error = cache_lookup(vdp, vpp, cnp))) {
		if (error == ENOENT)
			return (error);
		return (0);
	}
	
	len = cnp->cn_namelen;
	name = cnp->cn_nameptr;
	altname[0] = '\0';
	/*
	 * A "._" prefix means, we are looking for an associated file
	 */
	if (imp->iso_ftype != ISO_FTYPE_RRIP &&
	    *name == ASSOCCHAR1 && *(name+1) == ASSOCCHAR2) {
		wantassoc = 1;
		len -= 2;
		name += 2;
	}
	/*
	 * Decode search name into UCS-2 (Unicode)
	 */
	if ((imp->iso_ftype == ISO_FTYPE_JOLIET) &&
	    !((len == 1 && *name == '.') || (flags & ISDOTDOT))) {
		int flags1 = UTF_PRECOMPOSED;

		if (BYTE_ORDER != BIG_ENDIAN)
			flags1 |= UTF_REVERSE_ENDIAN;

		(void) utf8_decodestr(name, len, (u_int16_t*) altname, &altlen,
					sizeof(altname), 0, flags1);
		name = altname;
		len = altlen;
	}
	/*
	 * If there is cached information on a previous search of
	 * this directory, pick up where we last left off.
	 * We cache only lookups as these are the most common
	 * and have the greatest payoff. Caching CREATE has little
	 * benefit as it usually must search the entire directory
	 * to determine that the entry does not exist. Caching the
	 * location of the last DELETE or RENAME has not reduced
	 * profiling time and hence has been removed in the interest
	 * of simplicity.
	 */
	bmask = imp->im_sector_size - 1;
	if (nameiop != LOOKUP || dp->i_diroff == 0 ||
	    dp->i_diroff > dp->i_size) {
		entryoffsetinblock = 0;
		dp->i_offset = 0;
		numdirpasses = 1;
	} else {
		dp->i_offset = dp->i_diroff;
		
		if ((entryoffsetinblock = dp->i_offset & bmask) &&
		    (error = cd9660_blkatoff(vdp, SECTOFF(imp, dp->i_offset), NULL, &bp)))
				return (error);
		numdirpasses = 2;
		iso_nchstats.ncs_2passes++;
	}
	endsearch = dp->i_size;
	
searchloop:
	while (dp->i_offset < endsearch) {
		/*
		 * If offset is on a block boundary,
		 * read the next directory block.
		 * Release previous if it exists.
		 */
		if ((dp->i_offset & bmask) == 0) {
			if (bp != NULL)
				buf_brelse(bp);
			if ( (error = cd9660_blkatoff(vdp, SECTOFF(imp,dp->i_offset), NULL, &bp)) )
				return (error);
			entryoffsetinblock = 0;
		}
		/*
		 * Get pointer to next entry.
		 */
		ep = (struct iso_directory_record *)
			((char *)buf_dataptr(bp) + entryoffsetinblock);
		
		reclen = isonum_711(ep->length);
		if (reclen == 0) {
			/* skip to next block, if any */
			dp->i_offset =
			    (dp->i_offset & ~bmask) + imp->im_sector_size;
			continue;
		}
		
		if (reclen < ISO_DIRECTORY_RECORD_SIZE) {
			/* illegal entry, stop */
			break;
		}
		if (entryoffsetinblock + reclen > imp->im_sector_size) {
			/* entries are not allowed to cross sector boundaries */
			break;
		}
		namelen = isonum_711(ep->name_len);
		isoflags = isonum_711(ep->flags);
		
		if (reclen < ISO_DIRECTORY_RECORD_SIZE + namelen)
			/* illegal entry, stop */
			break;
		/*
		 * Check for a name match.
		 */
		if (imp->iso_ftype == ISO_FTYPE_RRIP) {
			if (isoflags & directoryBit)
				ino = isodirino(ep, imp);
			else
				ino = ((daddr_t)buf_blkno(bp) << imp->im_bshift) + entryoffsetinblock;
			dp->i_ino = ino;
			cd9660_rrip_getname(ep,altname,&namelen,&dp->i_ino,imp);
			if (namelen == cnp->cn_namelen
			    && !bcmp(name,altname,namelen))
				goto found;
			ino = 0;
		} else {
			if ((!(isoflags & associatedBit)) == !wantassoc) {
				if ((len == 1
				     && *name == '.')
				    || (flags & ISDOTDOT)) {
					if (namelen == 1
					    && ep->name[0] == ((flags & ISDOTDOT) ? 1 : 0)) {
						/*
						 * Save directory entry's inode number and
						 * release directory buffer.
						 */
						dp->i_ino = isodirino(ep, imp);
						goto found;
					}
					if (namelen != 1
					    || ep->name[0] != 0)
						goto notfound;
				} else if (imp->iso_ftype != ISO_FTYPE_JOLIET && !(res = isofncmp(name,len,
							    ep->name,namelen))) {
					if ( isoflags & directoryBit )
						ino = isodirino(ep, imp);
					else
						ino = ((daddr_t)buf_blkno(bp) << imp->im_bshift) + entryoffsetinblock;
					saveoffset = dp->i_offset;
				} else if (imp->iso_ftype == ISO_FTYPE_JOLIET && !(res = ucsfncmp((u_int16_t*)name, len,
							    (u_int16_t*) ep->name, namelen))) {
					if ( isoflags & directoryBit )
						ino = isodirino(ep, imp);
					else
						ino = ((daddr_t)buf_blkno(bp) << imp->im_bshift) + entryoffsetinblock;
					saveoffset = dp->i_offset;
				} else if (ino)
					goto foundino;
#ifdef	NOSORTBUG	/* On some CDs directory entries are not sorted correctly */
				else if (res < 0)
					goto notfound;
				else if (res > 0 && numdirpasses == 2)
					numdirpasses++;
#endif
			}
		}
		dp->i_offset += reclen;
		entryoffsetinblock += reclen;
	} /* endwhile */
	
	if (ino) {
foundino:
		dp->i_ino = ino;
		if (saveoffset != dp->i_offset) {
			if (lblkno(imp, dp->i_offset) !=
			    lblkno(imp, saveoffset)) {
				if (bp != NULL)
					buf_brelse(bp);
				if ( (error = cd9660_blkatoff(vdp, SECTOFF(imp, saveoffset), NULL, &bp)) )
					return (error);
			}
			entryoffsetinblock = saveoffset & bmask;
			ep = (struct iso_directory_record *)
				((char *)buf_dataptr(bp) + entryoffsetinblock);
			dp->i_offset = saveoffset;
		}
		goto found;
	}
notfound:
	/*
	 * If we started in the middle of the directory and failed
	 * to find our target, we must check the beginning as well.
	 */
	if (numdirpasses == 2) {
		numdirpasses--;
		dp->i_offset = 0;
		endsearch = dp->i_diroff;
		goto searchloop;
	}
	if (bp != NULL)
		buf_brelse(bp);

	/*
	 * Insert name into cache (as non-existent) if appropriate.
	 */
	if (cnp->cn_flags & MAKEENTRY)
		cache_enter(vdp, *vpp, cnp);
	return (ENOENT);
	
found:
	if (numdirpasses == 2)
		iso_nchstats.ncs_pass2++;
	
	/*
	 * Found component in pathname.
	 * If the final component of path name, save information
	 * in the cache as to where the entry was found.
	 */
	if ((flags & ISLASTCN) && nameiop == LOOKUP)
		dp->i_diroff = dp->i_offset;
	
	/*
	 * Step through the translation in the name.  We do not `iput' the
	 * directory because we may need it again if a symbolic link
	 * is relative to the current directory.  Instead we save it
	 * unlocked as "pdp".  We must get the target inode before unlocking
	 * the directory to insure that the inode will not be removed
	 * before we get it.  We prevent deadlock by always fetching
	 * inodes from the root, moving down the directory tree. Thus
	 * when following backward pointers ".." we must unlock the
	 * parent directory before getting the requested directory.
	 * There is a potential race condition here if both the current
	 * and parent directories are removed before the `iget' for the
	 * inode associated with ".." returns.  We hope that this occurs
	 * infrequently since we cannot avoid this race condition without
	 * implementing a sophisticated deadlock detection algorithm.
	 * Note also that this simple deadlock detection scheme will not
	 * work if the file system has any hard links other than ".."
	 * that point backwards in the directory structure.
	 */
	pdp = vdp;
	/*
	 * If ino is different from dp->i_ino,
	 * it's a relocated directory.
	 */
	if (flags & ISDOTDOT) {
		error = cd9660_vget_internal(vnode_mount(vdp), dp->i_ino, &tdp, NULL, NULL,
					     dp->i_ino != ino, ep, p);
		VTOI(tdp)->i_parent = VTOI(pdp)->i_number;
		buf_brelse(bp);

		*vpp = tdp;
	} else if (dp->i_number == dp->i_ino) {
		buf_brelse(bp);
		vnode_get(vdp);	/* we want ourself, ie "." */
		*vpp = vdp;
	} else {
	        error = cd9660_vget_internal(vnode_mount(vdp), dp->i_ino, &tdp, vdp, cnp,
					     dp->i_ino != ino, ep, p);
		/* save parent inode number */
		VTOI(tdp)->i_parent = VTOI(pdp)->i_number;
		buf_brelse(bp);
		if (error)
			return (error);
		*vpp = tdp;
	}
	return (0);
}


/*
 * Return buffer with the contents of block "offset" from the beginning of
 * directory "ip".  If "res" is non-zero, fill it in with a pointer to the
 * remaining space in the directory.
 */
int
cd9660_blkatoff(vnode_t vp, off_t offset, char **res, buf_t *bpp)
{
	struct iso_node *ip;
	register struct iso_mnt *imp;
	buf_t	bp;
	daddr_t lbn;
	int bsize, error;

	ip = VTOI(vp);
	imp = ip->i_mnt;
	lbn = lblkno(imp, offset);
	bsize = blksize(imp, ip, lbn);

	if ((bsize != imp->im_sector_size) &&
	    (offset & (imp->im_sector_size - 1)) == 0) {
		bsize = imp->im_sector_size;
	}

	if ( (error = (int)buf_bread(vp, (daddr64_t)((unsigned)lbn), bsize, NOCRED, &bp)) ) {
		buf_brelse(bp);
		*bpp = NULL;
		return (error);
	}
	if (res)
		*res = (char *)buf_dataptr(bp) + blkoff(imp, offset);
	*bpp = bp;
	
	return (0);
}
