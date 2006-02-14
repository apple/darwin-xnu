/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/*	$NetBSD: cd9660_vfsops.c,v 1.18 1995/03/09 12:05:36 mycroft Exp $	*/

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
 *	@(#)cd9660_vfsops.c	8.9 (Berkeley) 12/5/94
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/vnode_internal.h>
#include <sys/mount.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <miscfs/specfs/specdev.h>
#include <sys/buf.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/disk.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/stat.h>
#include <sys/ubc.h>
#include <sys/utfconv.h>
#include <architecture/byte_order.h>

#include <isofs/cd9660/iso.h>
#include <isofs/cd9660/iso_rrip.h>
#include <isofs/cd9660/cd9660_node.h>
#include <isofs/cd9660/cd9660_mount.h>

/*
 * Minutes, Seconds, Frames (M:S:F)
 */
struct CDMSF {
	u_char   minute;
	u_char   second;
	u_char   frame;
};

/*
 * Table Of Contents
 */
struct CDTOC_Desc {
	u_char        session;
	u_char        ctrl_adr;  /* typed to be machine and compiler independent */
	u_char        tno;
	u_char        point;
	struct CDMSF  address;
	u_char        zero;
	struct CDMSF  p;
};

struct CDTOC {
	u_short            length;  /* in native cpu endian */
	u_char             first_session;
	u_char             last_session;
	struct CDTOC_Desc  trackdesc[1];
};

#define MSF_TO_LBA(msf)		\
	(((((msf).minute * 60UL) + (msf).second) * 75UL) + (msf).frame - 150)

u_char isonullname[] = "\0";

struct vfsops cd9660_vfsops = {
	cd9660_mount,
	cd9660_start,
	cd9660_unmount,
	cd9660_root,
	NULL, 			/* quotactl */
	cd9660_vfs_getattr,
	cd9660_sync,
	cd9660_vget,
	cd9660_fhtovp,
	cd9660_vptofh,
	cd9660_init,
	cd9660_sysctl
};

/*
 * Called by vfs_mountroot when iso is going to be mounted as root.
 *
 * Name is updated by mount(8) after booting.
 */
#define ROOTNAME	"root_device"

static int iso_mountfs(struct vnode *devvp, struct mount *mp, struct user_iso_args *argp,
                       vfs_context_t context);

static void DRGetTypeCreatorAndFlags(
				struct iso_mnt * theMountPointPtr,
				struct iso_directory_record * theDirRecPtr, 
				u_int32_t * theTypePtr, 
				u_int32_t * theCreatorPtr, 
				u_int16_t * theFlagsPtr);

int
cd9660_mountroot(mount_t mp, vnode_t rvp, vfs_context_t context)
{
	int	error;
	struct user_iso_args args;

	args.flags = ISOFSMNT_ROOT;
	args.ssector = 0;
	args.toc_length = 0;
	args.toc = USER_ADDR_NULL;

	if ((error = iso_mountfs(rvp, mp, &args, context)))
		return (error);

	(void)cd9660_statfs(mp, vfs_statfs(mp), context);

	return (0);
}

/*
 * VFS Operations.
 *
 * mount system call
 */
int
cd9660_mount(mount_t mp, vnode_t devvp, user_addr_t data, vfs_context_t context)
{
	struct user_iso_args args;
	int error;
	struct iso_mnt *imp = NULL;

	if (vfs_context_is64bit(context)) {
		error = copyin(data, (caddr_t)&args, sizeof (args));
	}
	else {
		struct iso_args temp;
		error = copyin(data, (caddr_t)&temp, sizeof (temp));
		args.flags = temp.flags;
		args.ssector = temp.ssector;
		args.toc_length = temp.toc_length;
		args.toc = CAST_USER_ADDR_T(temp.toc);
	}
	if (error)
		return (error);
	
	if (vfs_isrdwr(mp))
		return (EROFS);

	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (vfs_isupdate(mp)) {
		imp = VFSTOISOFS(mp);
		if (devvp == 0)
			return (0);
	}
	if ( !vfs_isupdate(mp))
		error = iso_mountfs(devvp, mp, &args, context);
	else {
		if (devvp != imp->im_devvp)
			error = EINVAL;	/* needs translation */
	}
	if (error) {
		return (error);
	}

	/* Indicate that we don't support volfs */
	vfs_clearflags(mp, MNT_DOVOLFS);

	return (0);
}

/*
 * Find the BSD device for the physical disk corresponding to the
 * mount point's device.  We use this physical device to read whole
 * (2352 byte) sectors from the CD to get the content for the video
 * files (tracks).
 *
 * The "path" argument is the path to the block device that the volume
 * is being mounted on (args.fspec).  It should be of the form:
 *	/dev/disk1s0
 * where the last "s0" part is stripped off to determine the physical
 * device's path.  It is assumed to be in user memory.
 */
static struct vnode *
cd9660_phys_device(mount_t mp, vfs_context_t context)
{
	int err;
	char whole_path[64];	// path to "whole" device
	char *s, *saved;
	struct nameidata nd;
	struct vnode *result;
	struct vfsstatfs * sfs;
	
	sfs = vfs_statfs(mp);
	result = NULL;

	if (strlen(sfs->f_mntfromname) >= sizeof(whole_path))
		return (NULL);

	/* Make a copy of the mount from name, then remove trailing "s...". */
	strncpy(whole_path, sfs->f_mntfromname, sizeof(whole_path)-1); 
	
	/*
	 * I would use strrchr or rindex here, but those are declared __private_extern__,
	 * and can't be used across component boundaries at this time.
	 */
	for (s=whole_path, saved=NULL; *s; ++s)
		if (*s == 's')
			saved = s;
	*saved = '\0';

	/* Lookup the "whole" device. */
	NDINIT(&nd, LOOKUP, FOLLOW, UIO_SYSSPACE, CAST_USER_ADDR_T(whole_path), context);
	err = namei(&nd);
	if (err) {
		printf("isofs: Cannot find physical device: %s\n", whole_path);
		goto done;
	}
	nameidone(&nd);

	/* Open the "whole" device. */
	err = VNOP_OPEN(nd.ni_vp, FREAD, context);
	if (err) {
		vnode_put(nd.ni_vp);
		printf("isofs: Cannot open physical device: %s\n", whole_path);
		goto done;
	}
	result = nd.ni_vp;
done:
	return result;
}


/*
 * See if the given CD-ROM XA disc appears to be a Video CD
 * (version < 2.0; so, not SVCD).  If so, fill in the extent
 * information for the MPEGAV directory, set the VCD flag,
 * and return true.
 */
static int
cd9660_find_video_dir(struct iso_mnt *isomp)
{
	int result, err;
	struct vnode *rvp = NULL;
	struct vnode *videovp = NULL;
	struct componentname cn;
	struct vfs_context context;
	char dirname[] = "MPEGAV";
	
	result = 0;		/* Assume not a video CD */
	
	err = cd9660_root(isomp->im_mountp, &rvp, NULL);
	if (err) {
		printf("cd9660_find_video_dir: cd9660_root failed (%d)\n", err);
		return 0;	/* couldn't find video dir */
	}
	
	context.vc_proc = current_proc();
	context.vc_ucred = kauth_cred_get();

	cn.cn_nameiop = LOOKUP;
	cn.cn_flags = ISLASTCN;
	cn.cn_context = &context;
	cn.cn_pnbuf = dirname;
	cn.cn_pnlen = sizeof(dirname)-1;
	cn.cn_nameptr = cn.cn_pnbuf;
	cn.cn_namelen = cn.cn_pnlen;
	
	err = VNOP_LOOKUP(rvp, &videovp, &cn, &context);
	if (err == 0) {
		struct iso_node *ip = VTOI(videovp);
		result = 1;		/* Looks like video CD */
		isomp->video_dir_start = ip->iso_start;
		isomp->video_dir_end = ip->iso_start + (ip->i_size >> isomp->im_bshift);
		isomp->im_flags2 |= IMF2_IS_VCD;

		vnode_put(videovp);
	}
	vnode_put(rvp);
	
	return result;
}

/*
 * Common code for mount and mountroot
 */
static int
iso_mountfs(devvp, mp, argp, context)
	register struct vnode *devvp;
	struct mount *mp;
	struct user_iso_args *argp;
	vfs_context_t context;
{
	struct proc *p;
	register struct iso_mnt *isomp = (struct iso_mnt *)0;
	struct buf *bp = NULL;
	struct buf *pribp = NULL, *supbp = NULL;
	dev_t dev = vnode_specrdev(devvp);
	int error = EINVAL;
	int breaderr = 0;
	u_long iso_bsize;
	int iso_blknum;
	int joliet_level;
	struct iso_volume_descriptor *vdp = NULL;
	struct iso_primary_descriptor *pri = NULL;
	struct iso_primary_descriptor *sup = NULL;
	struct iso_directory_record *rootp;
	int logical_block_size;
	u_int8_t vdtype;
	int blkoff = argp->ssector;
	
	if (vfs_isrdwr(mp))
		return (EROFS);

	/* This is the "logical sector size".  The standard says this
	 * should be 2048 or the physical sector size on the device,
	 * whichever is greater.  For now, we'll just use a constant.
	 */
	iso_bsize = ISO_DEFAULT_BLOCK_SIZE;

	/* tell IOKit that we're assuming 2K sectors */
	if ((error = VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE,
	     (caddr_t)&iso_bsize, FWRITE, context)))
		return (error);

	joliet_level = 0;
	for (iso_blknum = 16 + blkoff; iso_blknum < (100 + blkoff); iso_blknum++) {
		if ((error = (int)buf_bread(devvp, (daddr64_t)((unsigned)iso_blknum), iso_bsize, NOCRED, &bp))) {
			if (bp) {
				buf_markaged(bp);
				buf_brelse(bp);
				bp = NULL;
			}
			breaderr = error;
			printf("iso_mountfs: buf_bread error %d reading block %d\n", error, iso_blknum);
			continue;
		}

		vdp = (struct iso_volume_descriptor *)buf_dataptr(bp);
		if (bcmp (vdp->volume_desc_id, ISO_STANDARD_ID, sizeof(vdp->volume_desc_id)) != 0) {
#ifdef DEBUG
		        printf("cd9660_vfsops.c: iso_mountfs: "
					"Invalid ID in volume desciptor.\n");
#endif
			/* There should be a primary volume descriptor followed by any
			 * secondary volume descriptors, then an end volume descriptor.
			 * Some discs are mastered without an end volume descriptor or
			 * they have the type field set and the volume descriptor ID is
			 * not set. If we at least found a primary volume descriptor,
			 * mount the disc.
			 */
			if (pri != NULL)
				break;
			
			error = EINVAL;
			goto out;
		}
		
		vdtype = isonum_711 (vdp->type);
		if (vdtype == ISO_VD_END) 
			break;

		if (vdtype == ISO_VD_PRIMARY) {
			if (pribp == NULL) {
				pribp = bp;
				bp = NULL;
				pri = (struct iso_primary_descriptor *)vdp;
			}
		} else if(vdtype == ISO_VD_SUPPLEMENTARY) {
			if (supbp == NULL) {
				supbp = bp;
				bp = NULL;
				sup = (struct iso_primary_descriptor *)vdp;

				if ((argp->flags & ISOFSMNT_NOJOLIET) == 0) {
					/*
					 * some Joliet CDs are "out-of-spec and don't correctly
					 * set the SVD flags. We ignore the flags and rely soely
					 * on the escape_seq
					 */
					if (bcmp(sup->escape_seq, ISO_UCS2_Level_1, 3) == 0)
						joliet_level = 1;
					else if (bcmp(sup->escape_seq, ISO_UCS2_Level_2, 3) == 0)
						joliet_level = 2;
					else if (bcmp(sup->escape_seq, ISO_UCS2_Level_3, 3) == 0)
						joliet_level = 3;
				}
			}
		}

		if (bp) {
			buf_markaged(bp);
			buf_brelse(bp);
			bp = NULL;
		}
	}

	if (bp) {
		buf_markaged(bp);
		buf_brelse(bp);
		bp = NULL;
	}
	
	if (pri == NULL) {
		if (breaderr)
			error = breaderr;
		else
			error = EINVAL;
		goto out;
	}
	
	logical_block_size = isonum_723 (pri->logical_block_size);
	
	if (logical_block_size < DEV_BSIZE || logical_block_size > MAXBSIZE
	    || (logical_block_size & (logical_block_size - 1)) != 0) {
		error = EINVAL;
		goto out;
	}
	
	rootp = (struct iso_directory_record *)pri->root_directory_record;
	
	MALLOC(isomp, struct iso_mnt *, sizeof *isomp, M_ISOFSMNT, M_WAITOK);
	bzero((caddr_t)isomp, sizeof *isomp);
	isomp->im_sector_size = ISO_DEFAULT_BLOCK_SIZE;
	isomp->logical_block_size = logical_block_size;
	isomp->volume_space_size = isonum_733 (pri->volume_space_size);
	/*
	 * Since an ISO9660 multi-session CD can also access previous
	 * sessions, we have to include them into the space consider-
	 * ations.  This doesn't yield a very accurate number since
	 * parts of the old sessions might be inaccessible now, but we
	 * can't do much better.  This is also important for the NFS
	 * filehandle validation.
	 */
	isomp->volume_space_size += blkoff;
	bcopy (rootp, isomp->root, sizeof isomp->root);
	isomp->root_extent = isonum_733 (rootp->extent);
	isomp->root_size = isonum_733 (rootp->size);

	/*
	 * getattrlist wants the volume name, create date and modify date
	 */

	/* Remove any trailing white space */
	if ( strlen(pri->volume_id) ) {
		char    	*myPtr;

		myPtr = pri->volume_id + strlen( pri->volume_id ) - 1;
		while ( *myPtr == ' ' && myPtr >= pri->volume_id ) {
			*myPtr = 0x00;
			myPtr--;
		}
	}

	if (pri->volume_id[0] == 0)
		strcpy(isomp->volume_id, ISO_DFLT_VOLUME_ID);
	else
		bcopy(pri->volume_id, isomp->volume_id, sizeof(isomp->volume_id));
	cd9660_tstamp_conv17(pri->creation_date, &isomp->creation_date);
	cd9660_tstamp_conv17(pri->modification_date, &isomp->modification_date);

	/* See if this is a CD-XA volume */
	if (bcmp( pri->CDXASignature, ISO_XA_ID,
			sizeof(pri->CDXASignature) ) == 0 ) {
		isomp->im_flags2 |= IMF2_IS_CDXA;
	}

	isomp->im_bmask = logical_block_size - 1;
	isomp->im_bshift = 0;
	while ((1 << isomp->im_bshift) < isomp->logical_block_size)
		isomp->im_bshift++;

	buf_markaged(pribp);
	buf_brelse(pribp);
	pribp = NULL;

	vfs_setfsprivate(mp, (void *)isomp);
	vfs_statfs(mp)->f_fsid.val[0] = (long)dev;
	vfs_statfs(mp)->f_fsid.val[1] = vfs_typenum(mp);
	vfs_setmaxsymlen(mp, 0);
	vfs_setflags(mp, MNT_LOCAL);

	isomp->im_mountp = mp;
	isomp->im_dev = dev;
	isomp->im_devvp = devvp;	

	/*
	 * If the logical block size is not 2K then we must
	 * set the block device's physical block size to this
	 * disc's logical block size.
	 *
	 */
	if (logical_block_size != iso_bsize) {
		iso_bsize = logical_block_size;
		if ((error = VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE,
		     (caddr_t)&iso_bsize, FWRITE, context)))
			goto out;
	}
	
	/* Check the Rock Ridge Extention support */
	if (!(argp->flags & ISOFSMNT_NORRIP)) {
		if ( (error = (int)buf_bread(isomp->im_devvp,
					     (daddr64_t)((unsigned)((isomp->root_extent + isonum_711(rootp->ext_attr_length)))),
					     isomp->logical_block_size, NOCRED, &bp)) ) {

			printf("iso_mountfs: buf_bread error %d reading block %d\n",
			   error, isomp->root_extent + isonum_711(rootp->ext_attr_length));
			argp->flags |= ISOFSMNT_NORRIP;
			goto skipRRIP;
		}
		rootp = (struct iso_directory_record *)buf_dataptr(bp);
		
		if ((isomp->rr_skip = cd9660_rrip_offset(rootp,isomp)) < 0) {
			argp->flags  |= ISOFSMNT_NORRIP;
		} else {
			argp->flags  &= ~ISOFSMNT_GENS;
		}
		
		/*
		 * The contents are valid,
		 * but they will get reread as part of another vnode, so...
		 */
		buf_markaged(bp);
		buf_brelse(bp);
		bp = NULL;
	}
skipRRIP:

	isomp->im_flags = argp->flags & (ISOFSMNT_NORRIP | ISOFSMNT_GENS |
					 ISOFSMNT_EXTATT | ISOFSMNT_NOJOLIET);

	switch (isomp->im_flags&(ISOFSMNT_NORRIP|ISOFSMNT_GENS)) {
	default:
		isomp->iso_ftype = ISO_FTYPE_DEFAULT;
		break;
	case ISOFSMNT_GENS|ISOFSMNT_NORRIP:
		isomp->iso_ftype = ISO_FTYPE_9660;
		break;
	case 0:
		isomp->iso_ftype = ISO_FTYPE_RRIP;
		break;
	}
	
	/* Decide whether to use the Joliet descriptor */

	if (isomp->iso_ftype != ISO_FTYPE_RRIP && joliet_level != 0) {
		char vol_id[32];
		int i, convflags;
		size_t convbytes;
		u_int16_t *uchp;
		
		/*
		 * On Joliet CDs use the UCS-2 volume identifier.
		 *
		 * This name can have up to 16 UCS-2 chars.
		 */
		convflags = UTF_DECOMPOSED;
		if (BYTE_ORDER != BIG_ENDIAN)
			convflags |= UTF_REVERSE_ENDIAN;
		uchp = (u_int16_t *)sup->volume_id;
		for (i = 0; i < 16 && uchp[i]; ++i);
		if ((utf8_encodestr((u_int16_t *)sup->volume_id, (i * 2), vol_id,
			&convbytes, sizeof(vol_id), 0, convflags) == 0)
			&& convbytes && (vol_id[0] != ' ')) {
			char * strp;

			/* Remove trailing spaces */
			strp = vol_id + convbytes - 1;
			while (strp > vol_id && *strp == ' ')
				*strp-- = '\0';
			bcopy(vol_id, isomp->volume_id, convbytes + 1);
		}

		rootp = (struct iso_directory_record *)
			sup->root_directory_record;
		bcopy (rootp, isomp->root, sizeof isomp->root);
		isomp->root_extent = isonum_733 (rootp->extent);
		isomp->root_size = isonum_733 (rootp->size);
		buf_markaged(supbp);
		isomp->iso_ftype = ISO_FTYPE_JOLIET;
	}

	if (supbp) {
		buf_brelse(supbp);
		supbp = NULL;
	}

	/* If there was a TOC in the arguments, copy it in. */
	if (argp->flags & ISOFSMNT_TOC) {
		MALLOC(isomp->toc, struct CDTOC *, argp->toc_length, M_ISOFSMNT, M_WAITOK);
		if ((error = copyin(argp->toc, isomp->toc, argp->toc_length)))
			goto out;
	}

	/* See if this could be a Video CD */
	if ((isomp->im_flags2 & IMF2_IS_CDXA) && cd9660_find_video_dir(isomp)) {
		/* Get the 2352-bytes-per-block device. */
		isomp->phys_devvp = cd9660_phys_device(mp, context);
	}

	/* Fill the default statfs information */
	(void) cd9660_statfs(mp, vfs_statfs(mp), context);

	return (0);
out:
	if (bp)
		buf_brelse(bp);
	if (pribp)
		buf_brelse(pribp);
	if (supbp)
		buf_brelse(supbp);

	if (isomp) {
		if (isomp->toc)
			FREE((caddr_t)isomp->toc, M_ISOFSMNT);
		FREE((caddr_t)isomp, M_ISOFSMNT);

		vfs_setfsprivate(mp, (void *)0);
	}
	return (error);
}

/*
 * Make a filesystem operational.
 * Nothing to do at the moment.
 */
/* ARGSUSED */
int
cd9660_start(__unused struct mount *mp, __unused int flags,
	     __unused vfs_context_t context)
{
	return (0);
}

/*
 * unmount system call
 */
int
cd9660_unmount(struct mount *mp, int mntflags, vfs_context_t context)
{
	register struct iso_mnt *isomp;
	int error, flags = 0;
	int force = 0;
	
	if ( (mntflags & MNT_FORCE) ) {
		flags |= FORCECLOSE;
		force = 1;
	}

	if ( (error = vflush(mp, NULLVP, flags)) && !force )
		return (error);

	isomp = VFSTOISOFS(mp);

#ifdef	ISODEVMAP
	if (isomp->iso_ftype == ISO_FTYPE_RRIP)
		iso_dunmap(isomp->im_dev);
#endif
	if (isomp->phys_devvp) {
		error = VNOP_CLOSE(isomp->phys_devvp, FREAD, context);
		if (error && !force)
			return error;
		vnode_put(isomp->phys_devvp);
	}

	if (isomp->toc)
		FREE((caddr_t)isomp->toc, M_ISOFSMNT);
	FREE((caddr_t)isomp, M_ISOFSMNT);

	return (0);
}

/*
 * Return root of a filesystem
 */
int
cd9660_root(struct mount *mp, struct vnode **vpp, __unused vfs_context_t context)
{
	struct iso_mnt *imp = VFSTOISOFS(mp);
	struct iso_directory_record *dp =
		(struct iso_directory_record *)imp->root;
	ino_t ino = isodirino(dp, imp);

	/*
	 * With RRIP we must use the `.' entry of the root directory.
	 * Simply tell vget, that it's a relocated directory.
	 */
	return (cd9660_vget_internal(mp, ino, vpp, NULL, NULL,
		imp->iso_ftype == ISO_FTYPE_RRIP, dp, current_proc()));
}

/*
 * Get file system statistics.
 */
/* ARGSUSED */
int
cd9660_statfs(struct mount *mp, register struct vfsstatfs *sbp,
	      __unused vfs_context_t context)
{
	register struct iso_mnt *isomp;
	
	isomp = VFSTOISOFS(mp);

#if 0
#ifdef COMPAT_09
	sbp->f_type = 5;
#else
	sbp->f_type = 0;
#endif
#endif
	sbp->f_bsize = (uint32_t)isomp->logical_block_size;
	sbp->f_iosize = (size_t)sbp->f_bsize;	/* XXX */
	sbp->f_blocks = (uint64_t)((unsigned long)isomp->volume_space_size);
	sbp->f_bfree = (uint64_t)0; /* total free blocks */
	sbp->f_bavail = (uint64_t)0; /* blocks free for non superuser */
	sbp->f_files =  (uint64_t)0; /* total files */
	sbp->f_ffree = (uint64_t)0; /* free file nodes */
	sbp->f_fstypename[(MFSTYPENAMELEN - 1)] = '\0';

	/*
	 * Subtypes (flavors) for ISO 9660
	 *   0:   ISO-9660
	 *   1:   ISO-9660 (Joliet) 
	 *   2:   ISO-9660 (Rockridge) 
	 */
	if (isomp->iso_ftype == ISO_FTYPE_JOLIET)
		sbp->f_fssubtype = 1;
	else if (isomp->iso_ftype == ISO_FTYPE_RRIP)
		sbp->f_fssubtype = 2;
	else
		sbp->f_fssubtype = 0;

	/* DO NOT use the first spare for flags; it's been reassigned for another use: */
	/* sbp->f_spare[0] = isomp->im_flags; */

	return (0);
}

int cd9660_vfs_getattr(struct mount *mp, struct vfs_attr *fsap, vfs_context_t context)
{
	struct iso_mnt *imp;
	struct vfsstatfs *stats = vfs_statfs(mp);

	imp = VFSTOISOFS(mp);

	/*
	 * We don't know reasonable values for f_objcount, f_filecount,
	 * f_dircount, f_maxobjcount so don't bother making up (poor)
	 * numbers like 10.3.x and earlier did.
	 */
	
	VFSATTR_RETURN(fsap, f_iosize, stats->f_iosize);
	VFSATTR_RETURN(fsap, f_blocks, stats->f_blocks);
	VFSATTR_RETURN(fsap, f_bfree,  stats->f_bfree);
	VFSATTR_RETURN(fsap, f_bavail, stats->f_bavail);
	VFSATTR_RETURN(fsap, f_bused,  stats->f_blocks);
	
	/* We don't have file counts, so don't return them */
	
	/* f_fsid and f_owner should be handled by VFS */
	
	/* We don't have a value for f_uuid */
	
	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] =
			(imp->iso_ftype == ISO_FTYPE_RRIP ? VOL_CAP_FMT_SYMBOLICLINKS : 0) |
			(imp->iso_ftype == ISO_FTYPE_RRIP ? VOL_CAP_FMT_HARDLINKS : 0) |
			(imp->iso_ftype == ISO_FTYPE_RRIP || imp->iso_ftype == ISO_FTYPE_JOLIET
				? VOL_CAP_FMT_CASE_SENSITIVE : 0) |
			VOL_CAP_FMT_CASE_PRESERVING |
			VOL_CAP_FMT_FAST_STATFS;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2] = 0;
		
		fsap->f_capabilities.valid[VOL_CAPABILITIES_FORMAT] =
			VOL_CAP_FMT_PERSISTENTOBJECTIDS |
			VOL_CAP_FMT_SYMBOLICLINKS |
			VOL_CAP_FMT_HARDLINKS |
			VOL_CAP_FMT_JOURNAL |
			VOL_CAP_FMT_JOURNAL_ACTIVE |
			VOL_CAP_FMT_NO_ROOT_TIMES |
			VOL_CAP_FMT_SPARSE_FILES |
			VOL_CAP_FMT_ZERO_RUNS |
			VOL_CAP_FMT_CASE_SENSITIVE |
			VOL_CAP_FMT_CASE_PRESERVING |
			VOL_CAP_FMT_FAST_STATFS | 
			VOL_CAP_FMT_2TB_FILESIZE;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_INTERFACES] =
			VOL_CAP_INT_SEARCHFS |
			VOL_CAP_INT_ATTRLIST |
			VOL_CAP_INT_NFSEXPORT |
			VOL_CAP_INT_READDIRATTR |
			VOL_CAP_INT_EXCHANGEDATA |
			VOL_CAP_INT_COPYFILE |
			VOL_CAP_INT_ALLOCATE |
			VOL_CAP_INT_VOL_RENAME |
			VOL_CAP_INT_ADVLOCK |
			VOL_CAP_INT_FLOCK;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED2] = 0;
		
		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}
	
	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		/*
		 * VFS should really set these based on the vfs_attr and vnop_attr
		 * fields the file system supports, combined with the conversions
		 * VFS has implemented.
		 */

		fsap->f_attributes.validattr.commonattr = ATTR_CMN_VALIDMASK;
        fsap->f_attributes.validattr.volattr = ATTR_VOL_VALIDMASK;
        fsap->f_attributes.validattr.dirattr = ATTR_DIR_VALIDMASK;
        fsap->f_attributes.validattr.fileattr = ATTR_FILE_VALIDMASK;
        fsap->f_attributes.validattr.forkattr = ATTR_FORK_VALIDMASK;

		fsap->f_attributes.nativeattr.commonattr = ATTR_CMN_VALIDMASK;
        fsap->f_attributes.nativeattr.volattr = ATTR_VOL_VALIDMASK;
        fsap->f_attributes.nativeattr.dirattr = ATTR_DIR_VALIDMASK;
        fsap->f_attributes.nativeattr.fileattr = ATTR_FILE_VALIDMASK;
        fsap->f_attributes.nativeattr.forkattr = ATTR_FORK_VALIDMASK;

		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}
	
	VFSATTR_RETURN(fsap, f_create_time, imp->creation_date);
	VFSATTR_RETURN(fsap, f_modify_time, imp->modification_date);
	/* No explicit access time, so let VFS pick a default value */
	/* No explicit backup time, so let VFS pick a default value */
	
	return 0;
}

/* ARGSUSED */
int
cd9660_sync(__unused struct mount *mp, __unused int waitfor,
	    __unused vfs_context_t context)
{

	return (0);
}

/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the inode number is in range
 * - call iget() to get the locked inode
 * - check for an unallocated inode (i_mode == 0)
 * - check that the generation number matches
 */

struct ifid {
	int	ifid_ino;
	long	ifid_start;
};

/* ARGSUSED */
int
cd9660_fhtovp(mount_t mp, int fhlen, unsigned char *fhp, vnode_t *vpp, vfs_context_t context)
{
	struct ifid *ifhp = (struct ifid *)fhp;
	register struct iso_node *ip;
	struct vnode *nvp;
	int error;
	
	if (fhlen < (int)sizeof(struct ifid))
		return (EINVAL);

#ifdef	ISOFS_DBG
	printf("fhtovp: ino %d, start %ld\n",
	       ifhp->ifid_ino, ifhp->ifid_start);
#endif
	
	if ( (error = VFS_VGET(mp, (ino64_t)ifhp->ifid_ino, &nvp, context)) ) {
		*vpp = NULLVP;
		return (error);
	}
	ip = VTOI(nvp);
	if (ip->inode.iso_mode == 0) {
		vnode_put(nvp);
		*vpp = NULLVP;
		return (ESTALE);
	}
	*vpp = nvp;
	return (0);
}

/*
 * Scan the TOC for the track which contains the given sector.
 *
 * If there is no matching track, or no TOC, then return -1.
 */
static int
cd9660_track_for_sector(struct CDTOC *toc, u_int sector)
{
	int i, tracks, result;
	
	if (toc == NULL)
		return -1;

	tracks = toc->length / sizeof(struct CDTOC_Desc);
	
	result = -1;		/* Sentinel in case we don't find the right track. */
	for (i=0; i<tracks; ++i) {
		if (toc->trackdesc[i].point < 100 && MSF_TO_LBA(toc->trackdesc[i].p) <= sector) {
			result = toc->trackdesc[i].point;
		}
	}
	
	return result;
}

/*
 * Determine whether the given node is really a video CD video
 * file.  Return non-zero if it appears to be a video file.
 */
static int
cd9660_is_video_file(struct iso_node *ip, struct iso_mnt *imp)
{
	int lbn;
	int track;
	
	/* Check whether this could really be a Video CD at all */
	if (((imp->im_flags2 & IMF2_IS_VCD) == 0) ||
		imp->phys_devvp == NULL ||
		imp->toc == NULL)
	{
		return 0;	/* Doesn't even look like VCD... */
	}

	/* Make sure it is a file */
	if ((ip->inode.iso_mode & S_IFMT) != S_IFREG)
		return 0;	/* Not even a file... */

	/*
	 * And in the right directory.  This assumes the same inode
	 * number convention that cd9660_vget_internal uses (that
	 * part of the inode number is the block containing the
	 * file's directory entry).
	 */
	lbn = lblkno(imp, ip->i_number);
	if (lbn < imp->video_dir_start || lbn >= imp->video_dir_end)
		return 0;	/* Not in the correct directory */
	
	/*
	 * If we get here, the file should be a video file, but
	 * do a couple of extra sanity checks just to be sure.
	 * First, verify the form of the name
	 */
	if (strlen(ip->i_namep) != 11 ||		/* Wrong length? */
		bcmp(ip->i_namep+7, ".DAT", 4) ||	/* Wrong extension? */
		(bcmp(ip->i_namep, "AVSEQ", 5) &&	/* Wrong beginning? */
		 bcmp(ip->i_namep, "MUSIC", 5)))
	{
		return 0;	/* Invalid name format */
	}
	
	/*
	 * Verify that AVSEQnn.DAT is in track #(nn+1).  This would
	 * not be appropriate for Super Video CD, which allows
	 * multiple sessions, so the track numbers might not
	 * match up like this. 
	 */
	track = (ip->i_namep[5] - '0') * 10 + ip->i_namep[6] - '0';
	if (track != (cd9660_track_for_sector(imp->toc, ip->iso_start) - 1))
	{
		return 0;	/* Wrong number in name */
	}

	/* It must be a video file if we got here. */
	return 1;
}

int
cd9660_vget(struct mount *mp, ino64_t ino, struct vnode **vpp, __unused vfs_context_t context)
{
	/*
	 * XXXX
	 * It would be nice if we didn't always set the `relocated' flag
	 * and force the extra read, but I don't want to think about fixing
	 * that right now.
	 */

	return ( cd9660_vget_internal( mp, (ino_t)ino, vpp, NULL, NULL,
				       0, (struct iso_directory_record *) 0, current_proc()) );
}

int
cd9660_vget_internal(mount_t mp, ino_t ino, vnode_t *vpp, vnode_t dvp,
		     struct componentname *cnp, int relocated,
		     struct iso_directory_record *isodir, proc_t p)
{
	register struct iso_mnt *imp;
	struct iso_node *ip;
	buf_t	bp = NULL;
	vnode_t	vp;
	dev_t	dev;
	int	error;
	struct vnode_fsparam vfsp;
	enum vtype vtype;
	int is_video_file = 0;

	*vpp = NULLVP;
	imp  = VFSTOISOFS(mp);
	dev  = imp->im_dev;
#if 0
	/* Check for unmount in progress */
	if (mp->mnt_kern_flag & MNTK_UNMOUNT)
		return (EPERM);
#endif

	MALLOC_ZONE(ip, struct iso_node *, sizeof(struct iso_node),
		    M_ISOFSNODE, M_WAITOK);
	/*
	 * MALLOC_ZONE may block, so check for the inode being 
	 * present in the hash after we get back...
	 * we also assume that we're under a filesystem lock
	 * so that we're not reentered between the ihashget and
	 * the ihashins...
	 */
	if ((*vpp = cd9660_ihashget(dev, ino, p)) != NULLVP) {
	        FREE_ZONE(ip, sizeof(struct iso_node), M_ISOFSNODE);
		return (0);
	}
	bzero((caddr_t)ip, sizeof(struct iso_node));

	ip->i_dev = dev;
	ip->i_number = ino;
	ip->i_namep = &isonullname[0];
	ip->i_mnt = imp;
	ip->i_devvp = imp->im_devvp;

	SET(ip->i_flag, ISO_INALLOC);
	/*
	 * Put it onto its hash chain and lock it so that other requests for
	 * this inode will block if they arrive while we are sleeping waiting
	 * for old data structures to be purged or for the contents of the
	 * disk portion of this inode to be read.
	 */
	cd9660_ihashins(ip);

	if (isodir == 0) {
		int lbn, off;

		lbn = lblkno(imp, ino);

		if (lbn >= imp->volume_space_size) {
			printf("fhtovp: lbn exceed volume space %d\n", lbn);
			error = ESTALE;
			goto errout;
		}
		off = blkoff(imp, ino);

		if (off + ISO_DIRECTORY_RECORD_SIZE > imp->logical_block_size) {
			printf("fhtovp: crosses block boundary %d\n",
				off + ISO_DIRECTORY_RECORD_SIZE);
			error = ESTALE;
			goto errout;
		}
	
		error = (int)buf_bread(imp->im_devvp, (daddr64_t)((unsigned)lbn),
				       imp->logical_block_size, NOCRED, &bp);
		if (error) {
			printf("fhtovp: buf_bread error %d\n",error);
			goto errout;
		}
		isodir = (struct iso_directory_record *)(buf_dataptr(bp) + off);

		if (off + isonum_711(isodir->length) > imp->logical_block_size) {
			printf("fhtovp: directory crosses block boundary "
				"%d[off=%d/len=%d]\n",
				off +isonum_711(isodir->length), off,
				isonum_711(isodir->length));
			error = ESTALE;
			goto errout;
		}

		/*
		 * for directories we can get parentID from adjacent 
		 * parent directory record
		 */
		if ((isonum_711(isodir->flags) & directoryBit)
				&& (isodir->name[0] == 0)) {
			struct iso_directory_record *pdp;

			pdp = (struct iso_directory_record *)
					((char *)buf_dataptr(bp) + isonum_711(isodir->length));
			if ((isonum_711(pdp->flags) & directoryBit)
					&& (pdp->name[0] == 1))
				ip->i_parent = isodirino(pdp, imp);
		}
	}
	if (relocated) {
	        daddr64_t lbn;

		if (bp) {
			buf_brelse(bp);
			bp = NULL;
		}
		/*
		 * On relocated directories we must
		 * read the `.' entry out of a dir.
		 */
		ip->iso_start = ino >> imp->im_bshift;
		/*
		 * caclulate the correct lbn to read block 0
		 * of this node... this used to be a cd9660_blkatoff, but
		 * that requires the vnode to already be 'cooked'... in
		 * the new world, we don't create a vnode until the inode
		 * has been fully initialized... cd9660_blkatoff generates
		 * a buf_bread for im_sector_size associated with the node's vp
		 * I'm replacing it with a buf_bread for the same size and from
		 * the same location on the disk, but associated with the devvp
		 */
		lbn = (daddr64_t)((unsigned)ip->iso_start) + 0;

		if ((error = (int)buf_bread(imp->im_devvp, lbn, imp->im_sector_size, NOCRED, &bp)))
		        goto errout;

		isodir = (struct iso_directory_record *)buf_dataptr(bp);
	}

	/*
	 * go get apple extensions to ISO directory record or use
	 * defaults when there are no apple extensions.
	 */
	if ( ((isonum_711( isodir->flags ) & directoryBit) == 0) &&
	     (imp->iso_ftype != ISO_FTYPE_RRIP) ) {
		/* This is an ISO directory record for a file */
		DRGetTypeCreatorAndFlags(imp, isodir, &ip->i_FileType, 
		                         &ip->i_Creator, &ip->i_FinderFlags);

		if (isonum_711(isodir->flags) & associatedBit)
			ip->i_flag |= ISO_ASSOCIATED;
	}

	/*
	 * Shadow the ISO 9660 invisible state to the FinderInfo
	 */
	if (isonum_711(isodir->flags) & existenceBit) {
		ip->i_FinderFlags |= fInvisibleBit;
	}

	ip->iso_extent = isonum_733(isodir->extent);
	ip->i_size = isonum_733(isodir->size);
	ip->iso_start = isonum_711(isodir->ext_attr_length) + ip->iso_extent;
	/*
	 * account for AppleDouble header
	 */
	if (ip->i_flag & ISO_ASSOCIATED)
		ip->i_size += ADH_SIZE;

	/*
	 * if we have a valid name, fill in i_namep with UTF-8 name
	 */
	if (isonum_711(isodir->name_len) != 0) {
		u_char *utf8namep;
		u_short namelen;
		ino_t inump = 0;

		MALLOC(utf8namep, u_char *, ISO_RRIP_NAMEMAX + 1, M_TEMP, M_WAITOK);
		namelen = isonum_711(isodir->name_len);

		switch (imp->iso_ftype) {
		case ISO_FTYPE_RRIP:
			cd9660_rrip_getname(isodir, utf8namep, &namelen, &inump, imp);
			break;

		case ISO_FTYPE_JOLIET:
			ucsfntrans((u_int16_t *)isodir->name, namelen,
				   utf8namep, &namelen,
				   isonum_711(isodir->flags) & directoryBit, ip->i_flag & ISO_ASSOCIATED);
			break;

		default:
			isofntrans (isodir->name, namelen,
					utf8namep, &namelen,
					imp->iso_ftype == ISO_FTYPE_9660, ip->i_flag & ISO_ASSOCIATED);
		}

		utf8namep[namelen] = '\0';
		MALLOC(ip->i_namep, u_char *, namelen + 1, M_TEMP, M_WAITOK);
		bcopy(utf8namep, ip->i_namep, namelen + 1);
		FREE(utf8namep, M_TEMP);
	}

	/*
	 * Setup time stamp, attribute
	 */
	switch (imp->iso_ftype) {
	default:	/* ISO_FTYPE_9660 */
		{
		buf_t	bp2 = NULL;
		daddr64_t lbn;
		int	off;

		if ((imp->im_flags & ISOFSMNT_EXTATT) && (off = isonum_711(isodir->ext_attr_length))) {

		        lbn = (daddr64_t)((unsigned)ip->iso_start - off);

		        if ((error = (int)buf_bread(imp->im_devvp, lbn, imp->im_sector_size, NOCRED, &bp2))) {
			        if (bp2)
				        buf_brelse(bp2);
				goto errout;
			}
		} else
			bp2 = NULL;

		cd9660_defattr(isodir, ip, bp2);
		cd9660_deftstamp(isodir, ip, bp2);

		if (bp2)
			buf_brelse(bp2);
		break;
		}
	case ISO_FTYPE_RRIP:
		cd9660_rrip_analyze(isodir, ip, imp);
		break;
	}
	/*
	 * See if this is a Video CD file.  If so, we must adjust the
	 * length to account for larger sectors plus the RIFF header.
	 * We also must substitute the vnop_read and vnop_pagein functions.
	 *
	 * The cd9660_is_video_file routine assumes that the inode has
	 * been completely set up; it refers to several fields.
	 *
	 * This must be done before we release bp, because isodir
	 * points into bp's data.
	 */
	if (cd9660_is_video_file(ip, imp))
	{
		cd9660_xa_init(ip, isodir);
		
		is_video_file = 1;
	}
	if (ip->iso_extent == imp->root_extent) {
		ip->i_parent = 1;	/* root's parent is always 1 by convention */
		/* mode type must be S_IFDIR */
		ip->inode.iso_mode = (ip->inode.iso_mode & ~S_IFMT) | S_IFDIR;
	}
	vtype = IFTOVT(ip->inode.iso_mode);
#if !FIFO
	if (vtype == VFIFO) {
	        error = ENOTSUP;
		goto errout;
	}
#endif
#ifdef  ISODEVMAP
	if (vtype == VCHR || vtype == VBLK) {
	        struct iso_dnode *dp;

	        if (dp = iso_dmap(dev, ino, 0))
		        ip->inode.iso_rdev = dp->d_dev;
	}
#endif
	/*
	 * create the associated vnode
	 */
	//bzero(&vfsp, sizeof(struct vnode_fsparam));
	vfsp.vnfs_mp = mp;
	vfsp.vnfs_vtype = vtype;
	vfsp.vnfs_str = "cd9660";
	vfsp.vnfs_dvp = dvp;
	vfsp.vnfs_fsnode = ip;
	vfsp.vnfs_cnp = cnp;

	if (is_video_file)
	        vfsp.vnfs_vops = cd9660_cdxaop_p;
	else if (vtype == VFIFO )
		vfsp.vnfs_vops = cd9660_fifoop_p;
	else if (vtype == VBLK || vtype == VCHR)
		vfsp.vnfs_vops = cd9660_specop_p;
	else
		vfsp.vnfs_vops = cd9660_vnodeop_p;
		
	if (vtype == VBLK || vtype == VCHR)
	        vfsp.vnfs_rdev = ip->inode.iso_rdev;
	else
		vfsp.vnfs_rdev = 0;

	vfsp.vnfs_filesize = ip->i_size;

	if (dvp && cnp && (cnp->cn_flags & MAKEENTRY))
		vfsp.vnfs_flags = 0;
	else
		vfsp.vnfs_flags = VNFS_NOCACHE;

	/* Tag root directory */
	if (ip->iso_extent == imp->root_extent)
		vfsp.vnfs_markroot = 1;
	else	
		vfsp.vnfs_markroot = 0;

	vfsp.vnfs_marksystem = 0;

	if ( (error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &vp)) )
	        goto errout;

	ip->i_vnode = vp;

	vnode_ref(ip->i_devvp);
	vnode_addfsref(vp);
	vnode_settag(vp, VT_ISOFS);

	if (bp)
		buf_brelse(bp);
	*vpp = vp;

	CLR(ip->i_flag, ISO_INALLOC);

	if (ISSET(ip->i_flag, ISO_INWALLOC))
	        wakeup(ip);

	return (0);

errout:
	if (bp)
		buf_brelse(bp);
	cd9660_ihashrem(ip);

	if (ISSET(ip->i_flag, ISO_INWALLOC))
	        wakeup(ip);

	FREE_ZONE(ip, sizeof(struct iso_node), M_ISOFSNODE);

	return (error);
}


/************************************************************************
 *
 *  Function:	DRGetTypeCreatorAndFlags
 *
 *  Purpose:	Set up the fileType, fileCreator and fileFlags
 *
 *  Returns:	none
 *
 *  Side Effects:	sets *theTypePtr, *theCreatorPtr, and *theFlagsPtr
 *
 *  Description:
 *
 *  Revision History:
 *	28 Jul 88	BL¡B	Added a new extension type of 6, which allows
 *						the specification of four of the finder flags.
 *						We let the creator of the disk just copy over
 *						the finder flags, but we only look at always
 *						switch launch, system, bundle, and locked bits.
 *	15 Aug 88	BL¡B	The Apple extensions to ISO 9660 implemented the
 *						padding field at the end of a directory record
 *						incorrectly.
 *	19 Jul 89	BG		Rewrote routine to handle the "new" Apple
 *						Extensions definition, as well as take into
 *						account the possibility of "other" definitions.
 *	02 Nov 89	BG		Corrected the 'AA' SystemUseID processing to
 *						check for SystemUseID == 2 (HFS).  Was incorrectly
 *						checking for SystemUseID == 1 (ProDOS) before.
 *	18 Mar 92	CMP		Fixed the check for whether len_fi was odd or even.
 *						Before it would always assume even for an XA record.
 *	26 Dec 97	jwc		Swiped from MacOS implementation of ISO 9660 CD-ROM
 *						support and modified to work in MacOSX file system.
 *
 *********************************************************************** */
 
static void
DRGetTypeCreatorAndFlags(	struct iso_mnt * theMountPointPtr,
							struct iso_directory_record * theDirRecPtr, 
							u_int32_t * theTypePtr, 
							u_int32_t * theCreatorPtr, 
							u_int16_t * theFlagsPtr )
{
	int					foundStuff;
	u_int32_t			myType;
	u_int32_t			myCreator;
	AppleExtension		*myAppleExtPtr;
	NewAppleExtension	*myNewAppleExtPtr;
	u_int16_t			myFinderFlags;
	char				*myPtr;

	foundStuff = 1;
	myType = 0x3f3f3f3f;
	myCreator = 0x3f3f3f3f;
	myFinderFlags = 0;
	*theFlagsPtr = 0x0000;

	/*
	 * handle the fact that our original apple extensions didn't take
	 * into account the padding byte on a file name
	 */

	myPtr = &theDirRecPtr->name[ (isonum_711(theDirRecPtr->name_len)) ];
	
	/* if string length is even, bump myPtr for padding byte */
	if ( ((isonum_711(theDirRecPtr->name_len)) & 0x01) == 0 )
		myPtr++;
	myAppleExtPtr = (AppleExtension *) myPtr;

	/*
	 * checking for whether or not the new 'AA' code is being 
	 * called (and if so, correctly)
	 */
	if ( (isonum_711(theDirRecPtr->length)) <= 
		 ISO_DIRECTORY_RECORD_SIZE + (isonum_711(theDirRecPtr->name_len)) ) {
		foundStuff = 0;
		goto DoneLooking;
	}

	foundStuff = 0;	/* now we default to *false* until we find a good one */
	myPtr = (char *) myAppleExtPtr;

	if ( (theMountPointPtr->im_flags2 & IMF2_IS_CDXA) != 0 )
		myPtr += 14;/* add in CD-XA fixed record offset (tnx, Phillips) */
	myNewAppleExtPtr = (NewAppleExtension *) myPtr;

	/*
	 * Calculate the "real" end of the directory record information.
	 *
	 * Note: We always read the first 4 bytes of the System-Use data, so
	 * adjust myPtr down so we don't read off the end of the directory!
	 */
	myPtr = ((char *) theDirRecPtr) + (isonum_711(theDirRecPtr->length));
	myPtr -= sizeof(NewAppleExtension) - 1;
	while( (char *) myNewAppleExtPtr < myPtr ) 	/* end of directory buffer */
	{
		/*
		 *	If we get here, we can assume that ALL further entries in this
		 *	directory record are of the form:
		 *
		 *		struct OptionalSystemUse
		 *		{
		 *			byte	Signature[2];
		 *			byte	OSULength;
		 *			byte	systemUseID;
		 *			byte	fileType[4];		# only if HFS
		 *			byte	fileCreator[4];		# only if HFS
		 *			byte	finderFlags[2];		# only if HFS
		 *		};
		 *
		 *	This means that we can examine the Signature bytes to see
		 *	if they are 'AA' (the NEW Apple extension signature).
		 *	If they are, deal with them.  If they aren't,
		 *	the OSULength field will tell us how long this extension
		 *	info is (including the signature and length bytes) and that
		 *	will allow us to walk the OptionalSystemUse records until
		 *	we hit the end of them or run off the end of the 
		 *	directory record.
		 */
		u_char				*myFromPtr, *myToPtr;
		union
		{
			u_int32_t		fourchars;
			u_char			chars[4];
		} myChars;

		if ( (myNewAppleExtPtr->signature[0] == 'A') &&
			(myNewAppleExtPtr->signature[1] == 'A') ) {
			if ( isonum_711(myNewAppleExtPtr->systemUseID) == 2 ) {
				/* HFS */
				foundStuff = 1;			/* we got one! */

				myFromPtr = &myNewAppleExtPtr->fileType[0]; 
				myToPtr = &myChars.chars[0];
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr = *myFromPtr;
				myType = myChars.fourchars;	/* copy file type to user var */

				myFromPtr = &myNewAppleExtPtr->fileCreator[0]; 
				myToPtr = &myChars.chars[0];
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr = *myFromPtr;
				myCreator = myChars.fourchars;	/* copy creator to user var */

				myFromPtr = &myNewAppleExtPtr->finderFlags[0]; 
				myToPtr = &myChars.chars[2];	/* *flags* is a short */
				myChars.fourchars = 0; 
				*myToPtr++ = *myFromPtr++; 
				*myToPtr = *myFromPtr;
				myFinderFlags = myChars.fourchars;
				myFinderFlags &=
					( fAlwaysBit | fSystemBit | fHasBundleBit | fLockedBit );
				/* return Finder flags to user var */
				*theFlagsPtr = (myFinderFlags | fInitedBit);

				break;		/* exit the loop */
			}
		}

		/*
		 *	Check to see if we have a reasonable OSULength value.
		 *	ZERO is not an acceptable value.  Nor is any value less than 4.
		 */

		if ( (isonum_711(myNewAppleExtPtr->OSULength)) < 4 ) 
			break;	/* not acceptable - get out! */

		/* otherwise, step past this SystemUse record */
		(char *)myNewAppleExtPtr += (isonum_711(myNewAppleExtPtr->OSULength));
		
	} /* end of while loop */

DoneLooking:
	if ( foundStuff != 0 ) {
		*theTypePtr    = myType;
		*theCreatorPtr = myCreator;
	} else {
		*theTypePtr = 0;
		*theCreatorPtr = 0;
	}
	
	return;
	
} /* DRGetTypeCreatorAndFlags */


/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
cd9660_vptofh(struct vnode *vp, int *fhlenp, unsigned char *fhp, __unused vfs_context_t context)
{
	register struct iso_node *ip = VTOI(vp);
	register struct ifid *ifhp;

	if (*fhlenp < (int)sizeof(struct ifid))
		return (EOVERFLOW);
	
	ifhp = (struct ifid *)fhp;
	
	ifhp->ifid_ino = ip->i_number;
	ifhp->ifid_start = ip->iso_start;
	*fhlenp = sizeof(struct ifid);
	
#ifdef	ISOFS_DBG
	printf("vptofh: ino %d, start %ld\n",
	       ifhp->ifid_ino,ifhp->ifid_start);
#endif
	return (0);
}

/*
 * Fast-FileSystem only?
 */
int
cd9660_sysctl(__unused int *name, __unused u_int namelen, __unused user_addr_t oldp,
	      __unused size_t *oldlenp, __unused user_addr_t newp,
	      __unused size_t newlen, __unused vfs_context_t context)
{
     return (ENOTSUP);
}

