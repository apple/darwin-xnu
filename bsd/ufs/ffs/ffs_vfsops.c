/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1989, 1991, 1993, 1994
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
 *	@(#)ffs_vfsops.c	8.31 (Berkeley) 5/20/95
 */

#include <rev_endian_fs.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/namei.h>
#include <sys/proc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/socket.h>
#include <sys/mount.h>
#include <sys/buf.h>
#include <sys/mbuf.h>
#include <sys/file.h>
#include <sys/disk.h>
#include <sys/ioctl.h>
#include <sys/errno.h>
#include <sys/malloc.h>
#include <sys/ubc.h>
#include <sys/quota.h>

#include <miscfs/specfs/specdev.h>

#include <ufs/ufs/quota.h>
#include <ufs/ufs/ufsmount.h>
#include <ufs/ufs/inode.h>
#include <ufs/ufs/ufs_extern.h>

#include <ufs/ffs/fs.h>
#include <ufs/ffs/ffs_extern.h>
#if REV_ENDIAN_FS
#include <ufs/ufs/ufs_byte_order.h>
#include <architecture/byte_order.h>
#endif /* REV_ENDIAN_FS */

int ffs_sbupdate __P((struct ufsmount *, int));

struct vfsops ufs_vfsops = {
	ffs_mount,
	ufs_start,
	ffs_unmount,
	ufs_root,
	ufs_quotactl,
	ffs_statfs,
	ffs_sync,
	ffs_vget,
	ffs_fhtovp,
	ffs_vptofh,
	ffs_init,
	ffs_sysctl,
};

extern u_long nextgennumber;

/*
 * Called by main() when ufs is going to be mounted as root.
 */
ffs_mountroot()
{
	extern struct vnode *rootvp;
	struct fs *fs;
	struct mount *mp;
	struct proc *p = current_proc();	/* XXX */
	struct ufsmount *ump;
	u_int size;
	int error;
	
	/*
	 * Get vnode for rootdev.
	 */
	if (error = bdevvp(rootdev, &rootvp)) {
		printf("ffs_mountroot: can't setup bdevvp");
		return (error);
	}
	if (error = vfs_rootmountalloc("ufs", "root_device", &mp)) {
		vrele(rootvp); /* release the reference from bdevvp() */
		return (error);
	}

	/* Must set the MNT_ROOTFS flag before doing the actual mount */
	mp->mnt_flag |= MNT_ROOTFS;

	/* Set asynchronous flag by default */
	mp->mnt_flag |= MNT_ASYNC;

	if (error = ffs_mountfs(rootvp, mp, p)) {
		mp->mnt_vfc->vfc_refcount--;

		if (mp->mnt_kern_flag & MNTK_IO_XINFO)
		        FREE(mp->mnt_xinfo_ptr, M_TEMP);
		vfs_unbusy(mp, p);

		vrele(rootvp); /* release the reference from bdevvp() */
		FREE_ZONE(mp, sizeof (struct mount), M_MOUNT);
		return (error);
	}
	simple_lock(&mountlist_slock);
	CIRCLEQ_INSERT_TAIL(&mountlist, mp, mnt_list);
	simple_unlock(&mountlist_slock);
	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	(void) copystr(mp->mnt_stat.f_mntonname, fs->fs_fsmnt, MNAMELEN - 1, 0);
	(void)ffs_statfs(mp, &mp->mnt_stat, p);
	vfs_unbusy(mp, p);
	inittodr(fs->fs_time);
	return (0);
}

/*
 * VFS Operations.
 *
 * mount system call
 */
int
ffs_mount(mp, path, data, ndp, p)
	register struct mount *mp;
	char *path;
	caddr_t data;
	struct nameidata *ndp;
	struct proc *p;
{
	struct vnode *devvp;
	struct ufs_args args;
	struct ufsmount *ump;
	register struct fs *fs;
	u_int size;
	int error, flags;
	mode_t accessmode;
	int ronly;
	int reload = 0;

	if (error = copyin(data, (caddr_t)&args, sizeof (struct ufs_args)))
		return (error);
	/*
	 * If updating, check whether changing from read-only to
	 * read/write; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		ump = VFSTOUFS(mp);
		fs = ump->um_fs;
		if (fs->fs_ronly == 0 && (mp->mnt_flag & MNT_RDONLY)) {
			flags = WRITECLOSE;
			if (mp->mnt_flag & MNT_FORCE)
				flags |= FORCECLOSE;
			if (error = ffs_flushfiles(mp, flags, p))
				return (error);
			fs->fs_clean = 1;
			fs->fs_ronly = 1;
			if (error = ffs_sbupdate(ump, MNT_WAIT)) {
				fs->fs_clean = 0;
				fs->fs_ronly = 0;
				return (error);
			}
		}
		/* save fs_ronly to later use */
		ronly = fs->fs_ronly;
		if ((mp->mnt_flag & MNT_RELOAD) || ronly)
			reload = 1;
		if ((reload) &&
		    (error = ffs_reload(mp, ndp->ni_cnd.cn_cred, p)))
			return (error);
		/* replace the ronly after load */
		fs->fs_ronly = ronly;
		/* 
		* Do not update the file system if the user was in singleuser
		* and then tries to mount -uw without fscking
		*/
		if (!fs->fs_clean && ronly) {
			printf("WARNING: trying to mount a dirty file system\n");
			if (issingleuser() && (mp->mnt_flag & MNT_ROOTFS)) {
				printf("WARNING: R/W mount of %s denied. Filesystem is not clean - run fsck\n",fs->fs_fsmnt);
				/* 
				 * Reset the readonly bit as reload might have
				 * modified this bit 
				 */
				fs->fs_ronly = 1;
				return(EPERM);
			}
		}

		if (ronly && (mp->mnt_kern_flag & MNTK_WANTRDWR)) {
			/*
			 * If upgrade to read-write by non-root, then verify
			 * that user has necessary permissions on the device.
			 */
			if (p->p_ucred->cr_uid != 0) {
				devvp = ump->um_devvp;
				vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, p);
				if (error = VOP_ACCESS(devvp, VREAD | VWRITE,
				    p->p_ucred, p)) {
					VOP_UNLOCK(devvp, 0, p);
					return (error);
				}
				VOP_UNLOCK(devvp, 0, p);
			}
			fs->fs_ronly = 0;
			fs->fs_clean = 0;
			(void) ffs_sbupdate(ump, MNT_WAIT);
		}
		if (args.fspec == 0) {
			/*
			 * Process export requests.
			 */
			return (vfs_export(mp, &ump->um_export, &args.export));
		}
	}
	/*
	 * Not an update, or updating the name: look up the name
	 * and verify that it refers to a sensible block device.
	 */
	NDINIT(ndp, LOOKUP, FOLLOW, UIO_USERSPACE, args.fspec, p);
	if (error = namei(ndp))
		return (error);
	devvp = ndp->ni_vp;

	if (devvp->v_type != VBLK) {
		vrele(devvp);
		return (ENOTBLK);
	}
	if (major(devvp->v_rdev) >= nblkdev) {
		vrele(devvp);
		return (ENXIO);
	}
	/*
	 * If mount by non-root, then verify that user has necessary
	 * permissions on the device.
	 */
	if (p->p_ucred->cr_uid != 0) {
		accessmode = VREAD;
		if ((mp->mnt_flag & MNT_RDONLY) == 0)
			accessmode |= VWRITE;
		vn_lock(devvp, LK_EXCLUSIVE | LK_RETRY, p);
		if (error = VOP_ACCESS(devvp, accessmode, p->p_ucred, p)) {
			vput(devvp);
			return (error);
		}
		VOP_UNLOCK(devvp, 0, p);
	}
	if ((mp->mnt_flag & MNT_UPDATE) == 0)
		error = ffs_mountfs(devvp, mp, p);
	else {
		if (devvp != ump->um_devvp)
			error = EINVAL;	/* needs translation */
		else
			vrele(devvp);
	}
	if (error) {
		vrele(devvp);
		return (error);
	}
	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	(void) copyinstr(path, fs->fs_fsmnt, sizeof(fs->fs_fsmnt) - 1,
		(size_t *)&size);
	bzero(fs->fs_fsmnt + size, sizeof(fs->fs_fsmnt) - size);
	bcopy((caddr_t)fs->fs_fsmnt, (caddr_t)mp->mnt_stat.f_mntonname,
	    MNAMELEN);
	(void) copyinstr(args.fspec, mp->mnt_stat.f_mntfromname, MNAMELEN - 1, 
	    (size_t *)&size);
	bzero(mp->mnt_stat.f_mntfromname + size, MNAMELEN - size);
	(void)ffs_statfs(mp, &mp->mnt_stat, p);
	return (0);
}

/*
 * Reload all incore data for a filesystem (used after running fsck on
 * the root filesystem and finding things to fix). The filesystem must
 * be mounted read-only.
 *
 * Things to do to update the mount:
 *	1) invalidate all cached meta-data.
 *	2) re-read superblock from disk.
 *	3) re-read summary information from disk.
 *	4) invalidate all inactive vnodes.
 *	5) invalidate all cached file data.
 *	6) re-read inode data for all active vnodes.
 */
ffs_reload(mountp, cred, p)
	register struct mount *mountp;
	struct ucred *cred;
	struct proc *p;
{
	register struct vnode *vp, *nvp, *devvp;
	struct inode *ip;
	void *space;
	struct buf *bp;
	struct fs *fs, *newfs;
	int i, blks, size, error;
	u_int64_t maxfilesize;					/* XXX */
	int32_t *lp;
#if REV_ENDIAN_FS
	int rev_endian = (mountp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	if ((mountp->mnt_flag & MNT_RDONLY) == 0)
		return (EINVAL);
	/*
	 * Step 1: invalidate all cached meta-data.
	 */
	devvp = VFSTOUFS(mountp)->um_devvp;
	if (vinvalbuf(devvp, 0, cred, p, 0, 0))
		panic("ffs_reload: dirty1");
	/*
	 * Step 2: re-read superblock from disk.
	 */
	VOP_DEVBLOCKSIZE(devvp,&size);

	if (error = bread(devvp, (ufs_daddr_t)(SBOFF/size), SBSIZE, NOCRED,&bp)) {
		brelse(bp);
		return (error);
	}
	newfs = (struct fs *)bp->b_data;
#if REV_ENDIAN_FS
	if (rev_endian) {
		byte_swap_sbin(newfs);
	}
#endif /* REV_ENDIAN_FS */
	if (newfs->fs_magic != FS_MAGIC || newfs->fs_bsize > MAXBSIZE ||
	    newfs->fs_bsize < sizeof(struct fs)) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_sbout(newfs);
#endif /* REV_ENDIAN_FS */

		brelse(bp);
		return (EIO);		/* XXX needs translation */
	}
	fs = VFSTOUFS(mountp)->um_fs;
	/*
	 * Copy pointer fields back into superblock before copying in	XXX
	 * new superblock. These should really be in the ufsmount.	XXX
	 * Note that important parameters (eg fs_ncg) are unchanged.
	 */
	newfs->fs_csp = fs->fs_csp;
	newfs->fs_maxcluster = fs->fs_maxcluster;
	newfs->fs_contigdirs = fs->fs_contigdirs;
	bcopy(newfs, fs, (u_int)fs->fs_sbsize);
	if (fs->fs_sbsize < SBSIZE)
		bp->b_flags |= B_INVAL;
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_sbout(newfs);
#endif /* REV_ENDIAN_FS */
	brelse(bp);
	mountp->mnt_maxsymlinklen = fs->fs_maxsymlinklen;
	ffs_oldfscompat(fs);
	maxfilesize = 0x100000000ULL;    /* 4GB */
	if (fs->fs_maxfilesize > maxfilesize)			/* XXX */
		fs->fs_maxfilesize = maxfilesize;		/* XXX */
	/*
	 * Step 3: re-read summary information from disk.
	 */
	blks = howmany(fs->fs_cssize, fs->fs_fsize);
	space = fs->fs_csp;
	for (i = 0; i < blks; i += fs->fs_frag) {
		size = fs->fs_bsize;
		if (i + fs->fs_frag > blks)
			size = (blks - i) * fs->fs_fsize;
		if (error = bread(devvp, fsbtodb(fs, fs->fs_csaddr + i), size,
		    NOCRED, &bp)) {
			brelse(bp);
			return (error);
		}
#if REV_ENDIAN_FS
		if (rev_endian) {
			/* csum swaps */
			byte_swap_ints((int *)bp->b_data, size / sizeof(int));
		}
#endif /* REV_ENDIAN_FS */
		bcopy(bp->b_data, space, (u_int)size);
#if REV_ENDIAN_FS
		if (rev_endian) {
			/* csum swaps */
			byte_swap_ints((int *)bp->b_data, size / sizeof(int));
		}
#endif /* REV_ENDIAN_FS */
		space = (char *) space + size;
		brelse(bp);
	}
	/*
	 * We no longer know anything about clusters per cylinder group.
	 */
	if (fs->fs_contigsumsize > 0) {
		lp = fs->fs_maxcluster;
		for (i = 0; i < fs->fs_ncg; i++)
			*lp++ = fs->fs_contigsumsize;
	}

loop:
	simple_lock(&mntvnode_slock);
	for (vp = mountp->mnt_vnodelist.lh_first; vp != NULL; vp = nvp) {
		if (vp->v_mount != mountp) {
			simple_unlock(&mntvnode_slock);
			goto loop;
		}
		nvp = vp->v_mntvnodes.le_next;
		/*
		 * Step 4: invalidate all inactive vnodes.
		 */
		if (vrecycle(vp, &mntvnode_slock, p))
			goto loop;
		/*
		 * Step 5: invalidate all cached file data.
		 */
		simple_lock(&vp->v_interlock);
		simple_unlock(&mntvnode_slock);
		if (vget(vp, LK_EXCLUSIVE | LK_INTERLOCK, p)) {
			goto loop;
		}
		if (vinvalbuf(vp, 0, cred, p, 0, 0))
			panic("ffs_reload: dirty2");
		/*
		 * Step 6: re-read inode data for all active vnodes.
		 */
		ip = VTOI(vp);
		if (error =
		    bread(devvp, fsbtodb(fs, ino_to_fsba(fs, ip->i_number)),
		    (int)fs->fs_bsize, NOCRED, &bp)) {
			brelse(bp);
			vput(vp);
			return (error);
		}
#if REV_ENDIAN_FS
	if (rev_endian) {
		byte_swap_inode_in(((struct dinode *)bp->b_data +
		    ino_to_fsbo(fs, ip->i_number)), ip);
	} else {
#endif /* REV_ENDIAN_FS */
		ip->i_din = *((struct dinode *)bp->b_data +
		    ino_to_fsbo(fs, ip->i_number));
#if REV_ENDIAN_FS
	}
#endif /* REV_ENDIAN_FS */
		brelse(bp);
		vput(vp);
		simple_lock(&mntvnode_slock);
	}
	simple_unlock(&mntvnode_slock);
	return (0);
}

/*
 * Common code for mount and mountroot
 */
int
ffs_mountfs(devvp, mp, p)
	register struct vnode *devvp;
	struct mount *mp;
	struct proc *p;
{
	register struct ufsmount *ump;
	struct buf *bp;
	register struct fs *fs;
	dev_t dev;
	struct buf *cgbp;
	struct cg *cgp;
	int32_t clustersumoff;
	void *space;
	int error, i, blks, size, ronly;
	int32_t *lp;
	struct ucred *cred;
	extern struct vnode *rootvp;
	u_int64_t maxfilesize;					/* XXX */
        u_int dbsize = DEV_BSIZE;
#if REV_ENDIAN_FS
	int rev_endian=0;
#endif /* REV_ENDIAN_FS */
	dev = devvp->v_rdev;
	cred = p ? p->p_ucred : NOCRED;
	/*
	 * Disallow multiple mounts of the same device.
	 * Disallow mounting of a device that is currently in use
	 * (except for root, which might share swap device for miniroot).
	 * Flush out any old buffers remaining from a previous use.
	 */
	if (error = vfs_mountedon(devvp))
		return (error);
	if (vcount(devvp) > 1 && devvp != rootvp)
		return (EBUSY);
	if (error = vinvalbuf(devvp, V_SAVE, cred, p, 0, 0))
		return (error);

	ronly = (mp->mnt_flag & MNT_RDONLY) != 0;
	if (error = VOP_OPEN(devvp, ronly ? FREAD : FREAD|FWRITE, FSCRED, p))
		return (error);

	VOP_DEVBLOCKSIZE(devvp,&size);

	bp = NULL;
	ump = NULL;
	if (error = bread(devvp, (ufs_daddr_t)(SBOFF/size), SBSIZE, cred, &bp))
		goto out;
	fs = (struct fs *)bp->b_data;
#if REV_ENDIAN_FS
	if (fs->fs_magic != FS_MAGIC || fs->fs_bsize > MAXBSIZE ||
	    fs->fs_bsize < sizeof(struct fs)) {
	    	int magic = fs->fs_magic;
	    	
	    	byte_swap_ints(&magic, 1);
	    	if (magic != FS_MAGIC) {
			error = EINVAL;
			goto out;
	    	}
		byte_swap_sbin(fs);
		if (fs->fs_magic != FS_MAGIC || fs->fs_bsize > MAXBSIZE ||
	    		fs->fs_bsize < sizeof(struct fs)) {
			byte_swap_sbout(fs);
			error = EINVAL;		/* XXX needs translation */
			goto out;
		}
		rev_endian=1;
	}
#endif /* REV_ENDIAN_FS */
	if (fs->fs_magic != FS_MAGIC || fs->fs_bsize > MAXBSIZE ||
	    fs->fs_bsize < sizeof(struct fs)) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_sbout(fs);
#endif /* REV_ENDIAN_FS */
		error = EINVAL;		/* XXX needs translation */
		goto out;
	}


	/*
	 * Buffer cache does not handle multiple pages in a buf when
	 * invalidating incore buffer in pageout. There are no locks 
	 * in the pageout path.  So there is a danger of loosing data when
	 * block allocation happens at the same time a pageout of buddy
	 * page occurs. incore() returns buf with both
	 * pages, this leads vnode-pageout to incorrectly flush of entire. 
	 * buf. Till the low level ffs code is modified to deal with these
	 * do not mount any FS more than 4K size.
	 */
	/*
	 * Can't mount filesystems with a fragment size less than DIRBLKSIZ
	 */
	/*
	 * Don't mount dirty filesystems, except for the root filesystem
	 */
	if ((fs->fs_bsize > PAGE_SIZE) || (fs->fs_fsize < DIRBLKSIZ) ||
        ((!(mp->mnt_flag & MNT_ROOTFS)) && (!fs->fs_clean))) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_sbout(fs);
#endif /* REV_ENDIAN_FS */
        error = ENOTSUP;
        goto out;
    }
         
	/* Let's figure out the devblock size the file system is with */
	/* the device block size = fragment size / number of sectors per frag */

	dbsize = fs->fs_fsize / NSPF(fs);
	if(dbsize <= 0 ) {
		kprintf("device blocksize computaion failed\n");
	} else {
		if (VOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&dbsize,
				FWRITE, NOCRED, p) != 0) {  
			kprintf("failed to set device blocksize\n");
		}  
		/* force the specfs to reread blocksize from size() */
		set_fsblocksize(devvp);
	} 

	/* cache the IO attributes */
	error = vfs_init_io_attributes(devvp, mp);
	if (error) {
		printf("ffs_mountfs: vfs_init_io_attributes returned %d\n",
			error);
		goto out;
	}

	/* XXX updating 4.2 FFS superblocks trashes rotational layout tables */
	if (fs->fs_postblformat == FS_42POSTBLFMT && !ronly) {
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_sbout(fs);
#endif /* REV_ENDIAN_FS */
		error = EROFS;          /* needs translation */
		goto out;
	}

	/* If we are not mounting read only, then check for overlap 
	 * condition in cylinder group's free block map.
	 * If overlap exists, then force this into a read only mount
	 * to avoid further corruption. PR#2216969
	 */
	if (ronly == 0){
	    if (error = bread (devvp, fsbtodb(fs, cgtod(fs, 0)),
						 (int)fs->fs_cgsize, NOCRED, &cgbp)) {
		    	brelse(cgbp);
		    	goto out;
	    	}
	    	cgp = (struct cg *)cgbp->b_data;
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgin(cgp,fs);
#endif /* REV_ENDIAN_FS */
	    	if (!cg_chkmagic(cgp)){
#if REV_ENDIAN_FS
				if (rev_endian)
					byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		    	brelse(cgbp);
		    	goto out;
	    	}
	    	if (cgp->cg_clustersumoff != 0) {
	      		/* Check for overlap */
	      		clustersumoff = cgp->cg_freeoff +
		      	howmany(fs->fs_cpg * fs->fs_spc / NSPF(fs), NBBY);
	      		clustersumoff = roundup(clustersumoff, sizeof(long));
	      		if (cgp->cg_clustersumoff < clustersumoff) {
		    	/* Overlap exists */
              		mp->mnt_flag |= MNT_RDONLY;
		      		ronly = 1;
	      		}
	    	}
#if REV_ENDIAN_FS
			if (rev_endian)
				byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
			brelse(cgbp);
	}

	ump = _MALLOC(sizeof *ump, M_UFSMNT, M_WAITOK);
	bzero((caddr_t)ump, sizeof *ump);
	ump->um_fs = _MALLOC((u_long)fs->fs_sbsize, M_UFSMNT,
	    M_WAITOK);
	bcopy(bp->b_data, ump->um_fs, (u_int)fs->fs_sbsize);
	if (fs->fs_sbsize < SBSIZE)
		bp->b_flags |= B_INVAL;
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_sbout(fs);
#endif /* REV_ENDIAN_FS */
	brelse(bp);
	bp = NULL;
	fs = ump->um_fs;
	fs->fs_ronly = ronly;
	size = fs->fs_cssize;
	blks = howmany(size, fs->fs_fsize);
	if (fs->fs_contigsumsize > 0)
		size += fs->fs_ncg * sizeof(int32_t);
	size += fs->fs_ncg * sizeof(u_int8_t);
	space = _MALLOC((u_long)size, M_UFSMNT, M_WAITOK);
	fs->fs_csp = space;
	for (i = 0; i < blks; i += fs->fs_frag) {
		size = fs->fs_bsize;
		if (i + fs->fs_frag > blks)
			size = (blks - i) * fs->fs_fsize;
		if (error = bread(devvp, fsbtodb(fs, fs->fs_csaddr + i), size,
		    cred, &bp)) {
			_FREE(fs->fs_csp, M_UFSMNT);
			goto out;
		}
		bcopy(bp->b_data, space, (u_int)size);
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_ints((int *) space, size / sizeof(int));
#endif /* REV_ENDIAN_FS */
		space = (char *)space + size;
		brelse(bp);
		bp = NULL;
	}
	if (fs->fs_contigsumsize > 0) {
		fs->fs_maxcluster = lp = space;
		for (i = 0; i < fs->fs_ncg; i++)
			*lp++ = fs->fs_contigsumsize;
		space = lp;
	}
	size = fs->fs_ncg * sizeof(u_int8_t);
	fs->fs_contigdirs = (u_int8_t *)space;
	space = (u_int8_t *)space + size;
	bzero(fs->fs_contigdirs, size);
	/* XXX Compatibility for old filesystems */
	if (fs->fs_avgfilesize <= 0)
		fs->fs_avgfilesize = AVFILESIZ;
	if (fs->fs_avgfpdir <= 0)
		fs->fs_avgfpdir = AFPDIR;
	/* XXX End of compatibility */
	mp->mnt_data = (qaddr_t)ump;
	mp->mnt_stat.f_fsid.val[0] = (long)dev;
	mp->mnt_stat.f_fsid.val[1] = mp->mnt_vfc->vfc_typenum;
	/* XXX warning hardcoded max symlen and not "mp->mnt_maxsymlinklen = fs->fs_maxsymlinklen;" */
	mp->mnt_maxsymlinklen = 60;
#if REV_ENDIAN_FS
	if (rev_endian)
		mp->mnt_flag |= MNT_REVEND;
#endif /* REV_ENDIAN_FS */
	ump->um_mountp = mp;
	ump->um_dev = dev;
	ump->um_devvp = devvp;
	ump->um_nindir = fs->fs_nindir;
	ump->um_bptrtodb = fs->fs_fsbtodb;
	ump->um_seqinc = fs->fs_frag;
	for (i = 0; i < MAXQUOTAS; i++)
		ump->um_qfiles[i].qf_vp = NULLVP;
	devvp->v_specflags |= SI_MOUNTEDON;
	ffs_oldfscompat(fs);
	ump->um_savedmaxfilesize = fs->fs_maxfilesize;		/* XXX */
	maxfilesize = 0x100000000ULL;    /* 4GB */
#if 0
	maxfilesize = (u_int64_t)0x40000000 * fs->fs_bsize - 1;	/* XXX */
#endif /* 0 */
	if (fs->fs_maxfilesize > maxfilesize)			/* XXX */
		fs->fs_maxfilesize = maxfilesize;		/* XXX */
	if (ronly == 0) {
		fs->fs_clean = 0;
		(void) ffs_sbupdate(ump, MNT_WAIT);
	}
	return (0);
out:
	if (bp)
		brelse(bp);
	(void)VOP_CLOSE(devvp, ronly ? FREAD : FREAD|FWRITE, cred, p);
	if (ump) {
		_FREE(ump->um_fs, M_UFSMNT);
		_FREE(ump, M_UFSMNT);
		mp->mnt_data = (qaddr_t)0;
	}
	return (error);
}

/*
 * Sanity checks for old file systems.
 *
 * XXX - goes away some day.
 */
ffs_oldfscompat(fs)
	struct fs *fs;
{
	int i;

	fs->fs_npsect = max(fs->fs_npsect, fs->fs_nsect);	/* XXX */
	fs->fs_interleave = max(fs->fs_interleave, 1);		/* XXX */
	if (fs->fs_postblformat == FS_42POSTBLFMT)		/* XXX */
		fs->fs_nrpos = 8;				/* XXX */
	if (fs->fs_inodefmt < FS_44INODEFMT) {			/* XXX */
		u_int64_t sizepb = fs->fs_bsize;		/* XXX */
								/* XXX */
		fs->fs_maxfilesize = fs->fs_bsize * NDADDR - 1;	/* XXX */
		for (i = 0; i < NIADDR; i++) {			/* XXX */
			sizepb *= NINDIR(fs);			/* XXX */
			fs->fs_maxfilesize += sizepb;		/* XXX */
		}						/* XXX */
		fs->fs_qbmask = ~fs->fs_bmask;			/* XXX */
		fs->fs_qfmask = ~fs->fs_fmask;			/* XXX */
	}							/* XXX */
	return (0);
}

/*
 * unmount system call
 */
int
ffs_unmount(mp, mntflags, p)
	struct mount *mp;
	int mntflags;
	struct proc *p;
{
	register struct ufsmount *ump;
	register struct fs *fs;
	int error, flags;
	int force;

	flags = 0;
	force = 0;
	if (mntflags & MNT_FORCE) {
		flags |= FORCECLOSE;
		force = 1;
	}
	if ( (error = ffs_flushfiles(mp, flags, p)) && !force )
		return (error);
	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	if (fs->fs_ronly == 0) {
		fs->fs_clean = 1;
		if (error = ffs_sbupdate(ump, MNT_WAIT)) {
			fs->fs_clean = 0;
#ifdef notyet
		/* we can atleast cleanup ; as the media could be WP */
		/* & during mount, we do not check for write failures  */
		/* FIXME LATER : the Correct fix would be to have */
		/* mount detect the WP media and downgrade to readonly mount */
		/* For now, here it is */
			return (error);
#endif /* notyet */
		}
	}
	ump->um_devvp->v_specflags &= ~SI_MOUNTEDON;
	error = VOP_CLOSE(ump->um_devvp, fs->fs_ronly ? FREAD : FREAD|FWRITE,
		NOCRED, p);
	if (error && !force)
		return (error);
	vrele(ump->um_devvp);

	_FREE(fs->fs_csp, M_UFSMNT);
	_FREE(fs, M_UFSMNT);
	_FREE(ump, M_UFSMNT);
	mp->mnt_data = (qaddr_t)0;
#if REV_ENDIAN_FS
	mp->mnt_flag &= ~MNT_REVEND;
#endif /* REV_ENDIAN_FS */
	return (0);
}

/*
 * Flush out all the files in a filesystem.
 */
ffs_flushfiles(mp, flags, p)
	register struct mount *mp;
	int flags;
	struct proc *p;
{
	register struct ufsmount *ump;
	int i, error;

	ump = VFSTOUFS(mp);

#if QUOTA
	/*
	 * NOTE: The open quota files have an indirect reference
	 * on the root directory vnode.  We must account for this
	 * extra reference when doing the intial vflush.
	 */
	if (mp->mnt_flag & MNT_QUOTA) {
		struct vnode *rootvp = NULLVP;
		int quotafilecnt = 0;

		/* Find out how many quota files we have open. */
		for (i = 0; i < MAXQUOTAS; i++) {
			if (ump->um_qfiles[i].qf_vp != NULLVP)
				++quotafilecnt;
		}

		/*
		 * Check if the root vnode is in our inode hash
		 * (so we can skip over it).
		 */
		rootvp = ufs_ihashget(ump->um_dev, ROOTINO);

		error = vflush(mp, rootvp, SKIPSYSTEM|flags);

		if (rootvp) {
			/*
			 * See if there are additional references on the
			 * root vp besides the ones obtained from the open
			 * quota files and the hfs_chashget call above.
			 */
			if ((error == 0) &&
			    (rootvp->v_usecount > (1 + quotafilecnt))) {
				error = EBUSY;  /* root dir is still open */
			}
			vput(rootvp);
		}
		if (error && (flags & FORCECLOSE) == 0)
			return (error);

		for (i = 0; i < MAXQUOTAS; i++) {
			if (ump->um_qfiles[i].qf_vp == NULLVP)
				continue;
			quotaoff(p, mp, i);
		}
		/*
		 * Here we fall through to vflush again to ensure
		 * that we have gotten rid of all the system vnodes.
		 */
	}
#endif
	error = vflush(mp, NULLVP, SKIPSWAP|flags);
	error = vflush(mp, NULLVP, flags);
	return (error);
}

/*
 * Get file system statistics.
 */
int
ffs_statfs(mp, sbp, p)
	struct mount *mp;
	register struct statfs *sbp;
	struct proc *p;
{
	register struct ufsmount *ump;
	register struct fs *fs;

	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	if (fs->fs_magic != FS_MAGIC)
		panic("ffs_statfs");
	sbp->f_bsize = fs->fs_fsize;
	sbp->f_iosize = fs->fs_bsize;
	sbp->f_blocks = fs->fs_dsize;
	sbp->f_bfree = fs->fs_cstotal.cs_nbfree * fs->fs_frag +
		fs->fs_cstotal.cs_nffree;
	sbp->f_bavail = freespace(fs, fs->fs_minfree);
	sbp->f_files =  fs->fs_ncg * fs->fs_ipg - ROOTINO;
	sbp->f_ffree = fs->fs_cstotal.cs_nifree;
	if (sbp != &mp->mnt_stat) {
		sbp->f_type = mp->mnt_vfc->vfc_typenum;
		bcopy((caddr_t)mp->mnt_stat.f_mntonname,
			(caddr_t)&sbp->f_mntonname[0], MNAMELEN);
		bcopy((caddr_t)mp->mnt_stat.f_mntfromname,
			(caddr_t)&sbp->f_mntfromname[0], MNAMELEN);
	}
	return (0);
}

/*
 * Go through the disk queues to initiate sandbagged IO;
 * go through the inodes to write those that have been modified;
 * initiate the writing of the super block if it has been modified.
 *
 * Note: we are always called with the filesystem marked `MPBUSY'.
 */
int
ffs_sync(mp, waitfor, cred, p)
	struct mount *mp;
	int waitfor;
	struct ucred *cred;
	struct proc *p;
{
	struct vnode *nvp, *vp;
	struct inode *ip;
	struct ufsmount *ump = VFSTOUFS(mp);
	struct fs *fs;
	int error, allerror = 0;

	fs = ump->um_fs;
	if (fs->fs_fmod != 0 && fs->fs_ronly != 0) {		/* XXX */
		printf("fs = %s\n", fs->fs_fsmnt);
		panic("update: rofs mod");
	}
	/*
	 * Write back each (modified) inode.
	 */
	simple_lock(&mntvnode_slock);
loop:
	for (vp = mp->mnt_vnodelist.lh_first;
	     vp != NULL;
	     vp = nvp) {
		int didhold = 0;

		/*
		 * If the vnode that we are about to sync is no longer
		 * associated with this mount point, start over.
		 */
		if (vp->v_mount != mp)
			goto loop;
		simple_lock(&vp->v_interlock);
		nvp = vp->v_mntvnodes.le_next;
		ip = VTOI(vp);

		// restart our whole search if this guy is locked
		// or being reclaimed.
		if (ip == NULL || vp->v_flag & (VXLOCK|VORECLAIM)) {
			simple_unlock(&vp->v_interlock);
			continue;
		}

		if ((vp->v_type == VNON) ||
		    ((ip->i_flag & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) == 0 &&
		     vp->v_dirtyblkhd.lh_first == NULL && !(vp->v_flag & VHASDIRTY))) {
			simple_unlock(&vp->v_interlock);
			continue;
		}
		simple_unlock(&mntvnode_slock);
		error = vget(vp, LK_EXCLUSIVE | LK_NOWAIT | LK_INTERLOCK, p);
		if (error) {
			simple_lock(&mntvnode_slock);
			if (error == ENOENT)
				goto loop;
			continue;
		}
		didhold = ubc_hold(vp);
		if (error = VOP_FSYNC(vp, cred, waitfor, p))
			allerror = error;
		VOP_UNLOCK(vp, 0, p);
		if (didhold)
			ubc_rele(vp);
		vrele(vp);
		simple_lock(&mntvnode_slock);
	}
	simple_unlock(&mntvnode_slock);
	/*
	 * Force stale file system control information to be flushed.
	 */
	if (error = VOP_FSYNC(ump->um_devvp, cred, waitfor, p))
		allerror = error;
#if QUOTA
	qsync(mp);
#endif
	/*
	 * Write back modified superblock.
	 */
	if (fs->fs_fmod != 0) {
		fs->fs_fmod = 0;
		fs->fs_time = time.tv_sec;
		if (error = ffs_sbupdate(ump, waitfor))
			allerror = error;
	}
	return (allerror);
}

/*
 * Look up a FFS dinode number to find its incore vnode, otherwise read it
 * in from disk.  If it is in core, wait for the lock bit to clear, then
 * return the inode locked.  Detection and handling of mount points must be
 * done by the calling routine.
 */
int
ffs_vget(mp, inop, vpp)
	struct mount *mp;
	void *inop;
	struct vnode **vpp;
{
	struct proc *p = current_proc();		/* XXX */
	struct fs *fs;
	struct inode *ip;
	struct ufsmount *ump;
	struct buf *bp;
	struct vnode *vp;
	ino_t ino;
	dev_t dev;
	int i, type, error = 0;

	ino = (ino_t) inop;
	ump = VFSTOUFS(mp);
	dev = ump->um_dev;

	/* Check for unmount in progress */
	if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
		*vpp = NULL;
		return (EPERM);
	}

	/* check in the inode hash */
	if ((*vpp = ufs_ihashget(dev, ino)) != NULL) {
		vp = *vpp;
		UBCINFOCHECK("ffs_vget", vp);
		return (0);
	}

	/*
	 * Not in inode hash.
	 * Allocate a new vnode/inode.
	 */
	type = ump->um_devvp->v_tag == VT_MFS ? M_MFSNODE : M_FFSNODE; /* XXX */
	MALLOC_ZONE(ip, struct inode *, sizeof(struct inode), type, M_WAITOK);
	bzero((caddr_t)ip, sizeof(struct inode));
	lockinit(&ip->i_lock, PINOD, "inode", 0, 0);
	/* lock the inode */
	lockmgr(&ip->i_lock, LK_EXCLUSIVE, (struct slock *)0, p);

	ip->i_fs = fs = ump->um_fs;
	ip->i_dev = dev;
	ip->i_number = ino;
	SET(ip->i_flag, IN_ALLOC);
#if QUOTA
	for (i = 0; i < MAXQUOTAS; i++)
		ip->i_dquot[i] = NODQUOT;
#endif

	/*
	 * We could have blocked in MALLOC_ZONE. Check for the race.
	 */
	if ((*vpp = ufs_ihashget(dev, ino)) != NULL) {
		/* lost the race, clean up */
		FREE_ZONE(ip, sizeof(struct inode), type);
		vp = *vpp;
		UBCINFOCHECK("ffs_vget", vp);
		return (0);
	}

	/*
	 * Put it onto its hash chain locked so that other requests for
	 * this inode will block if they arrive while we are sleeping waiting
	 * for old data structures to be purged or for the contents of the
	 * disk portion of this inode to be read.
	 */
	ufs_ihashins(ip);

	/* Read in the disk contents for the inode, copy into the inode. */
	if (error = bread(ump->um_devvp, fsbtodb(fs, ino_to_fsba(fs, ino)),
	    (int)fs->fs_bsize, NOCRED, &bp)) {
		brelse(bp);
		goto errout;
	}
#if REV_ENDIAN_FS
	if (mp->mnt_flag & MNT_REVEND) {
		byte_swap_inode_in(((struct dinode *)bp->b_data + ino_to_fsbo(fs, ino)),ip);
	} else {
		ip->i_din = *((struct dinode *)bp->b_data + ino_to_fsbo(fs, ino));
	}
#else
	ip->i_din = *((struct dinode *)bp->b_data + ino_to_fsbo(fs, ino));
#endif /* REV_ENDIAN_FS */
	brelse(bp);

	if (error = getnewvnode(VT_UFS, mp, ffs_vnodeop_p, &vp))
		goto errout;

	vp->v_data = ip;
	ip->i_vnode = vp;

	/*
	 * Initialize the vnode from the inode, check for aliases.
	 * Note that the underlying vnode may have changed.
	 */
	if (error = ufs_vinit(mp, ffs_specop_p, FFS_FIFOOPS, &vp)) {
		vput(vp);
		*vpp = NULL;
		goto out;
	}
	/*
	 * Finish inode initialization now that aliasing has been resolved.
	 */
	ip->i_devvp = ump->um_devvp;
	VREF(ip->i_devvp);
	/*
	 * Set up a generation number for this inode if it does not
	 * already have one. This should only happen on old filesystems.
	 */
	if (ip->i_gen == 0) {
		if (++nextgennumber < (u_long)time.tv_sec)
			nextgennumber = time.tv_sec;
		ip->i_gen = nextgennumber;
		if ((vp->v_mount->mnt_flag & MNT_RDONLY) == 0)
			ip->i_flag |= IN_MODIFIED;
	}
	/*
	 * Ensure that uid and gid are correct. This is a temporary
	 * fix until fsck has been changed to do the update.
	 */
	if (fs->fs_inodefmt < FS_44INODEFMT) {		/* XXX */
		ip->i_uid = ip->i_din.di_ouid;		/* XXX */
		ip->i_gid = ip->i_din.di_ogid;		/* XXX */
	}						/* XXX */

	if (UBCINFOMISSING(vp) || UBCINFORECLAIMED(vp))
		ubc_info_init(vp);
	*vpp = vp;

out:
	CLR(ip->i_flag, IN_ALLOC);
	if (ISSET(ip->i_flag, IN_WALLOC))
		wakeup(ip);
	return (error);

errout:
	ufs_ihashrem(ip);
	CLR(ip->i_flag, IN_ALLOC);
	if (ISSET(ip->i_flag, IN_WALLOC))
		wakeup(ip);
	FREE_ZONE(ip, sizeof(struct inode), type);
	*vpp = NULL;
	return (error);
}

/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the inode number is valid
 * - call ffs_vget() to get the locked inode
 * - check for an unallocated inode (i_mode == 0)
 * - check that the given client host has export rights and return
 *   those rights via. exflagsp and credanonp
 */
int
ffs_fhtovp(mp, fhp, nam, vpp, exflagsp, credanonp)
	register struct mount *mp;
	struct fid *fhp;
	struct mbuf *nam;
	struct vnode **vpp;
	int *exflagsp;
	struct ucred **credanonp;
{
	register struct ufid *ufhp;
	struct fs *fs;

	ufhp = (struct ufid *)fhp;
	fs = VFSTOUFS(mp)->um_fs;
	if (ufhp->ufid_ino < ROOTINO ||
	    ufhp->ufid_ino >= fs->fs_ncg * fs->fs_ipg)
		return (ESTALE);
	return (ufs_check_export(mp, ufhp, nam, vpp, exflagsp, credanonp));
}

/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
ffs_vptofh(vp, fhp)
	struct vnode *vp;
	struct fid *fhp;
{
	register struct inode *ip;
	register struct ufid *ufhp;

	ip = VTOI(vp);
	ufhp = (struct ufid *)fhp;
	ufhp->ufid_len = sizeof(struct ufid);
	ufhp->ufid_ino = ip->i_number;
	ufhp->ufid_gen = ip->i_gen;
	return (0);
}

/*
 * Initialize the filesystem; just use ufs_init.
 */
int
ffs_init(vfsp)
	struct vfsconf *vfsp;
{

	return (ufs_init(vfsp));
}

/*
 * fast filesystem related variables.
 */
ffs_sysctl(name, namelen, oldp, oldlenp, newp, newlen, p)
	int *name;
	u_int namelen;
	void *oldp;
	size_t *oldlenp;
	void *newp;
	size_t newlen;
	struct proc *p;
{
	extern int doclusterread, doclusterwrite, doreallocblks, doasyncfree;

	/* all sysctl names at this level are terminal */
	if (namelen != 1)
		return (ENOTDIR);		/* overloaded */

	switch (name[0]) {
	case FFS_CLUSTERREAD:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &doclusterread));
	case FFS_CLUSTERWRITE:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &doclusterwrite));
	case FFS_REALLOCBLKS:
		return (sysctl_int(oldp, oldlenp, newp, newlen,
		    &doreallocblks));
	case FFS_ASYNCFREE:
		return (sysctl_int(oldp, oldlenp, newp, newlen, &doasyncfree));
	default:
		return (EOPNOTSUPP);
	}
	/* NOTREACHED */
}

/*
 * Write a superblock and associated information back to disk.
 */
int
ffs_sbupdate(mp, waitfor)
	struct ufsmount *mp;
	int waitfor;
{
	register struct fs *dfs, *fs = mp->um_fs;
	register struct buf *bp;
	int blks;
	void *space;
	int i, size, error, allerror = 0;
	int devBlockSize=0;
#if REV_ENDIAN_FS
	int rev_endian=(mp->um_mountp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	/*
	 * First write back the summary information.
	 */
	blks = howmany(fs->fs_cssize, fs->fs_fsize);
	space = fs->fs_csp;
	for (i = 0; i < blks; i += fs->fs_frag) {
		size = fs->fs_bsize;
		if (i + fs->fs_frag > blks)
			size = (blks - i) * fs->fs_fsize;
		bp = getblk(mp->um_devvp, fsbtodb(fs, fs->fs_csaddr + i),
		    size, 0, 0, BLK_META);
		bcopy(space, bp->b_data, (u_int)size);
#if REV_ENDIAN_FS
		if (rev_endian) {
			byte_swap_ints((int *)bp->b_data, size / sizeof(int));
		}
#endif /* REV_ENDIAN_FS */
		space = (char *)space + size;
		if (waitfor != MNT_WAIT)
			bawrite(bp);
		else if (error = bwrite(bp))
			allerror = error;
	}
	/*
	 * Now write back the superblock itself. If any errors occurred
	 * up to this point, then fail so that the superblock avoids
	 * being written out as clean.
	 */
	if (allerror)
		return (allerror);
	VOP_DEVBLOCKSIZE(mp->um_devvp,&devBlockSize);
	bp = getblk(mp->um_devvp, (SBOFF/devBlockSize), (int)fs->fs_sbsize, 0, 0, BLK_META);
	bcopy((caddr_t)fs, bp->b_data, (u_int)fs->fs_sbsize);
	/* Restore compatibility to old file systems.		   XXX */
	dfs = (struct fs *)bp->b_data;				/* XXX */
	if (fs->fs_postblformat == FS_42POSTBLFMT)		/* XXX */
		dfs->fs_nrpos = -1;				/* XXX */
#if REV_ENDIAN_FS
	/*  
	*  Swapping bytes here ; so that in case
	*   of inode format < FS_44INODEFMT appropriate
	*   fields get moved 
	*/
	if (rev_endian) {
		byte_swap_sbout((struct fs *)bp->b_data);
	}
#endif /* REV_ENDIAN_FS */
	if (fs->fs_inodefmt < FS_44INODEFMT) {			/* XXX */
		int32_t *lp, tmp;				/* XXX */
								/* XXX */
		lp = (int32_t *)&dfs->fs_qbmask;		/* XXX */
		tmp = lp[4];					/* XXX */
		for (i = 4; i > 0; i--)				/* XXX */
			lp[i] = lp[i-1];			/* XXX */
		lp[0] = tmp;					/* XXX */
	}							/* XXX */
#if REV_ENDIAN_FS
	/* Note that dfs is already swapped so swap the filesize
	*  before writing
	*/
	if (rev_endian) {
		dfs->fs_maxfilesize = NXSwapLongLong(mp->um_savedmaxfilesize);		/* XXX */
	} else {
#endif /* REV_ENDIAN_FS */
		dfs->fs_maxfilesize = mp->um_savedmaxfilesize;	/* XXX */
#if REV_ENDIAN_FS
	}
#endif /* REV_ENDIAN_FS */
	if (waitfor != MNT_WAIT)
		bawrite(bp);
	else if (error = bwrite(bp))
		allerror = error;

	return (allerror);
}
