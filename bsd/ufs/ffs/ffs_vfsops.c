/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
#include <sys/kauth.h>
#include <sys/kernel.h>
#include <sys/vnode_internal.h>
#include <sys/socket.h>
#include <sys/mount_internal.h>
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
#include <libkern/OSByteOrder.h>
#endif /* REV_ENDIAN_FS */

int ffs_sbupdate(struct ufsmount *, int);

struct vfsops ufs_vfsops = {
	ffs_mount,
	ufs_start,
	ffs_unmount,
	ufs_root,
	ufs_quotactl,
	ffs_vfs_getattr,
	ffs_sync,
	ffs_vget,
	ffs_fhtovp,
	ffs_vptofh,
	ffs_init,
	ffs_sysctl,
	ffs_vfs_setattr,
	{0}
};

extern u_long nextgennumber;

union _qcvt {
	int64_t qcvt;
	int32_t val[2];
};
#define SETHIGH(q, h) { \
	union _qcvt tmp; \
	tmp.qcvt = (q); \
	tmp.val[_QUAD_HIGHWORD] = (h); \
	(q) = tmp.qcvt; \
}
#define SETLOW(q, l) { \
	union _qcvt tmp; \
	tmp.qcvt = (q); \
	tmp.val[_QUAD_LOWWORD] = (l); \
	(q) = tmp.qcvt; \
}

/*
 * Called by main() when ufs is going to be mounted as root.
 */
int
ffs_mountroot(mount_t mp, vnode_t rvp, vfs_context_t context)
{
	struct proc *p = current_proc();	/* XXX */
	int	error;
	
	/* Set asynchronous flag by default */
	vfs_setflags(mp, MNT_ASYNC);

	if (error = ffs_mountfs(rvp, mp, context))
		return (error);

	(void)ffs_statfs(mp, vfs_statfs(mp), NULL);

	return (0);
}

/*
 * VFS Operations.
 *
 * mount system call
 */
int
ffs_mount(struct mount *mp, vnode_t devvp, __unused user_addr_t data,  vfs_context_t context)
{
	struct proc *p = vfs_context_proc(context);
	struct ufsmount *ump;
	register struct fs *fs;
	u_int size;
	int error  = 0, flags;
	mode_t accessmode;
	int ronly;
	int reload = 0;

	/*
	 * If updating, check whether changing from read-write to
	 * read-only; if there is no device name, that's all we do.
	 */
	if (mp->mnt_flag & MNT_UPDATE) {
		ump = VFSTOUFS(mp);
		fs = ump->um_fs;
		if (fs->fs_ronly == 0 && (mp->mnt_flag & MNT_RDONLY)) {
			/*
			 * Flush any dirty data.
			 */
			VFS_SYNC(mp, MNT_WAIT, context);
			/*
			 * Check for and optionally get rid of files open
			 * for writing.
			 */
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
		    (error = ffs_reload(mp, vfs_context_ucred(context), p)))
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
			fs->fs_ronly = 0;
			fs->fs_clean = 0;
			(void) ffs_sbupdate(ump, MNT_WAIT);
		}
		if (devvp == 0) {
			return(0);
		}
	}
	if ((mp->mnt_flag & MNT_UPDATE) == 0)
		error = ffs_mountfs(devvp, mp, context);
	else {
		if (devvp != ump->um_devvp)
			error = EINVAL;	/* needs translation */
	}
	if (error) {
		return (error);
	}
	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	bzero(fs->fs_fsmnt , sizeof(fs->fs_fsmnt));
	strncpy(fs->fs_fsmnt,  (caddr_t)mp->mnt_vfsstat.f_mntonname, sizeof(fs->fs_fsmnt) - 1); 
	(void)ffs_statfs(mp, &mp->mnt_vfsstat, p);
	return (0);
}


struct ffs_reload_cargs {
        struct vnode	*devvp;
        kauth_cred_t cred;
        struct fs 	*fs;
        struct proc	*p;
        int		error;
#if REV_ENDIAN_FS
        int		rev_endian;
#endif /* REV_ENDIAN_FS */
};


static int
ffs_reload_callback(struct vnode *vp, void *cargs)
{
	struct inode *ip;
	struct buf   *bp;
	struct fs    *fs;
	struct ffs_reload_cargs *args;

	args = (struct ffs_reload_cargs *)cargs;

	/*
	 * flush all the buffers associated with this node
	 */
	if (buf_invalidateblks(vp, 0, 0, 0))
	        panic("ffs_reload: dirty2");

	/*
	 * Step 6: re-read inode data
	 */
	ip = VTOI(vp);
	fs = args->fs;

	if (args->error = (int)buf_bread(args->devvp, (daddr64_t)((unsigned)fsbtodb(fs, ino_to_fsba(fs, ip->i_number))),
					 (int)fs->fs_bsize, NOCRED, &bp)) {
	        buf_brelse(bp);

		return (VNODE_RETURNED_DONE);
	}

#if REV_ENDIAN_FS
	if (args->rev_endian) {
	        byte_swap_inode_in(((struct dinode *)buf_dataptr(bp) +
				    ino_to_fsbo(fs, ip->i_number)), ip);
	} else {
#endif /* REV_ENDIAN_FS */
	        ip->i_din = *((struct dinode *)buf_dataptr(bp) +
			      ino_to_fsbo(fs, ip->i_number));
#if REV_ENDIAN_FS
	}
#endif /* REV_ENDIAN_FS */

	buf_brelse(bp);

	return (VNODE_RETURNED);
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
ffs_reload(struct mount *mountp, kauth_cred_t cred, struct proc *p)
{
	register struct vnode *devvp;
	void *space;
	struct buf *bp;
	struct fs *fs, *newfs;
	int i, blks, size, error;
	u_int64_t maxfilesize;					/* XXX */
	int32_t *lp;
	struct ffs_reload_cargs args;
#if REV_ENDIAN_FS
	int rev_endian = (mountp->mnt_flag & MNT_REVEND);
#endif /* REV_ENDIAN_FS */

	if ((mountp->mnt_flag & MNT_RDONLY) == 0)
		return (EINVAL);
	/*
	 * Step 1: invalidate all cached meta-data.
	 */
	devvp = VFSTOUFS(mountp)->um_devvp;
	if (buf_invalidateblks(devvp, 0, 0, 0))
		panic("ffs_reload: dirty1");
	/*
	 * Step 2: re-read superblock from disk.
	 */
	size = vfs_devblocksize(mountp);

	if (error = (int)buf_bread(devvp, (daddr64_t)((unsigned)(SBOFF/size)), SBSIZE, NOCRED,&bp)) {
		buf_brelse(bp);
		return (error);
	}
	newfs = (struct fs *)buf_dataptr(bp);
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

		buf_brelse(bp);
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
		buf_markinvalid(bp);
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_sbout(newfs);
#endif /* REV_ENDIAN_FS */
	buf_brelse(bp);
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
		if (error = (int)buf_bread(devvp, (daddr64_t)((unsigned)fsbtodb(fs, fs->fs_csaddr + i)), size,
					   NOCRED, &bp)) {
			buf_brelse(bp);
			return (error);
		}
#if REV_ENDIAN_FS
		if (rev_endian) {
			/* csum swaps */
			byte_swap_ints((int *)buf_dataptr(bp), size / sizeof(int));
		}
#endif /* REV_ENDIAN_FS */
		bcopy((char *)buf_dataptr(bp), space, (u_int)size);
#if REV_ENDIAN_FS
		if (rev_endian) {
			/* csum swaps */
			byte_swap_ints((int *)buf_dataptr(bp), size / sizeof(int));
		}
#endif /* REV_ENDIAN_FS */
		space = (char *) space + size;
		buf_brelse(bp);
	}
	/*
	 * We no longer know anything about clusters per cylinder group.
	 */
	if (fs->fs_contigsumsize > 0) {
		lp = fs->fs_maxcluster;
		for (i = 0; i < fs->fs_ncg; i++)
			*lp++ = fs->fs_contigsumsize;
	}
#if REV_ENDIAN_FS
	args.rev_endian = rev_endian;
#endif /* REV_ENDIAN_FS */
	args.devvp = devvp;
	args.cred = cred;
	args.fs = fs;
	args.p = p;
	args.error = 0;
	/*
	 * ffs_reload_callback will be called for each vnode
	 * hung off of this mount point that can't be recycled...
	 * vnode_iterate will recycle those that it can (the VNODE_RELOAD option)
	 * the vnode will be in an 'unbusy' state (VNODE_WAIT) and 
	 * properly referenced and unreferenced around the callback
	 */
	vnode_iterate(mountp, VNODE_RELOAD | VNODE_WAIT, ffs_reload_callback, (void *)&args);

	return (args.error);
}

/*
 * Common code for mount and mountroot
 */
int
ffs_mountfs(devvp, mp, context)
	struct vnode *devvp;
	struct mount *mp;
	vfs_context_t context;
{
	struct ufsmount *ump;
	struct buf *bp;
	struct fs *fs;
	dev_t dev;
	struct buf *cgbp;
	struct cg *cgp;
	int32_t clustersumoff;
	void *space;
	int error, i, blks, ronly;
	u_int32_t size;
	int32_t *lp;
	kauth_cred_t cred;
	u_int64_t maxfilesize;					/* XXX */
        u_int dbsize = DEV_BSIZE;
#if REV_ENDIAN_FS
	int rev_endian=0;
#endif /* REV_ENDIAN_FS */
	dev = devvp->v_rdev;
	cred = vfs_context_ucred(context);

	ronly = vfs_isrdonly(mp);
	bp  = NULL;
	ump = NULL;

	/* Advisory locking should be handled at the VFS layer */
	vfs_setlocklocal(mp);

	/* Obtain the actual device block size */
	if (VNOP_IOCTL(devvp, DKIOCGETBLOCKSIZE, (caddr_t)&size, 0, context)) {
		error = ENXIO;
		goto out;
	}

	if (error = (int)buf_bread(devvp, (daddr64_t)((unsigned)(SBOFF/size)),
	    SBSIZE, cred, &bp))
		goto out;
	fs = (struct fs *)buf_dataptr(bp);
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
		if (VNOP_IOCTL(devvp, DKIOCSETBLOCKSIZE, (caddr_t)&dbsize,
				FWRITE, context) != 0) {  
			kprintf("failed to set device blocksize\n");
		}  
		/* force the specfs to reread blocksize from size() */
		set_fsblocksize(devvp);
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
	    if (error = (int)buf_bread (devvp, (daddr64_t)((unsigned)fsbtodb(fs, cgtod(fs, 0))),
					(int)fs->fs_cgsize, NOCRED, &cgbp)) {
		    	buf_brelse(cgbp);
		    	goto out;
	    	}
	    	cgp = (struct cg *)buf_dataptr(cgbp);
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_cgin(cgp,fs);
#endif /* REV_ENDIAN_FS */
	    	if (!cg_chkmagic(cgp)){
#if REV_ENDIAN_FS
				if (rev_endian)
					byte_swap_cgout(cgp,fs);
#endif /* REV_ENDIAN_FS */
		    	buf_brelse(cgbp);
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
			buf_brelse(cgbp);
	}

	ump = _MALLOC(sizeof *ump, M_UFSMNT, M_WAITOK);
	bzero((caddr_t)ump, sizeof *ump);
	ump->um_fs = _MALLOC((u_long)fs->fs_sbsize, M_UFSMNT,
	    M_WAITOK);
	bcopy((char *)buf_dataptr(bp), ump->um_fs, (u_int)fs->fs_sbsize);
	if (fs->fs_sbsize < SBSIZE)
		buf_markinvalid(bp);
#if REV_ENDIAN_FS
	if (rev_endian)
		byte_swap_sbout(fs);
#endif /* REV_ENDIAN_FS */
	buf_brelse(bp);
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
		if (error = (int)buf_bread(devvp, (daddr64_t)((unsigned)fsbtodb(fs, fs->fs_csaddr + i)),
					   size, cred, &bp)) {
			_FREE(fs->fs_csp, M_UFSMNT);
			goto out;
		}
		bcopy((char *)buf_dataptr(bp), space, (u_int)size);
#if REV_ENDIAN_FS
		if (rev_endian)
			byte_swap_ints((int *) space, size / sizeof(int));
#endif /* REV_ENDIAN_FS */
		space = (char *)space + size;
		buf_brelse(bp);
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
	mp->mnt_vfsstat.f_fsid.val[0] = (long)dev;
	mp->mnt_vfsstat.f_fsid.val[1] = vfs_typenum(mp);
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
		dqfileinit(&ump->um_qfiles[i]);
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
		buf_brelse(bp);
	if (ump) {
		_FREE(ump->um_fs, M_UFSMNT);
		_FREE(ump, M_UFSMNT);
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
ffs_unmount(mp, mntflags, context)
	struct mount *mp;
	int mntflags;
	vfs_context_t context;
{
	struct proc *p = vfs_context_proc(context);
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
	_FREE(fs->fs_csp, M_UFSMNT);
	_FREE(fs, M_UFSMNT);
	_FREE(ump, M_UFSMNT);

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
			vnode_put(rootvp);
		}
		if (error && (flags & FORCECLOSE) == 0)
			return (error);

		for (i = 0; i < MAXQUOTAS; i++) {
			if (ump->um_qfiles[i].qf_vp == NULLVP)
				continue;
			quotaoff(mp, i);
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
ffs_statfs(mp, sbp, context)
	struct mount *mp;
	register struct vfsstatfs *sbp;
	vfs_context_t context;
{
	register struct ufsmount *ump;
	register struct fs *fs;

	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	if (fs->fs_magic != FS_MAGIC)
		panic("ffs_statfs");
	sbp->f_bsize = fs->fs_fsize;
	sbp->f_iosize = fs->fs_bsize;
	sbp->f_blocks = (uint64_t)((unsigned long)fs->fs_dsize);
	sbp->f_bfree = (uint64_t) ((unsigned long)(fs->fs_cstotal.cs_nbfree * fs->fs_frag +
		fs->fs_cstotal.cs_nffree));
	sbp->f_bavail = (uint64_t) ((unsigned long)freespace(fs, fs->fs_minfree));
	sbp->f_files =  (uint64_t) ((unsigned long)(fs->fs_ncg * fs->fs_ipg - ROOTINO));
	sbp->f_ffree = (uint64_t) ((unsigned long)fs->fs_cstotal.cs_nifree);
	return (0);
}

int
ffs_vfs_getattr(mp, fsap, context)
	struct mount *mp;
	struct vfs_attr *fsap;
	vfs_context_t context;
{
	struct ufsmount *ump;
	struct fs *fs;
	kauth_cred_t cred;
	struct vnode *devvp;
	struct buf *bp;
	struct ufslabel *ulp;
	char *offset;
	int bs, error, length;

	ump = VFSTOUFS(mp);
	fs = ump->um_fs;
	cred = vfs_context_ucred(context);

	VFSATTR_RETURN(fsap, f_bsize, fs->fs_fsize);
	VFSATTR_RETURN(fsap, f_iosize, fs->fs_bsize);
	VFSATTR_RETURN(fsap, f_blocks, (uint64_t)((unsigned long)fs->fs_dsize));
	VFSATTR_RETURN(fsap, f_bfree, (uint64_t)((unsigned long)
	    (fs->fs_cstotal.cs_nbfree * fs->fs_frag +
	    fs->fs_cstotal.cs_nffree)));
	VFSATTR_RETURN(fsap, f_bavail, (uint64_t)((unsigned long)freespace(fs,
	    fs->fs_minfree)));
	VFSATTR_RETURN(fsap, f_files, (uint64_t)((unsigned long)
	    (fs->fs_ncg * fs->fs_ipg - ROOTINO)));
	VFSATTR_RETURN(fsap, f_ffree, (uint64_t)((unsigned long)
	    fs->fs_cstotal.cs_nifree));

	if (VFSATTR_IS_ACTIVE(fsap, f_fsid)) {
		fsap->f_fsid.val[0] = mp->mnt_vfsstat.f_fsid.val[0];
		fsap->f_fsid.val[1] = mp->mnt_vfsstat.f_fsid.val[1];
		VFSATTR_SET_SUPPORTED(fsap, f_fsid);
	}

	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		devvp = ump->um_devvp;
		bs = vfs_devblocksize(mp);

		if (error = (int)buf_meta_bread(devvp,
		    (daddr64_t)(UFS_LABEL_OFFSET / bs),
		    MAX(bs, UFS_LABEL_SIZE), cred, &bp)) {
			if (bp)
				buf_brelse(bp);
			return (error);
		}

		/*
		 * Since the disklabel is read directly by older user space
		 * code, make sure this buffer won't remain in the cache when
		 * we release it.
		 */
		buf_setflags(bp, B_NOCACHE);

		offset = buf_dataptr(bp) + (UFS_LABEL_OFFSET % bs);
		ulp = (struct ufslabel *)offset;

		if (ufs_label_check(ulp)) {
			length = ulp->ul_namelen;
#if REV_ENDIAN_FS
			if (mp->mnt_flag & MNT_REVEND)
				length = OSSwapInt16(length);
#endif
			if (length > 0 && length <= UFS_MAX_LABEL_NAME) {
				bcopy(ulp->ul_name, fsap->f_vol_name, length);
				fsap->f_vol_name[UFS_MAX_LABEL_NAME - 1] = '\0';
				fsap->f_vol_name[length] = '\0';
			}
		}

		buf_brelse(bp);
		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}

	if (VFSATTR_IS_ACTIVE(fsap, f_capabilities)) {
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_FORMAT] =
		    VOL_CAP_FMT_SYMBOLICLINKS |
		    VOL_CAP_FMT_HARDLINKS |
		    VOL_CAP_FMT_SPARSE_FILES |
		    VOL_CAP_FMT_CASE_SENSITIVE |
		    VOL_CAP_FMT_CASE_PRESERVING |
		    VOL_CAP_FMT_FAST_STATFS ;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_INTERFACES]
		    = VOL_CAP_INT_NFSEXPORT |
		    VOL_CAP_INT_VOL_RENAME |
		    VOL_CAP_INT_ADVLOCK |
		    VOL_CAP_INT_FLOCK;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED1]
		    = 0;
		fsap->f_capabilities.capabilities[VOL_CAPABILITIES_RESERVED2]
		    = 0;

		/* Capabilities we know about: */
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
		    VOL_CAP_INT_FLOCK ;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED1] = 0;
		fsap->f_capabilities.valid[VOL_CAPABILITIES_RESERVED2] = 0;

		VFSATTR_SET_SUPPORTED(fsap, f_capabilities);
	}

	if (VFSATTR_IS_ACTIVE(fsap, f_attributes)) {
		fsap->f_attributes.validattr.commonattr = 0;
		fsap->f_attributes.validattr.volattr =
		    ATTR_VOL_NAME | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
		fsap->f_attributes.validattr.dirattr = 0;
		fsap->f_attributes.validattr.fileattr = 0;
		fsap->f_attributes.validattr.forkattr = 0;

		fsap->f_attributes.nativeattr.commonattr = 0;
		fsap->f_attributes.nativeattr.volattr =
		    ATTR_VOL_NAME | ATTR_VOL_CAPABILITIES | ATTR_VOL_ATTRIBUTES;
		fsap->f_attributes.nativeattr.dirattr = 0;
		fsap->f_attributes.nativeattr.fileattr = 0;
		fsap->f_attributes.nativeattr.forkattr = 0;

		VFSATTR_SET_SUPPORTED(fsap, f_attributes);
	}

	return (0);
}


int
ffs_vfs_setattr(mp, fsap, context)
	struct mount *mp;
	struct vfs_attr *fsap;
	vfs_context_t context;
{
	struct ufsmount *ump;
	struct vnode *devvp;
	struct buf *bp;
	struct ufslabel *ulp;
	kauth_cred_t cred;
	char *offset;
	int bs, error;


	ump = VFSTOUFS(mp);
	cred = vfs_context_ucred(context);

	if (VFSATTR_IS_ACTIVE(fsap, f_vol_name)) {
		devvp = ump->um_devvp;
		bs = vfs_devblocksize(mp);
		if (error = buf_meta_bread(devvp,
		    (daddr64_t)(UFS_LABEL_OFFSET / bs),
		    MAX(bs, UFS_LABEL_SIZE), cred, &bp)) {
			if (bp)
				buf_brelse(bp);
			return (error);
		}

		/*
		 * Since the disklabel is read directly by older user space
		 * code, make sure this buffer won't remain in the cache when
		 * we release it.
		 */
		buf_setflags(bp, B_NOCACHE);

		/* Validate the label structure; init if not valid */
		offset = buf_dataptr(bp) + (UFS_LABEL_OFFSET % bs);
		ulp = (struct ufslabel *)offset;
		if (!ufs_label_check(ulp))
			ufs_label_init(ulp);

		/* Copy new name over existing name */
		ulp->ul_namelen = strlen(fsap->f_vol_name);
		bcopy(fsap->f_vol_name, ulp->ul_name, ulp->ul_namelen);
		ulp->ul_name[UFS_MAX_LABEL_NAME - 1] = '\0';
		ulp->ul_name[ulp->ul_namelen] = '\0';

#if REV_ENDIAN_FS
		if (mp->mnt_flag & MNT_REVEND)
			ulp->ul_namelen = OSSwapInt16(ulp->ul_namelen);
#endif

		/* Update the checksum */
		ulp->ul_checksum = 0;
		ulp->ul_checksum = ul_cksum(ulp, sizeof(*ulp));

		/* Write the label back to disk */
		buf_bwrite(bp);
		bp = NULL;

		VFSATTR_SET_SUPPORTED(fsap, f_vol_name);
	}

 	return (0);
 }
struct ffs_sync_cargs {
        vfs_context_t context;
        int    waitfor;
        int    error;
};


static int
ffs_sync_callback(struct vnode *vp, void *cargs)
{
	struct inode *ip;
	struct ffs_sync_cargs *args;
	int error;

	args = (struct ffs_sync_cargs *)cargs;

	ip = VTOI(vp);

	if ((ip->i_flag & (IN_ACCESS | IN_CHANGE | IN_MODIFIED | IN_UPDATE)) || vnode_hasdirtyblks(vp)) {
	        error = VNOP_FSYNC(vp, args->waitfor, args->context);

		if (error)
		        args->error = error;

	}
	return (VNODE_RETURNED);
}

/*
 * Go through the disk queues to initiate sandbagged IO;
 * go through the inodes to write those that have been modified;
 * initiate the writing of the super block if it has been modified.
 *
 * Note: we are always called with the filesystem marked `MPBUSY'.
 */
int
ffs_sync(mp, waitfor, context)
	struct mount *mp;
	int waitfor;
	vfs_context_t context;
{
	struct vnode *nvp, *vp;
	struct ufsmount *ump = VFSTOUFS(mp);
	struct fs *fs;
	struct timeval tv;
	int error, allerror = 0;
	struct ffs_sync_cargs args;

	fs = ump->um_fs;
	if (fs->fs_fmod != 0 && fs->fs_ronly != 0) {		/* XXX */
		printf("fs = %s\n", fs->fs_fsmnt);
		panic("update: rofs mod");
	}
	/*
	 * Write back each (modified) inode.
	 */
	args.context = context;
	args.waitfor = waitfor;
	args.error = 0;
	/*
	 * ffs_sync_callback will be called for each vnode
	 * hung off of this mount point... the vnode will be
	 * properly referenced and unreferenced around the callback
	 */
	vnode_iterate(mp, 0, ffs_sync_callback, (void *)&args);

	if (args.error)
	        allerror = args.error;

	/*
	 * Force stale file system control information to be flushed.
	 */
	if (error = VNOP_FSYNC(ump->um_devvp, waitfor, context))
		allerror = error;
#if QUOTA
	qsync(mp);
#endif
	/*
	 * Write back modified superblock.
	 */
	if (fs->fs_fmod != 0) {
		fs->fs_fmod = 0;
		microtime(&tv);
		fs->fs_time = tv.tv_sec;
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
ffs_vget(mp, ino, vpp, context)
	mount_t	mp;
	ino64_t ino;
	vnode_t *vpp;
	vfs_context_t context;
{
        return(ffs_vget_internal(mp, (ino_t)ino, vpp, NULL, NULL, 0, 0));
}


int
ffs_vget_internal(mp, ino, vpp, dvp, cnp, mode, fhwanted)
	mount_t	mp;
	ino_t	ino;
	vnode_t	*vpp;
	vnode_t	dvp;
	struct	componentname *cnp;
	int	mode;
	int	fhwanted;
{
	struct proc *p = current_proc();		/* XXX */
	struct fs *fs;
	struct inode *ip;
	struct ufsmount *ump;
	struct buf *bp;
	struct vnode *vp;
	struct vnode_fsparam vfsp;
	struct timeval tv;
	enum vtype vtype;
	dev_t dev;
	int i, type, error = 0;

	*vpp = NULL;
	ump  = VFSTOUFS(mp);
	dev  = ump->um_dev;
#if 0
	/* Check for unmount in progress */
	if (mp->mnt_kern_flag & MNTK_UNMOUNT) {
		return (EPERM);
	}
#endif
	/*
	 * Allocate a new inode... do it before we check the
	 * cache, because the MALLOC_ZONE may block
	 */
	type = M_FFSNODE;
	MALLOC_ZONE(ip, struct inode *, sizeof(struct inode), type, M_WAITOK);

	/*
	 * check in the inode hash
	 */
	if ((*vpp = ufs_ihashget(dev, ino)) != NULL) {
	       /*
		* found it... get rid of the allocation
		* that we didn't need and return
		* the 'found' vnode
		*/
		FREE_ZONE(ip, sizeof(struct inode), type);
		vp = *vpp;
		return (0);
	}
	bzero((caddr_t)ip, sizeof(struct inode));
	/*
	 * lock the inode
	 */
//	lockinit(&ip->i_lock, PINOD, "inode", 0, 0);
//	lockmgr(&ip->i_lock, LK_EXCLUSIVE, (struct slock *)0, p);

	ip->i_fs = fs = ump->um_fs;
	ip->i_dev = dev;
	ip->i_number = ino;
#if QUOTA
	for (i = 0; i < MAXQUOTAS; i++)
		ip->i_dquot[i] = NODQUOT;
#endif
	SET(ip->i_flag, IN_ALLOC);
	/*
	 * Put it onto its hash chain locked so that other requests for
	 * this inode will block if they arrive while we are sleeping waiting
	 * for old data structures to be purged or for the contents of the
	 * disk portion of this inode to be read.
	 */
	ufs_ihashins(ip);

	/* Read in the disk contents for the inode, copy into the inode. */
	if (error = (int)buf_bread(ump->um_devvp, (daddr64_t)((unsigned)fsbtodb(fs, ino_to_fsba(fs, ino))),
				   (int)fs->fs_bsize, NOCRED, &bp)) {
		buf_brelse(bp);
		goto errout;
	}
#if REV_ENDIAN_FS
	if (mp->mnt_flag & MNT_REVEND) {
		byte_swap_inode_in(((struct dinode *)buf_dataptr(bp) + ino_to_fsbo(fs, ino)),ip);
	} else {
		ip->i_din = *((struct dinode *)buf_dataptr(bp) + ino_to_fsbo(fs, ino));
	}
#else
	ip->i_din = *((struct dinode *)buf_dataptr(bp) + ino_to_fsbo(fs, ino));
#endif /* REV_ENDIAN_FS */
	buf_brelse(bp);

	if (mode == 0)
	        vtype = IFTOVT(ip->i_mode);
	else
	        vtype = IFTOVT(mode);

	if (vtype == VNON) {
		if (fhwanted) {
			/* NFS is in play */
			error = ESTALE;
			goto errout;
		} else {
			error = ENOENT;
			goto errout;
		}
	}

	vfsp.vnfs_mp = mp;
	vfsp.vnfs_vtype = vtype;
	vfsp.vnfs_str = "ufs";
	vfsp.vnfs_dvp = dvp;
	vfsp.vnfs_fsnode = ip;
	vfsp.vnfs_cnp = cnp;

	if (mode == 0)
	        vfsp.vnfs_filesize = ip->i_din.di_size;
	else
	        vfsp.vnfs_filesize = 0;

	if (vtype == VFIFO )
		vfsp.vnfs_vops = FFS_FIFOOPS;
	else if (vtype == VBLK || vtype == VCHR)
		vfsp.vnfs_vops = ffs_specop_p;
	else
		vfsp.vnfs_vops = ffs_vnodeop_p;
		
	if (vtype == VBLK || vtype == VCHR)
		vfsp.vnfs_rdev = ip->i_rdev;
	else
		vfsp.vnfs_rdev = 0;

	if (dvp && cnp && (cnp->cn_flags & MAKEENTRY))
		vfsp.vnfs_flags = 0;
	else
	        vfsp.vnfs_flags = VNFS_NOCACHE;

	/*
	 * Tag root directory
	 */
	vfsp.vnfs_markroot = (ip->i_number == ROOTINO);
	vfsp.vnfs_marksystem = 0;

	if ((error = vnode_create(VNCREATE_FLAVOR, VCREATESIZE, &vfsp, &vp)))
		goto errout;

	/*
	 * Finish inode initialization now that aliasing has been resolved.
	 */
	ip->i_devvp = ump->um_devvp;
	ip->i_vnode = vp;

	vnode_ref(ip->i_devvp);
	vnode_addfsref(vp);
	vnode_settag(vp, VT_UFS);

	/*
	 * Initialize modrev times
	 */
	microtime(&tv);
	SETHIGH(ip->i_modrev, tv.tv_sec);
	SETLOW(ip->i_modrev, tv.tv_usec * 4294);

	/*
	 * Set up a generation number for this inode if it does not
	 * already have one. This should only happen on old filesystems.
	 */
	if (ip->i_gen == 0) {
		if (++nextgennumber < (u_long)tv.tv_sec)
			nextgennumber = tv.tv_sec;
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
	*vpp = vp;

	CLR(ip->i_flag, IN_ALLOC);

	if (ISSET(ip->i_flag, IN_WALLOC))
		wakeup(ip);

	return (0);

errout:
	ufs_ihashrem(ip);

	if (ISSET(ip->i_flag, IN_WALLOC))
		wakeup(ip);
	FREE_ZONE(ip, sizeof(struct inode), type);

	return (error);
}

/*
 * File handle to vnode
 *
 * Have to be really careful about stale file handles:
 * - check that the inode number is valid
 * - call vget to get the locked inode
 * - check for an unallocated inode (i_mode == 0)
 */
int
ffs_fhtovp(mp, fhlen, fhp, vpp, context)
	register struct mount *mp;
	int fhlen;
	unsigned char *fhp;
	struct vnode **vpp;
	vfs_context_t context;
{
	register struct ufid *ufhp;
	register struct inode *ip;
	struct vnode *nvp;
	struct fs *fs;
	int error;
	ino_t	  ino;

	if (fhlen < (int)sizeof(struct ufid))
		return (EINVAL);
	ufhp = (struct ufid *)fhp;
	fs = VFSTOUFS(mp)->um_fs;
	ino = ntohl(ufhp->ufid_ino);
	if (ino < ROOTINO || ino >= fs->fs_ncg * fs->fs_ipg)
		return (ESTALE);
	error = ffs_vget_internal(mp, ino, &nvp, NULL, NULL, 0, 1);
	if (error) {
		*vpp = NULLVP;
		return (error);
	}
	ip = VTOI(nvp);
	if (ip->i_mode == 0 || ip->i_gen != ntohl(ufhp->ufid_gen)) {
		vnode_put(nvp);
		*vpp = NULLVP;
		return (ESTALE);
	}
	*vpp = nvp;
	return (0);
}

/*
 * Vnode pointer to File handle
 */
/* ARGSUSED */
int
ffs_vptofh(vp, fhlenp, fhp, context)
	struct vnode *vp;
	int *fhlenp;
	unsigned char *fhp;
	vfs_context_t context;
{
	register struct inode *ip;
	register struct ufid *ufhp;

	if (*fhlenp < (int)sizeof(struct ufid))
		return (EOVERFLOW);
	ip = VTOI(vp);
	ufhp = (struct ufid *)fhp;
	ufhp->ufid_ino = htonl(ip->i_number);
	ufhp->ufid_gen = htonl(ip->i_gen);
	*fhlenp = sizeof(struct ufid);
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
ffs_sysctl(int *name, u_int namelen, user_addr_t oldp, size_t *oldlenp, 
		   user_addr_t newp, size_t newlen, vfs_context_t context)
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
		return (ENOTSUP);
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
		bp = buf_getblk(mp->um_devvp, (daddr64_t)((unsigned)fsbtodb(fs, fs->fs_csaddr + i)),
				size, 0, 0, BLK_META);
		bcopy(space, (char *)buf_dataptr(bp), (u_int)size);
#if REV_ENDIAN_FS
		if (rev_endian) {
			byte_swap_ints((int *)buf_dataptr(bp), size / sizeof(int));
		}
#endif /* REV_ENDIAN_FS */
		space = (char *)space + size;
		if (waitfor != MNT_WAIT)
			buf_bawrite(bp);
		else if (error = (int)buf_bwrite(bp))
			allerror = error;
	}
	/*
	 * Now write back the superblock itself. If any errors occurred
	 * up to this point, then fail so that the superblock avoids
	 * being written out as clean.
	 */
	if (allerror)
		return (allerror);
	devBlockSize = vfs_devblocksize(mp->um_mountp);

	bp = buf_getblk(mp->um_devvp, (daddr64_t)((unsigned)(SBOFF/devBlockSize)), (int)fs->fs_sbsize, 0, 0, BLK_META);
	bcopy((caddr_t)fs, (char *)buf_dataptr(bp), (u_int)fs->fs_sbsize);
	/* Restore compatibility to old file systems.		   XXX */
	dfs = (struct fs *)buf_dataptr(bp);			/* XXX */
	if (fs->fs_postblformat == FS_42POSTBLFMT)		/* XXX */
		dfs->fs_nrpos = -1;				/* XXX */
#if REV_ENDIAN_FS
	/*  
	*  Swapping bytes here ; so that in case
	*   of inode format < FS_44INODEFMT appropriate
	*   fields get moved 
	*/
	if (rev_endian) {
		byte_swap_sbout((struct fs *)buf_dataptr(bp));
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
		dfs->fs_maxfilesize = OSSwapInt64(mp->um_savedmaxfilesize);		/* XXX */
	} else {
#endif /* REV_ENDIAN_FS */
		dfs->fs_maxfilesize = mp->um_savedmaxfilesize;	/* XXX */
#if REV_ENDIAN_FS
	}
#endif /* REV_ENDIAN_FS */
	if (waitfor != MNT_WAIT)
		buf_bawrite(bp);
	else if (error = (int)buf_bwrite(bp))
		allerror = error;

	return (allerror);
}
