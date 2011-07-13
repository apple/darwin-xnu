/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1998 Apple Computer, Inc.  All rights reserved.
 *
 *	File:	bsd/kern/kern_symfile.c
 *
 * HISTORY
 */

#include <mach/vm_param.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signalvar.h>
#include <sys/resourcevar.h>
#include <sys/namei.h>
#include <sys/vnode_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/timeb.h>
#include <sys/times.h>
#include <sys/acct.h>
#include <sys/file_internal.h>
#include <sys/uio.h>
#include <sys/kernel.h>
#include <sys/stat.h>
#include <sys/disk.h>
#include <sys/conf.h>

#include <mach-o/loader.h>
#include <mach-o/nlist.h>

#include <kern/kalloc.h>
#include <vm/vm_kern.h>
#include <pexpert/pexpert.h>
#include <IOKit/IOHibernatePrivate.h>

/* This function is called from kern_sysctl in the current process context;
 * it is exported with the System6.0.exports, but this appears to be a legacy
 * export, as there are no internal consumers.
 */
int
get_kernel_symfile(__unused proc_t p, __unused char const **symfile)
{
    return KERN_FAILURE;
}

struct kern_direct_file_io_ref_t
{
    vfs_context_t  ctx;
    struct vnode * vp;
    dev_t          device;
};


static int file_ioctl(void * p1, void * p2, u_long theIoctl, caddr_t result)
{
    dev_t device = *(dev_t*) p1;

    return ((*bdevsw[major(device)].d_ioctl)
		    (device, theIoctl, result, S_IFBLK, p2));
}

static int device_ioctl(void * p1, __unused void * p2, u_long theIoctl, caddr_t result)
{
    return (VNOP_IOCTL(p1, theIoctl, result, 0, p2));
}

struct kern_direct_file_io_ref_t *
kern_open_file_for_direct_io(const char * name, 
			     kern_get_file_extents_callback_t callback, 
			     void * callback_ref,
			     dev_t * partition_device_result,
			     dev_t * image_device_result,
                             uint64_t * partitionbase_result,
                             uint64_t * maxiocount_result,
                             uint32_t * oflags,
                             off_t offset,
                             caddr_t addr,
                             vm_size_t len)
{
    struct kern_direct_file_io_ref_t * ref;

    proc_t			p;
    struct vnode_attr		va;
    int				error;
    off_t			f_offset;
    off_t			filelength;
    uint64_t                    fileblk;
    size_t                      filechunk;
    uint64_t                    physoffset;
    dev_t			device;
    dev_t			target = 0;
    int			        isssd = 0;
    uint32_t                    flags = 0;
    uint32_t			blksize;
    off_t 			maxiocount, count;
    boolean_t                   locked = FALSE;

    int (*do_ioctl)(void * p1, void * p2, u_long theIoctl, caddr_t result);
    void * p1 = NULL;
    void * p2 = NULL;

    error = EFAULT;

    ref = (struct kern_direct_file_io_ref_t *) kalloc(sizeof(struct kern_direct_file_io_ref_t));
    if (!ref)
    {
	error = EFAULT;
    	goto out;
    }

    ref->vp = NULL;
    p = kernproc;
    ref->ctx = vfs_context_create(vfs_context_current());

    if ((error = vnode_open(name, (O_CREAT | FWRITE), (0), 0, &ref->vp, ref->ctx)))
        goto out;

    if (addr && len)
    {
	if ((error = kern_write_file(ref, offset, addr, len)))
	    goto out;
    }

    VATTR_INIT(&va);
    VATTR_WANTED(&va, va_rdev);
    VATTR_WANTED(&va, va_fsid);
    VATTR_WANTED(&va, va_data_size);
    VATTR_WANTED(&va, va_nlink);
    error = EFAULT;
    if (vnode_getattr(ref->vp, &va, ref->ctx))
    	goto out;

    kprintf("vp va_rdev major %d minor %d\n", major(va.va_rdev), minor(va.va_rdev));
    kprintf("vp va_fsid major %d minor %d\n", major(va.va_fsid), minor(va.va_fsid));
    kprintf("vp size %qd\n", va.va_data_size);

    if (ref->vp->v_type == VREG)
    {
	/* Don't dump files with links. */
	if (va.va_nlink != 1)
	    goto out;

        device = va.va_fsid;
        p1 = &device;
        p2 = p;
        do_ioctl = &file_ioctl;
    }
    else if ((ref->vp->v_type == VBLK) || (ref->vp->v_type == VCHR))
    {
	/* Partition. */
        device = va.va_rdev;

        p1 = ref->vp;
        p2 = ref->ctx;
        do_ioctl = &device_ioctl;
    }
    else
    {
	/* Don't dump to non-regular files. */
	error = EFAULT;
        goto out;
    }
    ref->device = device;

    // generate the block list

    error = do_ioctl(p1, p2, DKIOCLOCKPHYSICALEXTENTS, NULL);
    if (error)
        goto out;
    locked = TRUE;

    // get block size

    error = do_ioctl(p1, p2, DKIOCGETBLOCKSIZE, (caddr_t) &blksize);
    if (error)
        goto out;

    if (ref->vp->v_type == VREG)
        filelength = va.va_data_size;
    else
    {
        error = do_ioctl(p1, p2, DKIOCGETBLOCKCOUNT, (caddr_t) &fileblk);
        if (error)
            goto out;
	filelength = fileblk * blksize;    
    }

    f_offset = 0;
    while (f_offset < filelength) 
    {
        if (ref->vp->v_type == VREG)
        {
            filechunk = 1*1024*1024*1024;
            daddr64_t blkno;

            error = VNOP_BLOCKMAP(ref->vp, f_offset, filechunk, &blkno, &filechunk, NULL, 0, NULL);
            if (error)
                goto out;

            fileblk = blkno * blksize;
        }
        else if ((ref->vp->v_type == VBLK) || (ref->vp->v_type == VCHR))
        {
            fileblk = f_offset;
            filechunk = f_offset ? 0 : filelength;
        }

        physoffset = 0;
        while (physoffset < filechunk)
        {
            dk_physical_extent_t getphysreq;
            bzero(&getphysreq, sizeof(getphysreq));

            getphysreq.offset = fileblk + physoffset;
            getphysreq.length = (filechunk - physoffset);
            error = do_ioctl(p1, p2, DKIOCGETPHYSICALEXTENT, (caddr_t) &getphysreq);
            if (error)
                goto out;
            if (!target)
            {
                target = getphysreq.dev;
            }
            else if (target != getphysreq.dev)
            {
                error = ENOTSUP;
                goto out;
            }
            callback(callback_ref, getphysreq.offset, getphysreq.length);
            physoffset += getphysreq.length;
        }
        f_offset += filechunk;
    }
    callback(callback_ref, 0ULL, 0ULL);

    if (ref->vp->v_type == VREG)
        p1 = &target;

    // get partition base

    error = do_ioctl(p1, p2, DKIOCGETBASE, (caddr_t) partitionbase_result);
    if (error)
        goto out;

    // get block size & constraints

    error = do_ioctl(p1, p2, DKIOCGETBLOCKSIZE, (caddr_t) &blksize);
    if (error)
        goto out;

    maxiocount = 1*1024*1024*1024;

    error = do_ioctl(p1, p2, DKIOCGETMAXBLOCKCOUNTREAD, (caddr_t) &count);
    if (error)
        count = 0;
    count *= blksize;
    if (count && (count < maxiocount))
        maxiocount = count;

    error = do_ioctl(p1, p2, DKIOCGETMAXBLOCKCOUNTWRITE, (caddr_t) &count);
    if (error)
        count = 0;
    count *= blksize;
    if (count && (count < maxiocount))
        maxiocount = count;

    error = do_ioctl(p1, p2, DKIOCGETMAXBYTECOUNTREAD, (caddr_t) &count);
    if (error)
        count = 0;
    if (count && (count < maxiocount))
        maxiocount = count;

    error = do_ioctl(p1, p2, DKIOCGETMAXBYTECOUNTWRITE, (caddr_t) &count);
    if (error)
        count = 0;
    if (count && (count < maxiocount))
        maxiocount = count;

    error = do_ioctl(p1, p2, DKIOCGETMAXSEGMENTBYTECOUNTREAD, (caddr_t) &count);
    if (error)
        count = 0;
    if (count && (count < maxiocount))
        maxiocount = count;

    error = do_ioctl(p1, p2, DKIOCGETMAXSEGMENTBYTECOUNTWRITE, (caddr_t) &count);
    if (error)
        count = 0;
    if (count && (count < maxiocount))
        maxiocount = count;

    kprintf("max io 0x%qx bytes\n", maxiocount);
    if (maxiocount_result)
        *maxiocount_result = maxiocount;

    error = do_ioctl(p1, p2, DKIOCISSOLIDSTATE, (caddr_t)&isssd);
    if (!error && isssd)
        flags |= kIOHibernateOptionSSD;

    if (partition_device_result)
        *partition_device_result = device;
    if (image_device_result)
        *image_device_result = target;
    if (flags)
        *oflags = flags;

out:
    kprintf("kern_open_file_for_direct_io(%d)\n", error);

    if (error && locked)
    {
        p1 = &device;
        (void) do_ioctl(p1, p2, DKIOCUNLOCKPHYSICALEXTENTS, NULL);
    }

    if (error && ref)
    {
	if (ref->vp)
	{
	    vnode_close(ref->vp, FWRITE, ref->ctx);
	    ref->vp = NULLVP;
	}
	vfs_context_rele(ref->ctx);
	kfree(ref, sizeof(struct kern_direct_file_io_ref_t));
	ref = NULL;
    }
    return(ref);
}

int
kern_write_file(struct kern_direct_file_io_ref_t * ref, off_t offset, caddr_t addr, vm_size_t len)
{
    return (vn_rdwr(UIO_WRITE, ref->vp,
			addr, len, offset,
			UIO_SYSSPACE, IO_SYNC|IO_NODELOCKED|IO_UNIT, 
                        vfs_context_ucred(ref->ctx), (int *) 0,
			vfs_context_proc(ref->ctx)));
}

void
kern_close_file_for_direct_io(struct kern_direct_file_io_ref_t * ref,
			      off_t offset, caddr_t addr, vm_size_t len)
{
    int error;
    kprintf("kern_close_file_for_direct_io\n");

    if (!ref) return;

    if (ref->vp)
    {
        int (*do_ioctl)(void * p1, void * p2, u_long theIoctl, caddr_t result);
        void * p1;
        void * p2;

        if (ref->vp->v_type == VREG)
        {
            p1 = &ref->device;
            p2 = kernproc;
            do_ioctl = &file_ioctl;
        }
        else
        {
            /* Partition. */
            p1 = ref->vp;
            p2 = ref->ctx;
            do_ioctl = &device_ioctl;
        }
        (void) do_ioctl(p1, p2, DKIOCUNLOCKPHYSICALEXTENTS, NULL);
        
        if (addr && len)
        {
            (void) kern_write_file(ref, offset, addr, len);
        }

        error = vnode_close(ref->vp, FWRITE, ref->ctx);

        ref->vp = NULLVP;
        kprintf("vnode_close(%d)\n", error);
    }
    vfs_context_rele(ref->ctx);
    ref->ctx = NULL;
    kfree(ref, sizeof(struct kern_direct_file_io_ref_t));
}

