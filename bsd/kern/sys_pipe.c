/*
 * Copyright (c) 1996 John S. Dyson
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice immediately at the beginning of the file, without modification,
 *    this list of conditions, and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Absolutely no warranty of function or purpose is made by the author
 *    John S. Dyson.
 * 4. Modifications may be freely made to this file if the above conditions
 *    are met.
 */
/*
 * Copyright (c) 2003-2004 Apple Computer, Inc. All rights reserved.
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

/*
 * This file contains a high-performance replacement for the socket-based
 * pipes scheme originally used in FreeBSD/4.4Lite.  It does not support
 * all features of sockets, but does do everything that pipes normally
 * do.
 */

/*
 * This code has two modes of operation, a small write mode and a large
 * write mode.  The small write mode acts like conventional pipes with
 * a kernel buffer.  If the buffer is less than PIPE_MINDIRECT, then the
 * "normal" pipe buffering is done.  If the buffer is between PIPE_MINDIRECT
 * and PIPE_SIZE in size, it is fully mapped and wired into the kernel, and
 * the receiving process can copy it directly from the pages in the sending
 * process.
 *
 * If the sending process receives a signal, it is possible that it will
 * go away, and certainly its address space can change, because control
 * is returned back to the user-mode side.  In that case, the pipe code
 * arranges to copy the buffer supplied by the user process, to a pageable
 * kernel buffer, and the receiving process will grab the data from the
 * pageable kernel buffer.  Since signals don't happen all that often,
 * the copy operation is normally eliminated.
 *
 * The constant PIPE_MINDIRECT is chosen to make sure that buffering will
 * happen for small transfers so that the system will not spend all of
 * its time context switching.
 *
 * In order to limit the resource use of pipes, two sysctls exist:
 *
 * kern.ipc.maxpipekva - This is a hard limit on the amount of pageable
 * address space available to us in pipe_map.  Whenever the amount in use
 * exceeds half of this value, all new pipes will be created with size
 * SMALL_PIPE_SIZE, rather than PIPE_SIZE.  Big pipe creation will be limited
 * as well.  This value is loader tunable only.
 *
 * kern.ipc.maxpipekvawired - This value limits the amount of memory that may
 * be wired in order to facilitate direct copies using page flipping.
 * Whenever this value is exceeded, pipes will fall back to using regular
 * copies.  This value is sysctl controllable at all times.
 *
 * These values are autotuned in subr_param.c.
 *
 * Memory usage may be monitored through the sysctls
 * kern.ipc.pipes, kern.ipc.pipekva and kern.ipc.pipekvawired.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/vnode.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/fcntl.h>
#include <sys/malloc.h>
#include <sys/syslog.h>
#include <sys/unistd.h>
#include <sys/resourcevar.h>
#include <sys/aio_kern.h>
#include <sys/signalvar.h>
#include <sys/pipe.h>
#include <sys/sysproto.h>

#include <bsm/audit_kernel.h>

#include <sys/kdebug.h>

#include <kern/zalloc.h>
#include <vm/vm_kern.h>
#include <libkern/OSAtomic.h>

#define f_flag f_fglob->fg_flag
#define f_type f_fglob->fg_type
#define f_msgcount f_fglob->fg_msgcount
#define f_cred f_fglob->fg_cred
#define f_ops f_fglob->fg_ops
#define f_offset f_fglob->fg_offset
#define f_data f_fglob->fg_data
/*
 * Use this define if you want to disable *fancy* VM things.  Expect an
 * approx 30% decrease in transfer rate.  This could be useful for
 * NetBSD or OpenBSD.
 *
 * this needs to be ported to X and the performance measured
 * before committing to supporting it
 */
#define PIPE_NODIRECT  1

#ifndef PIPE_NODIRECT

#include <vm/vm.h>
#include <vm/vm_param.h>
#include <vm/vm_object.h>
#include <vm/vm_kern.h>
#include <vm/vm_extern.h>
#include <vm/pmap.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <vm/uma.h>

#endif


/*
 * interfaces to the outside world
 */
static int pipe_read(struct fileproc *fp, struct uio *uio,
                kauth_cred_t cred, int flags, struct proc *p);

static int pipe_write(struct fileproc *fp, struct uio *uio,
                kauth_cred_t cred, int flags, struct proc *p);

static int pipe_close(struct fileglob *fg, struct proc *p);

static int pipe_select(struct fileproc *fp, int which, void * wql, struct proc *p);

static int pipe_kqfilter(struct fileproc *fp, struct knote *kn, struct proc *p);

static int pipe_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, struct proc *p);


struct  fileops pipeops =
  { pipe_read,
    pipe_write,
    pipe_ioctl,
    pipe_select,
    pipe_close,
    pipe_kqfilter,
    0 };


static void	filt_pipedetach(struct knote *kn);
static int	filt_piperead(struct knote *kn, long hint);
static int	filt_pipewrite(struct knote *kn, long hint);

static struct filterops pipe_rfiltops =
	{ 1, NULL, filt_pipedetach, filt_piperead };
static struct filterops pipe_wfiltops =
	{ 1, NULL, filt_pipedetach, filt_pipewrite };

/*
 * Default pipe buffer size(s), this can be kind-of large now because pipe
 * space is pageable.  The pipe code will try to maintain locality of
 * reference for performance reasons, so small amounts of outstanding I/O
 * will not wipe the cache.
 */
#define MINPIPESIZE (PIPE_SIZE/3)

/*
 * Limit the number of "big" pipes
 */
#define LIMITBIGPIPES	32
static int nbigpipe;

static int amountpipes;
static int amountpipekva;

#ifndef PIPE_NODIRECT
static int amountpipekvawired;
#endif
int maxpipekva = 1024 * 1024 * 16;

#if PIPE_SYSCTLS
SYSCTL_DECL(_kern_ipc);

SYSCTL_INT(_kern_ipc, OID_AUTO, maxpipekva, CTLFLAG_RD,
	   &maxpipekva, 0, "Pipe KVA limit");
SYSCTL_INT(_kern_ipc, OID_AUTO, maxpipekvawired, CTLFLAG_RW,
	   &maxpipekvawired, 0, "Pipe KVA wired limit");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipes, CTLFLAG_RD,
	   &amountpipes, 0, "Current # of pipes");
SYSCTL_INT(_kern_ipc, OID_AUTO, bigpipes, CTLFLAG_RD,
	   &nbigpipe, 0, "Current # of big pipes");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipekva, CTLFLAG_RD,
	   &amountpipekva, 0, "Pipe KVA usage");
SYSCTL_INT(_kern_ipc, OID_AUTO, pipekvawired, CTLFLAG_RD,
	   &amountpipekvawired, 0, "Pipe wired KVA usage");
#endif

void pipeinit(void *dummy __unused);
static void pipeclose(struct pipe *cpipe);
static void pipe_free_kmem(struct pipe *cpipe);
static int pipe_create(struct pipe **cpipep);
static void pipeselwakeup(struct pipe *cpipe, struct pipe *spipe);
static __inline int pipelock(struct pipe *cpipe, int catch);
static __inline void pipeunlock(struct pipe *cpipe);

#ifndef PIPE_NODIRECT
static int pipe_build_write_buffer(struct pipe *wpipe, struct uio *uio);
static void pipe_destroy_write_buffer(struct pipe *wpipe);
static int pipe_direct_write(struct pipe *wpipe, struct uio *uio);
static void pipe_clone_write_buffer(struct pipe *wpipe);
#endif

extern int postpipeevent(struct pipe *, int);
extern void evpipefree(struct pipe *cpipe);


static int pipespace(struct pipe *cpipe, int size);

static lck_grp_t	*pipe_mtx_grp;
static lck_attr_t	*pipe_mtx_attr;
static lck_grp_attr_t	*pipe_mtx_grp_attr;

static zone_t pipe_zone;

SYSINIT(vfs, SI_SUB_VFS, SI_ORDER_ANY, pipeinit, NULL);

void
pipeinit(void *dummy __unused)
{
        pipe_zone = (zone_t)zinit(sizeof(struct pipe), 8192 * sizeof(struct pipe), 4096, "pipe zone");

	/*
	 * allocate lock group attribute and group for pipe mutexes
	 */
	pipe_mtx_grp_attr = lck_grp_attr_alloc_init();
	//lck_grp_attr_setstat(pipe_mtx_grp_attr);
	pipe_mtx_grp = lck_grp_alloc_init("pipe", pipe_mtx_grp_attr);

	/*
	 * allocate the lock attribute for pipe mutexes
	 */
	pipe_mtx_attr = lck_attr_alloc_init();
	//lck_attr_setdebug(pipe_mtx_attr);
}



/*
 * The pipe system call for the DTYPE_PIPE type of pipes
 */

/* ARGSUSED */
int
pipe(struct proc *p, __unused struct pipe_args *uap, register_t *retval)
{
	struct fileproc *rf, *wf;
	struct pipe *rpipe, *wpipe;
	lck_mtx_t   *pmtx;
	int fd, error;

	if ((pmtx = lck_mtx_alloc_init(pipe_mtx_grp, pipe_mtx_attr)) == NULL)
	        return (ENOMEM);
	
	rpipe = wpipe = NULL;
	if (pipe_create(&rpipe) || pipe_create(&wpipe)) {
	        error = ENFILE;
		goto freepipes;
	}
        /*
	 * allocate the space for the normal I/O direction up
	 * front... we'll delay the allocation for the other
	 * direction until a write actually occurs (most
	 * likely it won't)...
	 *
         * Reduce to 1/4th pipe size if we're over our global max.
         */
        if (amountpipekva > maxpipekva / 2)
	        error = pipespace(rpipe, SMALL_PIPE_SIZE);
        else
	        error = pipespace(rpipe, PIPE_SIZE);
        if (error)
	        goto freepipes;

#ifndef PIPE_NODIRECT
	rpipe->pipe_state |= PIPE_DIRECTOK;
	wpipe->pipe_state |= PIPE_DIRECTOK;
#endif
	TAILQ_INIT(&rpipe->pipe_evlist);
	TAILQ_INIT(&wpipe->pipe_evlist);

	error = falloc(p, &rf, &fd);
	if (error) {
	        goto freepipes;
	}
	retval[0] = fd;

	/*
	 * for now we'll create half-duplex
	 * pipes... this is what we've always
	 * supported..
	 */
	rf->f_flag = FREAD;
	rf->f_type = DTYPE_PIPE;
	rf->f_data = (caddr_t)rpipe;
	rf->f_ops = &pipeops;

	error = falloc(p, &wf, &fd);
	if (error) {
		fp_free(p, retval[0], rf);
	        goto freepipes;
	}
	wf->f_flag = FWRITE;
	wf->f_type = DTYPE_PIPE;
	wf->f_data = (caddr_t)wpipe;
	wf->f_ops = &pipeops;

	retval[1] = fd;
#ifdef MAC
	/*
	 * XXXXXXXX SHOULD NOT HOLD FILE_LOCK() XXXXXXXXXXXX
	 *
	 * struct pipe represents a pipe endpoint.  The MAC label is shared
	 * between the connected endpoints.  As a result mac_init_pipe() and
	 * mac_create_pipe() should only be called on one of the endpoints
	 * after they have been connected.
	 */
	mac_init_pipe(rpipe);
	mac_create_pipe(td->td_ucred, rpipe);
#endif
	proc_fdlock(p);
        *fdflags(p, retval[0]) &= ~UF_RESERVED;
        *fdflags(p, retval[1]) &= ~UF_RESERVED;
	fp_drop(p, retval[0], rf, 1);
	fp_drop(p, retval[1], wf, 1);
	proc_fdunlock(p);

	rpipe->pipe_peer = wpipe;
	wpipe->pipe_peer = rpipe;

	rpipe->pipe_mtxp = wpipe->pipe_mtxp = pmtx;

	return (0);

freepipes:
	pipeclose(rpipe); 
	pipeclose(wpipe); 
	lck_mtx_free(pmtx, pipe_mtx_grp);

	return (error);
}


int
pipe_stat(struct pipe *cpipe, struct stat *ub)
{
#ifdef MAC
        int error;
#endif
	struct timeval now;

	if (cpipe == NULL)
	        return (EBADF);
#ifdef MAC
	PIPE_LOCK(cpipe);
	error = mac_check_pipe_stat(active_cred, cpipe);
	PIPE_UNLOCK(cpipe);
	if (error)
	        return (error);
#endif
	if (cpipe->pipe_buffer.buffer == 0) {
	        /*
		 * must be stat'ing the write fd
		 */
	        cpipe = cpipe->pipe_peer;

		if (cpipe == NULL)
		        return (EBADF);
	}
	bzero(ub, sizeof(*ub));
	ub->st_mode = S_IFIFO | S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP;
	ub->st_blksize = cpipe->pipe_buffer.size;
	ub->st_size = cpipe->pipe_buffer.cnt;
	ub->st_blocks = (ub->st_size + ub->st_blksize - 1) / ub->st_blksize;
	ub->st_nlink = 1;

	ub->st_uid = kauth_getuid();
	ub->st_gid = kauth_getgid();

	microtime(&now);
	ub->st_atimespec.tv_sec  = now.tv_sec;
	ub->st_atimespec.tv_nsec = now.tv_usec * 1000;

	ub->st_mtimespec.tv_sec  = now.tv_sec;
	ub->st_mtimespec.tv_nsec = now.tv_usec * 1000;

	ub->st_ctimespec.tv_sec  = now.tv_sec;
	ub->st_ctimespec.tv_nsec = now.tv_usec * 1000;

	/*
	 * Left as 0: st_dev, st_ino, st_nlink, st_rdev, st_flags, st_gen, st_uid, st_gid.
	 * XXX (st_dev, st_ino) should be unique.
	 */
	return (0);
}


/*
 * Allocate kva for pipe circular buffer, the space is pageable
 * This routine will 'realloc' the size of a pipe safely, if it fails
 * it will retain the old buffer.
 * If it fails it will return ENOMEM.
 */
static int
pipespace(struct pipe *cpipe, int size)
{
	vm_offset_t buffer;

	size = round_page(size);

	if (kmem_alloc(kernel_map, &buffer, size) != KERN_SUCCESS)
	        return(ENOMEM);

	/* free old resources if we're resizing */
	pipe_free_kmem(cpipe);
	cpipe->pipe_buffer.buffer = (caddr_t)buffer;
	cpipe->pipe_buffer.size = size;
	cpipe->pipe_buffer.in = 0;
	cpipe->pipe_buffer.out = 0;
	cpipe->pipe_buffer.cnt = 0;

	OSAddAtomic(1, (SInt32 *)&amountpipes);
	OSAddAtomic(cpipe->pipe_buffer.size, (SInt32 *)&amountpipekva);

	return (0);
}

/*
 * initialize and allocate VM and memory for pipe
 */
static int
pipe_create(struct pipe **cpipep)
{
	struct pipe *cpipe;

	cpipe = (struct pipe *)zalloc(pipe_zone);

	if ((*cpipep = cpipe) == NULL)
		return (ENOMEM);

	/*
	 * protect so pipespace or pipeclose don't follow a junk pointer
	 * if pipespace() fails.
	 */
	bzero(cpipe, sizeof *cpipe);

	return (0);
}


/*
 * lock a pipe for I/O, blocking other access
 */
static __inline int
pipelock(cpipe, catch)
	struct pipe *cpipe;
	int catch;
{
	int error;

	while (cpipe->pipe_state & PIPE_LOCKFL) {
		cpipe->pipe_state |= PIPE_LWANT;

		error = msleep(cpipe, PIPE_MTX(cpipe), catch ? (PRIBIO | PCATCH) : PRIBIO,
			       "pipelk", 0);
		if (error != 0) 
			return (error);
	}
	cpipe->pipe_state |= PIPE_LOCKFL;

	return (0);
}

/*
 * unlock a pipe I/O lock
 */
static __inline void
pipeunlock(cpipe)
	struct pipe *cpipe;
{

	cpipe->pipe_state &= ~PIPE_LOCKFL;

	if (cpipe->pipe_state & PIPE_LWANT) {
		cpipe->pipe_state &= ~PIPE_LWANT;
		wakeup(cpipe);
	}
}

static void
pipeselwakeup(cpipe, spipe)
	struct pipe *cpipe;
	struct pipe *spipe;
{

	if (cpipe->pipe_state & PIPE_SEL) {
		cpipe->pipe_state &= ~PIPE_SEL;
		selwakeup(&cpipe->pipe_sel);
	}
        if (cpipe->pipe_state & PIPE_KNOTE) 
	       KNOTE(&cpipe->pipe_sel.si_note, 1);

	postpipeevent(cpipe, EV_RWBYTES);

	if (spipe && (spipe->pipe_state & PIPE_ASYNC) && spipe->pipe_pgid) {
	        struct proc *p;

	        if (spipe->pipe_pgid < 0)
		        gsignal(-spipe->pipe_pgid, SIGIO);
		else if ((p = pfind(spipe->pipe_pgid)) != (struct proc *)0)
		        psignal(p, SIGIO);
        }
}

/* ARGSUSED */
static int
pipe_read(struct fileproc *fp, struct uio *uio, __unused kauth_cred_t active_cred, __unused int flags, __unused struct proc *p)
{
	struct pipe *rpipe = (struct pipe *)fp->f_data;
	int error;
	int nread = 0;
	u_int size;

	PIPE_LOCK(rpipe);
	++rpipe->pipe_busy;

	error = pipelock(rpipe, 1);
	if (error)
		goto unlocked_error;

#ifdef MAC
	error = mac_check_pipe_read(active_cred, rpipe);
	if (error)
		goto locked_error;
#endif

	while (uio_resid(uio)) {
		/*
		 * normal pipe buffer receive
		 */
		if (rpipe->pipe_buffer.cnt > 0) {
			size = rpipe->pipe_buffer.size - rpipe->pipe_buffer.out;
			if (size > rpipe->pipe_buffer.cnt)
				size = rpipe->pipe_buffer.cnt;
			// LP64todo - fix this!
			if (size > (u_int) uio_resid(uio))
				size = (u_int) uio_resid(uio);

			PIPE_UNLOCK(rpipe);
			error = uiomove(
			    &rpipe->pipe_buffer.buffer[rpipe->pipe_buffer.out],
			    size, uio);
			PIPE_LOCK(rpipe);
			if (error)
				break;

			rpipe->pipe_buffer.out += size;
			if (rpipe->pipe_buffer.out >= rpipe->pipe_buffer.size)
				rpipe->pipe_buffer.out = 0;

			rpipe->pipe_buffer.cnt -= size;

			/*
			 * If there is no more to read in the pipe, reset
			 * its pointers to the beginning.  This improves
			 * cache hit stats.
			 */
			if (rpipe->pipe_buffer.cnt == 0) {
				rpipe->pipe_buffer.in = 0;
				rpipe->pipe_buffer.out = 0;
			}
			nread += size;
#ifndef PIPE_NODIRECT
		/*
		 * Direct copy, bypassing a kernel buffer.
		 */
		} else if ((size = rpipe->pipe_map.cnt) &&
			   (rpipe->pipe_state & PIPE_DIRECTW)) {
			caddr_t	va;
			// LP64todo - fix this!
			if (size > (u_int) uio_resid(uio))
				size = (u_int) uio_resid(uio);

			va = (caddr_t) rpipe->pipe_map.kva +
			    rpipe->pipe_map.pos;
			PIPE_UNLOCK(rpipe);
			error = uiomove(va, size, uio);
			PIPE_LOCK(rpipe);
			if (error)
				break;
			nread += size;
			rpipe->pipe_map.pos += size;
			rpipe->pipe_map.cnt -= size;
			if (rpipe->pipe_map.cnt == 0) {
				rpipe->pipe_state &= ~PIPE_DIRECTW;
				wakeup(rpipe);
			}
#endif
		} else {
			/*
			 * detect EOF condition
			 * read returns 0 on EOF, no need to set error
			 */
			if (rpipe->pipe_state & PIPE_EOF)
				break;

			/*
			 * If the "write-side" has been blocked, wake it up now.
			 */
			if (rpipe->pipe_state & PIPE_WANTW) {
				rpipe->pipe_state &= ~PIPE_WANTW;
				wakeup(rpipe);
			}

			/*
			 * Break if some data was read.
			 */
			if (nread > 0)
				break;

			/*
			 * Unlock the pipe buffer for our remaining processing. 
			 * We will either break out with an error or we will
			 * sleep and relock to loop.
			 */
			pipeunlock(rpipe);

			/*
			 * Handle non-blocking mode operation or
			 * wait for more data.
			 */
			if (fp->f_flag & FNONBLOCK) {
				error = EAGAIN;
			} else {
				rpipe->pipe_state |= PIPE_WANTR;

				error = msleep(rpipe, PIPE_MTX(rpipe), PRIBIO | PCATCH, "piperd", 0);

				if (error == 0)
				        error = pipelock(rpipe, 1);
			}
			if (error)
				goto unlocked_error;
		}
	}
#ifdef MAC
locked_error:
#endif
	pipeunlock(rpipe);

unlocked_error:
	--rpipe->pipe_busy;

	/*
	 * PIPE_WANT processing only makes sense if pipe_busy is 0.
	 */
	if ((rpipe->pipe_busy == 0) && (rpipe->pipe_state & PIPE_WANT)) {
		rpipe->pipe_state &= ~(PIPE_WANT|PIPE_WANTW);
		wakeup(rpipe);
	} else if (rpipe->pipe_buffer.cnt < MINPIPESIZE) {
		/*
		 * Handle write blocking hysteresis.
		 */
		if (rpipe->pipe_state & PIPE_WANTW) {
			rpipe->pipe_state &= ~PIPE_WANTW;
			wakeup(rpipe);
		}
	}

	if ((rpipe->pipe_buffer.size - rpipe->pipe_buffer.cnt) >= PIPE_BUF)
		pipeselwakeup(rpipe, rpipe->pipe_peer);

	PIPE_UNLOCK(rpipe);

	return (error);
}



#ifndef PIPE_NODIRECT
/*
 * Map the sending processes' buffer into kernel space and wire it.
 * This is similar to a physical write operation.
 */
static int
pipe_build_write_buffer(wpipe, uio)
	struct pipe *wpipe;
	struct uio *uio;
{
	pmap_t pmap;
	u_int size;
	int i, j;
	vm_offset_t addr, endaddr;


	size = (u_int) uio->uio_iov->iov_len;
	if (size > wpipe->pipe_buffer.size)
		size = wpipe->pipe_buffer.size;

	pmap = vmspace_pmap(curproc->p_vmspace);
	endaddr = round_page((vm_offset_t)uio->uio_iov->iov_base + size);
	addr = trunc_page((vm_offset_t)uio->uio_iov->iov_base);
	for (i = 0; addr < endaddr; addr += PAGE_SIZE, i++) {
		/*
		 * vm_fault_quick() can sleep.  Consequently,
		 * vm_page_lock_queue() and vm_page_unlock_queue()
		 * should not be performed outside of this loop.
		 */
	race:
		if (vm_fault_quick((caddr_t)addr, VM_PROT_READ) < 0) {
			vm_page_lock_queues();
			for (j = 0; j < i; j++)
				vm_page_unhold(wpipe->pipe_map.ms[j]);
			vm_page_unlock_queues();
			return (EFAULT);
		}
		wpipe->pipe_map.ms[i] = pmap_extract_and_hold(pmap, addr,
		    VM_PROT_READ);
		if (wpipe->pipe_map.ms[i] == NULL)
			goto race;
	}

/*
 * set up the control block
 */
	wpipe->pipe_map.npages = i;
	wpipe->pipe_map.pos =
	    ((vm_offset_t) uio->uio_iov->iov_base) & PAGE_MASK;
	wpipe->pipe_map.cnt = size;

/*
 * and map the buffer
 */
	if (wpipe->pipe_map.kva == 0) {
		/*
		 * We need to allocate space for an extra page because the
		 * address range might (will) span pages at times.
		 */
		wpipe->pipe_map.kva = kmem_alloc_nofault(kernel_map,
			wpipe->pipe_buffer.size + PAGE_SIZE);
		atomic_add_int(&amountpipekvawired,
		    wpipe->pipe_buffer.size + PAGE_SIZE);
	}
	pmap_qenter(wpipe->pipe_map.kva, wpipe->pipe_map.ms,
		wpipe->pipe_map.npages);

/*
 * and update the uio data
 */

	uio->uio_iov->iov_len -= size;
	uio->uio_iov->iov_base = (char *)uio->uio_iov->iov_base + size;
	if (uio->uio_iov->iov_len == 0)
		uio->uio_iov++;
	uio_setresid(uio, (uio_resid(uio) - size));
	uio->uio_offset += size;
	return (0);
}

/*
 * unmap and unwire the process buffer
 */
static void
pipe_destroy_write_buffer(wpipe)
	struct pipe *wpipe;
{
	int i;

	if (wpipe->pipe_map.kva) {
		pmap_qremove(wpipe->pipe_map.kva, wpipe->pipe_map.npages);

		if (amountpipekvawired > maxpipekvawired / 2) {
			/* Conserve address space */
			vm_offset_t kva = wpipe->pipe_map.kva;
			wpipe->pipe_map.kva = 0;
			kmem_free(kernel_map, kva,
			    wpipe->pipe_buffer.size + PAGE_SIZE);
			atomic_subtract_int(&amountpipekvawired,
			    wpipe->pipe_buffer.size + PAGE_SIZE);
		}
	}
	vm_page_lock_queues();
	for (i = 0; i < wpipe->pipe_map.npages; i++) {
		vm_page_unhold(wpipe->pipe_map.ms[i]);
	}
	vm_page_unlock_queues();
	wpipe->pipe_map.npages = 0;
}

/*
 * In the case of a signal, the writing process might go away.  This
 * code copies the data into the circular buffer so that the source
 * pages can be freed without loss of data.
 */
static void
pipe_clone_write_buffer(wpipe)
	struct pipe *wpipe;
{
	int size;
	int pos;

	size = wpipe->pipe_map.cnt;
	pos = wpipe->pipe_map.pos;

	wpipe->pipe_buffer.in = size;
	wpipe->pipe_buffer.out = 0;
	wpipe->pipe_buffer.cnt = size;
	wpipe->pipe_state &= ~PIPE_DIRECTW;

	PIPE_UNLOCK(wpipe);
	bcopy((caddr_t) wpipe->pipe_map.kva + pos,
	    wpipe->pipe_buffer.buffer, size);
	pipe_destroy_write_buffer(wpipe);
	PIPE_LOCK(wpipe);
}

/*
 * This implements the pipe buffer write mechanism.  Note that only
 * a direct write OR a normal pipe write can be pending at any given time.
 * If there are any characters in the pipe buffer, the direct write will
 * be deferred until the receiving process grabs all of the bytes from
 * the pipe buffer.  Then the direct mapping write is set-up.
 */
static int
pipe_direct_write(wpipe, uio)
	struct pipe *wpipe;
	struct uio *uio;
{
	int error;

retry:
	while (wpipe->pipe_state & PIPE_DIRECTW) {
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
		wpipe->pipe_state |= PIPE_WANTW;
		error = msleep(wpipe, PIPE_MTX(wpipe),
		    PRIBIO | PCATCH, "pipdww", 0);
		if (error)
			goto error1;
		if (wpipe->pipe_state & PIPE_EOF) {
			error = EPIPE;
			goto error1;
		}
	}
	wpipe->pipe_map.cnt = 0;	/* transfer not ready yet */
	if (wpipe->pipe_buffer.cnt > 0) {
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
			
		wpipe->pipe_state |= PIPE_WANTW;
		error = msleep(wpipe, PIPE_MTX(wpipe),
		    PRIBIO | PCATCH, "pipdwc", 0);
		if (error)
			goto error1;
		if (wpipe->pipe_state & PIPE_EOF) {
			error = EPIPE;
			goto error1;
		}
		goto retry;
	}

	wpipe->pipe_state |= PIPE_DIRECTW;

	pipelock(wpipe, 0);
	PIPE_UNLOCK(wpipe);
	error = pipe_build_write_buffer(wpipe, uio);
	PIPE_LOCK(wpipe);
	pipeunlock(wpipe);
	if (error) {
		wpipe->pipe_state &= ~PIPE_DIRECTW;
		goto error1;
	}

	error = 0;
	while (!error && (wpipe->pipe_state & PIPE_DIRECTW)) {
		if (wpipe->pipe_state & PIPE_EOF) {
			pipelock(wpipe, 0);
			PIPE_UNLOCK(wpipe);
			pipe_destroy_write_buffer(wpipe);
			PIPE_LOCK(wpipe);
			pipeselwakeup(wpipe, wpipe);
			pipeunlock(wpipe);
			error = EPIPE;
			goto error1;
		}
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
		pipeselwakeup(wpipe, wpipe);
		error = msleep(wpipe, PIPE_MTX(wpipe), PRIBIO | PCATCH,
		    "pipdwt", 0);
	}

	pipelock(wpipe,0);
	if (wpipe->pipe_state & PIPE_DIRECTW) {
		/*
		 * this bit of trickery substitutes a kernel buffer for
		 * the process that might be going away.
		 */
		pipe_clone_write_buffer(wpipe);
	} else {
		PIPE_UNLOCK(wpipe);
		pipe_destroy_write_buffer(wpipe);
		PIPE_LOCK(wpipe);
	}
	pipeunlock(wpipe);
	return (error);

error1:
	wakeup(wpipe);
	return (error);
}
#endif
	


static int
pipe_write(struct fileproc *fp, struct uio *uio, __unused kauth_cred_t active_cred, __unused int flags, __unused struct proc *p)
{
	int error = 0;
	int orig_resid;
	int pipe_size;
	struct pipe *wpipe, *rpipe;

	rpipe = (struct pipe *)fp->f_data;

	PIPE_LOCK(rpipe);
	wpipe = rpipe->pipe_peer;

	/*
	 * detect loss of pipe read side, issue SIGPIPE if lost.
	 */
	if (wpipe == NULL || (wpipe->pipe_state & PIPE_EOF)) {
		PIPE_UNLOCK(rpipe);
		return (EPIPE);
	}
#ifdef MAC
	error = mac_check_pipe_write(active_cred, wpipe);
	if (error) {
		PIPE_UNLOCK(rpipe);
		return (error);
	}
#endif
	++wpipe->pipe_busy;

	pipe_size = 0;

	if (wpipe->pipe_buffer.buffer == 0) {
	        /*
		 * need to allocate some storage... we delay the allocation
		 * until the first write on fd[0] to avoid allocating storage for both
		 * 'pipe ends'... most pipes are half-duplex with the writes targeting
		 * fd[1], so allocating space for both ends is a waste...
	         *
		 * Reduce to 1/4th pipe size if we're over our global max.
		 */
	        if (amountpipekva > maxpipekva / 2)
		        pipe_size = SMALL_PIPE_SIZE;
	        else
		        pipe_size = PIPE_SIZE;
	}

	/*
	 * If it is advantageous to resize the pipe buffer, do
	 * so.
	 */
	if ((uio_resid(uio) > PIPE_SIZE) &&
		(wpipe->pipe_buffer.size <= PIPE_SIZE) &&
		(amountpipekva < maxpipekva / 2) &&
		(nbigpipe < LIMITBIGPIPES) &&
#ifndef PIPE_NODIRECT
		(wpipe->pipe_state & PIPE_DIRECTW) == 0 &&
#endif
		(wpipe->pipe_buffer.cnt == 0)) {

	        pipe_size = BIG_PIPE_SIZE;

	}
	if (pipe_size) {
	        /*
		 * need to do initial allocation or resizing of pipe
		 */
		if ((error = pipelock(wpipe, 1)) == 0) {
			PIPE_UNLOCK(wpipe);
			if (pipespace(wpipe, pipe_size) == 0)
				OSAddAtomic(1, (SInt32 *)&nbigpipe);
			PIPE_LOCK(wpipe);
			pipeunlock(wpipe);

			if (wpipe->pipe_buffer.buffer == 0) {
			        /*
				 * initial allocation failed
				 */
			        error = ENOMEM;
			}
		}
		if (error) {
		        /*
			 * If an error occurred unbusy and return, waking up any pending
			 * readers.
			 */
		        --wpipe->pipe_busy;
			if ((wpipe->pipe_busy == 0) && 
			    (wpipe->pipe_state & PIPE_WANT)) {
			        wpipe->pipe_state &= ~(PIPE_WANT | PIPE_WANTR);
				wakeup(wpipe);
			}
			PIPE_UNLOCK(rpipe);
			return(error);
		}
	}
	// LP64todo - fix this!
	orig_resid = uio_resid(uio);

	while (uio_resid(uio)) {
		int space;

#ifndef PIPE_NODIRECT
		/*
		 * If the transfer is large, we can gain performance if
		 * we do process-to-process copies directly.
		 * If the write is non-blocking, we don't use the
		 * direct write mechanism.
		 *
		 * The direct write mechanism will detect the reader going
		 * away on us.
		 */
		if ((uio->uio_iov->iov_len >= PIPE_MINDIRECT) &&
		    (fp->f_flag & FNONBLOCK) == 0 &&
		    amountpipekvawired + uio->uio_resid < maxpipekvawired) { 
			error = pipe_direct_write(wpipe, uio);
			if (error)
				break;
			continue;
		}

		/*
		 * Pipe buffered writes cannot be coincidental with
		 * direct writes.  We wait until the currently executing
		 * direct write is completed before we start filling the
		 * pipe buffer.  We break out if a signal occurs or the
		 * reader goes away.
		 */
	retrywrite:
		while (wpipe->pipe_state & PIPE_DIRECTW) {
			if (wpipe->pipe_state & PIPE_WANTR) {
				wpipe->pipe_state &= ~PIPE_WANTR;
				wakeup(wpipe);
			}
			error = msleep(wpipe, PIPE_MTX(wpipe), PRIBIO | PCATCH, "pipbww", 0);

			if (wpipe->pipe_state & PIPE_EOF)
				break;
			if (error)
				break;
		}
#else
	retrywrite:
#endif
		space = wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt;

		/*
		 * Writes of size <= PIPE_BUF must be atomic.
		 */
		if ((space < uio_resid(uio)) && (orig_resid <= PIPE_BUF))
			space = 0;

		if (space > 0) {

			if ((error = pipelock(wpipe,1)) == 0) {
				int size;	/* Transfer size */
				int segsize;	/* first segment to transfer */

				if (wpipe->pipe_state & PIPE_EOF) {
					pipeunlock(wpipe);
				        error = EPIPE;
					break;
				}
#ifndef PIPE_NODIRECT
				/*
				 * It is possible for a direct write to
				 * slip in on us... handle it here...
				 */
				if (wpipe->pipe_state & PIPE_DIRECTW) {
					pipeunlock(wpipe);
					goto retrywrite;
				}
#endif
				/* 
				 * If a process blocked in pipelock, our
				 * value for space might be bad... the mutex
				 * is dropped while we're blocked
				 */
				if (space > (int)(wpipe->pipe_buffer.size - 
				    wpipe->pipe_buffer.cnt)) {
					pipeunlock(wpipe);
					goto retrywrite;
				}

				/*
				 * Transfer size is minimum of uio transfer
				 * and free space in pipe buffer.
				 */
				// LP64todo - fix this!
				if (space > uio_resid(uio))
					size = uio_resid(uio);
				else
					size = space;
				/*
				 * First segment to transfer is minimum of 
				 * transfer size and contiguous space in
				 * pipe buffer.  If first segment to transfer
				 * is less than the transfer size, we've got
				 * a wraparound in the buffer.
				 */
				segsize = wpipe->pipe_buffer.size - 
					wpipe->pipe_buffer.in;
				if (segsize > size)
					segsize = size;
				
				/* Transfer first segment */

				PIPE_UNLOCK(rpipe);
				error = uiomove(&wpipe->pipe_buffer.buffer[wpipe->pipe_buffer.in], 
						segsize, uio);
				PIPE_LOCK(rpipe);
				
				if (error == 0 && segsize < size) {
					/* 
					 * Transfer remaining part now, to
					 * support atomic writes.  Wraparound
					 * happened.
					 */
					if (wpipe->pipe_buffer.in + segsize != 
					    wpipe->pipe_buffer.size)
						panic("Expected pipe buffer "
						    "wraparound disappeared");
						
					PIPE_UNLOCK(rpipe);
					error = uiomove(
					    &wpipe->pipe_buffer.buffer[0],
				    	    size - segsize, uio);
					PIPE_LOCK(rpipe);
				}
				if (error == 0) {
					wpipe->pipe_buffer.in += size;
					if (wpipe->pipe_buffer.in >=
					    wpipe->pipe_buffer.size) {
						if (wpipe->pipe_buffer.in !=
						    size - segsize +
						    wpipe->pipe_buffer.size)
							panic("Expected "
							    "wraparound bad");
						wpipe->pipe_buffer.in = size -
						    segsize;
					}
				
					wpipe->pipe_buffer.cnt += size;
					if (wpipe->pipe_buffer.cnt >
					    wpipe->pipe_buffer.size)
						panic("Pipe buffer overflow");
				
				}
				pipeunlock(wpipe);
			}
			if (error)
				break;

		} else {
			/*
			 * If the "read-side" has been blocked, wake it up now.
			 */
			if (wpipe->pipe_state & PIPE_WANTR) {
				wpipe->pipe_state &= ~PIPE_WANTR;
				wakeup(wpipe);
			}
			/*
			 * don't block on non-blocking I/O
			 * we'll do the pipeselwakeup on the way out
			 */
			if (fp->f_flag & FNONBLOCK) {
				error = EAGAIN;
				break;
			}
			/*
			 * We have no more space and have something to offer,
			 * wake up select/poll.
			 */
			pipeselwakeup(wpipe, wpipe);

			wpipe->pipe_state |= PIPE_WANTW;

			error = msleep(wpipe, PIPE_MTX(wpipe), PRIBIO | PCATCH, "pipewr", 0);

			if (error != 0)
				break;
			/*
			 * If read side wants to go away, we just issue a signal
			 * to ourselves.
			 */
			if (wpipe->pipe_state & PIPE_EOF) {
				error = EPIPE;
				break;
			}	
		}
	}
	--wpipe->pipe_busy;

	if ((wpipe->pipe_busy == 0) && (wpipe->pipe_state & PIPE_WANT)) {
		wpipe->pipe_state &= ~(PIPE_WANT | PIPE_WANTR);
		wakeup(wpipe);
	}
	if (wpipe->pipe_buffer.cnt > 0) {
		/*
		 * If there are any characters in the buffer, we wake up
		 * the reader if it was blocked waiting for data.
		 */
		if (wpipe->pipe_state & PIPE_WANTR) {
			wpipe->pipe_state &= ~PIPE_WANTR;
			wakeup(wpipe);
		}
		/*
		 * wake up thread blocked in select/poll or post the notification
		 */
		pipeselwakeup(wpipe, wpipe);
	}
	PIPE_UNLOCK(rpipe);

	return (error);
}

/*
 * we implement a very minimal set of ioctls for compatibility with sockets.
 */
/* ARGSUSED 3 */
static int
pipe_ioctl(struct fileproc *fp, u_long cmd, caddr_t data, __unused struct proc *p)
{
	struct pipe *mpipe = (struct pipe *)fp->f_data;
#ifdef MAC
	int error;
#endif

	PIPE_LOCK(mpipe);

#ifdef MAC
	error = mac_check_pipe_ioctl(active_cred, mpipe, cmd, data);
	if (error) {
		PIPE_UNLOCK(mpipe);

		return (error);
	}
#endif

	switch (cmd) {

	case FIONBIO:
		PIPE_UNLOCK(mpipe);
		return (0);

	case FIOASYNC:
		if (*(int *)data) {
			mpipe->pipe_state |= PIPE_ASYNC;
		} else {
			mpipe->pipe_state &= ~PIPE_ASYNC;
		}
		PIPE_UNLOCK(mpipe);
		return (0);

	case FIONREAD:
#ifndef PIPE_NODIRECT
		if (mpipe->pipe_state & PIPE_DIRECTW)
			*(int *)data = mpipe->pipe_map.cnt;
		else
#endif
			*(int *)data = mpipe->pipe_buffer.cnt;
		PIPE_UNLOCK(mpipe);
		return (0);

	case TIOCSPGRP:
		mpipe->pipe_pgid = *(int *)data;

		PIPE_UNLOCK(mpipe);
		return (0);

	case TIOCGPGRP:
		*(int *)data = mpipe->pipe_pgid;

		PIPE_UNLOCK(mpipe);
		return (0);

	}
	PIPE_UNLOCK(mpipe);
	return (ENOTTY);
}


static int
pipe_select(struct fileproc *fp, int which, void *wql, struct proc *p)
{
	struct pipe *rpipe = (struct pipe *)fp->f_data;
	struct pipe *wpipe;
	int    retnum = 0;

	if (rpipe == NULL || rpipe == (struct pipe *)-1)
	        return (retnum);

	PIPE_LOCK(rpipe);

	wpipe = rpipe->pipe_peer;

        switch (which) {

        case FREAD:
		if ((rpipe->pipe_state & PIPE_DIRECTW) ||
		    (rpipe->pipe_buffer.cnt > 0) ||
		    (rpipe->pipe_state & PIPE_EOF)) {

		        retnum = 1;
		} else {
		        rpipe->pipe_state |= PIPE_SEL;
		        selrecord(p, &rpipe->pipe_sel, wql);
		}
		break;

        case FWRITE:
		if (wpipe == NULL || (wpipe->pipe_state & PIPE_EOF) ||
		    (((wpipe->pipe_state & PIPE_DIRECTW) == 0) &&
		     (wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt) >= PIPE_BUF)) {

		        retnum = 1;
		} else {
		        wpipe->pipe_state |= PIPE_SEL;
			selrecord(p, &wpipe->pipe_sel, wql);
		}
		break;
        case 0:
	        rpipe->pipe_state |= PIPE_SEL;
		selrecord(p, &rpipe->pipe_sel, wql);
		break;
        }
	PIPE_UNLOCK(rpipe);

        return (retnum);
}


/* ARGSUSED 1 */
static int
pipe_close(struct fileglob *fg, __unused struct proc *p)
{
        struct pipe *cpipe;

	proc_fdlock(p);
	cpipe = (struct pipe *)fg->fg_data;
	fg->fg_data = NULL;
	proc_fdunlock(p);

	if (cpipe)
	        pipeclose(cpipe);

	return (0);
}

static void
pipe_free_kmem(struct pipe *cpipe)
{

	if (cpipe->pipe_buffer.buffer != NULL) {
		if (cpipe->pipe_buffer.size > PIPE_SIZE)
			OSAddAtomic(-1, (SInt32 *)&nbigpipe);
		OSAddAtomic(cpipe->pipe_buffer.size, (SInt32 *)&amountpipekva);
		OSAddAtomic(-1, (SInt32 *)&amountpipes);

		kmem_free(kernel_map, (vm_offset_t)cpipe->pipe_buffer.buffer,
			  cpipe->pipe_buffer.size);
		cpipe->pipe_buffer.buffer = NULL;
	}
#ifndef PIPE_NODIRECT
	if (cpipe->pipe_map.kva != 0) {
		atomic_subtract_int(&amountpipekvawired,
		    cpipe->pipe_buffer.size + PAGE_SIZE);
		kmem_free(kernel_map,
			cpipe->pipe_map.kva,
			cpipe->pipe_buffer.size + PAGE_SIZE);
		cpipe->pipe_map.cnt = 0;
		cpipe->pipe_map.kva = 0;
		cpipe->pipe_map.pos = 0;
		cpipe->pipe_map.npages = 0;
	}
#endif
}

/*
 * shutdown the pipe
 */
static void
pipeclose(struct pipe *cpipe)
{
	struct pipe *ppipe;

	if (cpipe == NULL)
		return;

	/* partially created pipes won't have a valid mutex. */
	if (PIPE_MTX(cpipe) != NULL)
		PIPE_LOCK(cpipe);
		
	pipeselwakeup(cpipe, cpipe);

	/*
	 * If the other side is blocked, wake it up saying that
	 * we want to close it down.
	 */
	while (cpipe->pipe_busy) {
		cpipe->pipe_state |= PIPE_WANT | PIPE_EOF;

		wakeup(cpipe);

 		msleep(cpipe, PIPE_MTX(cpipe), PRIBIO, "pipecl", 0);
	}

#ifdef MAC
	if (cpipe->pipe_label != NULL && cpipe->pipe_peer == NULL)
		mac_destroy_pipe(cpipe);
#endif

	/*
	 * Disconnect from peer
	 */
	if ((ppipe = cpipe->pipe_peer) != NULL) {

		ppipe->pipe_state |= PIPE_EOF;

		pipeselwakeup(ppipe, ppipe);
		wakeup(ppipe);

		if (cpipe->pipe_state & PIPE_KNOTE)
		        KNOTE(&ppipe->pipe_sel.si_note, 1);

		postpipeevent(ppipe, EV_RCLOSED);

		ppipe->pipe_peer = NULL;
	}
	evpipefree(cpipe);

	/*
	 * free resources
	 */
	if (PIPE_MTX(cpipe) != NULL) {
	        if (ppipe != NULL) {
		        /*
			 * since the mutex is shared and the peer is still
			 * alive, we need to release the mutex, not free it
			 */
		        PIPE_UNLOCK(cpipe);
		} else {
		        /*
			 * peer is gone, so we're the sole party left with
			 * interest in this mutex... we can just free it
			 */
			lck_mtx_free(PIPE_MTX(cpipe), pipe_mtx_grp);
		}
	}
	pipe_free_kmem(cpipe);

	zfree(pipe_zone, cpipe);
}


/*ARGSUSED*/
static int
pipe_kqfilter(__unused struct fileproc *fp, struct knote *kn, __unused struct proc *p)
{
	struct pipe *cpipe;

	cpipe = (struct pipe *)kn->kn_fp->f_data;

	PIPE_LOCK(cpipe);

	switch (kn->kn_filter) {
	case EVFILT_READ:
		kn->kn_fop = &pipe_rfiltops;
		break;
	case EVFILT_WRITE:
		kn->kn_fop = &pipe_wfiltops;

		if (cpipe->pipe_peer == NULL) {
			/*
			 * other end of pipe has been closed
			 */
		        PIPE_UNLOCK(cpipe);
			return (EPIPE);
		}
		cpipe = cpipe->pipe_peer;
		break;
	default:
	        PIPE_UNLOCK(cpipe);
		return (1);
	}

	if (KNOTE_ATTACH(&cpipe->pipe_sel.si_note, kn))
	        cpipe->pipe_state |= PIPE_KNOTE;

	PIPE_UNLOCK(cpipe);
	return (0);
}

static void
filt_pipedetach(struct knote *kn)
{
	struct pipe *cpipe = (struct pipe *)kn->kn_fp->f_data;

	PIPE_LOCK(cpipe);

	if (kn->kn_filter == EVFILT_WRITE) {
	        if (cpipe->pipe_peer == NULL) {
		        PIPE_UNLOCK(cpipe);
			return;
		}
		cpipe = cpipe->pipe_peer;
	}
	if (cpipe->pipe_state & PIPE_KNOTE) {
	        if (KNOTE_DETACH(&cpipe->pipe_sel.si_note, kn))
		        cpipe->pipe_state &= ~PIPE_KNOTE;
	}
	PIPE_UNLOCK(cpipe);
}

/*ARGSUSED*/
static int
filt_piperead(struct knote *kn, long hint)
{
	struct pipe *rpipe = (struct pipe *)kn->kn_fp->f_data;
	struct pipe *wpipe;
	int    retval;

	/*
	 * if hint == 0, then we've been called from the kevent
	 * world directly and do not currently hold the pipe mutex...
	 * if hint == 1, we're being called back via the KNOTE post
	 * we made in pipeselwakeup, and we already hold the mutex...
	 */
	if (hint == 0)
	        PIPE_LOCK(rpipe);

	wpipe = rpipe->pipe_peer;
	kn->kn_data = rpipe->pipe_buffer.cnt;

#ifndef PIPE_NODIRECT
	if ((kn->kn_data == 0) && (rpipe->pipe_state & PIPE_DIRECTW))
		kn->kn_data = rpipe->pipe_map.cnt;
#endif
	if ((rpipe->pipe_state & PIPE_EOF) ||
	    (wpipe == NULL) || (wpipe->pipe_state & PIPE_EOF)) {
		kn->kn_flags |= EV_EOF;
		retval = 1;
	} else
		retval = (kn->kn_sfflags & NOTE_LOWAT) ?
		         (kn->kn_data >= kn->kn_sdata) : (kn->kn_data > 0);

	if (hint == 0)
	        PIPE_UNLOCK(rpipe);

	return (retval);
}

/*ARGSUSED*/
static int
filt_pipewrite(struct knote *kn, long hint)
{
	struct pipe *rpipe = (struct pipe *)kn->kn_fp->f_data;
	struct pipe *wpipe;

	/*
	 * if hint == 0, then we've been called from the kevent
	 * world directly and do not currently hold the pipe mutex...
	 * if hint == 1, we're being called back via the KNOTE post
	 * we made in pipeselwakeup, and we already hold the mutex...
	 */
	if (hint == 0)
	        PIPE_LOCK(rpipe);

	wpipe = rpipe->pipe_peer;

	if ((wpipe == NULL) || (wpipe->pipe_state & PIPE_EOF)) {
		kn->kn_data = 0;
		kn->kn_flags |= EV_EOF; 

		if (hint == 0)
		        PIPE_UNLOCK(rpipe);
		return (1);
	}
	kn->kn_data = wpipe->pipe_buffer.size - wpipe->pipe_buffer.cnt;

#ifndef PIPE_NODIRECT
	if (wpipe->pipe_state & PIPE_DIRECTW)
		kn->kn_data = 0;
#endif
	if (hint == 0)
	        PIPE_UNLOCK(rpipe);

	return (kn->kn_data >= ((kn->kn_sfflags & NOTE_LOWAT) ?
	                         kn->kn_sdata : PIPE_BUF));
}
