/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
/*	$NetBSD: sysv_shm.c,v 1.23 1994/07/04 23:25:12 glass Exp $	*/

/*
 * Copyright (c) 1994 Adam Glass and Charles Hannum.  All rights reserved.
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
 *	This product includes software developed by Adam Glass and Charles
 *	Hannum.
 * 4. The names of the authors may not be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */


#include <sys/appleapiopts.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/shm_internal.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/malloc.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sys/ipcs.h>
#include <sys/sysent.h>
#include <sys/sysproto.h>

#include <bsm/audit_kernel.h>

#include <mach/mach_types.h>
#include <mach/vm_inherit.h>
#include <mach/vm_map.h>

#include <mach/mach_vm.h>

#include <vm/vm_map.h>
#include <vm/vm_shared_memory_server.h>
#include <vm/vm_protos.h>

#include <kern/locks.h>

static void shminit(void *);
#if 0
SYSINIT(sysv_shm, SI_SUB_SYSV_SHM, SI_ORDER_FIRST, shminit, NULL)
#endif 0

static lck_grp_t       *sysv_shm_subsys_lck_grp;
static lck_grp_attr_t  *sysv_shm_subsys_lck_grp_attr;
static lck_attr_t      *sysv_shm_subsys_lck_attr;
static lck_mtx_t        sysv_shm_subsys_mutex;

#define SYSV_SHM_SUBSYS_LOCK() lck_mtx_lock(&sysv_shm_subsys_mutex)
#define SYSV_SHM_SUBSYS_UNLOCK() lck_mtx_unlock(&sysv_shm_subsys_mutex)

static int oshmctl(void *p, void *uap, void *retval);
static int shmget_allocate_segment(struct proc *p, struct shmget_args *uap, int mode, int * retval);
static int shmget_existing(struct shmget_args *uap, int mode, int segnum, int  * retval);
static void shmid_ds_64to32(struct user_shmid_ds *in, struct shmid_ds *out);
static void shmid_ds_32to64(struct shmid_ds *in, struct user_shmid_ds *out);

/* XXX casting to (sy_call_t *) is bogus, as usual. */
static sy_call_t *shmcalls[] = {
	(sy_call_t *)shmat, (sy_call_t *)oshmctl,
	(sy_call_t *)shmdt, (sy_call_t *)shmget,
	(sy_call_t *)shmctl
};

#define	SHMSEG_FREE     	0x0200
#define	SHMSEG_REMOVED  	0x0400
#define	SHMSEG_ALLOCATED	0x0800
#define	SHMSEG_WANTED		0x1000

static int shm_last_free, shm_nused, shm_committed;
struct user_shmid_ds	*shmsegs;	/* 64 bit version */
static int shm_inited = 0;

struct shm_handle {
	void * shm_object;		/* vm_offset_t kva; */
};

struct shmmap_state {
	mach_vm_address_t va;		/* user address */
	int shmid;			/* segment id */
};

static void shm_deallocate_segment(struct user_shmid_ds *);
static int shm_find_segment_by_key(key_t);
static struct user_shmid_ds *shm_find_segment_by_shmid(int);
static int shm_delete_mapping(struct proc *, struct shmmap_state *, int);

#ifdef __APPLE_API_PRIVATE
struct  shminfo shminfo = {
        -1,	/* SHMMAX 4096 *1024 */
        -1,	/* SHMMIN = 1 */
        -1,	/* SHMMNI = 1 */
        -1,	/* SHMSEG = 8 */
        -1	/* SHMALL = 1024 */
};
#endif /* __APPLE_API_PRIVATE */

void sysv_shm_lock_init(void);

static __inline__ time_t
sysv_shmtime(void)
{
	struct timeval	tv;
	microtime(&tv);
	return (tv.tv_sec);
}

/*
 * This conversion is safe, since if we are converting for a 32 bit process,
 * then it's value of (struct shmid_ds)->shm_segsz will never exceed 4G.
 *
 * NOTE: Source and target may *NOT* overlap! (target is smaller)
 */
static void
shmid_ds_64to32(struct user_shmid_ds *in, struct shmid_ds *out)
{
	out->shm_perm = in->shm_perm;
	out->shm_segsz = (size_t)in->shm_segsz;
	out->shm_lpid = in->shm_lpid;
	out->shm_cpid = in->shm_cpid;
	out->shm_nattch = in->shm_nattch;
	out->shm_atime = in->shm_atime;
	out->shm_dtime = in->shm_dtime;
	out->shm_ctime = in->shm_ctime;
	out->shm_internal = CAST_DOWN(void *,in->shm_internal);
}

/*
 * NOTE: Source and target may are permitted to overlap! (source is smaller);
 * this works because we copy fields in order from the end of the struct to
 * the beginning.
 */
static void
shmid_ds_32to64(struct shmid_ds *in, struct user_shmid_ds *out)
{
	out->shm_internal = CAST_USER_ADDR_T(in->shm_internal);
	out->shm_ctime = in->shm_ctime;
	out->shm_dtime = in->shm_dtime;
	out->shm_atime = in->shm_atime;
	out->shm_nattch = in->shm_nattch;
	out->shm_cpid = in->shm_cpid;
	out->shm_lpid = in->shm_lpid;
	out->shm_segsz = (user_size_t)in->shm_segsz;
	out->shm_perm = in->shm_perm;
}


static int
shm_find_segment_by_key(key_t key)
{
	int i;

	for (i = 0; i < shminfo.shmmni; i++)
		if ((shmsegs[i].shm_perm.mode & SHMSEG_ALLOCATED) &&
		    shmsegs[i].shm_perm.key == key)
			return i;
	return -1;
}

static struct user_shmid_ds *
shm_find_segment_by_shmid(int shmid)
{
	int segnum;
	struct user_shmid_ds *shmseg;

	segnum = IPCID_TO_IX(shmid);
	if (segnum < 0 || segnum >= shminfo.shmmni)
		return NULL;
	shmseg = &shmsegs[segnum];
	if ((shmseg->shm_perm.mode & (SHMSEG_ALLOCATED | SHMSEG_REMOVED))
	    != SHMSEG_ALLOCATED ||
	    shmseg->shm_perm.seq != IPCID_TO_SEQ(shmid))
		return NULL;
	return shmseg;
}

static void
shm_deallocate_segment(struct user_shmid_ds *shmseg)
{
	struct shm_handle *shm_handle;
	mach_vm_size_t size;

	shm_handle = CAST_DOWN(void *,shmseg->shm_internal);	/* tunnel */
	size = mach_vm_round_page(shmseg->shm_segsz);
	mach_memory_entry_port_release(shm_handle->shm_object);
	shm_handle->shm_object = NULL;
	FREE((caddr_t)shm_handle, M_SHM);
	shmseg->shm_internal = USER_ADDR_NULL;		/* tunnel */
	shm_committed -= btoc(size);
	shm_nused--;
	shmseg->shm_perm.mode = SHMSEG_FREE;
}

static int
shm_delete_mapping(__unused struct proc *p, struct shmmap_state *shmmap_s,
	int deallocate)
{
	struct user_shmid_ds *shmseg;
	int segnum, result;
	mach_vm_size_t size;

	segnum = IPCID_TO_IX(shmmap_s->shmid);
	shmseg = &shmsegs[segnum];
	size = mach_vm_round_page(shmseg->shm_segsz);	/* XXX done for us? */
	if (deallocate) {
	result = mach_vm_deallocate(current_map(), shmmap_s->va, size);
	if (result != KERN_SUCCESS)
		return EINVAL;
	}
	shmmap_s->shmid = -1;
	shmseg->shm_dtime = sysv_shmtime();
	if ((--shmseg->shm_nattch <= 0) &&
	    (shmseg->shm_perm.mode & SHMSEG_REMOVED)) {
		shm_deallocate_segment(shmseg);
		shm_last_free = segnum;
	}
	return 0;
}

int
shmdt(struct proc *p, struct shmdt_args *uap, register_t *retval)
{
	struct shmmap_state *shmmap_s;
	int i;
	int shmdtret = 0;

	// LP64todo - fix this
	AUDIT_ARG(svipc_addr, CAST_DOWN(void *,uap->shmaddr));

	SYSV_SHM_SUBSYS_LOCK();

	if (!shm_inited) {
		shmdtret = EINVAL;
		goto shmdt_out;
	}
	shmmap_s = (struct shmmap_state *)p->vm_shm;
 	if (shmmap_s == NULL) {
		shmdtret = EINVAL;
		goto shmdt_out;
	}

	for (i = 0; i < shminfo.shmseg; i++, shmmap_s++)
		if (shmmap_s->shmid != -1 &&
		    shmmap_s->va == (mach_vm_offset_t)uap->shmaddr)
			break;
	if (i == shminfo.shmseg) {
		shmdtret = EINVAL;
		goto shmdt_out;
	}
	i = shm_delete_mapping(p, shmmap_s, 1);

	if (i == 0)
		*retval = 0;
	shmdtret = i;
shmdt_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return shmdtret;
}

int
shmat(struct proc *p, struct shmat_args *uap, register_t *retval)
{
	int error, i, flags;
	struct user_shmid_ds	*shmseg;
	struct shmmap_state	*shmmap_s = NULL;
	struct shm_handle	*shm_handle;
	mach_vm_address_t	attach_va;	/* attach address in/out */
	mach_vm_size_t		map_size;	/* size of map entry */
	vm_prot_t		prot;
	size_t			size;
	kern_return_t		rv;
	int shmat_ret = 0;

	AUDIT_ARG(svipc_id, uap->shmid);
	// LP64todo - fix this
	AUDIT_ARG(svipc_addr, CAST_DOWN(void *,uap->shmaddr));

	SYSV_SHM_SUBSYS_LOCK();

	if (!shm_inited) {
		shmat_ret = EINVAL;
		goto shmat_out;
	}

	shmmap_s = (struct shmmap_state *)p->vm_shm;

	if (shmmap_s == NULL) {
		size = shminfo.shmseg * sizeof(struct shmmap_state);
		MALLOC(shmmap_s, struct shmmap_state *, size, M_SHM, M_WAITOK);
		if (shmmap_s == NULL) {
			shmat_ret = ENOMEM;
			goto shmat_out;
		}
		for (i = 0; i < shminfo.shmseg; i++)
			shmmap_s[i].shmid = -1;
		p->vm_shm = (caddr_t)shmmap_s;
	}
	shmseg = shm_find_segment_by_shmid(uap->shmid);
	if (shmseg == NULL) {
		shmat_ret = EINVAL;
		goto shmat_out;
	}

	AUDIT_ARG(svipc_perm, &shmseg->shm_perm);
	error = ipcperm(kauth_cred_get(), &shmseg->shm_perm,
	    (uap->shmflg & SHM_RDONLY) ? IPC_R : IPC_R|IPC_W);
	if (error) {
		shmat_ret = error;
		goto shmat_out;
	}

	for (i = 0; i < shminfo.shmseg; i++) {
		if (shmmap_s->shmid == -1)
			break;
		shmmap_s++;
	}
	if (i >= shminfo.shmseg) {
		shmat_ret = EMFILE;
		goto shmat_out;
	}

	map_size = mach_vm_round_page(shmseg->shm_segsz);
	prot = VM_PROT_READ;
	if ((uap->shmflg & SHM_RDONLY) == 0)
		prot |= VM_PROT_WRITE;
	flags = MAP_ANON | MAP_SHARED;
	if (uap->shmaddr)
		flags |= MAP_FIXED;

	attach_va = (mach_vm_address_t)uap->shmaddr;
	if (uap->shmflg & SHM_RND)
		attach_va &= ~(SHMLBA-1);
	else if ((attach_va & (SHMLBA-1)) != 0) {
		shmat_ret = EINVAL;
		goto shmat_out;
	}

	shm_handle = CAST_DOWN(void *, shmseg->shm_internal);	/* tunnel */

	rv = mach_vm_map(current_map(),			/* process map */
			&attach_va,			/* attach address */
			map_size,			/* segment size */
			(mach_vm_offset_t)0,		/* alignment mask */
		(flags & MAP_FIXED)? VM_FLAGS_FIXED: VM_FLAGS_ANYWHERE,
			shm_handle->shm_object,
			(mach_vm_offset_t)0,
			FALSE,
			prot,
			prot,
			VM_INHERIT_DEFAULT);
	if (rv != KERN_SUCCESS) 
			goto out;

	rv = mach_vm_inherit(current_map(), attach_va, map_size, VM_INHERIT_SHARE);
	if (rv != KERN_SUCCESS) {
		(void)mach_vm_deallocate(current_map(), attach_va, map_size);
		goto out;
	}

	shmmap_s->va = attach_va;
	shmmap_s->shmid = uap->shmid;
	shmseg->shm_lpid = p->p_pid;
	shmseg->shm_atime = sysv_shmtime();
	shmseg->shm_nattch++;
	*retval = attach_va;	/* XXX return -1 on error */
	shmat_ret = 0;
	goto shmat_out;
out:
	switch (rv) {
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		shmat_ret = ENOMEM;
	case KERN_PROTECTION_FAILURE:
		shmat_ret = EACCES;
	default:
		shmat_ret = EINVAL;
	}
shmat_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return shmat_ret;
}

static int
oshmctl(__unused void *p, __unused void *uap, __unused void *retval)
{
	return EINVAL;
}

int
shmctl(__unused struct proc *p, struct shmctl_args *uap, register_t *retval)
{
	int error;
	kauth_cred_t cred = kauth_cred_get();
	struct user_shmid_ds inbuf;
	struct user_shmid_ds *shmseg;
	size_t shmid_ds_sz = sizeof(struct user_shmid_ds);

	int shmctl_ret = 0;

	AUDIT_ARG(svipc_cmd, uap->cmd);
	AUDIT_ARG(svipc_id, uap->shmid);

	SYSV_SHM_SUBSYS_LOCK();

	if (!shm_inited) {
		shmctl_ret = EINVAL;
		goto shmctl_out;
	}

	if (!IS_64BIT_PROCESS(p))
		shmid_ds_sz = sizeof(struct shmid_ds);

	shmseg = shm_find_segment_by_shmid(uap->shmid);
	if (shmseg == NULL) {
		shmctl_ret = EINVAL;
		goto shmctl_out;
	}

	/* XXAUDIT: This is the perms BEFORE any change by this call. This 
	 * may not be what is desired.
	 */
	AUDIT_ARG(svipc_perm, &shmseg->shm_perm);

	switch (uap->cmd) {
	case IPC_STAT:
		error = ipcperm(cred, &shmseg->shm_perm, IPC_R);
		if (error) {
			shmctl_ret = error;
			goto shmctl_out;
		}

		if (IS_64BIT_PROCESS(p)) {
			error = copyout(shmseg, uap->buf, sizeof(struct user_shmid_ds));
		} else {
			struct shmid_ds shmid_ds32;
			shmid_ds_64to32(shmseg, &shmid_ds32);
			error = copyout(&shmid_ds32, uap->buf, sizeof(struct shmid_ds));
		}
		if (error) {
			shmctl_ret = error;
			goto shmctl_out;
		}
		break;
	case IPC_SET:
		error = ipcperm(cred, &shmseg->shm_perm, IPC_M);
		if (error) {
			shmctl_ret = error;
			goto shmctl_out;
		}
		if (IS_64BIT_PROCESS(p)) {
			error = copyin(uap->buf, &inbuf, sizeof(struct user_shmid_ds));
		} else {
			error = copyin(uap->buf, &inbuf, sizeof(struct shmid_ds));
			/* convert in place; ugly, but safe */
			shmid_ds_32to64((struct shmid_ds *)&inbuf, &inbuf);
		}
		if (error) {
			shmctl_ret = error;
			goto shmctl_out;
		}
		shmseg->shm_perm.uid = inbuf.shm_perm.uid;
		shmseg->shm_perm.gid = inbuf.shm_perm.gid;
		shmseg->shm_perm.mode =
		    (shmseg->shm_perm.mode & ~ACCESSPERMS) |
		    (inbuf.shm_perm.mode & ACCESSPERMS);
		shmseg->shm_ctime = sysv_shmtime();
		break;
	case IPC_RMID:
		error = ipcperm(cred, &shmseg->shm_perm, IPC_M);
		if (error) {
			shmctl_ret = error;
			goto shmctl_out;
		}
		shmseg->shm_perm.key = IPC_PRIVATE;
		shmseg->shm_perm.mode |= SHMSEG_REMOVED;
		if (shmseg->shm_nattch <= 0) {
			shm_deallocate_segment(shmseg);
			shm_last_free = IPCID_TO_IX(uap->shmid);
		}
		break;
#if 0
	case SHM_LOCK:
	case SHM_UNLOCK:
#endif
	default:
		shmctl_ret = EINVAL;
		goto shmctl_out;
	}
	*retval = 0;
	shmctl_ret = 0;
shmctl_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return shmctl_ret;
}

static int
shmget_existing(struct shmget_args *uap, int mode, int segnum, int *retval)
{
	struct user_shmid_ds *shmseg;
	int error;

	shmseg = &shmsegs[segnum];
	if (shmseg->shm_perm.mode & SHMSEG_REMOVED) {
		/*
		 * This segment is in the process of being allocated.  Wait
		 * until it's done, and look the key up again (in case the
		 * allocation failed or it was freed).
		 */
		shmseg->shm_perm.mode |= SHMSEG_WANTED;
		error = tsleep((caddr_t)shmseg, PLOCK | PCATCH, "shmget", 0);
		if (error)
			return error;
		return EAGAIN;
	}
	error = ipcperm(kauth_cred_get(), &shmseg->shm_perm, mode);
	if (error)
		return error;
	if (uap->size && uap->size > shmseg->shm_segsz)
		return EINVAL;
       if ((uap->shmflg & (IPC_CREAT | IPC_EXCL)) == (IPC_CREAT | IPC_EXCL))
		return EEXIST;
	*retval = IXSEQ_TO_IPCID(segnum, shmseg->shm_perm);
	return 0;
}

static int
shmget_allocate_segment(struct proc *p, struct shmget_args *uap, int mode,
	int *retval)
{
	int i, segnum, shmid, size;
	kauth_cred_t cred = kauth_cred_get();
	struct user_shmid_ds *shmseg;
	struct shm_handle *shm_handle;
	kern_return_t kret;
	vm_offset_t user_addr;
	void * mem_object;

	if (uap->size < (user_size_t)shminfo.shmmin ||
	    uap->size > (user_size_t)shminfo.shmmax)
		return EINVAL;
	if (shm_nused >= shminfo.shmmni) /* any shmids left? */
		return ENOSPC;
	size = mach_vm_round_page(uap->size);
	if (shm_committed + btoc(size) > shminfo.shmall)
		return ENOMEM;
	if (shm_last_free < 0) {
		for (i = 0; i < shminfo.shmmni; i++)
			if (shmsegs[i].shm_perm.mode & SHMSEG_FREE)
				break;
		if (i == shminfo.shmmni)
			panic("shmseg free count inconsistent");
		segnum = i;
	} else  {
		segnum = shm_last_free;
		shm_last_free = -1;
	}
	shmseg = &shmsegs[segnum];
	/*
	 * In case we sleep in malloc(), mark the segment present but deleted
	 * so that noone else tries to create the same key.
	 */
	kret = vm_allocate(current_map(), &user_addr, size, VM_FLAGS_ANYWHERE);
	if (kret != KERN_SUCCESS) 
		goto out;

	kret = mach_make_memory_entry (current_map(), &size, user_addr, 
		VM_PROT_DEFAULT, (mem_entry_name_port_t *)&mem_object, 0);

	if (kret != KERN_SUCCESS) 
		goto out;

	vm_deallocate(current_map(), user_addr, size);

	shmseg->shm_perm.mode = SHMSEG_ALLOCATED | SHMSEG_REMOVED;
	shmseg->shm_perm.key = uap->key;
	shmseg->shm_perm.seq = (shmseg->shm_perm.seq + 1) & 0x7fff;
	MALLOC(shm_handle, struct shm_handle *, sizeof(struct shm_handle), M_SHM, M_WAITOK);
	if (shm_handle == NULL) {
		kret = KERN_NO_SPACE;
		mach_memory_entry_port_release(mem_object);
		mem_object = NULL;
		goto out;
	}
	shm_handle->shm_object = mem_object;
	shmid = IXSEQ_TO_IPCID(segnum, shmseg->shm_perm);

	shmseg->shm_internal = CAST_USER_ADDR_T(shm_handle);	/* tunnel */
	shmseg->shm_perm.cuid = shmseg->shm_perm.uid = kauth_cred_getuid(cred);
	shmseg->shm_perm.cgid = shmseg->shm_perm.gid = cred->cr_gid;
	shmseg->shm_perm.mode = (shmseg->shm_perm.mode & SHMSEG_WANTED) |
	    (mode & ACCESSPERMS) | SHMSEG_ALLOCATED;
	shmseg->shm_segsz = uap->size;
	shmseg->shm_cpid = p->p_pid;
	shmseg->shm_lpid = shmseg->shm_nattch = 0;
	shmseg->shm_atime = shmseg->shm_dtime = 0;
	shmseg->shm_ctime = sysv_shmtime();
	shm_committed += btoc(size);
	shm_nused++;
	AUDIT_ARG(svipc_perm, &shmseg->shm_perm);
	if (shmseg->shm_perm.mode & SHMSEG_WANTED) {
		/*
		 * Somebody else wanted this key while we were asleep.  Wake
		 * them up now.
		 */
		shmseg->shm_perm.mode &= ~SHMSEG_WANTED;
		wakeup((caddr_t)shmseg);
	}
	*retval = shmid;
	AUDIT_ARG(svipc_id, shmid);
	return 0;
out: 
	switch (kret) {
	case KERN_INVALID_ADDRESS:
	case KERN_NO_SPACE:
		return (ENOMEM);
	case KERN_PROTECTION_FAILURE:
		return (EACCES);
	default:
		return (EINVAL);
	}

}

int
shmget(struct proc *p, struct shmget_args *uap, register_t *retval)
{
	int segnum, mode, error;
	int shmget_ret = 0;
	
	/* Auditing is actually done in shmget_allocate_segment() */

	SYSV_SHM_SUBSYS_LOCK();

	if (!shm_inited) {
		shmget_ret = EINVAL;
		goto shmget_out;
	}

	mode = uap->shmflg & ACCESSPERMS;
	if (uap->key != IPC_PRIVATE) {
	again:
		segnum = shm_find_segment_by_key(uap->key);
		if (segnum >= 0) {
			error = shmget_existing(uap, mode, segnum, retval);
			if (error == EAGAIN)
				goto again;
			shmget_ret = error;
			goto shmget_out;
		}
		if ((uap->shmflg & IPC_CREAT) == 0) {
			shmget_ret = ENOENT;
			goto shmget_out;
		}
	}
	shmget_ret = shmget_allocate_segment(p, uap, mode, retval);
shmget_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return shmget_ret;
	/*NOTREACHED*/

}

/* XXX actually varargs. */
int
shmsys(struct proc *p, struct shmsys_args *uap, register_t *retval)
{

	/* The routine that we are dispatching already does this */

	if (uap->which >= sizeof(shmcalls)/sizeof(shmcalls[0]))
		return EINVAL;
	return ((*shmcalls[uap->which])(p, &uap->a2, retval));
}

/*
 * Return 0 on success, 1 on failure.
 */
int
shmfork(struct proc *p1, struct proc *p2)
{
	struct shmmap_state *shmmap_s;
	size_t size;
	int i;
	int shmfork_ret = 0;

	SYSV_SHM_SUBSYS_LOCK();

	if (!shm_inited) {
		shmfork_ret = 0;
		goto shmfork_out;
	}
		
	size = shminfo.shmseg * sizeof(struct shmmap_state);
	MALLOC(shmmap_s, struct shmmap_state *, size, M_SHM, M_WAITOK);
	if (shmmap_s != NULL) {
		bcopy((caddr_t)p1->vm_shm, (caddr_t)shmmap_s, size);
		p2->vm_shm = (caddr_t)shmmap_s;
		for (i = 0; i < shminfo.shmseg; i++, shmmap_s++)
			if (shmmap_s->shmid != -1)
				shmsegs[IPCID_TO_IX(shmmap_s->shmid)].shm_nattch++;
		shmfork_ret = 0;
		goto shmfork_out;
	}

	shmfork_ret = 1;	/* failed to copy to child - ENOMEM */
shmfork_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return shmfork_ret;
}

void
shmexit(struct proc *p)
{
	struct shmmap_state *shmmap_s;
	int i;

	shmmap_s = (struct shmmap_state *)p->vm_shm;

	SYSV_SHM_SUBSYS_LOCK();
	for (i = 0; i < shminfo.shmseg; i++, shmmap_s++)
		if (shmmap_s->shmid != -1)
			shm_delete_mapping(p, shmmap_s, 1);
	FREE((caddr_t)p->vm_shm, M_SHM);
	p->vm_shm = NULL;
	SYSV_SHM_SUBSYS_UNLOCK();
}

/*
 * shmexec() is like shmexit(), only it doesn't delete the mappings,
 * since the old address space has already been destroyed and the new
 * one instantiated.  Instead, it just does the housekeeping work we
 * need to do to keep the System V shared memory subsystem sane.
 */
__private_extern__ void
shmexec(struct proc *p)
{
	struct shmmap_state *shmmap_s;
	int i;

	shmmap_s = (struct shmmap_state *)p->vm_shm;
	SYSV_SHM_SUBSYS_LOCK();
	for (i = 0; i < shminfo.shmseg; i++, shmmap_s++)
		if (shmmap_s->shmid != -1)
			shm_delete_mapping(p, shmmap_s, 0);
	FREE((caddr_t)p->vm_shm, M_SHM);
	p->vm_shm = NULL;
	SYSV_SHM_SUBSYS_UNLOCK();
}

void
shminit(__unused void *dummy)
{
	int i;
	int s;

	if (!shm_inited) {
		/*
		 * we store internally 64 bit, since if we didn't, we would
		 * be unable to represent a segment size in excess of 32 bits
		 * with the (struct shmid_ds)->shm_segsz field; also, POSIX
		 * dictates this filed be a size_t, which is 64 bits when
		 * running 64 bit binaries.
		 */
		s = sizeof(struct user_shmid_ds) * shminfo.shmmni;

		MALLOC(shmsegs, struct user_shmid_ds *, s, M_SHM, M_WAITOK);
		if (shmsegs == NULL) {
			/* XXX fail safely: leave shared memory uninited */
			return;
		}
		for (i = 0; i < shminfo.shmmni; i++) {
			shmsegs[i].shm_perm.mode = SHMSEG_FREE;
			shmsegs[i].shm_perm.seq = 0;
		}
		shm_last_free = 0;
		shm_nused = 0;
		shm_committed = 0;
		shm_inited = 1;
	}
}
/* Initialize the mutex governing access to the SysV shm subsystem */
__private_extern__ void
sysv_shm_lock_init( void )
{

	sysv_shm_subsys_lck_grp_attr = lck_grp_attr_alloc_init();
	
	sysv_shm_subsys_lck_grp = lck_grp_alloc_init("sysv_shm_subsys_lock", sysv_shm_subsys_lck_grp_attr);
	
	sysv_shm_subsys_lck_attr = lck_attr_alloc_init();
	lck_mtx_init(&sysv_shm_subsys_mutex, sysv_shm_subsys_lck_grp, sysv_shm_subsys_lck_attr);
}

/* (struct sysctl_oid *oidp, void *arg1, int arg2, \
        struct sysctl_req *req) */
static int
sysctl_shminfo(__unused struct sysctl_oid *oidp, void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	int error = 0;
	int sysctl_shminfo_ret = 0;

	error = SYSCTL_OUT(req, arg1, sizeof(int64_t));
	if (error || req->newptr == USER_ADDR_NULL)
		return(error);

	SYSV_SHM_SUBSYS_LOCK();
	/* Set the values only if shared memory is not initialised */
	if (!shm_inited) {
		if ((error = SYSCTL_IN(req, arg1, sizeof(int64_t))) 
		    != 0) {
			sysctl_shminfo_ret = error;
			goto sysctl_shminfo_out;
		}

		if (arg1 == &shminfo.shmmax) {
			if (shminfo.shmmax & PAGE_MASK_64) {
				shminfo.shmmax = (int64_t)-1;
				sysctl_shminfo_ret = EINVAL;
				goto sysctl_shminfo_out;
			}
		}

		/* Initialize only when all values are set */
		if ((shminfo.shmmax != (int64_t)-1) &&
			(shminfo.shmmin != (int64_t)-1) &&	
			(shminfo.shmmni != (int64_t)-1) &&
			(shminfo.shmseg != (int64_t)-1) &&
			(shminfo.shmall != (int64_t)-1)) {
				shminit(NULL);
		}
	}
	sysctl_shminfo_ret = 0;
sysctl_shminfo_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return sysctl_shminfo_ret;
}

static int
IPCS_shm_sysctl(__unused struct sysctl_oid *oidp, __unused void *arg1,
	__unused int arg2, struct sysctl_req *req)
{
	int error;
	int cursor;
	union {
		struct IPCS_command u32;
		struct user_IPCS_command u64;
	} ipcs;
	struct shmid_ds shmid_ds32;	/* post conversion, 32 bit version */
	void *shmid_dsp;
	size_t ipcs_sz = sizeof(struct user_IPCS_command);
	size_t shmid_ds_sz = sizeof(struct user_shmid_ds);
	struct proc *p = current_proc();

	int ipcs__shminfo_ret = 0;

	SYSV_SHM_SUBSYS_LOCK();

	if (!shm_inited) {
		error = EINVAL;
		goto ipcs_shm_sysctl_out;
	}

	if (!IS_64BIT_PROCESS(p)) {
		ipcs_sz = sizeof(struct IPCS_command);
		shmid_ds_sz = sizeof(struct shmid_ds);
	}

	/* Copy in the command structure */
	if ((error = SYSCTL_IN(req, &ipcs, ipcs_sz)) != 0) {
		goto ipcs_shm_sysctl_out;
	}

	if (!IS_64BIT_PROCESS(p))	/* convert in place */
		ipcs.u64.ipcs_data = CAST_USER_ADDR_T(ipcs.u32.ipcs_data);

	/* Let us version this interface... */
	if (ipcs.u64.ipcs_magic != IPCS_MAGIC) {
		error = EINVAL;
		goto ipcs_shm_sysctl_out;
	}

	switch(ipcs.u64.ipcs_op) {
	case IPCS_SHM_CONF:	/* Obtain global configuration data */
		if (ipcs.u64.ipcs_datalen != sizeof(struct shminfo)) {
			if (ipcs.u64.ipcs_cursor != 0) { /* fwd. compat. */
				error = ENOMEM;
				break;
			}
			error = ERANGE;
			break;
		}
		error = copyout(&shminfo, ipcs.u64.ipcs_data, ipcs.u64.ipcs_datalen);
		break;

	case IPCS_SHM_ITER:	/* Iterate over existing segments */
		cursor = ipcs.u64.ipcs_cursor;
		if (cursor < 0 || cursor >= shminfo.shmmni) {
			error = ERANGE;
			break;
		}
		if (ipcs.u64.ipcs_datalen != (int)shmid_ds_sz) {
			error = ENOMEM;
			break;
		}
		for( ; cursor < shminfo.shmmni; cursor++) {
			if (shmsegs[cursor].shm_perm.mode & SHMSEG_ALLOCATED)
				break;
			continue;
		}
		if (cursor == shminfo.shmmni) {
			error = ENOENT;
			break;
		}

		shmid_dsp = &shmsegs[cursor];	/* default: 64 bit */

		/*
		 * If necessary, convert the 64 bit kernel segment
		 * descriptor to a 32 bit user one.
		 */
		if (!IS_64BIT_PROCESS(p)) {
			shmid_ds_64to32(shmid_dsp, &shmid_ds32);
			shmid_dsp = &shmid_ds32;
		}
		error = copyout(shmid_dsp, ipcs.u64.ipcs_data, ipcs.u64.ipcs_datalen);
		if (!error) {
			/* update cursor */
			ipcs.u64.ipcs_cursor = cursor + 1;

		if (!IS_64BIT_PROCESS(p))	/* convert in place */
			ipcs.u32.ipcs_data = CAST_DOWN(void *,ipcs.u64.ipcs_data);
			error = SYSCTL_OUT(req, &ipcs, ipcs_sz);
		}
		break;

	default:
		error = EINVAL;
		break;
	}
ipcs_shm_sysctl_out:
	SYSV_SHM_SUBSYS_UNLOCK();
	return(error);
}

SYSCTL_NODE(_kern, KERN_SYSV, sysv, CTLFLAG_RW, 0, "SYSV");

SYSCTL_PROC(_kern_sysv, KSYSV_SHMMAX, shmmax, CTLTYPE_QUAD | CTLFLAG_RW,
    &shminfo.shmmax, 0, &sysctl_shminfo ,"Q","shmmax");

SYSCTL_PROC(_kern_sysv, KSYSV_SHMMIN, shmmin, CTLTYPE_QUAD | CTLFLAG_RW,
    &shminfo.shmmin, 0, &sysctl_shminfo ,"Q","shmmin");

SYSCTL_PROC(_kern_sysv, KSYSV_SHMMNI, shmmni, CTLTYPE_QUAD | CTLFLAG_RW,
    &shminfo.shmmni, 0, &sysctl_shminfo ,"Q","shmmni");

SYSCTL_PROC(_kern_sysv, KSYSV_SHMSEG, shmseg, CTLTYPE_QUAD | CTLFLAG_RW,
    &shminfo.shmseg, 0, &sysctl_shminfo ,"Q","shmseg");

SYSCTL_PROC(_kern_sysv, KSYSV_SHMALL, shmall, CTLTYPE_QUAD | CTLFLAG_RW,
    &shminfo.shmall, 0, &sysctl_shminfo ,"Q","shmall");

SYSCTL_NODE(_kern_sysv, OID_AUTO, ipcs, CTLFLAG_RW, 0, "SYSVIPCS");

SYSCTL_PROC(_kern_sysv_ipcs, OID_AUTO, shm, CTLFLAG_RW|CTLFLAG_ANYBODY,
	0, 0, IPCS_shm_sysctl,
	"S,IPCS_shm_command",
	"ipcs shm command interface");
