/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc_internal.h>
#include <sys/sysctl.h>
#include <sys/signal.h>
#include <sys/signalvar.h>
#include <sys/codesign.h>

#include <sys/fcntl.h>
#include <sys/file.h>
#include <sys/file_internal.h>
#include <sys/kauth.h>
#include <sys/mount.h>
#include <sys/msg.h>
#include <sys/proc.h>
#include <sys/socketvar.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>

#include <sys/ubc.h>
#include <sys/ubc_internal.h>

#include <security/mac.h>
#include <security/mac_policy.h>
#include <security/mac_framework.h>

#include <mach/mach_types.h>
#include <mach/vm_map.h>
#include <mach/mach_vm.h>

#include <kern/kern_types.h>
#include <kern/task.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>


#include <kern/assert.h>

#include <pexpert/pexpert.h>

#include <mach/shared_region.h>

unsigned long cs_procs_killed = 0;
unsigned long cs_procs_invalidated = 0;

int cs_force_kill = 0;
int cs_force_hard = 0;
int cs_debug = 0;
#if SECURE_KERNEL
const int cs_enforcement_enable=1;
const int cs_library_val_enable=1;
#else
#if CONFIG_ENFORCE_SIGNED_CODE
int cs_enforcement_enable=1;
#else
int cs_enforcement_enable=0;
#endif /* CONFIG_ENFORCE_SIGNED_CODE */

#if CONFIG_ENFORCE_LIBRARY_VALIDATION
int cs_library_val_enable = 1;
#else
int cs_library_val_enable = 0;
#endif /* CONFIG_ENFORCE_LIBRARY_VALIDATION */

int cs_enforcement_panic=0;
#endif /* SECURE_KERNEL */
int cs_all_vnodes = 0;

static lck_grp_t *cs_lockgrp;
static lck_rw_t * SigPUPLock;

SYSCTL_INT(_vm, OID_AUTO, cs_force_kill, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_force_kill, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_force_hard, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_force_hard, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_debug, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_debug, 0, "");

SYSCTL_INT(_vm, OID_AUTO, cs_all_vnodes, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_all_vnodes, 0, "");

#if !SECURE_KERNEL
SYSCTL_INT(_vm, OID_AUTO, cs_enforcement, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_enforcement_enable, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_enforcement_panic, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_enforcement_panic, 0, "");
#endif

int panic_on_cs_killed = 0;
void
cs_init(void)
{
#if MACH_ASSERT && __x86_64__
	panic_on_cs_killed = 1;
#endif /* MACH_ASSERT && __x86_64__ */
	PE_parse_boot_argn("panic_on_cs_killed", &panic_on_cs_killed,
			   sizeof (panic_on_cs_killed));
#if !SECURE_KERNEL
	int disable_cs_enforcement = 0;
	PE_parse_boot_argn("cs_enforcement_disable", &disable_cs_enforcement, 
			   sizeof (disable_cs_enforcement));
	if (disable_cs_enforcement) {
		cs_enforcement_enable = 0;
	} else {
		int panic = 0;
		PE_parse_boot_argn("cs_enforcement_panic", &panic, sizeof(panic));
		cs_enforcement_panic = (panic != 0);
	}

	PE_parse_boot_argn("cs_debug", &cs_debug, sizeof (cs_debug));
#endif
	lck_grp_attr_t *attr = lck_grp_attr_alloc_init();
	cs_lockgrp = lck_grp_alloc_init("KERNCS", attr);
	SigPUPLock = lck_rw_alloc_init(cs_lockgrp, NULL);
}

int
cs_allow_invalid(struct proc *p)
{
#if MACH_ASSERT
	lck_mtx_assert(&p->p_mlock, LCK_MTX_ASSERT_NOTOWNED);
#endif
#if CONFIG_MACF && CONFIG_ENFORCE_SIGNED_CODE
	/* There needs to be a MAC policy to implement this hook, or else the
	 * kill bits will be cleared here every time. If we have 
	 * CONFIG_ENFORCE_SIGNED_CODE, we can assume there is a policy
	 * implementing the hook. 
	 */
	if( 0 != mac_proc_check_run_cs_invalid(p)) {
		if(cs_debug) printf("CODE SIGNING: cs_allow_invalid() "
				    "not allowed: pid %d\n", 
				    p->p_pid);
		return 0;
	}
	if(cs_debug) printf("CODE SIGNING: cs_allow_invalid() "
			    "allowed: pid %d\n", 
			    p->p_pid);
	proc_lock(p);
	p->p_csflags &= ~(CS_KILL | CS_HARD);
	proc_unlock(p);
	vm_map_switch_protect(get_task_map(p->task), FALSE);
#endif
	return (p->p_csflags & (CS_KILL | CS_HARD)) == 0;
}

int
cs_invalid_page(
	addr64_t vaddr)
{
	struct proc	*p;
	int		send_kill = 0, retval = 0, verbose = cs_debug;
	uint32_t	csflags;

	p = current_proc();

	if (verbose)
		printf("CODE SIGNING: cs_invalid_page(0x%llx): p=%d[%s]\n",
		    vaddr, p->p_pid, p->p_comm);

	proc_lock(p);

	/* XXX for testing */
	if (cs_force_kill)
		p->p_csflags |= CS_KILL;
	if (cs_force_hard)
		p->p_csflags |= CS_HARD;

	/* CS_KILL triggers a kill signal, and no you can't have the page. Nothing else. */
	if (p->p_csflags & CS_KILL) {
		if (panic_on_cs_killed &&
		    vaddr >= SHARED_REGION_BASE &&
		    vaddr < SHARED_REGION_BASE + SHARED_REGION_SIZE) {
			panic("<rdar://14393620> cs_invalid_page(va=0x%llx): killing p=%p\n", (uint64_t) vaddr, p);
		}
		p->p_csflags |= CS_KILLED;
		cs_procs_killed++;
		send_kill = 1;
		retval = 1;
	}
	
#if __x86_64__
	if (panic_on_cs_killed &&
	    vaddr >= SHARED_REGION_BASE &&
	    vaddr < SHARED_REGION_BASE + SHARED_REGION_SIZE) {
		panic("<rdar://14393620> cs_invalid_page(va=0x%llx): cs error p=%p\n", (uint64_t) vaddr, p);
	}
#endif /* __x86_64__ */

	/* CS_HARD means fail the mapping operation so the process stays valid. */
	if (p->p_csflags & CS_HARD) {
		retval = 1;
	} else {
		if (p->p_csflags & CS_VALID) {
			p->p_csflags &= ~CS_VALID;
			cs_procs_invalidated++;
			verbose = 1;
		}
	}
	csflags = p->p_csflags;
	proc_unlock(p);

	if (verbose)
		printf("CODE SIGNING: cs_invalid_page(0x%llx): "
		       "p=%d[%s] final status 0x%x, %s page%s\n",
		       vaddr, p->p_pid, p->p_comm, p->p_csflags,
		       retval ? "denying" : "allowing (remove VALID)",
		       send_kill ? " sending SIGKILL" : "");

	if (send_kill)
		threadsignal(current_thread(), SIGKILL, EXC_BAD_ACCESS);


	return retval;
}

/*
 * Assumes p (if passed in) is locked with proc_lock().
 */

int
cs_enforcement(struct proc *p)
{

	if (cs_enforcement_enable)
		return 1;
	
	if (p == NULL)
		p = current_proc();

	if (p != NULL && (p->p_csflags & CS_ENFORCEMENT))
		return 1;

	return 0;
}

static struct {
	struct cscsr_functions *funcs;
	vm_map_offset_t csr_map_base;
	vm_map_size_t csr_map_size;
	int inuse;
	int disabled;
} csr_state;

SYSCTL_INT(_vm, OID_AUTO, sigpup_disable, CTLFLAG_RW | CTLFLAG_LOCKED, &csr_state.disabled, 0, "");

static int
vnsize(vfs_context_t vfs, vnode_t vp, uint64_t *size)
{
	struct vnode_attr va;
	int error;

	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_data_size);

	error = vnode_getattr(vp, &va, vfs);
	if (error)
		return error;
	*size = va.va_data_size;
	return 0;
}

int
sigpup_install(user_addr_t argsp)
{
	struct sigpup_install_table args;
	memory_object_control_t control;
	kern_return_t result;
	vfs_context_t vfs = NULL;
	struct vnode_attr va;
	vnode_t vp = NULL;
        char *buf = NULL;
	uint64_t size;
	size_t len = 0;
	int error = 0;
	
	if (!cs_enforcement_enable || csr_state.funcs == NULL)
		return ENOTSUP;

	lck_rw_lock_exclusive(SigPUPLock);

	if (kauth_cred_issuser(kauth_cred_get()) == 0) {
		error = EPERM;
		goto cleanup;
	}

	if (cs_debug > 10)
		printf("sigpup install\n");

	if (csr_state.csr_map_base != 0 || csr_state.inuse) {
		error = EPERM;
		goto cleanup;
	}

	if (USER_ADDR_NULL == argsp) {
		error = EINVAL;
		goto cleanup;
	}
	if ((error = copyin(argsp, &args, sizeof(args))) != 0)
		goto cleanup;

	if (cs_debug > 10)
		printf("sigpup install with args\n");

	MALLOC(buf, char *, MAXPATHLEN, M_TEMP, M_WAITOK);
	if (buf == NULL) {
		error = ENOMEM;
		goto cleanup;
	}
	if ((error = copyinstr((user_addr_t)args.path, buf, MAXPATHLEN, &len)) != 0)
		goto cleanup;

	if ((vfs = vfs_context_create(NULL)) == NULL) {
		error = ENOMEM;
		goto cleanup;
	}

	if ((error = vnode_lookup(buf, VNODE_LOOKUP_NOFOLLOW, &vp, vfs)) != 0)
		goto cleanup;

	if (cs_debug > 10)
		printf("sigpup found file: %s\n", buf);

	/* make sure vnode is on the process's root volume */
	if (rootvnode->v_mount != vp->v_mount) {
		if (cs_debug) printf("sigpup csr no on root volume\n");
		error = EPERM;
		goto cleanup;
	}

	/* make sure vnode is owned by "root" */
	VATTR_INIT(&va);
	VATTR_WANTED(&va, va_uid);
	error = vnode_getattr(vp, &va, vfs);
	if (error)
		goto cleanup;

	if (va.va_uid != 0) {
		if (cs_debug) printf("sigpup: csr file not owned by root\n");
		error = EPERM;
		goto cleanup;
	}

	error = vnsize(vfs, vp, &size);
	if (error)
		goto cleanup;

	control = ubc_getobject(vp, 0);
	if (control == MEMORY_OBJECT_CONTROL_NULL) {
		error = EINVAL;
		goto cleanup;
	}

	csr_state.csr_map_size = mach_vm_round_page(size);

	if (cs_debug > 10)
		printf("mmap!\n");

	result = vm_map_enter_mem_object_control(kernel_map,
						 &csr_state.csr_map_base,
						 csr_state.csr_map_size,
						 0, VM_FLAGS_ANYWHERE,
						 control, 0 /* file offset */,
						 0 /* cow */,
						 VM_PROT_READ,
						 VM_PROT_READ, 
						 VM_INHERIT_DEFAULT);
	if (result != KERN_SUCCESS) {
		error = EINVAL;
		goto cleanup;
	}

	error = csr_state.funcs->csr_validate_header((const uint8_t *)csr_state.csr_map_base,
	    csr_state.csr_map_size);
	if (error) {
		if (cs_debug > 10)
			printf("sigpup header invalid, dropping mapping");
		sigpup_drop();
		goto cleanup;
	}

	if (cs_debug > 10)
		printf("table loaded %ld bytes\n", (long)csr_state.csr_map_size);

cleanup:
	lck_rw_unlock_exclusive(SigPUPLock);

        if (buf)
                FREE(buf, M_TEMP);
	if (vp)
		(void)vnode_put(vp);
	if (vfs)
		(void)vfs_context_rele(vfs);
        
	if (error)
		printf("sigpup: load failed with error: %d\n", error);


	return error;
}

int
sigpup_drop(void)
{

	if (kauth_cred_issuser(kauth_cred_get()) == 0)
		return EPERM;

	lck_rw_lock_exclusive(SigPUPLock);

	if (csr_state.csr_map_base == 0 || csr_state.inuse) {
		printf("failed to unload the sigpup database\n");
		lck_rw_unlock_exclusive(SigPUPLock);
		return EINVAL;
	}

	if (cs_debug > 10)
		printf("sigpup: unloading\n");

	(void)mach_vm_deallocate(kernel_map,
	    csr_state.csr_map_base, csr_state.csr_map_size);

	csr_state.csr_map_base = 0;
	csr_state.csr_map_size = 0;

	lck_rw_unlock_exclusive(SigPUPLock);

	return 0;
}

void	sigpup_attach_vnode(vnode_t); /* XXX */

void
sigpup_attach_vnode(vnode_t vp)
{
	const void *csblob;
	size_t cslen;

	if (!cs_enforcement_enable || csr_state.funcs == NULL || csr_state.csr_map_base == 0 || csr_state.disabled)
		return;

	/* if the file is not on the root volumes or already been check, skip */
	if (vp->v_mount != rootvnode->v_mount || (vp->v_flag & VNOCS))
		return;

	csblob = csr_state.funcs->csr_find_file_codedirectory(vp, (const uint8_t *)csr_state.csr_map_base,
	    (size_t)csr_state.csr_map_size, &cslen);
	if (csblob) {
		ubc_cs_sigpup_add(vp, (vm_address_t)csblob, (vm_size_t)cslen);
		csr_state.inuse = 1;
	}
	vp->v_flag |= VNOCS;
}

void
cs_register_cscsr(struct cscsr_functions *funcs)
{
	if (csr_state.funcs || funcs->csr_version < CSCSR_VERSION)
		return;
	csr_state.funcs = funcs;
}

/*
 * Library validation functions 
 */
int
cs_require_lv(struct proc *p)
{
	
	if (cs_library_val_enable)
		return 1;

	if (p == NULL)
		p = current_proc();
	
	if (p != NULL && (p->p_csflags & CS_REQUIRE_LV))
		return 1;
	
	return 0;
}

/*
 * Function: csblob_get_teamid
 *
 * Description: This function returns a pointer to the team id
 		stored within the codedirectory of the csblob.
		If the codedirectory predates team-ids, it returns
		NULL.
		This does not copy the name but returns a pointer to
		it within the CD. Subsequently, the CD must be 
		available when this is used.
*/
const char *
csblob_get_teamid(struct cs_blob *csblob)
{
	const CS_CodeDirectory *cd;

	if ((cd = (const CS_CodeDirectory *)cs_find_blob(
						csblob, CSSLOT_CODEDIRECTORY, CSMAGIC_CODEDIRECTORY)) == NULL)
		return NULL;
	
	if (ntohl(cd->version) < CS_SUPPORTSTEAMID)
		return NULL;

	if (ntohl(cd->teamOffset) == 0)
		return NULL;
	
	const char *name = ((const char *)cd) + ntohl(cd->teamOffset);
	if (cs_debug > 1)
		printf("found team-id %s in cdblob\n", name);

	return name;
}

/*
 * Function: csproc_get_blob
 *
 * Description: This function returns the cs_blob
 *		for the process p
 */
static struct cs_blob *
csproc_get_blob(struct proc *p)
{
	if (NULL == p)
		return NULL;

	if (NULL == p->p_textvp)
		return NULL;

	return ubc_cs_blob_get(p->p_textvp, -1, p->p_textoff);
}

/*
 * Function: csproc_get_teamid 
 *
 * Description: This function returns a pointer to the
 *		team id of the process p
*/
const char *
csproc_get_teamid(struct proc *p)
{
	struct cs_blob *csblob;

	csblob = csproc_get_blob(p);

	return (csblob == NULL) ? NULL : csblob->csb_teamid;
}

/*
 * Function: csvnode_get_teamid 
 *
 * Description: This function returns a pointer to the
 *		team id of the binary at the given offset in vnode vp
*/
const char *
csvnode_get_teamid(struct vnode *vp, off_t offset)
{
	struct cs_blob *csblob;

	if (vp == NULL)
		return NULL;

	csblob = ubc_cs_blob_get(vp, -1, offset);

	return (csblob == NULL) ? NULL : csblob->csb_teamid;
}

/*
 * Function: csproc_get_platform_binary
 *
 * Description: This function returns the value
 *		of the platform_binary field for proc p
 */
int
csproc_get_platform_binary(struct proc *p)
{
	struct cs_blob *csblob;

	csblob = csproc_get_blob(p);

	/* If there is no csblob this returns 0 because
	   it is true that it is not a platform binary */
	return (csblob == NULL) ? 0 : csblob->csb_platform_binary;
}

/*
 * Function: csfg_get_platform_binary
 *
 * Description: This function returns the 
 *		platform binary field for the 
 * 		fileglob fg
 */
int 
csfg_get_platform_binary(struct fileglob *fg)
{
	int platform_binary = 0;
	struct ubc_info *uip;
	vnode_t vp;

	if (FILEGLOB_DTYPE(fg) != DTYPE_VNODE)
		return 0;
	
	vp = (struct vnode *)fg->fg_data;
	if (vp == NULL)
		return 0;

	vnode_lock(vp);
	if (!UBCINFOEXISTS(vp))
		goto out;
	
	uip = vp->v_ubcinfo;
	if (uip == NULL)
		goto out;
	
	if (uip->cs_blobs == NULL)
		goto out;

	/* It is OK to extract the teamid from the first blob
	   because all blobs of a vnode must have the same teamid */	
	platform_binary = uip->cs_blobs->csb_platform_binary;
out:
	vnode_unlock(vp);

	return platform_binary;
}

/*
 * Function: csfg_get_teamid
 *
 * Description: This returns a pointer to
 * 		the teamid for the fileglob fg
 */
const char *
csfg_get_teamid(struct fileglob *fg)
{
	struct ubc_info *uip;
	const char *str = NULL;
	vnode_t vp;

	if (FILEGLOB_DTYPE(fg) != DTYPE_VNODE)
		return NULL;
	
	vp = (struct vnode *)fg->fg_data;
	if (vp == NULL)
		return NULL;

	vnode_lock(vp);
	if (!UBCINFOEXISTS(vp))
		goto out;
	
	uip = vp->v_ubcinfo;
	if (uip == NULL)
		goto out;
	
	if (uip->cs_blobs == NULL)
		goto out;

	/* It is OK to extract the teamid from the first blob
	   because all blobs of a vnode must have the same teamid */	
	str = uip->cs_blobs->csb_teamid;
out:
	vnode_unlock(vp);

	return str;
}

uint32_t
cs_entitlement_flags(struct proc *p)
{
	return (p->p_csflags & CS_ENTITLEMENT_FLAGS);
}

/*
 * Function: csfg_get_path
 *
 * Description: This populates the buffer passed in
 *		with the path of the vnode
 *		When calling this, the fileglob
 *		cannot go away. The caller must have a
 *		a reference on the fileglob or fileproc
 */
int
csfg_get_path(struct fileglob *fg, char *path, int *len)
{
	vnode_t vp = NULL;

	if (FILEGLOB_DTYPE(fg) != DTYPE_VNODE)
		return -1;
	
	vp = (struct vnode *)fg->fg_data;

	/* vn_getpath returns 0 for success,
	   or an error code */
	return vn_getpath(vp, path, len);
}
