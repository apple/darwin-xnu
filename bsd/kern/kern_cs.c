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

#include <libkern/section_keywords.h>

unsigned long cs_procs_killed = 0;
unsigned long cs_procs_invalidated = 0;

int cs_force_kill = 0;
int cs_force_hard = 0;
int cs_debug = 0;
#if SECURE_KERNEL
const int cs_enforcement_enable = 1;
const int cs_library_val_enable = 1;
#else /* !SECURE_KERNEL */
int cs_enforcement_panic=0;

#if CONFIG_ENFORCE_SIGNED_CODE
#define DEFAULT_CS_ENFORCEMENT_ENABLE 1
#else
#define DEFAULT_CS_ENFORCEMENT_ENABLE 0
#endif
SECURITY_READ_ONLY_LATE(int) cs_enforcement_enable = DEFAULT_CS_ENFORCEMENT_ENABLE;

#if CONFIG_ENFORCE_LIBRARY_VALIDATION
#define DEFAULT_CS_LIBRARY_VA_ENABLE 1
#else
#define DEFAULT_CS_LIBRARY_VA_ENABLE 0
#endif
SECURITY_READ_ONLY_LATE(int) cs_library_val_enable = DEFAULT_CS_LIBRARY_VA_ENABLE;

#endif /* !SECURE_KERNEL */
int cs_all_vnodes = 0;

static lck_grp_t *cs_lockgrp;

SYSCTL_INT(_vm, OID_AUTO, cs_force_kill, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_force_kill, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_force_hard, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_force_hard, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_debug, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_debug, 0, "");

SYSCTL_INT(_vm, OID_AUTO, cs_all_vnodes, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_all_vnodes, 0, "");

#if !SECURE_KERNEL
SYSCTL_INT(_vm, OID_AUTO, cs_enforcement, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_enforcement_enable, 0, "");
SYSCTL_INT(_vm, OID_AUTO, cs_enforcement_panic, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_enforcement_panic, 0, "");

#if !CONFIG_ENFORCE_LIBRARY_VALIDATION
SYSCTL_INT(_vm, OID_AUTO, cs_library_validation, CTLFLAG_RW | CTLFLAG_LOCKED, &cs_library_val_enable, 0, "");
#endif
#endif /* !SECURE_KERNEL */

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

#if !CONFIG_ENFORCE_LIBRARY_VALIDATION
	PE_parse_boot_argn("cs_library_val_enable", &cs_library_val_enable,
			   sizeof (cs_library_val_enable));
#endif
#endif /* !SECURE_KERNEL */

	lck_grp_attr_t *attr = lck_grp_attr_alloc_init();
	cs_lockgrp = lck_grp_alloc_init("KERNCS", attr);
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
 * Function: csblob_get_platform_binary
 *
 * Description: This function returns true if the binary is
 *		in the trust cache.
*/

int
csblob_get_platform_binary(struct cs_blob *blob)
{
    if (blob && blob->csb_platform_binary)
	return 1;
    return 0;
}

/*
 * Function: csblob_get_flags
 *
 * Description: This function returns the flags for a given blob
*/

unsigned int
csblob_get_flags(struct cs_blob *blob)
{
	if (blob)
		return blob->csb_flags;
	return 0;
}

/*
 * Function: csproc_get_blob
 *
 * Description: This function returns the cs_blob
 *		for the process p
 */
struct cs_blob *
csproc_get_blob(struct proc *p)
{
	if (NULL == p)
		return NULL;

	if (NULL == p->p_textvp)
		return NULL;

	return ubc_cs_blob_get(p->p_textvp, -1, p->p_textoff);
}

/*
 * Function: csproc_get_blob
 *
 * Description: This function returns the cs_blob
 *		for the vnode vp
 */
struct cs_blob *
csvnode_get_blob(struct vnode *vp, off_t offset)
{
	return ubc_cs_blob_get(vp, -1, offset);
}

/*
 * Function: csblob_get_teamid
 *
 * Description: This function returns a pointer to the
 *		team id of csblob
*/
const char *
csblob_get_teamid(struct cs_blob *csblob)
{
	return csblob->csb_teamid;
}

/*
 * Function: csblob_get_identity
 *
 * Description: This function returns a pointer to the
 *		identity string
 */
const char *
csblob_get_identity(struct cs_blob *csblob)
{
	const CS_CodeDirectory *cd;

	cd = (const CS_CodeDirectory *)csblob_find_blob(csblob, CSSLOT_CODEDIRECTORY, CSMAGIC_CODEDIRECTORY);
	if (cd == NULL)
		return NULL;

	if (cd->identOffset == 0)
		return NULL;

	return ((const char *)cd) + ntohl(cd->identOffset);
}

/*
 * Function: csblob_get_cdhash
 *
 * Description: This function returns a pointer to the
 *		cdhash of csblob (20 byte array)
 */
const uint8_t *
csblob_get_cdhash(struct cs_blob *csblob)
{
	return csblob->csb_cdhash;
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
	if (csblob == NULL)
	    return NULL;

	return csblob_get_teamid(csblob);
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
	if (csblob == NULL)
	    return NULL;

	return csblob_get_teamid(csblob);
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

int
csproc_get_platform_path(struct proc *p)
{
	struct cs_blob *csblob = csproc_get_blob(p);

	return (csblob == NULL) ? 0 : csblob->csb_platform_path;
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

uint8_t *
csfg_get_cdhash(struct fileglob *fg, uint64_t offset, size_t *cdhash_size)
{
	vnode_t vp;

	if (FILEGLOB_DTYPE(fg) != DTYPE_VNODE)
		return NULL;

	vp = (struct vnode *)fg->fg_data;
	if (vp == NULL)
		return NULL;

	struct cs_blob *csblob = NULL;
	if ((csblob = ubc_cs_blob_get(vp, -1, offset)) == NULL) 
		return NULL;

	if (cdhash_size)
		*cdhash_size = CS_CDHASH_LEN;

	return csblob->csb_cdhash;
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

int
cs_restricted(struct proc *p)
{
	return (p->p_csflags & CS_RESTRICT) ? 1 : 0;
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

/* Retrieve the entitlements blob for a process.
 * Returns:
 *   EINVAL	no text vnode associated with the process
 *   EBADEXEC   invalid code signing data
 *   0		no error occurred
 *
 * On success, out_start and out_length will point to the
 * entitlements blob if found; or will be set to NULL/zero
 * if there were no entitlements.
 */

int
cs_entitlements_blob_get(proc_t p, void **out_start, size_t *out_length)
{
	struct cs_blob *csblob;

	*out_start = NULL;
	*out_length = 0;

	if (NULL == p->p_textvp)
		return EINVAL;

	if ((csblob = ubc_cs_blob_get(p->p_textvp, -1, p->p_textoff)) == NULL)
		return 0;

	return csblob_get_entitlements(csblob, out_start, out_length);
}

/* Retrieve the codesign identity for a process.
 * Returns:
 *   NULL	an error occured
 *   string	the cs_identity
 */

const char *
cs_identity_get(proc_t p)
{
	struct cs_blob *csblob;

	if (NULL == p->p_textvp)
		return NULL;

	if ((csblob = ubc_cs_blob_get(p->p_textvp, -1, p->p_textoff)) == NULL)
		return NULL;

	return csblob_get_identity(csblob);
}


/* Retrieve the codesign blob for a process.
 * Returns:
 *   EINVAL	no text vnode associated with the process
 *   0		no error occurred
 *
 * On success, out_start and out_length will point to the
 * cms blob if found; or will be set to NULL/zero
 * if there were no blob.
 */

int
cs_blob_get(proc_t p, void **out_start, size_t *out_length)
{
	struct cs_blob *csblob;

	*out_start = NULL;
	*out_length = 0;

	if (NULL == p->p_textvp)
		return EINVAL;

	if ((csblob = ubc_cs_blob_get(p->p_textvp, -1, p->p_textoff)) == NULL)
		return 0;

	*out_start = (void *)csblob->csb_mem_kaddr;
	*out_length = csblob->csb_mem_size;

	return 0;
}

/*
 * return cshash of a process, cdhash is of size CS_CDHASH_LEN
 */

uint8_t *
cs_get_cdhash(struct proc *p)
{
	struct cs_blob *csblob;

	if (NULL == p->p_textvp)
		return NULL;

	if ((csblob = ubc_cs_blob_get(p->p_textvp, -1, p->p_textoff)) == NULL)
		return NULL;

	return csblob->csb_cdhash;
}
