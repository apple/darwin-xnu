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

#include <sys/kasl.h>
#include <sys/syslog.h>

#include <kern/assert.h>

#include <pexpert/pexpert.h>

unsigned long cs_procs_killed = 0;
unsigned long cs_procs_invalidated = 0;

int cs_force_kill = 0;
int cs_force_hard = 0;
int cs_debug = 0;
#if SECURE_KERNEL
const int cs_enforcement_enable=1;
#else
#if CONFIG_ENFORCE_SIGNED_CODE
int cs_enforcement_enable=1;
#else
int cs_enforcement_enable=0;
#endif
int cs_enforcement_panic=0;
#endif
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

void
cs_init(void)
{
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

	/*
	 * XXX revisit locking when proc is no longer protected
	 * by the kernel funnel...
	 */

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
		p->p_csflags |= CS_KILLED;
		cs_procs_killed++;
		send_kill = 1;
		retval = 1;
	}
	
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

	if (verbose) {
		char pid_str[10];
		snprintf(pid_str, sizeof(pid_str), "%d", p->p_pid);
		kern_asl_msg(LOG_NOTICE, "messagetracer",
			5,
			"com.apple.message.domain", "com.apple.kernel.cs.invalidate",
			"com.apple.message.signature", send_kill ? "kill" : retval ? "deny" : "invalidate",
			"com.apple.message.signature4", pid_str,
			"com.apple.message.signature3", p->p_comm,
			"com.apple.message.summarize", "YES",
			NULL
		);
		printf("CODE SIGNING: cs_invalid_page(0x%llx): "
		       "p=%d[%s] final status 0x%x, %sing page%s\n",
		       vaddr, p->p_pid, p->p_comm, p->p_csflags,
		       retval ? "deny" : "allow (remove VALID)",
		       send_kill ? " sending SIGKILL" : "");
	}

	if (send_kill)
		psignal(p, SIGKILL);


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
