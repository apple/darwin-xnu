/*
 * Copyright (c) 2007-2016 Apple Inc. All rights reserved.
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
/*-
 * Copyright (c) 1999, 2000, 2001, 2002 Robert N. M. Watson
 * Copyright (c) 2001 Ilmar S. Habibulin
 * Copyright (c) 2001, 2002, 2003, 2004 Networks Associates Technology, Inc.
 * Copyright (c) 2005 SPARTA, Inc.
 *
 * This software was developed by Robert Watson and Ilmar Habibulin for the
 * TrustedBSD Project.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 */

#include <kern/kalloc.h>
#include <libkern/OSAtomic.h>

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/kauth.h>

#include <sys/file_internal.h>
#include <sys/imgact.h>
#include <sys/namei.h>
#include <sys/mount_internal.h>
#include <sys/pipe.h>
#include <sys/posix_sem.h>
#include <sys/posix_shm.h>
#include <sys/reason.h>
#include <sys/uio_internal.h>
#include <sys/vnode_internal.h>
#include <sys/kdebug.h>


#include <miscfs/devfs/devfsdefs.h>
#include <miscfs/devfs/fdesc.h>

#include <security/mac_internal.h>

/* convert {R,W,X}_OK values to V{READ,WRITE,EXEC} */
#define ACCESS_MODE_TO_VNODE_MASK(m)    (m << 6)


/*
 * Optional tracing of policy operations. Define VFS_TRACE_POLICY_OPS to trace the operations.
 *
 * Along with DBG_FSYSTEM and DBG_VFS, dcode in the macros below is used to construct
 * KDBG_EVENTID(DBG_FSYSTEM, DBG_VFS, dcode) global event id, see bsd/sys/kdebug.h.
 * Note that dcode is multiplied by 4 and ORed as part of the construction. See bsd/kern/trace_codes
 * for list of system-wide {global event id, name} pairs. Currently DBG_VFS event ids are in range
 * [0x3130000, 0x3130170].
 */

//#define VFS_TRACE_POLICY_OPS

#ifdef VFS_TRACE_POLICY_OPS
#define DBG_VFS_CODE(dcode)                     FSDBG_CODE(DBG_VFS, dcode)
#define VFS_KERNEL_DEBUG_START0(dcode)          KERNEL_DEBUG_CONSTANT(DBG_VFS_CODE(dcode) | DBG_FUNC_START, 0, 0, 0, 0, 0)
#define VFS_KERNEL_DEBUG_END0(dcode)            KERNEL_DEBUG_CONSTANT(DBG_VFS_CODE(dcode) | DBG_FUNC_END, 0, 0, 0, 0, 0)
#define VFS_KERNEL_DEBUG_START1(dcode, darg)    KERNEL_DEBUG_CONSTANT(DBG_VFS_CODE(dcode) | DBG_FUNC_START, darg, 0, 0, 0, 0)
#define VFS_KERNEL_DEBUG_END1(dcode, darg)      KERNEL_DEBUG_CONSTANT(DBG_VFS_CODE(dcode) | DBG_FUNC_END, darg, 0, 0, 0, 0)
#else
#define VFS_KERNEL_DEBUG_START0(dcode)          do {} while (0)
#define VFS_KERNEL_DEBUG_END0(dcode)            do {} while (0)
#define VFS_KERNEL_DEBUG_START1(dcode, darg)    do {} while (0)
#define VFS_KERNEL_DEBUG_END1(dcode, darg)      do {} while (0)
#endif

static struct label *
mac_devfsdirent_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL) {
		return NULL;
	}
	VFS_KERNEL_DEBUG_START0(0);
	MAC_PERFORM(devfs_label_init, label);
	VFS_KERNEL_DEBUG_END0(0);
	return label;
}

void
mac_devfs_label_init(struct devnode *de)
{
	de->dn_label = mac_devfsdirent_label_alloc();
}

static struct label *
mac_mount_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL) {
		return NULL;
	}
	VFS_KERNEL_DEBUG_START0(1);
	MAC_PERFORM(mount_label_init, label);
	VFS_KERNEL_DEBUG_END0(1);
	return label;
}

void
mac_mount_label_init(struct mount *mp)
{
	mp->mnt_mntlabel = mac_mount_label_alloc();
}

struct label *
mac_vnode_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL) {
		return NULL;
	}
	VFS_KERNEL_DEBUG_START0(2);
	MAC_PERFORM(vnode_label_init, label);
	VFS_KERNEL_DEBUG_END0(2);
	OSIncrementAtomic(&mac_vnode_label_count);
	return label;
}

void
mac_vnode_label_init(vnode_t vp)
{
	vp->v_label = mac_vnode_label_alloc();
}

int
mac_vnode_label_init_needed(vnode_t vp)
{
#if CONFIG_MACF_LAZY_VNODE_LABELS
	(void)vp;
	return false;
#else
	return mac_label_vnodes != 0 && vp->v_label == NULL;
#endif
}

struct label *
mac_vnode_label_allocate(vnode_t vp)
{
	if (mac_vnode_label_init_needed(vp)) {
		vp->v_label = mac_vnode_label_alloc();
	}
	return vp->v_label;
}

/*
 * vnode labels are allocated at the same time as vnodes, but vnodes are never
 * freed.  Instead, we want to remove any sensitive information before putting
 * them on the free list for reuse.
 */
void
mac_vnode_label_recycle(vnode_t vp)
{
	MAC_PERFORM(vnode_label_recycle, vp->v_label);
#if CONFIG_MACF_LAZY_VNODE_LABELS
	if (vp->v_label) {
		mac_vnode_label_destroy(vp);
		vp->v_label = NULL;
		vp->v_lflag &= ~VL_LABELED;
	}
#endif
}

static void
mac_devfs_label_free(struct label *label)
{
	VFS_KERNEL_DEBUG_START1(3, label);
	MAC_PERFORM(devfs_label_destroy, label);
	VFS_KERNEL_DEBUG_END1(3, label);
	mac_labelzone_free(label);
}

void
mac_devfs_label_destroy(struct devnode *de)
{
	if (de->dn_label != NULL) {
		mac_devfs_label_free(de->dn_label);
		de->dn_label = NULL;
	}
}

static void
mac_mount_label_free(struct label *label)
{
	VFS_KERNEL_DEBUG_START1(4, label);
	MAC_PERFORM(mount_label_destroy, label);
	VFS_KERNEL_DEBUG_END1(4, label);
	mac_labelzone_free(label);
}

void
mac_mount_label_destroy(struct mount *mp)
{
	if (mp->mnt_mntlabel != NULL) {
		mac_mount_label_free(mp->mnt_mntlabel);
		mp->mnt_mntlabel = NULL;
	}
}

void
mac_vnode_label_free(struct label *label)
{
	if (label != NULL) {
		VFS_KERNEL_DEBUG_START1(5, label);
		MAC_PERFORM(vnode_label_destroy, label);
		VFS_KERNEL_DEBUG_END1(5, label);
		mac_labelzone_free(label);
		OSDecrementAtomic(&mac_vnode_label_count);
	}
}

void
mac_vnode_label_destroy(struct vnode *vp)
{
	if (vp->v_label != NULL) {
		mac_vnode_label_free(vp->v_label);
		vp->v_label = NULL;
	}
}

void
mac_vnode_label_copy(struct label *src, struct label *dest)
{
	VFS_KERNEL_DEBUG_START1(6, src);
	if (src == NULL) {
		MAC_PERFORM(vnode_label_init, dest);
	} else {
		MAC_PERFORM(vnode_label_copy, src, dest);
	}
	VFS_KERNEL_DEBUG_END1(6, src);
}

int
mac_vnode_label_externalize_audit(struct vnode *vp, struct mac *mac)
{
	int error;

	/* It is assumed that any necessary vnode locking is done on entry */
	error = MAC_EXTERNALIZE_AUDIT(vnode, vp->v_label,
	    mac->m_string, mac->m_buflen);

	return error;
}

int
mac_vnode_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen, int flags __unused)
{
	int error;

	error = MAC_EXTERNALIZE(vnode, label, elements, outbuf, outbuflen);

	return error;
}

int
mac_vnode_label_internalize(struct label *label, char *string)
{
	int error;

	error = MAC_INTERNALIZE(vnode, label, string);

	return error;
}

int
mac_mount_label_internalize(struct label *label, char *string)
{
	int error;

	error = MAC_INTERNALIZE(mount, label, string);

	return error;
}

int
mac_mount_label_externalize(struct label *label, char *elements,
    char *outbuf, size_t outbuflen)
{
	int error;

	error = MAC_EXTERNALIZE(mount, label, elements, outbuf, outbuflen);

	return error;
}

void
mac_devfs_label_copy(struct label *src, struct label *dest)
{
#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_device_enforce) {
		return;
	}
#endif

	VFS_KERNEL_DEBUG_START1(7, src);
	MAC_PERFORM(devfs_label_copy, src, dest);
	VFS_KERNEL_DEBUG_END1(7, src);
}

void
mac_devfs_label_update(struct mount *mp, struct devnode *de,
    struct vnode *vp)
{
#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_device_enforce) {
		return;
	}
#endif

	VFS_KERNEL_DEBUG_START1(8, vp);
	MAC_PERFORM(devfs_label_update, mp, de, de->dn_label, vp,
	    vp->v_label);
	VFS_KERNEL_DEBUG_END1(8, vp);
}

int
mac_vnode_label_associate(struct mount *mp, struct vnode *vp, vfs_context_t ctx)
{
	struct devnode *dnp;
	struct fdescnode *fnp;
	int error = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return error;
	}
#endif

	/* XXX: should not inspect v_tag in kernel! */
	switch (vp->v_tag) {
	case VT_DEVFS:
		dnp = VTODN(vp);
		mac_vnode_label_associate_devfs(mp, dnp, vp);
		break;
	case VT_FDESC:
		fnp = VTOFDESC(vp);
		error = mac_vnode_label_associate_fdesc(mp, fnp, vp, ctx);
		break;
	default:
		error = mac_vnode_label_associate_extattr(mp, vp);
		break;
	}

	return error;
}

void
mac_vnode_label_associate_devfs(struct mount *mp, struct devnode *de,
    struct vnode *vp)
{
#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_device_enforce) {
		return;
	}
#endif

	VFS_KERNEL_DEBUG_START1(9, vp);
	MAC_PERFORM(vnode_label_associate_devfs,
	    mp, mp ? mp->mnt_mntlabel : NULL,
	    de, de->dn_label,
	    vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(9, vp);
}

int
mac_vnode_label_associate_extattr(struct mount *mp, struct vnode *vp)
{
	int error;

	VFS_KERNEL_DEBUG_START1(10, vp);
	MAC_CHECK(vnode_label_associate_extattr, mp, mp->mnt_mntlabel, vp,
	    vp->v_label);
	VFS_KERNEL_DEBUG_END1(10, vp);

	return error;
}

void
mac_vnode_label_associate_singlelabel(struct mount *mp, struct vnode *vp)
{
#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	if (!mac_label_vnodes) {
		return;
	}

	VFS_KERNEL_DEBUG_START1(11, vp);
	MAC_PERFORM(vnode_label_associate_singlelabel, mp,
	    mp ? mp->mnt_mntlabel : NULL, vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(11, vp);
}

int
mac_vnode_notify_create(vfs_context_t ctx, struct mount *mp,
    struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(12, vp);
	MAC_CHECK(vnode_notify_create, cred, mp, mp->mnt_mntlabel,
	    dvp, dvp->v_label, vp, vp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(12, vp);

	return error;
}

void
mac_vnode_notify_rename(vfs_context_t ctx, struct vnode *vp,
    struct vnode *dvp, struct componentname *cnp)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(13, vp);
	MAC_PERFORM(vnode_notify_rename, cred, vp, vp->v_label,
	    dvp, dvp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(13, vp);
}

void
mac_vnode_notify_open(vfs_context_t ctx, struct vnode *vp, int acc_flags)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(14, vp);
	MAC_PERFORM(vnode_notify_open, cred, vp, vp->v_label, acc_flags);
	VFS_KERNEL_DEBUG_END1(14, vp);
}

void
mac_vnode_notify_link(vfs_context_t ctx, struct vnode *vp,
    struct vnode *dvp, struct componentname *cnp)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(15, vp);
	MAC_PERFORM(vnode_notify_link, cred, dvp, dvp->v_label, vp, vp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(15, vp);
}

void
mac_vnode_notify_deleteextattr(vfs_context_t ctx, struct vnode *vp, const char *name)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(16, vp);
	MAC_PERFORM(vnode_notify_deleteextattr, cred, vp, vp->v_label, name);
	VFS_KERNEL_DEBUG_END1(16, vp);
}

void
mac_vnode_notify_setacl(vfs_context_t ctx, struct vnode *vp, struct kauth_acl *acl)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(17, vp);
	MAC_PERFORM(vnode_notify_setacl, cred, vp, vp->v_label, acl);
	VFS_KERNEL_DEBUG_END1(17, vp);
}

void
mac_vnode_notify_setattrlist(vfs_context_t ctx, struct vnode *vp, struct attrlist *alist)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(18, vp);
	MAC_PERFORM(vnode_notify_setattrlist, cred, vp, vp->v_label, alist);
	VFS_KERNEL_DEBUG_END1(18, vp);
}

void
mac_vnode_notify_setextattr(vfs_context_t ctx, struct vnode *vp, const char *name, struct uio *uio)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(19, vp);
	MAC_PERFORM(vnode_notify_setextattr, cred, vp, vp->v_label, name, uio);
	VFS_KERNEL_DEBUG_END1(19, vp);
}

void
mac_vnode_notify_setflags(vfs_context_t ctx, struct vnode *vp, u_long flags)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(20, vp);
	MAC_PERFORM(vnode_notify_setflags, cred, vp, vp->v_label, flags);
	VFS_KERNEL_DEBUG_END1(20, vp);
}

void
mac_vnode_notify_setmode(vfs_context_t ctx, struct vnode *vp, mode_t mode)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(21, vp);
	MAC_PERFORM(vnode_notify_setmode, cred, vp, vp->v_label, mode);
	VFS_KERNEL_DEBUG_END1(21, vp);
}

void
mac_vnode_notify_setowner(vfs_context_t ctx, struct vnode *vp, uid_t uid, gid_t gid)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(22, vp);
	MAC_PERFORM(vnode_notify_setowner, cred, vp, vp->v_label, uid, gid);
	VFS_KERNEL_DEBUG_END1(22, vp);
}

void
mac_vnode_notify_setutimes(vfs_context_t ctx, struct vnode *vp, struct timespec atime, struct timespec mtime)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(23, vp);
	MAC_PERFORM(vnode_notify_setutimes, cred, vp, vp->v_label, atime, mtime);
	VFS_KERNEL_DEBUG_END1(23, vp);
}

void
mac_vnode_notify_truncate(vfs_context_t ctx, kauth_cred_t file_cred, struct vnode *vp)
{
	kauth_cred_t cred;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return;
	}
	VFS_KERNEL_DEBUG_START1(24, vp);
	MAC_PERFORM(vnode_notify_truncate, cred, file_cred, vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(24, vp);
}

/*
 * Extended attribute 'name' was updated via
 * vn_setxattr() or vn_removexattr().  Allow the
 * policy to update the vnode label.
 */
void
mac_vnode_label_update_extattr(struct mount *mp, struct vnode *vp,
    const char *name)
{
	int error = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return;
	}
#endif
	if (!mac_label_vnodes) {
		return;
	}

	VFS_KERNEL_DEBUG_START1(25, vp);
	MAC_PERFORM(vnode_label_update_extattr, mp, mp->mnt_mntlabel, vp,
	    vp->v_label, name);
	VFS_KERNEL_DEBUG_END1(25, vp);
	if (error == 0) {
		return;
	}

	vnode_lock(vp);
	vnode_relabel(vp);
	vnode_unlock(vp);
	return;
}

static int
mac_vnode_label_store(vfs_context_t ctx, struct vnode *vp,
    struct label *intlabel)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	if (!mac_label_vnodes) {
		return 0;
	}

	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(26, vp);
	MAC_CHECK(vnode_label_store, cred, vp, vp->v_label, intlabel);
	VFS_KERNEL_DEBUG_END1(26, vp);

	return error;
}

void
mac_cred_label_update_execve(vfs_context_t ctx, kauth_cred_t new, struct vnode *vp, off_t offset,
    struct vnode *scriptvp, struct label *scriptvnodelabel, struct label *execl, u_int *csflags,
    void *macextensions, int *disjoint, int *labelupdateerror)
{
	kauth_cred_t cred;
	*disjoint = 0;
	int error;
	posix_cred_t pcred = posix_cred_get(new);

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce || !mac_vnode_enforce) {
		return;
	}
#endif

	/* mark the new cred to indicate "matching" includes the label */
	pcred->cr_flags |= CRF_MAC_ENFORCE;

	cred = vfs_context_ucred(ctx);

	/*
	 * NB: Cannot use MAC_CHECK macro because we need a sequence point after
	 *     calling exec_spawnattr_getmacpolicyinfo() and before passing the
	 *     spawnattrlen as an argument to the hook.
	 */
	VFS_KERNEL_DEBUG_START1(27, vp);
	{
		struct mac_policy_conf *mpc;
		u_int i;

		error = 0;
		for (i = 0; i < mac_policy_list.staticmax; i++) {
			mpc = mac_policy_list.entries[i].mpc;
			if (mpc == NULL) {
				continue;
			}

			mpo_cred_label_update_execve_t *hook = mpc->mpc_ops->mpo_cred_label_update_execve;
			if (hook == NULL) {
				continue;
			}

			size_t spawnattrlen = 0;
			void *spawnattr = exec_spawnattr_getmacpolicyinfo(macextensions, mpc->mpc_name, &spawnattrlen);

			error = mac_error_select(hook(cred, new, vfs_context_proc(ctx), vp, offset, scriptvp,
			    vp->v_label, scriptvnodelabel, execl, csflags, spawnattr, spawnattrlen, disjoint),
			    error);
		}
		if (mac_policy_list_conditional_busy() != 0) {
			for (; i <= mac_policy_list.maxindex; i++) {
				mpc = mac_policy_list.entries[i].mpc;
				if (mpc == NULL) {
					continue;
				}

				mpo_cred_label_update_execve_t *hook = mpc->mpc_ops->mpo_cred_label_update_execve;
				if (hook == NULL) {
					continue;
				}

				size_t spawnattrlen = 0;
				void *spawnattr = exec_spawnattr_getmacpolicyinfo(macextensions, mpc->mpc_name, &spawnattrlen);

				error = mac_error_select(hook(cred, new, vfs_context_proc(ctx), vp, offset, scriptvp,
				    vp->v_label, scriptvnodelabel, execl, csflags, spawnattr, spawnattrlen, disjoint),
				    error);
			}
			mac_policy_list_unbusy();
		}
	}
	*labelupdateerror = error;
	VFS_KERNEL_DEBUG_END1(27, vp);
}

int
mac_cred_check_label_update_execve(vfs_context_t ctx, struct vnode *vp, off_t offset,
    struct vnode *scriptvp, struct label *scriptvnodelabel, struct label *execlabel,
    struct proc *p, void *macextensions)
{
	kauth_cred_t cred;
	int result = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce || !mac_vnode_enforce) {
		return result;
	}
#endif

	cred = vfs_context_ucred(ctx);

	VFS_KERNEL_DEBUG_START1(28, vp);
	/*
	 * NB: Cannot use MAC_BOOLEAN macro because we need a sequence point after
	 *     calling exec_spawnattr_getmacpolicyinfo() and before passing the
	 *     spawnattrlen as an argument to the hook.
	 */
	{
		struct mac_policy_conf *mpc;
		u_int i;

		for (i = 0; i < mac_policy_list.staticmax; i++) {
			mpc = mac_policy_list.entries[i].mpc;
			if (mpc == NULL) {
				continue;
			}

			mpo_cred_check_label_update_execve_t *hook = mpc->mpc_ops->mpo_cred_check_label_update_execve;
			if (hook == NULL) {
				continue;
			}

			size_t spawnattrlen = 0;
			void *spawnattr = exec_spawnattr_getmacpolicyinfo(macextensions, mpc->mpc_name, &spawnattrlen);

			result = result || hook(cred, vp, offset, scriptvp, vp->v_label, scriptvnodelabel, execlabel, p, spawnattr, spawnattrlen);
		}
		if (mac_policy_list_conditional_busy() != 0) {
			for (; i <= mac_policy_list.maxindex; i++) {
				mpc = mac_policy_list.entries[i].mpc;
				if (mpc == NULL) {
					continue;
				}

				mpo_cred_check_label_update_execve_t *hook = mpc->mpc_ops->mpo_cred_check_label_update_execve;
				if (hook == NULL) {
					continue;
				}

				size_t spawnattrlen = 0;
				void *spawnattr = exec_spawnattr_getmacpolicyinfo(macextensions, mpc->mpc_name, &spawnattrlen);

				result = result || hook(cred, vp, offset, scriptvp, vp->v_label, scriptvnodelabel, execlabel, p, spawnattr, spawnattrlen);
			}
			mac_policy_list_unbusy();
		}
	}
	VFS_KERNEL_DEBUG_END1(28, vp);

	return result;
}

int
mac_vnode_check_access(vfs_context_t ctx, struct vnode *vp,
    int acc_mode)
{
	kauth_cred_t cred;
	int error;
	int mask;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	/* Convert {R,W,X}_OK values to V{READ,WRITE,EXEC} for entry points */
	mask = ACCESS_MODE_TO_VNODE_MASK(acc_mode);
	VFS_KERNEL_DEBUG_START1(29, vp);
	MAC_CHECK(vnode_check_access, cred, vp, vp->v_label, mask);
	VFS_KERNEL_DEBUG_END1(29, vp);
	return error;
}

int
mac_vnode_check_chdir(vfs_context_t ctx, struct vnode *dvp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(30, dvp);
	MAC_CHECK(vnode_check_chdir, cred, dvp, dvp->v_label);
	VFS_KERNEL_DEBUG_END1(30, dvp);
	return error;
}

int
mac_vnode_check_chroot(vfs_context_t ctx, struct vnode *dvp,
    struct componentname *cnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(31, dvp);
	MAC_CHECK(vnode_check_chroot, cred, dvp, dvp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(31, dvp);
	return error;
}

int
mac_vnode_check_clone(vfs_context_t ctx, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(32, dvp);
	MAC_CHECK(vnode_check_clone, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(32, dvp);
	return error;
}
int
mac_vnode_check_create(vfs_context_t ctx, struct vnode *dvp,
    struct componentname *cnp, struct vnode_attr *vap)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(33, dvp);
	MAC_CHECK(vnode_check_create, cred, dvp, dvp->v_label, cnp, vap);
	VFS_KERNEL_DEBUG_END1(33, dvp);
	return error;
}

int
mac_vnode_check_unlink(vfs_context_t ctx, struct vnode *dvp, struct vnode *vp,
    struct componentname *cnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(34, dvp);
	MAC_CHECK(vnode_check_unlink, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(34, dvp);
	return error;
}
#if 0
int
mac_vnode_check_deleteacl(vfs_context_t ctx, struct vnode *vp,
    acl_type_t type)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(35, dvp);
	MAC_CHECK(vnode_check_deleteacl, cred, vp, vp->v_label, type);
	VFS_KERNEL_DEBUG_END1(35, dvp);
	return error;
}
#endif

int
mac_vnode_check_deleteextattr(vfs_context_t ctx, struct vnode *vp,
    const char *name)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(36, vp);
	MAC_CHECK(vnode_check_deleteextattr, cred, vp, vp->v_label, name);
	VFS_KERNEL_DEBUG_END1(36, vp);
	return error;
}
int
mac_vnode_check_exchangedata(vfs_context_t ctx,
    struct vnode *v1, struct vnode *v2)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(37, v1);
	MAC_CHECK(vnode_check_exchangedata, cred, v1, v1->v_label,
	    v2, v2->v_label);
	VFS_KERNEL_DEBUG_END1(37, v1);

	return error;
}

#if 0
int
mac_vnode_check_getacl(vfs_context_t ctx, struct vnode *vp, acl_type_t type)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(38, vp);
	MAC_CHECK(vnode_check_getacl, cred, vp, vp->v_label, type);
	VFS_KERNEL_DEBUG_END1(38, vp);
	return error;
}
#endif

int
mac_vnode_check_getattr(vfs_context_t ctx, struct ucred *file_cred,
    struct vnode *vp, struct vnode_attr *va)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(39, vp);
	MAC_CHECK(vnode_check_getattr, cred, file_cred, vp, vp->v_label, va);
	VFS_KERNEL_DEBUG_END1(39, vp);
	return error;
}

int
mac_vnode_check_getattrlist(vfs_context_t ctx, struct vnode *vp,
    struct attrlist *alist)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(40, vp);
	MAC_CHECK(vnode_check_getattrlist, cred, vp, vp->v_label, alist);
	VFS_KERNEL_DEBUG_END1(40, vp);

	/* Falsify results instead of returning error? */
	return error;
}

int
mac_vnode_check_exec(vfs_context_t ctx, struct vnode *vp,
    struct image_params *imgp)
{
	kauth_cred_t cred;
	int error = 0;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce || !mac_vnode_enforce) {
		return 0;
	}
#endif

	cred = vfs_context_ucred(ctx);

	/*
	 * NB: Cannot use MAC_CHECK macro because we need a sequence point after
	 *     calling exec_spawnattr_getmacpolicyinfo() and before passing the
	 *     spawnattrlen as an argument to the hook.
	 */
	VFS_KERNEL_DEBUG_START1(41, vp);
	{
		struct mac_policy_conf *mpc;
		u_int i;

		for (i = 0; i < mac_policy_list.staticmax; i++) {
			mpc = mac_policy_list.entries[i].mpc;
			if (mpc == NULL) {
				continue;
			}

			mpo_vnode_check_exec_t *hook = mpc->mpc_ops->mpo_vnode_check_exec;
			if (hook == NULL) {
				continue;
			}

			size_t spawnattrlen = 0;
			void *spawnattr = exec_spawnattr_getmacpolicyinfo(imgp->ip_px_smpx, mpc->mpc_name, &spawnattrlen);

			error = mac_error_select(
				hook(cred,
				vp, imgp->ip_scriptvp, vp->v_label, imgp->ip_scriptlabelp,
				imgp->ip_execlabelp, &imgp->ip_ndp->ni_cnd, &imgp->ip_csflags,
				spawnattr, spawnattrlen), error);
		}
		if (mac_policy_list_conditional_busy() != 0) {
			for (; i <= mac_policy_list.maxindex; i++) {
				mpc = mac_policy_list.entries[i].mpc;
				if (mpc == NULL) {
					continue;
				}

				mpo_vnode_check_exec_t *hook = mpc->mpc_ops->mpo_vnode_check_exec;
				if (hook == NULL) {
					continue;
				}

				size_t spawnattrlen = 0;
				void *spawnattr = exec_spawnattr_getmacpolicyinfo(imgp->ip_px_smpx, mpc->mpc_name, &spawnattrlen);

				error = mac_error_select(
					hook(cred,
					vp, imgp->ip_scriptvp, vp->v_label, imgp->ip_scriptlabelp,
					imgp->ip_execlabelp, &imgp->ip_ndp->ni_cnd, &imgp->ip_csflags,
					spawnattr, spawnattrlen), error);
			}
			mac_policy_list_unbusy();
		}
	}
	VFS_KERNEL_DEBUG_END1(41, vp);

	return error;
}

int
mac_vnode_check_fsgetpath(vfs_context_t ctx, struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(42, vp);
	MAC_CHECK(vnode_check_fsgetpath, cred, vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(42, vp);
	return error;
}

int
mac_vnode_check_signature(struct vnode *vp, struct cs_blob *cs_blob,
    struct image_params *imgp,
    unsigned int *cs_flags, unsigned int *signer_type,
    int flags)
{
	int error;
	char *fatal_failure_desc = NULL;
	size_t fatal_failure_desc_len = 0;

	char *vn_path = NULL;
	vm_size_t vn_pathlen = MAXPATHLEN;
	cpu_type_t cpu_type = (imgp == NULL) ? CPU_TYPE_ANY : imgp->ip_origcputype;


#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce || !mac_vnode_enforce) {
		return 0;
	}
#endif

	VFS_KERNEL_DEBUG_START1(43, vp);
	MAC_CHECK(vnode_check_signature, vp, vp->v_label, cpu_type, cs_blob,
	    cs_flags, signer_type, flags, &fatal_failure_desc, &fatal_failure_desc_len);
	VFS_KERNEL_DEBUG_END1(43, vp);

	if (fatal_failure_desc_len) {
		// A fatal code signature validation failure occured, formulate a crash
		// reason.

		char const *path = NULL;

		vn_path = (char *)kalloc(MAXPATHLEN);
		if (vn_path != NULL) {
			if (vn_getpath(vp, vn_path, (int*)&vn_pathlen) == 0) {
				path = vn_path;
			} else {
				path = "(get vnode path failed)";
			}
		} else {
			path = "(path alloc failed)";
		}

		if (error == 0) {
			panic("mac_vnode_check_signature: MAC hook returned no error, "
			    "but status is claimed to be fatal? "
			    "path: '%s', fatal_failure_desc_len: %ld, fatal_failure_desc:\n%s\n",
			    path, fatal_failure_desc_len, fatal_failure_desc);
		}

		printf("mac_vnode_check_signature: %s: code signature validation failed fatally: %s",
		    path, fatal_failure_desc);

		if (imgp == NULL) {
			goto out;
		}

		os_reason_t reason = os_reason_create(OS_REASON_CODESIGNING,
		    CODESIGNING_EXIT_REASON_TASKGATED_INVALID_SIG);

		if (reason == OS_REASON_NULL) {
			printf("mac_vnode_check_signature: %s: failure to allocate exit reason for validation failure: %s\n",
			    path, fatal_failure_desc);
			goto out;
		}

		imgp->ip_cs_error = reason;
		reason->osr_flags = (OS_REASON_FLAG_GENERATE_CRASH_REPORT |
		    OS_REASON_FLAG_CONSISTENT_FAILURE);

		if (fatal_failure_desc == NULL) {
			// This may happen if allocation for the buffer failed.
			printf("mac_vnode_check_signature: %s: fatal failure is missing its description.\n", path);
		} else {
			mach_vm_address_t data_addr = 0;

			int reason_error = 0;
			int kcdata_error = 0;

			if ((reason_error = os_reason_alloc_buffer_noblock(reason, kcdata_estimate_required_buffer_size
			    (1, fatal_failure_desc_len))) == 0 &&
			    (kcdata_error = kcdata_get_memory_addr(&reason->osr_kcd_descriptor,
			    EXIT_REASON_USER_DESC, fatal_failure_desc_len,
			    &data_addr)) == KERN_SUCCESS) {
				kern_return_t mc_error = kcdata_memcpy(&reason->osr_kcd_descriptor, (mach_vm_address_t)data_addr,
				    fatal_failure_desc, fatal_failure_desc_len);

				if (mc_error != KERN_SUCCESS) {
					printf("mac_vnode_check_signature: %s: failed to copy reason string "
					    "(kcdata_memcpy error: %d, length: %ld)\n",
					    path, mc_error, fatal_failure_desc_len);
				}
			} else {
				printf("mac_vnode_check_signature: %s: failed to allocate space for reason string "
				    "(os_reason_alloc_buffer error: %d, kcdata error: %d, length: %ld)\n",
				    path, reason_error, kcdata_error, fatal_failure_desc_len);
			}
		}
	}

out:
	if (vn_path) {
		kfree(vn_path, MAXPATHLEN);
	}

	if (fatal_failure_desc_len > 0 && fatal_failure_desc != NULL) {
		kfree(fatal_failure_desc, fatal_failure_desc_len);
	}

	return error;
}

#if 0
int
mac_vnode_check_getacl(vfs_context_t ctx, struct vnode *vp, acl_type_t type)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(44, vp);
	MAC_CHECK(vnode_check_getacl, cred, vp, vp->v_label, type);
	VFS_KERNEL_DEBUG_END1(44, vp);
	return error;
}
#endif

int
mac_vnode_check_getextattr(vfs_context_t ctx, struct vnode *vp,
    const char *name, struct uio *uio)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(45, vp);
	MAC_CHECK(vnode_check_getextattr, cred, vp, vp->v_label,
	    name, uio);
	VFS_KERNEL_DEBUG_END1(45, vp);
	return error;
}

int
mac_vnode_check_ioctl(vfs_context_t ctx, struct vnode *vp, u_int cmd)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(46, vp);
	MAC_CHECK(vnode_check_ioctl, cred, vp, vp->v_label, cmd);
	VFS_KERNEL_DEBUG_END1(46, vp);
	return error;
}

int
mac_vnode_check_kqfilter(vfs_context_t ctx, kauth_cred_t file_cred,
    struct knote *kn, struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(47, vp);
	MAC_CHECK(vnode_check_kqfilter, cred, file_cred, kn, vp,
	    vp->v_label);
	VFS_KERNEL_DEBUG_END1(47, vp);

	return error;
}

int
mac_vnode_check_link(vfs_context_t ctx, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(48, vp);
	MAC_CHECK(vnode_check_link, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(48, vp);
	return error;
}

int
mac_vnode_check_listextattr(vfs_context_t ctx, struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(49, vp);
	MAC_CHECK(vnode_check_listextattr, cred, vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(49, vp);
	return error;
}

int
mac_vnode_check_lookup_preflight(vfs_context_t ctx, struct vnode *dvp,
    const char *path, size_t pathlen)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(50, dvp);
	MAC_CHECK(vnode_check_lookup_preflight, cred, dvp, dvp->v_label, path, pathlen);
	VFS_KERNEL_DEBUG_END1(50, dvp);
	return error;
}

int
mac_vnode_check_lookup(vfs_context_t ctx, struct vnode *dvp,
    struct componentname *cnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(51, dvp);
	MAC_CHECK(vnode_check_lookup, cred, dvp, dvp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(51, dvp);
	return error;
}

int
mac_vnode_check_open(vfs_context_t ctx, struct vnode *vp, int acc_mode)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(52, vp);
	MAC_CHECK(vnode_check_open, cred, vp, vp->v_label, acc_mode);
	VFS_KERNEL_DEBUG_END1(52, vp);
	return error;
}

int
mac_vnode_check_read(vfs_context_t ctx, struct ucred *file_cred,
    struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(53, vp);
	MAC_CHECK(vnode_check_read, cred, file_cred, vp,
	    vp->v_label);
	VFS_KERNEL_DEBUG_END1(53, vp);

	return error;
}

int
mac_vnode_check_readdir(vfs_context_t ctx, struct vnode *dvp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(54, dvp);
	MAC_CHECK(vnode_check_readdir, cred, dvp, dvp->v_label);
	VFS_KERNEL_DEBUG_END1(54, dvp);
	return error;
}

int
mac_vnode_check_readlink(vfs_context_t ctx, struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(55, vp);
	MAC_CHECK(vnode_check_readlink, cred, vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(55, vp);
	return error;
}

int
mac_vnode_check_label_update(vfs_context_t ctx, struct vnode *vp,
    struct label *newlabel)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(56, vp);
	MAC_CHECK(vnode_check_label_update, cred, vp, vp->v_label, newlabel);
	VFS_KERNEL_DEBUG_END1(56, vp);

	return error;
}

int
mac_vnode_check_rename(vfs_context_t ctx, struct vnode *dvp,
    struct vnode *vp, struct componentname *cnp, struct vnode *tdvp,
    struct vnode *tvp, struct componentname *tcnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}

	VFS_KERNEL_DEBUG_START1(57, vp);
	MAC_CHECK(vnode_check_rename_from, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp);
	if (error) {
		VFS_KERNEL_DEBUG_END1(57, vp);
		return error;
	}

	MAC_CHECK(vnode_check_rename_to, cred, tdvp, tdvp->v_label, tvp,
	    tvp != NULL ? tvp->v_label : NULL, dvp == tdvp, tcnp);
	if (error) {
		VFS_KERNEL_DEBUG_END1(57, vp);
		return error;
	}

	MAC_CHECK(vnode_check_rename, cred, dvp, dvp->v_label, vp,
	    vp->v_label, cnp, tdvp, tdvp->v_label, tvp,
	    tvp != NULL ? tvp->v_label : NULL, tcnp);
	VFS_KERNEL_DEBUG_END1(57, vp);
	return error;
}

int
mac_vnode_check_revoke(vfs_context_t ctx, struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(58, vp);
	MAC_CHECK(vnode_check_revoke, cred, vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(58, vp);
	return error;
}

int
mac_vnode_check_searchfs(vfs_context_t ctx, struct vnode *vp, struct attrlist *alist)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(59, vp);
	MAC_CHECK(vnode_check_searchfs, cred, vp, vp->v_label, alist);
	VFS_KERNEL_DEBUG_END1(59, vp);
	return error;
}

int
mac_vnode_check_select(vfs_context_t ctx, struct vnode *vp, int which)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(60, vp);
	MAC_CHECK(vnode_check_select, cred, vp, vp->v_label, which);
	VFS_KERNEL_DEBUG_END1(60, vp);
	return error;
}

int
mac_vnode_check_setacl(vfs_context_t ctx, struct vnode *vp,
    struct kauth_acl *acl)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(61, vp);
	MAC_CHECK(vnode_check_setacl, cred, vp, vp->v_label, acl);
	VFS_KERNEL_DEBUG_END1(61, vp);
	return error;
}

int
mac_vnode_check_setattrlist(vfs_context_t ctx, struct vnode *vp,
    struct attrlist *alist)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(62, vp);
	MAC_CHECK(vnode_check_setattrlist, cred, vp, vp->v_label, alist);
	VFS_KERNEL_DEBUG_END1(62, vp);
	return error;
}

int
mac_vnode_check_setextattr(vfs_context_t ctx, struct vnode *vp,
    const char *name, struct uio *uio)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(63, vp);
	MAC_CHECK(vnode_check_setextattr, cred, vp, vp->v_label,
	    name, uio);
	VFS_KERNEL_DEBUG_END1(63, vp);
	return error;
}

int
mac_vnode_check_setflags(vfs_context_t ctx, struct vnode *vp, u_long flags)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(64, vp);
	MAC_CHECK(vnode_check_setflags, cred, vp, vp->v_label, flags);
	VFS_KERNEL_DEBUG_END1(64, vp);
	return error;
}

int
mac_vnode_check_setmode(vfs_context_t ctx, struct vnode *vp, mode_t mode)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(65, vp);
	MAC_CHECK(vnode_check_setmode, cred, vp, vp->v_label, mode);
	VFS_KERNEL_DEBUG_END1(65, vp);
	return error;
}

int
mac_vnode_check_setowner(vfs_context_t ctx, struct vnode *vp, uid_t uid,
    gid_t gid)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(66, vp);
	MAC_CHECK(vnode_check_setowner, cred, vp, vp->v_label, uid, gid);
	VFS_KERNEL_DEBUG_END1(66, vp);
	return error;
}

int
mac_vnode_check_setutimes(vfs_context_t ctx, struct vnode *vp,
    struct timespec atime, struct timespec mtime)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(67, vp);
	MAC_CHECK(vnode_check_setutimes, cred, vp, vp->v_label, atime,
	    mtime);
	VFS_KERNEL_DEBUG_END1(67, vp);
	return error;
}

int
mac_vnode_check_stat(vfs_context_t ctx, struct ucred *file_cred,
    struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(68, vp);
	MAC_CHECK(vnode_check_stat, cred, file_cred, vp,
	    vp->v_label);
	VFS_KERNEL_DEBUG_END1(68, vp);
	return error;
}

int
mac_vnode_check_trigger_resolve(vfs_context_t ctx, struct vnode *dvp,
    struct componentname *cnp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(69, dvp);
	MAC_CHECK(vnode_check_trigger_resolve, cred, dvp, dvp->v_label, cnp);
	VFS_KERNEL_DEBUG_END1(69, dvp);
	return error;
}

int
mac_vnode_check_truncate(vfs_context_t ctx, struct ucred *file_cred,
    struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(70, vp);
	MAC_CHECK(vnode_check_truncate, cred, file_cred, vp,
	    vp->v_label);
	VFS_KERNEL_DEBUG_END1(70, vp);

	return error;
}

int
mac_vnode_check_write(vfs_context_t ctx, struct ucred *file_cred,
    struct vnode *vp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(71, vp);
	MAC_CHECK(vnode_check_write, cred, file_cred, vp, vp->v_label);
	VFS_KERNEL_DEBUG_END1(71, vp);

	return error;
}

int
mac_vnode_check_uipc_bind(vfs_context_t ctx, struct vnode *dvp,
    struct componentname *cnp, struct vnode_attr *vap)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(72, dvp);
	MAC_CHECK(vnode_check_uipc_bind, cred, dvp, dvp->v_label, cnp, vap);
	VFS_KERNEL_DEBUG_END1(72, dvp);
	return error;
}

int
mac_vnode_check_uipc_connect(vfs_context_t ctx, struct vnode *vp, struct socket *so)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(73, vp);
	MAC_CHECK(vnode_check_uipc_connect, cred, vp, vp->v_label, (socket_t) so);
	VFS_KERNEL_DEBUG_END1(73, vp);
	return error;
}

void
mac_vnode_label_update(vfs_context_t ctx, struct vnode *vp, struct label *newlabel)
{
	kauth_cred_t cred = vfs_context_ucred(ctx);
	struct label *tmpl = NULL;

	if (vp->v_label == NULL) {
		tmpl = mac_vnode_label_alloc();
	}

	vnode_lock(vp);

	/* recheck after lock */
	if (vp->v_label == NULL) {
		vp->v_label = tmpl;
		tmpl = NULL;
	}

	VFS_KERNEL_DEBUG_START1(74, vp);
	MAC_PERFORM(vnode_label_update, cred, vp, vp->v_label, newlabel);
	VFS_KERNEL_DEBUG_END1(74, vp);
	vnode_unlock(vp);

	if (tmpl != NULL) {
		mac_vnode_label_free(tmpl);
	}
}

int
mac_vnode_find_sigs(struct proc *p, struct vnode *vp, off_t offset)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_proc_enforce || !mac_vnode_enforce) {
		return 0;
	}
#endif

	VFS_KERNEL_DEBUG_START1(75, vp);
	MAC_CHECK(vnode_find_sigs, p, vp, offset, vp->v_label);
	VFS_KERNEL_DEBUG_END1(75, vp);

	return error;
}

void
mac_mount_label_associate(vfs_context_t ctx, struct mount *mp)
{
	kauth_cred_t cred = vfs_context_ucred(ctx);

	/* XXX: eventually this logic may be handled by the policy? */

	/* We desire MULTILABEL for the root filesystem. */
	if ((mp->mnt_flag & MNT_ROOTFS) &&
	    (strcmp(mp->mnt_vfsstat.f_fstypename, "hfs") == 0)) {
		mp->mnt_flag |= MNT_MULTILABEL;
	}

	/* MULTILABEL on DEVFS. */
	if (strcmp(mp->mnt_vfsstat.f_fstypename, "devfs") == 0) {
		mp->mnt_flag |= MNT_MULTILABEL;
	}

	/* MULTILABEL on FDESC pseudo-filesystem. */
	if (strcmp(mp->mnt_vfsstat.f_fstypename, "fdesc") == 0) {
		mp->mnt_flag |= MNT_MULTILABEL;
	}

	/* MULTILABEL on all NFS filesystems. */
	if (strcmp(mp->mnt_vfsstat.f_fstypename, "nfs") == 0) {
		mp->mnt_flag |= MNT_MULTILABEL;
	}

	/* MULTILABEL on all AFP filesystems. */
	if (strcmp(mp->mnt_vfsstat.f_fstypename, "afpfs") == 0) {
		mp->mnt_flag |= MNT_MULTILABEL;
	}

	if (mp->mnt_vtable != NULL) {
		/* Any filesystem that supports native XATTRs. */
		if ((mp->mnt_vtable->vfc_vfsflags & VFC_VFSNATIVEXATTR)) {
			mp->mnt_flag |= MNT_MULTILABEL;
		}

		/* Filesystem does not support multilabel. */
		if ((mp->mnt_vtable->vfc_vfsflags & VFC_VFSNOMACLABEL) &&
		    (mp->mnt_flag & MNT_MULTILABEL)) {
			mp->mnt_flag &= ~MNT_MULTILABEL;
		}
	}

	VFS_KERNEL_DEBUG_START1(76, mp);
	MAC_PERFORM(mount_label_associate, cred, mp, mp->mnt_mntlabel);
	VFS_KERNEL_DEBUG_END1(76, mp);
#if DEBUG
	printf("MAC Framework enabling %s support: %s -> %s (%s)\n",
	    mp->mnt_flag & MNT_MULTILABEL ? "multilabel" : "singlelabel",
	    mp->mnt_vfsstat.f_mntfromname,
	    mp->mnt_vfsstat.f_mntonname,
	    mp->mnt_vfsstat.f_fstypename);
#endif
}

int
mac_mount_check_mount(vfs_context_t ctx, struct vnode *vp,
    struct componentname *cnp, const char *vfc_name)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(77, vp);
	MAC_CHECK(mount_check_mount, cred, vp, vp->v_label, cnp, vfc_name);
	VFS_KERNEL_DEBUG_END1(77, vp);

	return error;
}

int
mac_mount_check_mount_late(vfs_context_t ctx, struct mount *mp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(78, mp);
	MAC_CHECK(mount_check_mount_late, cred, mp);
	VFS_KERNEL_DEBUG_END1(78, mp);

	return error;
}

int
mac_mount_check_snapshot_create(vfs_context_t ctx, struct mount *mp,
    const char *name)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(79, mp);
	MAC_CHECK(mount_check_snapshot_create, cred, mp, name);
	VFS_KERNEL_DEBUG_END1(79, mp);
	return error;
}

int
mac_mount_check_snapshot_delete(vfs_context_t ctx, struct mount *mp,
    const char *name)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(80, mp);
	MAC_CHECK(mount_check_snapshot_delete, cred, mp, name);
	VFS_KERNEL_DEBUG_END1(80, mp);
	return error;
}

int
mac_mount_check_snapshot_mount(vfs_context_t ctx, struct vnode *rvp, struct vnode *vp, struct componentname *cnp,
    const char *name, const char *vfc_name)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(92, vp);
	MAC_CHECK(mount_check_snapshot_mount, cred, rvp, vp, cnp, name, vfc_name);
	VFS_KERNEL_DEBUG_END1(92, vp);
	return error;
}

int
mac_mount_check_snapshot_revert(vfs_context_t ctx, struct mount *mp,
    const char *name)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(81, mp);
	MAC_CHECK(mount_check_snapshot_revert, cred, mp, name);
	VFS_KERNEL_DEBUG_END1(81, mp);
	return error;
}

int
mac_mount_check_remount(vfs_context_t ctx, struct mount *mp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(82, mp);
	MAC_CHECK(mount_check_remount, cred, mp, mp->mnt_mntlabel);
	VFS_KERNEL_DEBUG_END1(82, mp);

	return error;
}

int
mac_mount_check_umount(vfs_context_t ctx, struct mount *mp)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(83, mp);
	MAC_CHECK(mount_check_umount, cred, mp, mp->mnt_mntlabel);
	VFS_KERNEL_DEBUG_END1(83, mp);

	return error;
}

int
mac_mount_check_getattr(vfs_context_t ctx, struct mount *mp,
    struct vfs_attr *vfa)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(84, mp);
	MAC_CHECK(mount_check_getattr, cred, mp, mp->mnt_mntlabel, vfa);
	VFS_KERNEL_DEBUG_END1(84, mp);
	return error;
}

int
mac_mount_check_setattr(vfs_context_t ctx, struct mount *mp,
    struct vfs_attr *vfa)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(85, mp);
	MAC_CHECK(mount_check_setattr, cred, mp, mp->mnt_mntlabel, vfa);
	VFS_KERNEL_DEBUG_END1(85, mp);
	return error;
}

int
mac_mount_check_stat(vfs_context_t ctx, struct mount *mount)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(86, mount);
	MAC_CHECK(mount_check_stat, cred, mount, mount->mnt_mntlabel);
	VFS_KERNEL_DEBUG_END1(86, mount);

	return error;
}

int
mac_mount_check_label_update(vfs_context_t ctx, struct mount *mount)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(87, mount);
	MAC_CHECK(mount_check_label_update, cred, mount, mount->mnt_mntlabel);
	VFS_KERNEL_DEBUG_END1(87, mount);

	return error;
}

int
mac_mount_check_fsctl(vfs_context_t ctx, struct mount *mp, u_int cmd)
{
	kauth_cred_t cred;
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	cred = vfs_context_ucred(ctx);
	if (!mac_cred_check_enforce(cred)) {
		return 0;
	}
	VFS_KERNEL_DEBUG_START1(88, mp);
	MAC_CHECK(mount_check_fsctl, cred, mp, mp->mnt_mntlabel, cmd);
	VFS_KERNEL_DEBUG_END1(88, mp);

	return error;
}

void
mac_devfs_label_associate_device(dev_t dev, struct devnode *de,
    const char *fullpath)
{
#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_device_enforce) {
		return;
	}
#endif

	VFS_KERNEL_DEBUG_START1(89, de);
	MAC_PERFORM(devfs_label_associate_device, dev, de, de->dn_label,
	    fullpath);
	VFS_KERNEL_DEBUG_END1(89, de);
}

void
mac_devfs_label_associate_directory(const char *dirname, int dirnamelen,
    struct devnode *de, const char *fullpath)
{
#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_device_enforce) {
		return;
	}
#endif

	VFS_KERNEL_DEBUG_START1(90, de);
	MAC_PERFORM(devfs_label_associate_directory, dirname, dirnamelen, de,
	    de->dn_label, fullpath);
	VFS_KERNEL_DEBUG_END1(90, de);
}

int
vn_setlabel(struct vnode *vp, struct label *intlabel, vfs_context_t context)
{
	int error;

#if SECURITY_MAC_CHECK_ENFORCE
	/* 21167099 - only check if we allow write */
	if (!mac_vnode_enforce) {
		return 0;
	}
#endif
	if (!mac_label_vnodes) {
		return 0;
	}

	if (vp->v_mount == NULL) {
		printf("vn_setlabel: null v_mount\n");
		if (vp->v_type != VNON) {
			printf("vn_setlabel: null v_mount with non-VNON\n");
		}
		return EBADF;
	}

	if ((vp->v_mount->mnt_flag & MNT_MULTILABEL) == 0) {
		return ENOTSUP;
	}

	/*
	 * Multi-phase commit.  First check the policies to confirm the
	 * change is OK.  Then commit via the filesystem.  Finally,
	 * update the actual vnode label.  Question: maybe the filesystem
	 * should update the vnode at the end as part of VNOP_SETLABEL()?
	 */
	error = mac_vnode_check_label_update(context, vp, intlabel);
	if (error) {
		return error;
	}

	error = VNOP_SETLABEL(vp, intlabel, context);
	if (error == ENOTSUP) {
		error = mac_vnode_label_store(context, vp,
		    intlabel);
		if (error) {
			printf("%s: mac_vnode_label_store failed %d\n",
			    __func__, error);
			return error;
		}
		mac_vnode_label_update(context, vp, intlabel);
	} else if (error) {
		printf("vn_setlabel: vop setlabel failed %d\n", error);
		return error;
	}

	return 0;
}

int
mac_vnode_label_associate_fdesc(struct mount *mp, struct fdescnode *fnp,
    struct vnode *vp, vfs_context_t ctx)
{
	struct fileproc *fp;
#if CONFIG_MACF_SOCKET_SUBSET
	struct socket *so;
#endif
	struct pipe *cpipe;
	struct vnode *fvp;
	struct proc *p;
	int error;

	error = 0;

	VFS_KERNEL_DEBUG_START1(91, vp);
	/*
	 * If no backing file, let the policy choose which label to use.
	 */
	if (fnp->fd_fd == -1) {
		MAC_PERFORM(vnode_label_associate_file, vfs_context_ucred(ctx),
		    mp, mp->mnt_mntlabel, NULL, NULL, vp, vp->v_label);
		VFS_KERNEL_DEBUG_END1(91, vp);
		return 0;
	}

	p = vfs_context_proc(ctx);
	error = fp_lookup(p, fnp->fd_fd, &fp, 0);
	if (error) {
		VFS_KERNEL_DEBUG_END1(91, vp);
		return error;
	}

	if (fp->f_fglob == NULL) {
		error = EBADF;
		goto out;
	}

	switch (FILEGLOB_DTYPE(fp->f_fglob)) {
	case DTYPE_VNODE:
		fvp = (struct vnode *)fp->f_fglob->fg_data;
		if ((error = vnode_getwithref(fvp))) {
			goto out;
		}
		if (fvp->v_label != NULL) {
			if (mac_label_vnodes != 0 && vp->v_label == NULL) {
				mac_vnode_label_init(vp); /* init dst label */
			}
			MAC_PERFORM(vnode_label_copy, fvp->v_label, vp->v_label);
		}
		(void)vnode_put(fvp);
		break;
#if CONFIG_MACF_SOCKET_SUBSET
	case DTYPE_SOCKET:
		so = (struct socket *)fp->f_fglob->fg_data;
		socket_lock(so, 1);
		MAC_PERFORM(vnode_label_associate_socket,
		    vfs_context_ucred(ctx), (socket_t)so, so->so_label,
		    vp, vp->v_label);
		socket_unlock(so, 1);
		break;
#endif
	case DTYPE_PSXSHM:
		pshm_label_associate(fp, vp, ctx);
		break;
	case DTYPE_PSXSEM:
		psem_label_associate(fp, vp, ctx);
		break;
	case DTYPE_PIPE:
		cpipe = (struct pipe *)fp->f_fglob->fg_data;
		/* kern/sys_pipe.c:pipe_select() suggests this test. */
		if (cpipe == (struct pipe *)-1) {
			error = EINVAL;
			goto out;
		}
		PIPE_LOCK(cpipe);
		MAC_PERFORM(vnode_label_associate_pipe, vfs_context_ucred(ctx),
		    cpipe, cpipe->pipe_label, vp, vp->v_label);
		PIPE_UNLOCK(cpipe);
		break;
	case DTYPE_KQUEUE:
	case DTYPE_FSEVENTS:
	case DTYPE_ATALK:
	case DTYPE_NETPOLICY:
	default:
		MAC_PERFORM(vnode_label_associate_file, vfs_context_ucred(ctx),
		    mp, mp->mnt_mntlabel, fp->f_fglob, fp->f_fglob->fg_label,
		    vp, vp->v_label);
		break;
	}
out:
	VFS_KERNEL_DEBUG_END1(91, vp);
	fp_drop(p, fnp->fd_fd, fp, 0);
	return error;
}

intptr_t
mac_vnode_label_get(struct vnode *vp, int slot, intptr_t sentinel)
{
	struct label *l;

	KASSERT(vp != NULL, ("mac_vnode_label_get: NULL vnode"));
	l = vp->v_label;
	if (l != NULL) {
		return mac_label_get(l, slot);
	} else {
		return sentinel;
	}
}

void
mac_vnode_label_set(struct vnode *vp, int slot, intptr_t v)
{
	struct label *l;
	KASSERT(vp != NULL, ("mac_vnode_label_set: NULL vnode"));
	l = vp->v_label;
	if (l == NULL) {
		mac_vnode_label_init(vp);
		l = vp->v_label;
	}
	mac_label_set(l, slot, v);
}
