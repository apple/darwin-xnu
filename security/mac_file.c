/*-
 * Copyright (c) 2002, 2003 Networks Associates Technology, Inc.
 * Copyright (c) 2006 SPARTA, Inc.
 * All rights reserved.
 *
 * This software was developed for the FreeBSD Project in part by Network
 * Associates Laboratories, the Security Research Division of Network
 * Associates, Inc. under DARPA/SPAWAR contract N66001-01-C-8035 ("CBOSS"),
 * as part of the DARPA CHATS research program.
 *
 * This software was enhanced by SPARTA ISSO under SPAWAR contract
 * N66001-04-C-6019 ("SEFOS").
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
 */

#include <sys/param.h>
#include <sys/kernel.h>
#include <sys/lock.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sbuf.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/file.h>
#include <sys/file_internal.h>

#include <security/mac_internal.h>


static struct label *
mac_file_label_alloc(void)
{
	struct label *label;

	label = mac_labelzone_alloc(MAC_WAITOK);
	if (label == NULL)
		return (NULL);
	MAC_PERFORM(file_label_init, label);
	return (label);
}

void
mac_file_label_init(struct fileglob *fg)
{

	fg->fg_label = mac_file_label_alloc();
}

static void
mac_file_label_free(struct label *label)
{

	MAC_PERFORM(file_label_destroy, label);
	mac_labelzone_free(label);
}

void
mac_file_label_associate(struct ucred *cred, struct fileglob *fg)
{

	MAC_PERFORM(file_label_associate, cred, fg, fg->fg_label);
}

void
mac_file_label_destroy(struct fileglob *fg)
{

	mac_file_label_free(fg->fg_label);
	fg->fg_label = NULL;
}

int
mac_file_check_create(struct ucred *cred)
{
	int error;

	MAC_CHECK(file_check_create, cred);
	return (error);
}

int
mac_file_check_dup(struct ucred *cred, struct fileglob *fg, int newfd)
{
	int error;

	MAC_CHECK(file_check_dup, cred, fg, fg->fg_label, newfd);
	return (error);
}

int
mac_file_check_fcntl(struct ucred *cred, struct fileglob *fg, int cmd,
    user_long_t arg)
{
	int error;

	MAC_CHECK(file_check_fcntl, cred, fg, fg->fg_label, cmd, arg);
	return (error);
}

int
mac_file_check_ioctl(struct ucred *cred, struct fileglob *fg, u_int cmd)
{
	int error;

	MAC_CHECK(file_check_ioctl, cred, fg, fg->fg_label, cmd);
	return (error);
}

int
mac_file_check_inherit(struct ucred *cred, struct fileglob *fg)
{
	int error;

	MAC_CHECK(file_check_inherit, cred, fg, fg->fg_label);
	return (error);
}

int
mac_file_check_receive(struct ucred *cred, struct fileglob *fg)
{
	int error;

	MAC_CHECK(file_check_receive, cred, fg, fg->fg_label);
	return (error);
}

int
mac_file_check_get_offset(struct ucred *cred, struct fileglob *fg)
{
	int error;

	MAC_CHECK(file_check_get_offset, cred, fg, fg->fg_label);
	return (error);
}

int
mac_file_check_change_offset(struct ucred *cred, struct fileglob *fg)
{
	int error;

	MAC_CHECK(file_check_change_offset, cred, fg, fg->fg_label);
	return (error);
}
 
int
mac_file_check_get(struct ucred *cred, struct fileglob *fg, char *elements,
    int len)
{
	int error;
	
	MAC_CHECK(file_check_get, cred, fg, elements, len);
	return (error);
}

int
mac_file_check_set(struct ucred *cred, struct fileglob *fg, char *buf,
    int buflen)
{
	int error;
	
	MAC_CHECK(file_check_set, cred, fg, buf, buflen);
	return (error);
}

int
mac_file_check_lock(struct ucred *cred, struct fileglob *fg, int op,
    struct flock *fl)
{
	int error;
	
	MAC_CHECK(file_check_lock, cred, fg, fg->fg_label, op, fl);
	return (error);
}

int
mac_file_check_library_validation(struct proc *proc,
	struct fileglob *fg, off_t slice_offset,
	user_long_t error_message, size_t error_message_size)
{
	int error;

	MAC_CHECK(file_check_library_validation, proc, fg, slice_offset, error_message, error_message_size);
	return (error);
}

/*
 * On some platforms, VM_PROT_READ implies VM_PROT_EXECUTE. If that is true,
 * both prot and maxprot will have VM_PROT_EXECUTE set after file_check_mmap
 * if VM_PROT_READ is set.
 *
 * The type of maxprot in file_check_mmap must be equivalent to vm_prot_t *
 * (defined in <mach/vm_prot.h>). mac_policy.h does not include any header
 * files, so cannot use the typedef itself.
 */
int
mac_file_check_mmap(struct ucred *cred, struct fileglob *fg, int prot,
    int flags, uint64_t offset, int *maxprot)
{
	int error;
	int maxp;

	maxp = *maxprot;
	MAC_CHECK(file_check_mmap, cred, fg, fg->fg_label, prot, flags, offset, &maxp);
	if ((maxp | *maxprot) != *maxprot)
		panic("file_check_mmap increased max protections");
	*maxprot = maxp;
	return (error);
}

void
mac_file_check_mmap_downgrade(struct ucred *cred, struct fileglob *fg,
    int *prot)
{
	int result = *prot;

	MAC_PERFORM(file_check_mmap_downgrade, cred, fg, fg->fg_label,
	    &result);

	*prot = result;
}


/*
 * fileglob XATTR helpers.
 */

int
mac_file_setxattr(struct fileglob *fg, const char *name, char *buf, size_t len) {
	struct vnode *vp = NULL;

	if (!fg || FILEGLOB_DTYPE(fg) != DTYPE_VNODE) {
		return EFTYPE;
	}

	vp = (struct vnode *)fg->fg_data;
	return mac_vnop_setxattr(vp, name, buf, len);
}

int
mac_file_getxattr(struct fileglob *fg, const char *name, char *buf, size_t len,
		size_t *attrlen) {
	struct vnode *vp = NULL;

	if (!fg || FILEGLOB_DTYPE(fg) != DTYPE_VNODE) {
		return EFTYPE;
	}

	vp = (struct vnode *)fg->fg_data;
	return mac_vnop_getxattr(vp, name, buf, len, attrlen);
}

int
mac_file_removexattr(struct fileglob *fg, const char *name) {
	struct vnode *vp = NULL;

	if (!fg || FILEGLOB_DTYPE(fg) != DTYPE_VNODE) {
		return EFTYPE;
	}

	vp = (struct vnode *)fg->fg_data;
	return mac_vnop_removexattr(vp, name);
}
