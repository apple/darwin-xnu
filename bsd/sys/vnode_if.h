
/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved
 * Copyright (c) 1992, 1993, 1994, 1995
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
 *      This product includes software developed by the University of
 *      California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS AND
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
 */


/*
 * Warning: This file is generated automatically.
 * (Modifications made here may easily be lost!)
 *
 * Created by the script:
 *	@(#)vnode_if.sh	8.7 (Berkeley) 5/11/95
 */


#ifndef _SYS_VNODE_IF_H_
#define _SYS_VNODE_IF_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE
extern struct vnodeop_desc vop_default_desc;


struct vop_lookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
};
extern struct vnodeop_desc vop_lookup_desc;
#define VOP_LOOKUP(dvp, vpp, cnp) _VOP_LOOKUP(dvp, vpp, cnp)
static __inline int _VOP_LOOKUP(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp)
{
	struct vop_lookup_args a;
	a.a_desc = VDESC(vop_lookup);
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	return (VCALL(dvp, VOFFSET(vop_lookup), &a));
}

struct vop_cachedlookup_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
};
extern struct vnodeop_desc vop_cachedlookup_desc;
#define VOP_CACHEDLOOKUP(dvp, vpp, cnp) _VOP_CACHEDLOOKUP(dvp, vpp, cnp)
static __inline int _VOP_CACHEDLOOKUP(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp)
{
	struct vop_cachedlookup_args a;
	a.a_desc = VDESC(vop_cachedlookup);
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	return (VCALL(dvp, VOFFSET(vop_cachedlookup), &a));
}

struct vop_create_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
};
extern struct vnodeop_desc vop_create_desc;
#define VOP_CREATE(dvp, vpp, cnp, vap) _VOP_CREATE(dvp, vpp, cnp, vap)
static __inline int _VOP_CREATE(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp, struct vattr *vap)
{
	struct vop_create_args a;
	a.a_desc = VDESC(vop_create);
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	return (VCALL(dvp, VOFFSET(vop_create), &a));
}

struct vop_whiteout_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct componentname *a_cnp;
	int a_flags;
};
extern struct vnodeop_desc vop_whiteout_desc;
#define VOP_WHITEOUT(dvp, cnp, flags) _VOP_WHITEOUT(dvp, cnp, flags)
static __inline int _VOP_WHITEOUT(struct vnode *dvp, struct componentname *cnp, int flags)
{
	struct vop_whiteout_args a;
	a.a_desc = VDESC(vop_whiteout);
	a.a_dvp = dvp;
	a.a_cnp = cnp;
	a.a_flags = flags;
	return (VCALL(dvp, VOFFSET(vop_whiteout), &a));
}

struct vop_mknod_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
};
extern struct vnodeop_desc vop_mknod_desc;
#define VOP_MKNOD(dvp, vpp, cnp, vap) _VOP_MKNOD(dvp, vpp, cnp, vap)
static __inline int _VOP_MKNOD(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp, struct vattr *vap)
{
	struct vop_mknod_args a;
	a.a_desc = VDESC(vop_mknod);
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	return (VCALL(dvp, VOFFSET(vop_mknod), &a));
}

struct vop_mkcomplex_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
	u_long a_type;
};
extern struct vnodeop_desc vop_mkcomplex_desc;
#define VOP_MKCOMPLEX(dvp, vpp, cnp, vap, type) _VOP_MKCOMPLEX(dvp, vpp, cnp, vap, type)
static __inline int _VOP_MKCOMPLEX(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp, struct vattr *vap, u_long type)
{
	struct vop_mkcomplex_args a;
	a.a_desc = VDESC(vop_mkcomplex);
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_type = type;
	return (VCALL(dvp, VOFFSET(vop_mkcomplex), &a));
}

struct vop_open_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_mode;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_open_desc;
#define VOP_OPEN(vp, mode, cred, p) _VOP_OPEN(vp, mode, cred, p)
static __inline int _VOP_OPEN(struct vnode *vp, int mode, struct ucred *cred, struct proc *p)
{
	struct vop_open_args a;
	a.a_desc = VDESC(vop_open);
	a.a_vp = vp;
	a.a_mode = mode;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_open), &a));
}

struct vop_close_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_fflag;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_close_desc;
#define VOP_CLOSE(vp, fflag, cred, p) _VOP_CLOSE(vp, fflag, cred, p)
static __inline int _VOP_CLOSE(struct vnode *vp, int fflag, struct ucred *cred, struct proc *p)
{
	struct vop_close_args a;
	a.a_desc = VDESC(vop_close);
	a.a_vp = vp;
	a.a_fflag = fflag;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_close), &a));
}

struct vop_access_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_mode;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_access_desc;
#define VOP_ACCESS(vp, mode, cred, p) _VOP_ACCESS(vp, mode, cred, p)
static __inline int _VOP_ACCESS(struct vnode *vp, int mode, struct ucred *cred, struct proc *p)
{
	struct vop_access_args a;
	a.a_desc = VDESC(vop_access);
	a.a_vp = vp;
	a.a_mode = mode;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_access), &a));
}

struct vop_getattr_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_getattr_desc;
#define VOP_GETATTR(vp, vap, cred, p) _VOP_GETATTR(vp, vap, cred, p)
static __inline int _VOP_GETATTR(struct vnode *vp, struct vattr *vap, struct ucred *cred, struct proc *p)
{
	struct vop_getattr_args a;
	a.a_desc = VDESC(vop_getattr);
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_getattr), &a));
}

struct vop_setattr_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct vattr *a_vap;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_setattr_desc;
#define VOP_SETATTR(vp, vap, cred, p) _VOP_SETATTR(vp, vap, cred, p)
static __inline int _VOP_SETATTR(struct vnode *vp, struct vattr *vap, struct ucred *cred, struct proc *p)
{
	struct vop_setattr_args a;
	a.a_desc = VDESC(vop_setattr);
	a.a_vp = vp;
	a.a_vap = vap;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_setattr), &a));
}

struct vop_getattrlist_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_getattrlist_desc;
#define VOP_GETATTRLIST(vp, alist, uio, cred, p) _VOP_GETATTRLIST(vp, alist, uio, cred, p)
static __inline int _VOP_GETATTRLIST(struct vnode *vp, struct attrlist *alist, struct uio *uio, struct ucred *cred, struct proc *p)
{
	struct vop_getattrlist_args a;
	a.a_desc = VDESC(vop_getattrlist);
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_uio = uio;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_getattrlist), &a));
}

struct vop_setattrlist_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_setattrlist_desc;
#define VOP_SETATTRLIST(vp, alist, uio, cred, p) _VOP_SETATTRLIST(vp, alist, uio, cred, p)
static __inline int _VOP_SETATTRLIST(struct vnode *vp, struct attrlist *alist, struct uio *uio, struct ucred *cred, struct proc *p)
{
	struct vop_setattrlist_args a;
	a.a_desc = VDESC(vop_setattrlist);
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_uio = uio;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_setattrlist), &a));
}

struct vop_read_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct uio *a_uio;
	int a_ioflag;
	struct ucred *a_cred;
};
extern struct vnodeop_desc vop_read_desc;
#define VOP_READ(vp, uio, ioflag, cred) _VOP_READ(vp, uio, ioflag, cred)
static __inline int _VOP_READ(struct vnode *vp, struct uio *uio, int ioflag, struct ucred *cred)
{
	struct vop_read_args a;
	a.a_desc = VDESC(vop_read);
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_cred = cred;
	{
		int _err;
		extern int ubc_hold(struct vnode *vp);
		extern void ubc_rele(struct vnode *vp);
		int _didhold = ubc_hold(vp);
		_err = VCALL(vp, VOFFSET(vop_read), &a);
		if (_didhold)
			ubc_rele(vp);
		return (_err);
	}
}

struct vop_write_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct uio *a_uio;
	int a_ioflag;
	struct ucred *a_cred;
};
extern struct vnodeop_desc vop_write_desc;
#define VOP_WRITE(vp, uio, ioflag, cred) _VOP_WRITE(vp, uio, ioflag, cred)
static __inline int _VOP_WRITE(struct vnode *vp, struct uio *uio, int ioflag, struct ucred *cred)
{
	struct vop_write_args a;
	a.a_desc = VDESC(vop_write);
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_ioflag = ioflag;
	a.a_cred = cred;
	{
		int _err;
		extern int ubc_hold(struct vnode *vp);
		extern void ubc_rele(struct vnode *vp);
		int _didhold = ubc_hold(vp);
		_err = VCALL(vp, VOFFSET(vop_write), &a);
		if (_didhold)
			ubc_rele(vp);
		return (_err);
	}
}

struct vop_lease_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct proc *a_p;
	struct ucred *a_cred;
	int a_flag;
};
extern struct vnodeop_desc vop_lease_desc;
#define VOP_LEASE(vp, p, cred, flag) _VOP_LEASE(vp, p, cred, flag)
static __inline int _VOP_LEASE(struct vnode *vp, struct proc *p, struct ucred *cred, int flag)
{
	struct vop_lease_args a;
	a.a_desc = VDESC(vop_lease);
	a.a_vp = vp;
	a.a_p = p;
	a.a_cred = cred;
	a.a_flag = flag;
	return (VCALL(vp, VOFFSET(vop_lease), &a));
}

struct vop_ioctl_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	u_long a_command;
	caddr_t a_data;
	int a_fflag;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_ioctl_desc;
#define VOP_IOCTL(vp, command, data, fflag, cred, p) _VOP_IOCTL(vp, command, data, fflag, cred, p)
static __inline int _VOP_IOCTL(struct vnode *vp, u_long command, caddr_t data, int fflag, struct ucred *cred, struct proc *p)
{
	struct vop_ioctl_args a;
	a.a_desc = VDESC(vop_ioctl);
	a.a_vp = vp;
	a.a_command = command;
	a.a_data = data;
	a.a_fflag = fflag;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_ioctl), &a));
}

struct vop_select_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_which;
	int a_fflags;
	struct ucred *a_cred;
	void *a_wql;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_select_desc;
#define VOP_SELECT(vp, which, fflags, cred, wql, p) _VOP_SELECT(vp, which, fflags, cred, wql, p)
static __inline int _VOP_SELECT(struct vnode *vp, int which, int fflags, struct ucred *cred, void *wql, struct proc *p)
{
	struct vop_select_args a;
	a.a_desc = VDESC(vop_select);
	a.a_vp = vp;
	a.a_which = which;
	a.a_fflags = fflags;
	a.a_cred = cred;
	a.a_wql = wql;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_select), &a));
}

struct vop_exchange_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_fvp;
	struct vnode *a_tvp;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_exchange_desc;
#define VOP_EXCHANGE(fvp, tvp, cred, p) _VOP_EXCHANGE(fvp, tvp, cred, p)
static __inline int _VOP_EXCHANGE(struct vnode *fvp, struct vnode *tvp, struct ucred *cred, struct proc *p)
{
	struct vop_exchange_args a;
	a.a_desc = VDESC(vop_exchange);
	a.a_fvp = fvp;
	a.a_tvp = tvp;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(fvp, VOFFSET(vop_exchange), &a));
}

struct vop_revoke_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_flags;
};
extern struct vnodeop_desc vop_revoke_desc;
#define VOP_REVOKE(vp, flags) _VOP_REVOKE(vp, flags)
static __inline int _VOP_REVOKE(struct vnode *vp, int flags)
{
	struct vop_revoke_args a;
	a.a_desc = VDESC(vop_revoke);
	a.a_vp = vp;
	a.a_flags = flags;
	return (VCALL(vp, VOFFSET(vop_revoke), &a));
}

struct vop_mmap_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_fflags;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_mmap_desc;
#define VOP_MMAP(vp, fflags, cred, p) _VOP_MMAP(vp, fflags, cred, p)
static __inline int _VOP_MMAP(struct vnode *vp, int fflags, struct ucred *cred, struct proc *p)
{
	struct vop_mmap_args a;
	a.a_desc = VDESC(vop_mmap);
	a.a_vp = vp;
	a.a_fflags = fflags;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_mmap), &a));
}

struct vop_fsync_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct ucred *a_cred;
	int a_waitfor;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_fsync_desc;
#define VOP_FSYNC(vp, cred, waitfor, p) _VOP_FSYNC(vp, cred, waitfor, p)
static __inline int _VOP_FSYNC(struct vnode *vp, struct ucred *cred, int waitfor, struct proc *p)
{
	struct vop_fsync_args a;
	a.a_desc = VDESC(vop_fsync);
	a.a_vp = vp;
	a.a_cred = cred;
	a.a_waitfor = waitfor;
	a.a_p = p;
	{
		int _err;
		extern int ubc_hold(struct vnode *vp);
		extern void ubc_rele(struct vnode *vp);
		int _didhold = ubc_hold(vp);
		_err = VCALL(vp, VOFFSET(vop_fsync), &a);
		if (_didhold)
			ubc_rele(vp);
		return (_err);
	}
}

struct vop_seek_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	off_t a_oldoff;
	off_t a_newoff;
	struct ucred *a_cred;
};
extern struct vnodeop_desc vop_seek_desc;
#define VOP_SEEK(vp, oldoff, newoff, cred) _VOP_SEEK(vp, oldoff, newoff, cred)
static __inline int _VOP_SEEK(struct vnode *vp, off_t oldoff, off_t newoff, struct ucred *cred)
{
	struct vop_seek_args a;
	a.a_desc = VDESC(vop_seek);
	a.a_vp = vp;
	a.a_oldoff = oldoff;
	a.a_newoff = newoff;
	a.a_cred = cred;
	return (VCALL(vp, VOFFSET(vop_seek), &a));
}

struct vop_remove_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
};
extern struct vnodeop_desc vop_remove_desc;
#define VOP_REMOVE(dvp, vp, cnp) _VOP_REMOVE(dvp, vp, cnp)
static __inline int _VOP_REMOVE(struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
	struct vop_remove_args a;
	a.a_desc = VDESC(vop_remove);
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	return (VCALL(dvp, VOFFSET(vop_remove), &a));
}

struct vop_link_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct vnode *a_tdvp;
	struct componentname *a_cnp;
};
extern struct vnodeop_desc vop_link_desc;
#define VOP_LINK(vp, tdvp, cnp) _VOP_LINK(vp, tdvp, cnp)
static __inline int _VOP_LINK(struct vnode *vp, struct vnode *tdvp, struct componentname *cnp)
{
	struct vop_link_args a;
	a.a_desc = VDESC(vop_link);
	a.a_vp = vp;
	a.a_tdvp = tdvp;
	a.a_cnp = cnp;
	return (VCALL(vp, VOFFSET(vop_link), &a));
}

struct vop_rename_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_fdvp;
	struct vnode *a_fvp;
	struct componentname *a_fcnp;
	struct vnode *a_tdvp;
	struct vnode *a_tvp;
	struct componentname *a_tcnp;
};
extern struct vnodeop_desc vop_rename_desc;
#define VOP_RENAME(fdvp, fvp, fcnp, tdvp, tvp, tcnp) _VOP_RENAME(fdvp, fvp, fcnp, tdvp, tvp, tcnp)
static __inline int _VOP_RENAME(struct vnode *fdvp, struct vnode *fvp, struct componentname *fcnp, struct vnode *tdvp, struct vnode *tvp, struct componentname *tcnp)
{
	struct vop_rename_args a;
	a.a_desc = VDESC(vop_rename);
	a.a_fdvp = fdvp;
	a.a_fvp = fvp;
	a.a_fcnp = fcnp;
	a.a_tdvp = tdvp;
	a.a_tvp = tvp;
	a.a_tcnp = tcnp;
	return (VCALL(fdvp, VOFFSET(vop_rename), &a));
}

struct vop_mkdir_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
};
extern struct vnodeop_desc vop_mkdir_desc;
#define VOP_MKDIR(dvp, vpp, cnp, vap) _VOP_MKDIR(dvp, vpp, cnp, vap)
static __inline int _VOP_MKDIR(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp, struct vattr *vap)
{
	struct vop_mkdir_args a;
	a.a_desc = VDESC(vop_mkdir);
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	return (VCALL(dvp, VOFFSET(vop_mkdir), &a));
}

struct vop_rmdir_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode *a_vp;
	struct componentname *a_cnp;
};
extern struct vnodeop_desc vop_rmdir_desc;
#define VOP_RMDIR(dvp, vp, cnp) _VOP_RMDIR(dvp, vp, cnp)
static __inline int _VOP_RMDIR(struct vnode *dvp, struct vnode *vp, struct componentname *cnp)
{
	struct vop_rmdir_args a;
	a.a_desc = VDESC(vop_rmdir);
	a.a_dvp = dvp;
	a.a_vp = vp;
	a.a_cnp = cnp;
	return (VCALL(dvp, VOFFSET(vop_rmdir), &a));
}

struct vop_symlink_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct vnode **a_vpp;
	struct componentname *a_cnp;
	struct vattr *a_vap;
	char *a_target;
};
extern struct vnodeop_desc vop_symlink_desc;
#define VOP_SYMLINK(dvp, vpp, cnp, vap, target) _VOP_SYMLINK(dvp, vpp, cnp, vap, target)
static __inline int _VOP_SYMLINK(struct vnode *dvp, struct vnode **vpp, struct componentname *cnp, struct vattr *vap, char *target)
{
	struct vop_symlink_args a;
	a.a_desc = VDESC(vop_symlink);
	a.a_dvp = dvp;
	a.a_vpp = vpp;
	a.a_cnp = cnp;
	a.a_vap = vap;
	a.a_target = target;
	return (VCALL(dvp, VOFFSET(vop_symlink), &a));
}

struct vop_readdir_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
	int *a_eofflag;
	int *a_ncookies;
	u_long **a_cookies;
};
extern struct vnodeop_desc vop_readdir_desc;
#define VOP_READDIR(vp, uio, cred, eofflag, ncookies, cookies) _VOP_READDIR(vp, uio, cred, eofflag, ncookies, cookies)
static __inline int _VOP_READDIR(struct vnode *vp, struct uio *uio, struct ucred *cred, int *eofflag, int *ncookies, u_long **cookies)
{
	struct vop_readdir_args a;
	a.a_desc = VDESC(vop_readdir);
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_cred = cred;
	a.a_eofflag = eofflag;
	a.a_ncookies = ncookies;
	a.a_cookies = cookies;
	return (VCALL(vp, VOFFSET(vop_readdir), &a));
}

struct vop_readdirattr_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct attrlist *a_alist;
	struct uio *a_uio;
	u_long a_maxcount;
	u_long a_options;
	u_long *a_newstate;
	int *a_eofflag;
	u_long *a_actualcount;
	u_long **a_cookies;
	struct ucred *a_cred;
};
extern struct vnodeop_desc vop_readdirattr_desc;
#define VOP_READDIRATTR(vp, alist, uio, maxcount, options, newstate, eofflag, actualcount, cookies, cred) _VOP_READDIRATTR(vp, alist, uio, maxcount, options, newstate, eofflag, actualcount, cookies, cred)
static __inline int _VOP_READDIRATTR(struct vnode *vp, struct attrlist *alist, struct uio *uio, u_long maxcount, u_long options, u_long *newstate, int *eofflag, u_long *actualcount, u_long **cookies, struct ucred *cred)
{
	struct vop_readdirattr_args a;
	a.a_desc = VDESC(vop_readdirattr);
	a.a_vp = vp;
	a.a_alist = alist;
	a.a_uio = uio;
	a.a_maxcount = maxcount;
	a.a_options = options;
	a.a_newstate = newstate;
	a.a_eofflag = eofflag;
	a.a_actualcount = actualcount;
	a.a_cookies = cookies;
	a.a_cred = cred;
	return (VCALL(vp, VOFFSET(vop_readdirattr), &a));
}

struct vop_readlink_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
};
extern struct vnodeop_desc vop_readlink_desc;
#define VOP_READLINK(vp, uio, cred) _VOP_READLINK(vp, uio, cred)
static __inline int _VOP_READLINK(struct vnode *vp, struct uio *uio, struct ucred *cred)
{
	struct vop_readlink_args a;
	a.a_desc = VDESC(vop_readlink);
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_cred = cred;
	return (VCALL(vp, VOFFSET(vop_readlink), &a));
}

struct vop_abortop_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_dvp;
	struct componentname *a_cnp;
};
extern struct vnodeop_desc vop_abortop_desc;
#define VOP_ABORTOP(dvp, cnp) _VOP_ABORTOP(dvp, cnp)
static __inline int _VOP_ABORTOP(struct vnode *dvp, struct componentname *cnp)
{
	struct vop_abortop_args a;
	a.a_desc = VDESC(vop_abortop);
	a.a_dvp = dvp;
	a.a_cnp = cnp;
	return (VCALL(dvp, VOFFSET(vop_abortop), &a));
}

struct vop_inactive_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_inactive_desc;
#define VOP_INACTIVE(vp, p) _VOP_INACTIVE(vp, p)
static __inline int _VOP_INACTIVE(struct vnode *vp, struct proc *p)
{
	struct vop_inactive_args a;
	a.a_desc = VDESC(vop_inactive);
	a.a_vp = vp;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_inactive), &a));
}

struct vop_reclaim_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_reclaim_desc;
#define VOP_RECLAIM(vp, p) _VOP_RECLAIM(vp, p)
static __inline int _VOP_RECLAIM(struct vnode *vp, struct proc *p)
{
	struct vop_reclaim_args a;
	a.a_desc = VDESC(vop_reclaim);
	a.a_vp = vp;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_reclaim), &a));
}

struct vop_lock_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_flags;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_lock_desc;
#define VOP_LOCK(vp, flags, p) _VOP_LOCK(vp, flags, p)
static __inline int _VOP_LOCK(struct vnode *vp, int flags, struct proc *p)
{
	struct vop_lock_args a;
	a.a_desc = VDESC(vop_lock);
	a.a_vp = vp;
	a.a_flags = flags;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_lock), &a));
}

struct vop_unlock_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_flags;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_unlock_desc;
#define VOP_UNLOCK(vp, flags, p) _VOP_UNLOCK(vp, flags, p)
static __inline int _VOP_UNLOCK(struct vnode *vp, int flags, struct proc *p)
{
	struct vop_unlock_args a;
	a.a_desc = VDESC(vop_unlock);
	a.a_vp = vp;
	a.a_flags = flags;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_unlock), &a));
}

struct vop_bmap_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	daddr_t a_bn;
	struct vnode **a_vpp;
	daddr_t *a_bnp;
	int *a_runp;
};
extern struct vnodeop_desc vop_bmap_desc;
#define VOP_BMAP(vp, bn, vpp, bnp, runp) _VOP_BMAP(vp, bn, vpp, bnp, runp)
static __inline int _VOP_BMAP(struct vnode *vp, daddr_t bn, struct vnode **vpp, daddr_t *bnp, int *runp)
{
	struct vop_bmap_args a;
	a.a_desc = VDESC(vop_bmap);
	a.a_vp = vp;
	a.a_bn = bn;
	a.a_vpp = vpp;
	a.a_bnp = bnp;
	a.a_runp = runp;
	return (VCALL(vp, VOFFSET(vop_bmap), &a));
}

struct vop_print_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
};
extern struct vnodeop_desc vop_print_desc;
#define VOP_PRINT(vp) _VOP_PRINT(vp)
static __inline int _VOP_PRINT(struct vnode *vp)
{
	struct vop_print_args a;
	a.a_desc = VDESC(vop_print);
	a.a_vp = vp;
	return (VCALL(vp, VOFFSET(vop_print), &a));
}

struct vop_islocked_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
};
extern struct vnodeop_desc vop_islocked_desc;
#define VOP_ISLOCKED(vp) _VOP_ISLOCKED(vp)
static __inline int _VOP_ISLOCKED(struct vnode *vp)
{
	struct vop_islocked_args a;
	a.a_desc = VDESC(vop_islocked);
	a.a_vp = vp;
	return (VCALL(vp, VOFFSET(vop_islocked), &a));
}

struct vop_pathconf_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	int a_name;
	register_t *a_retval;
};
extern struct vnodeop_desc vop_pathconf_desc;
#define VOP_PATHCONF(vp, name, retval) _VOP_PATHCONF(vp, name, retval)
static __inline int _VOP_PATHCONF(struct vnode *vp, int name, register_t *retval)
{
	struct vop_pathconf_args a;
	a.a_desc = VDESC(vop_pathconf);
	a.a_vp = vp;
	a.a_name = name;
	a.a_retval = retval;
	return (VCALL(vp, VOFFSET(vop_pathconf), &a));
}

struct vop_advlock_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	caddr_t a_id;
	int a_op;
	struct flock *a_fl;
	int a_flags;
};
extern struct vnodeop_desc vop_advlock_desc;
#define VOP_ADVLOCK(vp, id, op, fl, flags) _VOP_ADVLOCK(vp, id, op, fl, flags)
static __inline int _VOP_ADVLOCK(struct vnode *vp, caddr_t id, int op, struct flock *fl, int flags)
{
	struct vop_advlock_args a;
	a.a_desc = VDESC(vop_advlock);
	a.a_vp = vp;
	a.a_id = id;
	a.a_op = op;
	a.a_fl = fl;
	a.a_flags = flags;
	return (VCALL(vp, VOFFSET(vop_advlock), &a));
}

struct vop_blkatoff_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	off_t a_offset;
	char **a_res;
	struct buf **a_bpp;
};
extern struct vnodeop_desc vop_blkatoff_desc;
#define VOP_BLKATOFF(vp, offset, res, bpp) _VOP_BLKATOFF(vp, offset, res, bpp)
static __inline int _VOP_BLKATOFF(struct vnode *vp, off_t offset, char **res, struct buf **bpp)
{
	struct vop_blkatoff_args a;
	a.a_desc = VDESC(vop_blkatoff);
	a.a_vp = vp;
	a.a_offset = offset;
	a.a_res = res;
	a.a_bpp = bpp;
	return (VCALL(vp, VOFFSET(vop_blkatoff), &a));
}

struct vop_valloc_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_pvp;
	int a_mode;
	struct ucred *a_cred;
	struct vnode **a_vpp;
};
extern struct vnodeop_desc vop_valloc_desc;
#define VOP_VALLOC(pvp, mode, cred, vpp) _VOP_VALLOC(pvp, mode, cred, vpp)
static __inline int _VOP_VALLOC(struct vnode *pvp, int mode, struct ucred *cred, struct vnode **vpp)
{
	struct vop_valloc_args a;
	a.a_desc = VDESC(vop_valloc);
	a.a_pvp = pvp;
	a.a_mode = mode;
	a.a_cred = cred;
	a.a_vpp = vpp;
	return (VCALL(pvp, VOFFSET(vop_valloc), &a));
}

struct vop_reallocblks_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct cluster_save *a_buflist;
};
extern struct vnodeop_desc vop_reallocblks_desc;
#define VOP_REALLOCBLKS(vp, buflist) _VOP_REALLOCBLKS(vp, buflist)
static __inline int _VOP_REALLOCBLKS(struct vnode *vp, struct cluster_save *buflist)
{
	struct vop_reallocblks_args a;
	a.a_desc = VDESC(vop_reallocblks);
	a.a_vp = vp;
	a.a_buflist = buflist;
	return (VCALL(vp, VOFFSET(vop_reallocblks), &a));
}

struct vop_vfree_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_pvp;
	ino_t a_ino;
	int a_mode;
};
extern struct vnodeop_desc vop_vfree_desc;
#define VOP_VFREE(pvp, ino, mode) _VOP_VFREE(pvp, ino, mode)
static __inline int _VOP_VFREE(struct vnode *pvp, ino_t ino, int mode)
{
	struct vop_vfree_args a;
	a.a_desc = VDESC(vop_vfree);
	a.a_pvp = pvp;
	a.a_ino = ino;
	a.a_mode = mode;
	return (VCALL(pvp, VOFFSET(vop_vfree), &a));
}

struct vop_truncate_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	off_t a_length;
	int a_flags;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_truncate_desc;
#define VOP_TRUNCATE(vp, length, flags, cred, p) _VOP_TRUNCATE(vp, length, flags, cred, p)
static __inline int _VOP_TRUNCATE(struct vnode *vp, off_t length, int flags, struct ucred *cred, struct proc *p)
{
	struct vop_truncate_args a;
	a.a_desc = VDESC(vop_truncate);
	a.a_vp = vp;
	a.a_length = length;
	a.a_flags = flags;
	a.a_cred = cred;
	a.a_p = p;
	{
		int _err;
		extern int ubc_hold(struct vnode *vp);
		extern void ubc_rele(struct vnode *vp);
		int _didhold = ubc_hold(vp);
		_err = VCALL(vp, VOFFSET(vop_truncate), &a);
		if (_didhold)
			ubc_rele(vp);
		return (_err);
	}
}

struct vop_allocate_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	off_t a_length;
	u_int32_t a_flags;
	off_t *a_bytesallocated;
	off_t a_offset;
	struct ucred *a_cred;
	struct proc *a_p;
};
extern struct vnodeop_desc vop_allocate_desc;
#define VOP_ALLOCATE(vp, length, flags, bytesallocated, offset, cred, p) _VOP_ALLOCATE(vp, length, flags, bytesallocated, offset, cred, p)
static __inline int _VOP_ALLOCATE(struct vnode *vp, off_t length, u_int32_t flags, off_t *bytesallocated, off_t offset, struct ucred *cred, struct proc *p)
{
	struct vop_allocate_args a;
	a.a_desc = VDESC(vop_allocate);
	a.a_vp = vp;
	a.a_length = length;
	a.a_flags = flags;
	a.a_bytesallocated = bytesallocated;
	a.a_offset = offset;
	a.a_cred = cred;
	a.a_p = p;
	return (VCALL(vp, VOFFSET(vop_allocate), &a));
}

struct vop_update_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct timeval *a_access;
	struct timeval *a_modify;
	int a_waitfor;
};
extern struct vnodeop_desc vop_update_desc;
#define VOP_UPDATE(vp, access, modify, waitfor) _VOP_UPDATE(vp, access, modify, waitfor)
static __inline int _VOP_UPDATE(struct vnode *vp, struct timeval *access, struct timeval *modify, int waitfor)
{
	struct vop_update_args a;
	a.a_desc = VDESC(vop_update);
	a.a_vp = vp;
	a.a_access = access;
	a.a_modify = modify;
	a.a_waitfor = waitfor;
	return (VCALL(vp, VOFFSET(vop_update), &a));
}

struct vop_pgrd_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
};
extern struct vnodeop_desc vop_pgrd_desc;
#define VOP_PGRD(vp, uio, cred) _VOP_PGRD(vp, uio, cred)
static __inline int _VOP_PGRD(struct vnode *vp, struct uio *uio, struct ucred *cred)
{
	struct vop_pgrd_args a;
	a.a_desc = VDESC(vop_pgrd);
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_cred = cred;
	return (VCALL(vp, VOFFSET(vop_pgrd), &a));
}

struct vop_pgwr_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	struct uio *a_uio;
	struct ucred *a_cred;
	vm_offset_t a_offset;
};
extern struct vnodeop_desc vop_pgwr_desc;
#define VOP_PGWR(vp, uio, cred, offset) _VOP_PGWR(vp, uio, cred, offset)
static __inline int _VOP_PGWR(struct vnode *vp, struct uio *uio, struct ucred *cred, vm_offset_t offset)
{
	struct vop_pgwr_args a;
	a.a_desc = VDESC(vop_pgwr);
	a.a_vp = vp;
	a.a_uio = uio;
	a.a_cred = cred;
	a.a_offset = offset;
	return (VCALL(vp, VOFFSET(vop_pgwr), &a));
}

struct vop_pagein_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	upl_t a_pl;
	vm_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	struct ucred *a_cred;
	int a_flags;
};
extern struct vnodeop_desc vop_pagein_desc;
#define VOP_PAGEIN(vp, pl, pl_offset, f_offset, size, cred, flags) _VOP_PAGEIN(vp, pl, pl_offset, f_offset, size, cred, flags)
static __inline int _VOP_PAGEIN(struct vnode *vp, upl_t pl, vm_offset_t pl_offset, off_t f_offset, size_t size, struct ucred *cred, int flags)
{
	struct vop_pagein_args a;
	a.a_desc = VDESC(vop_pagein);
	a.a_vp = vp;
	a.a_pl = pl;
	a.a_pl_offset = pl_offset;
	a.a_f_offset = f_offset;
	a.a_size = size;
	a.a_cred = cred;
	a.a_flags = flags;
	return (VCALL(vp, VOFFSET(vop_pagein), &a));
}

struct vop_pageout_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	upl_t a_pl;
	vm_offset_t a_pl_offset;
	off_t a_f_offset;
	size_t a_size;
	struct ucred *a_cred;
	int a_flags;
};
extern struct vnodeop_desc vop_pageout_desc;
#define VOP_PAGEOUT(vp, pl, pl_offset, f_offset, size, cred, flags) _VOP_PAGEOUT(vp, pl, pl_offset, f_offset, size, cred, flags)
static __inline int _VOP_PAGEOUT(struct vnode *vp, upl_t pl, vm_offset_t pl_offset, off_t f_offset, size_t size, struct ucred *cred, int flags)
{
	struct vop_pageout_args a;
	a.a_desc = VDESC(vop_pageout);
	a.a_vp = vp;
	a.a_pl = pl;
	a.a_pl_offset = pl_offset;
	a.a_f_offset = f_offset;
	a.a_size = size;
	a.a_cred = cred;
	a.a_flags = flags;
	return (VCALL(vp, VOFFSET(vop_pageout), &a));
}

struct vop_devblocksize_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	register_t *a_retval;
};
extern struct vnodeop_desc vop_devblocksize_desc;
#define VOP_DEVBLOCKSIZE(vp, retval) _VOP_DEVBLOCKSIZE(vp, retval)
static __inline int _VOP_DEVBLOCKSIZE(struct vnode *vp, register_t *retval)
{
	struct vop_devblocksize_args a;
	a.a_desc = VDESC(vop_devblocksize);
	a.a_vp = vp;
	a.a_retval = retval;
	return (VCALL(vp, VOFFSET(vop_devblocksize), &a));
}

struct vop_searchfs_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	void *a_searchparams1;
	void *a_searchparams2;
	struct attrlist *a_searchattrs;
	u_long a_maxmatches;
	struct timeval *a_timelimit;
	struct attrlist *a_returnattrs;
	u_long *a_nummatches;
	u_long a_scriptcode;
	u_long a_options;
	struct uio *a_uio;
	struct searchstate *a_searchstate;
};
extern struct vnodeop_desc vop_searchfs_desc;
#define VOP_SEARCHFS(vp, searchparams1, searchparams2, searchattrs, maxmatches, timelimit, returnattrs, nummatches, scriptcode, options, uio, searchstate) _VOP_SEARCHFS(vp, searchparams1, searchparams2, searchattrs, maxmatches, timelimit, returnattrs, nummatches, scriptcode, options, uio, searchstate)
static __inline int _VOP_SEARCHFS(struct vnode *vp, void *searchparams1, void *searchparams2, struct attrlist *searchattrs, u_long maxmatches, struct timeval *timelimit, struct attrlist *returnattrs, u_long *nummatches, u_long scriptcode, u_long options, struct uio *uio, struct searchstate *searchstate)
{
	struct vop_searchfs_args a;
	a.a_desc = VDESC(vop_searchfs);
	a.a_vp = vp;
	a.a_searchparams1 = searchparams1;
	a.a_searchparams2 = searchparams2;
	a.a_searchattrs = searchattrs;
	a.a_maxmatches = maxmatches;
	a.a_timelimit = timelimit;
	a.a_returnattrs = returnattrs;
	a.a_nummatches = nummatches;
	a.a_scriptcode = scriptcode;
	a.a_options = options;
	a.a_uio = uio;
	a.a_searchstate = searchstate;
	return (VCALL(vp, VOFFSET(vop_searchfs), &a));
}

struct vop_copyfile_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_fvp;
	struct vnode *a_tdvp;
	struct vnode *a_tvp;
	struct componentname *a_tcnp;
	int a_mode;
	int a_flags;
};
extern struct vnodeop_desc vop_copyfile_desc;
#define VOP_COPYFILE(fvp, tdvp, tvp, tcnp, mode, flags) _VOP_COPYFILE(fvp, tdvp, tvp, tcnp, mode, flags)
static __inline int _VOP_COPYFILE(struct vnode *fvp, struct vnode *tdvp, struct vnode *tvp, struct componentname *tcnp, int mode, int flags)
{
	struct vop_copyfile_args a;
	a.a_desc = VDESC(vop_copyfile);
	a.a_fvp = fvp;
	a.a_tdvp = tdvp;
	a.a_tvp = tvp;
	a.a_tcnp = tcnp;
	a.a_mode = mode;
	a.a_flags = flags;
	return (VCALL(fvp, VOFFSET(vop_copyfile), &a));
}

struct vop_blktooff_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	daddr_t a_lblkno;
	off_t *a_offset;
};
extern struct vnodeop_desc vop_blktooff_desc;
#define VOP_BLKTOOFF(vp, lblkno, offset) _VOP_BLKTOOFF(vp, lblkno, offset)
static __inline int _VOP_BLKTOOFF(struct vnode *vp, daddr_t lblkno, off_t *offset)
{
	struct vop_blktooff_args a;
	a.a_desc = VDESC(vop_blktooff);
	a.a_vp = vp;
	a.a_lblkno = lblkno;
	a.a_offset = offset;
	return (VCALL(vp, VOFFSET(vop_blktooff), &a));
}

struct vop_offtoblk_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	off_t a_offset;
	daddr_t *a_lblkno;
};
extern struct vnodeop_desc vop_offtoblk_desc;
#define VOP_OFFTOBLK(vp, offset, lblkno) _VOP_OFFTOBLK(vp, offset, lblkno)
static __inline int _VOP_OFFTOBLK(struct vnode *vp, off_t offset, daddr_t *lblkno)
{
	struct vop_offtoblk_args a;
	a.a_desc = VDESC(vop_offtoblk);
	a.a_vp = vp;
	a.a_offset = offset;
	a.a_lblkno = lblkno;
	return (VCALL(vp, VOFFSET(vop_offtoblk), &a));
}

struct vop_cmap_args {
	struct vnodeop_desc *a_desc;
	struct vnode *a_vp;
	off_t a_foffset;
	size_t a_size;
	daddr_t *a_bpn;
	size_t *a_run;
	void *a_poff;
};
extern struct vnodeop_desc vop_cmap_desc;
#define VOP_CMAP(vp, foffset, size, bpn, run, poff) _VOP_CMAP(vp, foffset, size, bpn, run, poff)
static __inline int _VOP_CMAP(struct vnode *vp, off_t foffset, size_t size, daddr_t *bpn, size_t *run, void *poff)
{
	struct vop_cmap_args a;
	a.a_desc = VDESC(vop_cmap);
	a.a_vp = vp;
	a.a_foffset = foffset;
	a.a_size = size;
	a.a_bpn = bpn;
	a.a_run = run;
	a.a_poff = poff;
	return (VCALL(vp, VOFFSET(vop_cmap), &a));
}

/* Special cases: */
#include <sys/buf.h>
#include <sys/vm.h>

struct vop_strategy_args {
	struct vnodeop_desc *a_desc;
	struct buf *a_bp;
};
extern struct vnodeop_desc vop_strategy_desc;
#define VOP_STRATEGY(bp) _VOP_STRATEGY(bp)
static __inline int _VOP_STRATEGY(struct buf *bp)
{
	struct vop_strategy_args a;
	a.a_desc = VDESC(vop_strategy);
	a.a_bp = bp;
	return (VCALL(bp->b_vp, VOFFSET(vop_strategy), &a));
}

struct vop_bwrite_args {
	struct vnodeop_desc *a_desc;
	struct buf *a_bp;
};
extern struct vnodeop_desc vop_bwrite_desc;
#define VOP_BWRITE(bp) _VOP_BWRITE(bp)
static __inline int _VOP_BWRITE(struct buf *bp)
{
	struct vop_bwrite_args a;
	a.a_desc = VDESC(vop_bwrite);
	a.a_bp = bp;
	return (VCALL(bp->b_vp, VOFFSET(vop_bwrite), &a));
}

/* End of special cases. */

#endif /* __APPLE_API_UNSTABLE */
#endif /* !_SYS_VNODE_IF_H_ */
