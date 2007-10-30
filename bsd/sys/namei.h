/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1985, 1989, 1991, 1993
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
 *	@(#)namei.h	8.4 (Berkeley) 8/20/94
 */

#ifndef _SYS_NAMEI_H_
#define	_SYS_NAMEI_H_

#include <sys/appleapiopts.h>

#ifdef KERNEL
#define	LOCKLEAF	0x0004	/* lock inode on return */
#define	LOCKPARENT	0x0008	/* want parent vnode returned */
#define	WANTPARENT	0x0010	/* want parent vnode returned */
#endif


#ifdef BSD_KERNEL_PRIVATE

#include <sys/queue.h>
#include <sys/uio.h>
#include <sys/vnode.h>
#include <sys/mount.h>
#include <sys/filedesc.h>

#define PATHBUFLEN	256

/*
 * Encapsulation of namei parameters.
 */
struct nameidata {
	/*
	 * Arguments to namei/lookup.
	 */
	user_addr_t ni_dirp;		/* pathname pointer */
	enum	uio_seg ni_segflg;	/* location of pathname */
	/*
	 * Arguments to lookup.
	 */
	struct	vnode *ni_startdir;	/* starting directory */
	struct	vnode *ni_rootdir;	/* logical root directory */
        struct  vnode *ni_usedvp;       /* directory passed in via USEDVP */
	/*
	 * Results: returned from/manipulated by lookup
	 */
	struct	vnode *ni_vp;		/* vnode of result */
	struct	vnode *ni_dvp;		/* vnode of intermediate directory */
	/*
	 * Shared between namei and lookup/commit routines.
	 */
	u_int	ni_pathlen;		/* remaining chars in path */
	char	*ni_next;		/* next location in pathname */
        char	ni_pathbuf[PATHBUFLEN];
	u_long	ni_loopcnt;		/* count of symlinks encountered */

	struct componentname ni_cnd;
};

#ifdef KERNEL
/*
 * namei operational modifier flags, stored in ni_cnd.flags
 */
#define	NOCACHE		0x0020	/* name must not be left in cache */
#define	NOFOLLOW	0x0000	/* do not follow symbolic links (pseudo) */
#define	SHAREDLEAF	0x0080	/* OK to have shared leaf lock */
#define	MODMASK		0x00fc	/* mask of operational modifiers */
/*
 * Namei parameter descriptors.
 *
 * SAVESTART is set only by the callers of namei. It implies SAVENAME
 * plus the addition of saving the parent directory that contains the
 * name in ni_startdir. It allows repeated calls to lookup for the
 * name being sought. The caller is responsible for releasing the
 * buffer and for vrele'ing ni_startdir.
 */
#define	NOCROSSMOUNT	0x00000100 /* do not cross mount points */
#define	RDONLY		0x00000200 /* lookup with read-only semantics */
#define	HASBUF		0x00000400 /* has allocated pathname buffer */
#define	SAVENAME	0x00000800 /* save pathanme buffer */
#define	SAVESTART	0x00001000 /* save starting directory */
#define	ISSYMLINK	0x00010000 /* symlink needs interpretation */
#define DONOTAUTH	0x00020000 /* do not authorize during lookup */
#define	WILLBEDIR	0x00080000 /* new files will be dirs; allow trailing / */
#define	AUDITVNPATH1	0x00100000 /* audit the path/vnode info */
#define	AUDITVNPATH2	0x00200000 /* audit the path/vnode info */
#define	USEDVP		0x00400000 /* start the lookup at ndp.ni_dvp */
#define	PARAMASK	0x003fff00 /* mask of parameter descriptors */
#define FSNODELOCKHELD	0x01000000

/*
 * Initialization of an nameidata structure.
 */
#define NDINIT(ndp, op, flags, segflg, namep, ctx) { \
	(ndp)->ni_cnd.cn_nameiop = op; \
	(ndp)->ni_cnd.cn_flags = flags; \
	if ((segflg) == UIO_USERSPACE) { \
		(ndp)->ni_segflg = ((IS_64BIT_PROCESS(vfs_context_proc(ctx))) ? UIO_USERSPACE64 : UIO_USERSPACE32); \
	} \
	else if ((segflg) == UIO_SYSSPACE) { \
		(ndp)->ni_segflg = UIO_SYSSPACE32; \
	} \
	else { \
		(ndp)->ni_segflg = segflg; \
	} \
	(ndp)->ni_dirp = namep; \
	(ndp)->ni_cnd.cn_context = ctx; \
}
#endif /* KERNEL */

/*
 * This structure describes the elements in the cache of recent
 * names looked up by namei.
 */

#define	NCHNAMLEN	31	/* maximum name segment length we bother with */
#define NCHASHMASK	0x7fffffff

struct	namecache {
	TAILQ_ENTRY(namecache)	nc_entry;	/* chain of all entries */
	LIST_ENTRY(namecache)	nc_hash;	/* hash chain */
        LIST_ENTRY(namecache)	nc_child;	/* chain of ncp's that are children of a vp */
        union {
	  LIST_ENTRY(namecache)	 nc_link;	/* chain of ncp's that 'name' a vp */
	  TAILQ_ENTRY(namecache) nc_negentry;	/* chain of ncp's that 'name' a vp */
	} nc_un;
	vnode_t			nc_dvp;		/* vnode of parent of name */
	vnode_t			nc_vp;		/* vnode the name refers to */
        unsigned int		nc_whiteout:1,	/* name has whiteout applied */
	                        nc_hashval:31;	/* hashval of stringname */
	char		*	nc_name;	/* pointer to segment name in string cache */
};


#ifdef KERNEL

int	namei(struct nameidata *ndp);
void	nameidone(struct nameidata *);
int	lookup(struct nameidata *ndp);
int	relookup(struct vnode *dvp, struct vnode **vpp,
		struct componentname *cnp);

/*
 * namecache function prototypes
 */
void    cache_purgevfs(mount_t mp);
int		cache_lookup_path(struct nameidata *ndp, struct componentname *cnp, vnode_t dp,
			  vfs_context_t context, int *trailing_slash, int *dp_authorized);

void	vnode_cache_credentials(vnode_t vp, vfs_context_t context);
void	vnode_uncache_credentials(vnode_t vp);
int		reverse_lookup(vnode_t start_vp, vnode_t *lookup_vpp, 
				struct filedesc *fdp, vfs_context_t context, int *dp_authorized);

#endif /* KERNEL */

/*
 * Stats on usefulness of namei caches.
 */
struct	nchstats {
	long	ncs_goodhits;		/* hits that we can really use */
	long	ncs_neghits;		/* negative hits that we can use */
	long	ncs_badhits;		/* hits we must drop */
	long	ncs_miss;		/* misses */
	long	ncs_pass2;		/* names found with passes == 2 */
	long	ncs_2passes;		/* number of times we attempt it */
        long	ncs_stolen;
        long	ncs_enters;
        long	ncs_deletes;
        long	ncs_badvid;
};
#endif /* BSD_KERNEL_PRIVATE */

#endif /* !_SYS_NAMEI_H_ */
