/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/*
 * Copyright (c) 1993, David Greenman
 * All rights reserved.
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
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
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
#ifndef _SYS_IMGACT_H_
#define	_SYS_IMGACT_H_

#define	IMG_SHSIZE	512	/* largest shell interpreter, in bytes */

struct proc;
struct nameidata;

struct image_params {
	user_addr_t	ip_user_fname;		/* argument */
	user_addr_t	ip_user_argv;		/* argument */
	user_addr_t	ip_user_envv;		/* argument */
	struct vnode	*ip_vp;			/* file */
	struct vnode_attr	*ip_vattr;	/* run file attributes */
	struct vnode_attr	*ip_origvattr;	/* invocation file attributes */
	char		*ip_vdata;		/* file data (up to one page) */
	int		ip_flags;		/* image flags */
	int		ip_argc;		/* argument count */
	char		*ip_argv;		/* argument vector beginning */
	int		ip_envc;		/* environment count */
	char		*ip_strings;		/* base address for strings */
	char		*ip_strendp;		/* current end pointer */
	char		*ip_strendargvp;	/* end of argv/start of envp */
	int		ip_strspace;		/* remaining space */
	user_size_t 	ip_arch_offset;		/* subfile offset in ip_vp */
	user_size_t 	ip_arch_size;		/* subfile length in ip_vp */
	char		ip_interp_name[IMG_SHSIZE];	/* interpreter name */

	/* Next two fields are for support of Classic... */
	char		*ip_p_comm;		/* optional alt p->p_comm */
	char		*ip_tws_cache_name;	/* task working set cache */
	struct vfs_context	*ip_vfs_context;	/* VFS context */
	struct nameidata *ip_ndp;		/* current nameidata */
	thread_t	ip_vfork_thread;	/* thread created, if vfork */
};

/*
 * Image flags
 */
#define	IMGPF_NONE	0x00000000		/* No flags */
#define	IMGPF_INTERPRET	0x00000001		/* Interpreter invoked */
#define	IMGPF_RESERVED1	0x00000002		/* reserved */
#define	IMGPF_WAS_64BIT	0x00000004		/* exec from a 64Bit binary */
#define	IMGPF_IS_64BIT	0x00000008		/* exec to a 64Bit binary */

#endif	/* !_SYS_IMGACT */
