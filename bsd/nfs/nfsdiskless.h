/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1995 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1991, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 * This code is derived from software contributed to Berkeley by
 * Rick Macklem at The University of Guelph.
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
 *	@(#)nfsdiskless.h	8.2 (Berkeley) 3/30/95
 * FreeBSD-Id: nfsdiskless.h,v 1.10 1997/09/07 12:56:46 bde Exp $
 */


#ifndef _NFS_NFSDISKLESS_H_
#define _NFS_NFSDISKLESS_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
/*
 * Structure that must be initialized for a diskless nfs client.
 * This structure is used by nfs_mountroot() to set up the root and swap
 * vnodes plus do a partial ifconfig(8) and route(8) so that the critical net
 * interface can communicate with the server.
 * The primary bootstrap is expected to fill in the appropriate fields before
 * starting the kernel. Whether or not the swap area is nfs mounted is
 * determined by the value in swdevt[0]. (equal to NODEV --> swap over nfs)
 * Currently only works for AF_INET protocols.
 * NB: All fields are stored in net byte order to avoid hassles with
 * client/server byte ordering differences.
 */

/*
 * I have defined a new structure that can handle an NFS Version 3 file handle
 * but the kernel still expects the old Version 2 one to be provided. The
 * changes required in nfs_vfsops.c for using the new are documented there in
 * comments. (I felt that breaking network booting code by changing this
 * structure would not be prudent at this time, since almost all servers are
 * still Version 2 anyhow.)
 */
struct nfsv3_diskless {
	struct ifaliasreq myif;			/* Default interface */
	struct sockaddr_in mygateway;		/* Default gateway */
	struct nfs_args	swap_args;		/* Mount args for swap file */
	int		swap_fhsize;		/* Size of file handle */
	u_char		swap_fh[NFSX_V3FHMAX];	/* Swap file's file handle */
	struct sockaddr_in swap_saddr;		/* Address of swap server */
	char		swap_hostnam[MNAMELEN];	/* Host name for mount pt */
	int		swap_nblks;		/* Size of server swap file */
	struct ucred	swap_ucred;		/* Swap credentials */
	struct nfs_args	root_args;		/* Mount args for root fs */
	int		root_fhsize;		/* Size of root file handle */
	u_char		root_fh[NFSX_V3FHMAX];	/* File handle of root dir */
	struct sockaddr_in root_saddr;		/* Address of root server */
	char		root_hostnam[MNAMELEN];	/* Host name for mount pt */
	long		root_time;		/* Timestamp of root fs */
	char		my_hostnam[MAXHOSTNAMELEN]; /* Client host name */
};

struct nfs_dlmount {
	struct sockaddr_in ndm_saddr;  		/* Address of file server */
	char		ndm_host[MNAMELEN]; 	/* Host name for mount pt */
	char		*ndm_path; 		/* path name for mount pt */
	u_long		ndm_nfsv3;		/* NFSv3 or NFSv2? */
	u_long		ndm_sotype;		/* SOCK_STREAM or SOCK_DGRAM? */
	u_long		ndm_fhlen;		/* length of file handle */
	u_char		ndm_fh[NFSX_V3FHMAX];	/* The file's file handle */
};

struct nfs_diskless {
	struct nfs_dlmount nd_root; 	/* Mount info for root */
	struct nfs_dlmount nd_private; 	/* Mount info for private */
};

#endif /* __APPLE_API_PRIVATE */
#endif /* _NFS_NFSDISKLESS_H_ */
