/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/* Copyright 1998 Apple Computer, Inc.
 *
 * UFS byte swapping routines to make a big endian file system useful on a
 * little endian machine.
 *
 */

#ifdef	KERNEL_PRIVATE

#ifndef _UFS_BYTE_ORDER_H_
#define _UFS_BYTE_ORDER_H_

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_PRIVATE
#include <rev_endian_fs.h>
#include <sys/vnode.h>
#include <sys/buf.h>
#include <ufs/ufs/quota.h>
#include <ufs/ufs/inode.h>
#include <ufs/ffs/fs.h>

void byte_swap_longlongs __P((unsigned long long *, int));
void byte_swap_ints __P((int *, int));
void byte_swap_shorts __P((short *, int));

/* void byte_swap_superblock __P((struct fs *)); */
void byte_swap_sbin __P((struct fs *));
void byte_swap_sbout __P((struct fs *));
void byte_swap_csum __P((struct csum *));
void byte_swap_ocylgroup __P((struct cg *));
void byte_swap_cgin __P((struct cg *, struct fs *));
void byte_swap_cgout __P((struct cg *, struct fs *));

void byte_swap_inode_in __P((struct dinode *, struct inode *));
void byte_swap_inode_out __P((struct inode *, struct dinode *));

void byte_swap_dir_block_in __P((char *, int));
void byte_swap_dir_block_out __P((struct buf *));
void byte_swap_direct __P((struct direct *));
void byte_swap_dirtemplate_in __P((struct dirtemplate *));
void byte_swap_minidir_in __P((struct direct *));

#endif /* __APPLE_API_PRIVATE */
#endif /* _UFS_BYTE_ORDER_H_ */
#endif	/* KERNEL_PRIVATE */
