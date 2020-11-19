/*
 * Copyright (c) 2006-2010 Apple Inc. All rights reserved.
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
#ifndef _IMAGEBOOT_H_
#define _IMAGEBOOT_H_

struct kalloc_heap;
struct vnode;

typedef enum imageboot_type {
	IMAGEBOOT_NONE,
	IMAGEBOOT_DMG,
	IMAGEBOOT_LOCKER,
} imageboot_type_t;

imageboot_type_t        imageboot_needed(void);
bool    imageboot_desired(void);
void    imageboot_setup(imageboot_type_t type);
int     imageboot_format_is_valid(const char *root_path);
int     imageboot_mount_image(const char *root_path, int height, imageboot_type_t type);
int     imageboot_pivot_image(const char *image_path, imageboot_type_t type, const char *mount_path, const char *outgoing_root_path, const bool rooted_dmg);
int     imageboot_read_file(struct kalloc_heap *kheap, const char *path, void **bufp, size_t *bufszp);
int     imageboot_read_file_from_offset(struct kalloc_heap *kheap, const char *path, off_t offset, void **bufp, size_t *bufszp);

struct vnode *
imgboot_get_image_file(const char *path, off_t *fsize, int *errp);

#define IMAGEBOOT_CONTAINER_ARG         "container-dmg"
#define IMAGEBOOT_ROOT_ARG              "root-dmg"
#define IMAGEBOOT_AUTHROOT_ARG          "auth-root-dmg"
#if CONFIG_LOCKERBOOT
#define IMAGEBOOT_LOCKER_ARG "locker"
#define LOCKERFS_NAME "lockerfs"
#endif

#endif
