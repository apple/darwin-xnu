/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

/*
 * Data structure definitions copied from dyld so that we can read dyld's saved UUID information
 * for each binary image not loaded from the shared cache during stackshots.
 */

/* From dyld/include/dyld_images.h */

struct user32_dyld_uuid_info {
	user32_addr_t	imageLoadAddress;	/* base address image is mapped into */
	uuid_t			imageUUID;			/* UUID of image */
};

struct user64_dyld_uuid_info {
	user64_addr_t	imageLoadAddress;	/* base address image is mapped into */
	uuid_t			imageUUID;			/* UUID of image */
};

struct user32_dyld_image_info {
	user32_addr_t	imageLoadAddress;	/* base address image is mapped int */
	user32_addr_t	imageFilePath;		/* path dyld used to load the image */
	user32_ulong_t	imageFileModDate;	/* time_t of image file */
};

struct user64_dyld_image_info {
	user64_addr_t	imageLoadAddress;	/* base address image is mapped int */
	user64_addr_t	imageFilePath;		/* path dyld used to load the image */
	user64_ulong_t	imageFileModDate;	/* time_t of image file */
};

// FIXME: dyld is in C++, and some of the fields in dyld_all_image_infos are C++ 
// native booleans.  There must be a better way...
typedef uint8_t bool;

struct user32_dyld_all_image_infos {
	uint32_t					version;
	uint32_t					infoArrayCount;
	user32_addr_t				infoArray;
	user32_addr_t				notification;
	bool						processDetachedFromSharedRegion;
	bool						libSystemInitialized;
	user32_addr_t				dyldImageLoadAddress;
	user32_addr_t				jitInfo;
	user32_addr_t				dyldVersion;
	user32_addr_t				errorMessage;
	user32_addr_t				terminationFlags;
	user32_addr_t				coreSymbolicationShmPage;
	user32_addr_t				systemOrderFlag;
	user32_size_t				uuidArrayCount; // dyld defines this as a uintptr_t despite it being a count
	user32_addr_t				uuidArray;
	user32_addr_t				dyldAllImageInfosAddress;
};

struct user64_dyld_all_image_infos {
	uint32_t					version;
	uint32_t					infoArrayCount;
	user64_addr_t				infoArray;
	user64_addr_t				notification;
	bool						processDetachedFromSharedRegion;
	bool						libSystemInitialized;
	user64_addr_t				dyldImageLoadAddress;
	user64_addr_t				jitInfo;
	user64_addr_t				dyldVersion;
	user64_addr_t				errorMessage;
	user64_addr_t				terminationFlags;
	user64_addr_t				coreSymbolicationShmPage;
	user64_addr_t				systemOrderFlag;
	user64_size_t				uuidArrayCount; // dyld defines this as a uintptr_t despite it being a count
	user64_addr_t				uuidArray;
	user64_addr_t				dyldAllImageInfosAddress;
};
