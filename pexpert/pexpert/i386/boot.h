/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
#ifndef _PEXPERT_I386_BOOT_H
#define _PEXPERT_I386_BOOT_H

#include <stdint.h>

/*
 * What the booter leaves behind for the kernel.
 */

/*
 * Types of boot driver that may be loaded by the booter.
 */
enum {
    kBootDriverTypeInvalid = 0,
    kBootDriverTypeKEXT    = 1,
    kBootDriverTypeMKEXT   = 2
};

/*
 * Video information.
 */
struct boot_video {
    uint32_t v_baseAddr;	// Base address of video memory
    uint32_t v_display;    // Display Code
    uint32_t v_rowBytes;   // Number of bytes per pixel row
    uint32_t v_width;      // Width
    uint32_t v_height;     // Height
    uint32_t v_depth;      // Pixel Depth
};

typedef struct boot_video  boot_video;

/* Values for v_display */

#define VGA_TEXT_MODE         0
#define GRAPHICS_MODE     1
#define FB_TEXT_MODE          2


enum {
    kEfiReservedMemoryType	= 0,
    kEfiLoaderCode		= 1,
    kEfiLoaderData		= 2,
    kEfiBootServicesCode	= 3,
    kEfiBootServicesData	= 4,
    kEfiRuntimeServicesCode	= 5,
    kEfiRuntimeServicesData	= 6,
    kEfiConventionalMemory	= 7,
    kEfiUnusableMemory		= 8,
    kEfiACPIReclaimMemory	= 9,
    kEfiACPIMemoryNVS		= 10,
    kEfiMemoryMappedIO		= 11,
    kEfiMemoryMappedIOPortSpace = 12,
    kEfiPalCode			= 13,
    kEfiMaxMemoryType		= 14
};

/*
 * Memory range descriptor.
 */
typedef struct EfiMemoryRange {
    uint32_t Type;
    uint32_t pad;
    uint64_t PhysicalStart;
    uint64_t VirtualStart;
    uint64_t NumberOfPages;
    uint64_t Attribute;
} EfiMemoryRange;

#define BOOT_LINE_LENGTH        1024
#define BOOT_STRING_LEN         BOOT_LINE_LENGTH

/*
 * Video information.. 
 */

struct Boot_Video {
	uint32_t	v_baseAddr;	/* Base address of video memory */
	uint32_t	v_display;	/* Display Code (if Applicable */
	uint32_t	v_rowBytes;	/* Number of bytes per pixel row */
	uint32_t	v_width;	/* Width */
	uint32_t	v_height;	/* Height */
	uint32_t	v_depth;	/* Pixel Depth */
} __attribute__((aligned(4)));

typedef struct Boot_Video	Boot_Video;


/* Boot argument structure - passed into Mach kernel at boot time.
 */
#define kBootArgsRevision		4
#define kBootArgsVersion		1

#define kBootArgsEfiMode32              32
#define kBootArgsEfiMode64              64

typedef struct boot_args {
    uint16_t	Revision;	/* Revision of boot_args structure */
    uint16_t	Version;	/* Version of boot_args structure */

    char	CommandLine[BOOT_LINE_LENGTH];	/* Passed in command line */

    uint32_t    MemoryMap;
    uint32_t    MemoryMapSize;
    uint32_t    MemoryMapDescriptorSize;
    uint32_t    MemoryMapDescriptorVersion;

    Boot_Video	Video;		/* Video Information */

    uint32_t    deviceTreeP;	/* Base of flattened device tree */
    uint32_t	deviceTreeLength;/* Length of flattened tree */

    uint32_t    kaddr;
    uint32_t    ksize;

    uint32_t    efiRuntimeServicesPageStart;
    uint32_t    efiRuntimeServicesPageCount;
    uint32_t    efiSystemTable;

    uint8_t     efiMode;       /* 32 = 32-bit, 64 = 64-bit */
    uint8_t     __reserved1[3];
    uint32_t    __reserved2[7];

} __attribute__((aligned(4))) boot_args;

#endif /* _PEXPERT_I386_BOOT_H */

