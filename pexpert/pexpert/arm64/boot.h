/*
 * Copyright (c) 2007-2009 Apple Inc. All rights reserved.
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifndef _PEXPERT_ARM64_BOOT_H_
#define _PEXPERT_ARM64_BOOT_H_

#include <kern/kern_types.h>
#include <pexpert/arm/consistent_debug.h>
#include <pexpert/arm/protos.h>

#define BOOT_LINE_LENGTH        256

/*
 * Video information..
 */

struct Boot_Video {
	unsigned long   v_baseAddr;     /* Base address of video memory */
	unsigned long   v_display;      /* Display Code (if Applicable */
	unsigned long   v_rowBytes;     /* Number of bytes per pixel row */
	unsigned long   v_width;        /* Width */
	unsigned long   v_height;       /* Height */
	unsigned long   v_depth;        /* Pixel Depth and other parameters */
};

#define kBootVideoDepthMask             (0xFF)
#define kBootVideoDepthDepthShift       (0)
#define kBootVideoDepthRotateShift      (8)
#define kBootVideoDepthScaleShift       (16)

#define kBootFlagsDarkBoot              (1ULL << 0)

typedef struct Boot_Video       Boot_Video;

/* Boot argument structure - passed into Mach kernel at boot time.
 */
#define kBootArgsRevision               1
#define kBootArgsRevision2              2       /* added boot_args.bootFlags */
#define kBootArgsVersion1               1
#define kBootArgsVersion2               2

typedef struct boot_args {
	uint16_t                Revision;                       /* Revision of boot_args structure */
	uint16_t                Version;                        /* Version of boot_args structure */
	uint64_t                virtBase;                       /* Virtual base of memory */
	uint64_t                physBase;                       /* Physical base of memory */
	uint64_t                memSize;                        /* Size of memory */
	uint64_t                topOfKernelData;        /* Highest physical address used in kernel data area */
	Boot_Video              Video;                          /* Video Information */
	uint32_t                machineType;            /* Machine Type */
	void                    *deviceTreeP;           /* Base of flattened device tree */
	uint32_t                deviceTreeLength;       /* Length of flattened tree */
	char                    CommandLine[BOOT_LINE_LENGTH];  /* Passed in command line */
	uint64_t                bootFlags;              /* Additional flags specified by the bootloader */
	uint64_t                memSizeActual;          /* Actual size of memory */
} boot_args;

#define SOC_DEVICE_TYPE_BUFFER_SIZE     32

#define PC_TRACE_BUF_SIZE               1024

#if SHMCON
#define SHMCON_MEM 0x4000
#else
#define SHMCON_MEM 0
#endif

#define CDBG_MEM ((sizeof(dbg_registry_t) + PAGE_SIZE - 1) & ~PAGE_MASK)

#define PE_EARLY_BOOT_VA (SHMCON_MEM + CDBG_MEM)

#endif /* _PEXPERT_ARM64_BOOT_H_ */
