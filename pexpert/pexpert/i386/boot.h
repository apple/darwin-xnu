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

/*
 * What the booter leaves behind for the kernel.
 */

/*
 * Maximum number of boot drivers that can be loaded.
 */
#define NDRIVERS  500

/*
 * Types of boot driver that may be loaded by the booter.
 */
enum {
    kBootDriverTypeInvalid = 0,
    kBootDriverTypeKEXT    = 1,
    kBootDriverTypeMKEXT   = 2
};

typedef struct {
    unsigned long address;  // address where driver was loaded
    unsigned long size;     // number of bytes
    unsigned long type;     // driver type
} driver_config_t;

/*
 * APM BIOS information.
 */
typedef struct {
    unsigned short major_vers;    // == 0 if not present
    unsigned short minor_vers;
    unsigned long  cs32_base;
    unsigned long  cs16_base;
    unsigned long  ds_base;
    unsigned long  cs_length;
    unsigned long  ds_length;
    unsigned long  entry_offset;
    union {
        struct {
            unsigned long mode_16        :1;
            unsigned long mode_32        :1;
            unsigned long idle_slows_cpu :1;
            unsigned long reserved       :29;
        } f;
        unsigned long data;
    } flags;
    unsigned long connected;
} APM_config_t;

/*
 * PCI bus information.
 */
typedef struct _PCI_bus_info_t {
    union {
        struct {
            unsigned char configMethod1 :1;
            unsigned char configMethod2 :1;
            unsigned char               :2;
            unsigned char specialCycle1 :1;
            unsigned char specialCycle2 :1;
        } s;
        unsigned char d;
    } u_bus;
    unsigned char maxBusNum;
    unsigned char majorVersion;
    unsigned char minorVersion;
    unsigned char BIOSPresent;
} PCI_bus_info_t;

/*
 * Video information.
 */
struct boot_video {
    unsigned long v_baseAddr;	// Base address of video memory
    unsigned long v_display;    // Display Code (if Applicable
    unsigned long v_rowBytes;   // Number of bytes per pixel row
    unsigned long v_width;      // Width
    unsigned long v_height;     // Height
    unsigned long v_depth;      // Pixel Depth
};

typedef struct boot_video  boot_video;

#define GRAPHICS_MODE     1
#define TEXT_MODE         0

#define BOOT_STRING_LEN   160
#define CONFIG_SIZE       (12 * 4096)

typedef struct {
    short            version;
    char             bootString[BOOT_STRING_LEN];  // boot arguments
    int              magicCookie;                  // KERNBOOTMAGIC
    int              numIDEs;                      // number of IDE drives
    int              rootdev;                      // root device
    int              convmem;                      // conventional memory
    int              extmem;                       // extended memory
    char             bootFile[128];                // kernel file name
    int              firstAddr0;                   // first address for kern convmem
    int              diskInfo[4];                  // info for bios dev 80-83
    int              graphicsMode;                 // booted in graphics mode?
    int              kernDev;                      // device kernel was fetched from
    int              numBootDrivers;               // number of drivers loaded
    char *           configEnd;                    // pointer to end of config files
    int              kaddr;                        // kernel load address
    int              ksize;                        // size of kernel
    driver_config_t  driverConfig[NDRIVERS];
    char             _reserved[2052];
    boot_video       video;
    PCI_bus_info_t   pciInfo;
    APM_config_t     apmConfig;
    char             config[CONFIG_SIZE];
} KERNBOOTSTRUCT;

#define KERNSTRUCT_ADDR   ((KERNBOOTSTRUCT *) 0x11000)
#define KERNBOOTMAGIC     0xa7a7a7a7

#ifndef KERNEL
extern KERNBOOTSTRUCT *   kernBootStruct;
#endif

#define BOOT_LINE_LENGTH        256

/*
 * Video information.. 
 */

struct Boot_Video {
	unsigned long	v_baseAddr;	/* Base address of video memory */
	unsigned long	v_display;	/* Display Code (if Applicable */
	unsigned long	v_rowBytes;	/* Number of bytes per pixel row */
	unsigned long	v_width;	/* Width */
	unsigned long	v_height;	/* Height */
	unsigned long	v_depth;	/* Pixel Depth */
};

typedef struct Boot_Video	Boot_Video;

/* DRAM Bank definitions - describes physical memory layout.
 */
#define	kMaxDRAMBanks	26		/* maximum number of DRAM banks */

struct DRAMBank
{
	unsigned long	base;		/* physical base of DRAM bank */
	unsigned long	size;		/* size of bank */
};
typedef struct DRAMBank DRAMBank;


/* Boot argument structure - passed into Mach kernel at boot time.
 */
#define kBootArgsVersion		1
#define kBootArgsRevision		1

typedef struct boot_args {
  unsigned short	Revision;	/* Revision of boot_args structure */
  unsigned short	Version;	/* Version of boot_args structure */
  char		CommandLine[BOOT_LINE_LENGTH];	/* Passed in command line */
  DRAMBank	PhysicalDRAM[kMaxDRAMBanks];	/* base and range pairs for the 26 DRAM banks */
  Boot_Video	Video;		/* Video Information */
    unsigned long	machineType;	/* Machine Type (gestalt) */
    void		*deviceTreeP;	/* Base of flattened device tree */
    unsigned long	deviceTreeLength;/* Length of flattened tree */
    unsigned long	topOfKernelData;/* Highest address used in kernel data area */
} boot_args;

extern boot_args passed_args;

#endif /* _PEXPERT_I386_BOOT_H */

