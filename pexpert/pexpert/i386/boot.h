/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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


/*
 * INT15, E820h - Query System Address Map.
 *
 * Documented in ACPI Specification Rev 2.0,
 * Chapter 15 (System Address Map Interfaces).
 */

/*
 * ACPI defined memory range types.
 */
enum {
    kMemoryRangeUsable   = 1,    // RAM usable by the OS.
    kMemoryRangeReserved = 2,    // Reserved. (Do not use)
    kMemoryRangeACPI     = 3,    // ACPI tables. Can be reclaimed.
    kMemoryRangeNVS      = 4,    // ACPI NVS memory. (Do not use)

    /* Undefined types should be treated as kMemoryRangeReserved */
};

/*
 * Memory range descriptor.
 */
typedef struct MemoryRange {
    unsigned long long base;     // 64-bit base address
    unsigned long long length;   // 64-bit length in bytes
    unsigned long      type;     // type of memory range
    unsigned long      reserved;
} MemoryRange;

#define kMemoryMapCountMax 40

/*
 * BIOS drive information.
 */
struct boot_drive_info {
    struct drive_params {
	unsigned short buf_size;
	unsigned short info_flags;
	unsigned long  phys_cyls;
	unsigned long  phys_heads;
	unsigned long  phys_spt;
	unsigned long long phys_sectors;
	unsigned short phys_nbps;
	unsigned short dpte_offset;
	unsigned short dpte_segment;
	unsigned short key;
	unsigned char  path_len;
	unsigned char  reserved1;
	unsigned short reserved2;
	unsigned char  bus_type[4];
	unsigned char  interface_type[8];
	unsigned char  interface_path[8];
	unsigned char  dev_path[8];
	unsigned char  reserved3;
	unsigned char  checksum;
    } params __attribute__((packed));
    struct drive_dpte {
	unsigned short io_port_base;
	unsigned short control_port_base;
	unsigned char  head_flags;
	unsigned char  vendor_info;
	unsigned char  irq         : 4;
	unsigned char  irq_unused  : 4;
	unsigned char  block_count;
	unsigned char  dma_channel : 4;
	unsigned char  dma_type    : 4;
	unsigned char  pio_type    : 4;
	unsigned char  pio_unused  : 4;
	unsigned short option_flags;
	unsigned short reserved;
	unsigned char  revision;
	unsigned char  checksum;
    } dpte __attribute__((packed));
} __attribute__((packed));
typedef struct boot_drive_info boot_drive_info_t;

#define MAX_BIOS_DEVICES 8

#define OLD_BOOT_STRING_LEN   160
#define BOOT_STRING_LEN   1024
#define CONFIG_SIZE       (12 * 4096)

/* Old structure for compatibility */

typedef struct {
    short            version;
    char             bootString[OLD_BOOT_STRING_LEN];  // boot arguments
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

/* New structures */


#define KERNEL_BOOT_MAGIC    0xa5b6d7e8

typedef struct KernelBootArgs {
    unsigned int     magicCookie;                  // KERNEL_BOOT_MAGIC
    unsigned short   version;
    unsigned short   revision;
    unsigned int     size;                         // size of KernelBootArgs structure
    int              numDrives;                    // number of BIOS drives
    int              rootdev;                      // root device
    int              convmem;                      // conventional memory
    int              extmem;                       // extended memory
    unsigned int     firstAddr0;                   // first address for kern convmem
    int              graphicsMode;                 // booted in graphics mode?
    int              kernDev;                      // device kernel was fetched from
    int              numBootDrivers;               // number of drivers loaded
    char *           configEnd;                    // pointer to end of config files
    unsigned int     kaddr;                        // kernel load address
    unsigned int     ksize;                        // size of kernel
    char             bootFile[128];                // kernel file name
    char             bootString[BOOT_STRING_LEN];  // boot arguments
    driver_config_t  driverConfig[NDRIVERS];
    unsigned long    memoryMapCount;
    MemoryRange      memoryMap[kMemoryMapCountMax];
    boot_drive_info_t  driveInfo[MAX_BIOS_DEVICES];
    boot_video       video;
    PCI_bus_info_t   pciInfo;
    APM_config_t     apmConfig;
    char             config[CONFIG_SIZE];
} KernelBootArgs_t;


#endif /* _PEXPERT_I386_BOOT_H */

