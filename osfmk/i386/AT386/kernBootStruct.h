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
/*
 * kernBootStruct.h
 * What the booter leaves behind for the kernel.
 */

/* The config table has room for 13 drivers if their config files
 * are the maximum size allowed.
 */
#define CONFIG_SIZE (13 * 4096)

/* Maximum number of boot drivers supported, assuming their
 * config files fit in the bootstruct.
 */
#define NDRIVERS		64

typedef struct {
    char    *address;			// address where driver was loaded
    int	    size;			// entry point for driver
} driver_config_t;

typedef struct {
    unsigned short	major_vers;	// == 0 if not present
    unsigned short	minor_vers;
    unsigned long	cs32_base;
    unsigned long	cs16_base;
    unsigned long	ds_base;
    unsigned long	cs_length;
    unsigned long	ds_length;
    unsigned long	entry_offset;
    union {
	struct {
	    unsigned long	mode_16		:1;
	    unsigned long	mode_32		:1;
	    unsigned long	idle_slows_cpu	:1;
	    unsigned long	reserved	:29;
	} f;
	unsigned long data;
    } flags;
    unsigned long	connected;
} APM_config_t;

typedef struct _EISA_slot_info_t {
    union {
	struct {
	    unsigned char	duplicateID	:4;
	    unsigned char	slotType	:1;
	    unsigned char	prodIDPresent	:1;
	    unsigned char	dupIDPresent	:1;
	} s;
	unsigned char d;
    } u_ID;
    unsigned char	configMajor;
    unsigned char 	configMinor;
    unsigned short	checksum;
    unsigned char	numFunctions;
    union {
	struct {
	    unsigned char	fnTypesPresent	:1;
	    unsigned char	memoryPresent	:1;
	    unsigned char	irqPresent	:1;
	    unsigned char	dmaPresent	:1;
	    unsigned char	portRangePresent:1;
	    unsigned char	portInitPresent	:1;
	    unsigned char	freeFormPresent	:1;
	    unsigned char	reserved:1;
	} s;
	unsigned char d;
    } u_resources;
    unsigned char	id[8];
} EISA_slot_info_t;

typedef struct _EISA_func_info_t {
    unsigned char	slot;
    unsigned char	function;
    unsigned char	reserved[2];
    unsigned char	data[320];
} EISA_func_info_t;

#define NUM_EISA_SLOTS	64

typedef struct _PCI_bus_info_t {
    union {
	struct {
	    unsigned char configMethod1	:1;
	    unsigned char configMethod2	:1;
	    unsigned char		:2;
	    unsigned char specialCycle1	:1;
	    unsigned char specialCycle2	:1;
	} s;
	unsigned char d;
    } u_bus;
    unsigned char maxBusNum;
    unsigned char majorVersion;
    unsigned char minorVersion;
    unsigned char BIOSPresent;
} PCI_bus_info_t;

/*
 * Video information..
 */

struct boot_video {
        unsigned long   v_baseAddr;     /* Base address of video memory */
        unsigned long   v_display;      /* Display Code (if Applicable */
        unsigned long   v_rowBytes;     /* Number of bytes per pixel row */
        unsigned long   v_width;        /* Width */
        unsigned long   v_height;       /* Height */
        unsigned long   v_depth;        /* Pixel Depth */
};

typedef struct boot_video       boot_video;

#define BOOT_STRING_LEN		160

typedef struct {
    short   version;
    char    bootString[BOOT_STRING_LEN];// string we booted with
    int	    magicCookie;		// KERNBOOTMAGIC if struct valid
    int	    numIDEs;			// how many IDE drives
    int	    rootdev;			// booters guess as to rootdev
    int	    convmem;			// conventional memory
    int	    extmem;			// extended memory
    char    boot_file[128];		// name of the kernel we booted
    int	    first_addr0;		// first address for kern convmem
    int	    diskInfo[4];		// bios info for bios dev 80-83
    int	    graphicsMode;		// did we boot in graphics mode?
    int	    kernDev;			// device kernel was fetched from
    int     numBootDrivers;		// number of drivers loaded by booter    
    char    *configEnd;			// pointer to end of config files
    int	    kaddr;			// kernel load address
    int     ksize;			// size of kernel
    void    *rld_entry;			// entry point for standalone rld

    driver_config_t driverConfig[NDRIVERS];
    APM_config_t apm_config;
    
    char   _reserved[7500];

    boot_video video;

    PCI_bus_info_t pciInfo;
    
    int	    eisaConfigFunctions;
    EISA_slot_info_t eisaSlotInfo[NUM_EISA_SLOTS];// EISA slot information

    char   config[CONFIG_SIZE];		// the config file contents
} KERNBOOTSTRUCT;

#define GRAPHICS_MODE	1
#define TEXT_MODE 0

#define KERNSTRUCT_ADDR ((KERNBOOTSTRUCT *)0x11000)
#define KERNBOOTMAGIC 0xa7a7a7a7

#ifndef EISA_CONFIG_ADDR
#define EISA_CONFIG_ADDR	0x20000
#define EISA_CONFIG_LEN		0x10000
#endif

#ifndef KERNEL
extern KERNBOOTSTRUCT *kernBootStruct;
#endif
