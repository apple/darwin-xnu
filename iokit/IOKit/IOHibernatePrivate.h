/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef KERNEL
#include <crypto/aes.h>
#endif

struct IOPolledFileExtent
{
    uint64_t	start;
    uint64_t	length;
};
typedef struct IOPolledFileExtent IOPolledFileExtent;

struct IOHibernateImageHeader
{
    uint64_t	imageSize;
    uint64_t	image1Size;
    
    uint32_t	restore1CodePage;
    uint32_t	restore1PageCount;
    uint32_t	restore1CodeOffset;
    uint32_t	restore1StackOffset;
    
    uint32_t	pageCount;
    uint32_t	bitmapSize;

    uint32_t	restore1Sum;
    uint32_t	image1Sum;
    uint32_t	image2Sum;

    uint32_t	actualRestore1Sum;
    uint32_t	actualImage1Sum;
    uint32_t	actualImage2Sum;

    uint32_t	actualUncompressedPages;
    uint32_t	conflictCount;
    uint32_t	nextFree;

    uint32_t	signature;
    uint32_t	processorFlags;

    uint32_t    runtimePages;
    uint32_t    runtimePageCount;
    uint64_t    runtimeVirtualPages __attribute__ ((packed));
    uint8_t     reserved2[8];
    
    uint64_t	encryptStart __attribute__ ((packed));
    uint64_t	machineSignature __attribute__ ((packed));

    uint32_t    previewSize;
    uint32_t    previewPageListSize;

    uint32_t	diag[4];

    int32_t	graphicsInfoOffset;
    int32_t	cryptVarsOffset;
    int32_t	memoryMapOffset;
    uint32_t    memoryMapSize;
    uint32_t    systemTableOffset;

    uint32_t	debugFlags;

    uint32_t	reserved[76];		// make sizeof == 512

    uint32_t		fileExtentMapSize;
    IOPolledFileExtent	fileExtentMap[2];
};
typedef struct IOHibernateImageHeader IOHibernateImageHeader;

enum
{
    kIOHibernateDebugRestoreLogs = 0x00000001
};

struct hibernate_bitmap_t
{
    uint32_t	first_page;
    uint32_t	last_page;
    uint32_t	bitmapwords;
    uint32_t	bitmap[0];
};
typedef struct hibernate_bitmap_t hibernate_bitmap_t;

struct hibernate_page_list_t
{
    uint32_t		  list_size;
    uint32_t		  page_count;
    uint32_t		  bank_count;
    hibernate_bitmap_t    bank_bitmap[0];
};
typedef struct hibernate_page_list_t hibernate_page_list_t;

#if defined(_AES_H)

struct hibernate_cryptwakevars_t
{
    uint8_t aes_iv[AES_BLOCK_SIZE];
};
typedef struct hibernate_cryptwakevars_t hibernate_cryptwakevars_t;

struct hibernate_cryptvars_t
{
    uint8_t aes_iv[AES_BLOCK_SIZE];
    aes_ctx ctx;
};
typedef struct hibernate_cryptvars_t hibernate_cryptvars_t;

#endif /* defined(_AES_H) */


enum 
{
    kIOHibernateProgressCount         = 19,
    kIOHibernateProgressWidth         = 7,
    kIOHibernateProgressHeight        = 16,
    kIOHibernateProgressSpacing       = 3,
    kIOHibernateProgressOriginY       = 81,

    kIOHibernateProgressSaveUnderSize = 2*5+14*2,

    kIOHibernateProgressLightGray     = 230,
    kIOHibernateProgressMidGray       = 174,
    kIOHibernateProgressDarkGray      = 92
};

enum
{
    kIOHibernatePostWriteSleep   = 0,
    kIOHibernatePostWriteWake    = 1,
    kIOHibernatePostWriteHalt    = 2,
    kIOHibernatePostWriteRestart = 3
};


struct hibernate_graphics_t
{
    uint32_t physicalAddress;		// Base address of video memory
    uint32_t mode;			// 
    uint32_t rowBytes;   		// Number of bytes per pixel row
    uint32_t width;      		// Width
    uint32_t height;     		// Height
    uint32_t depth;      		// Pixel Depth

    uint8_t progressSaveUnder[kIOHibernateProgressCount][kIOHibernateProgressSaveUnderSize];
};
typedef struct hibernate_graphics_t hibernate_graphics_t;

#define DECLARE_IOHIBERNATEPROGRESSALPHA				\
static const uint8_t gIOHibernateProgressAlpha			\
[kIOHibernateProgressHeight][kIOHibernateProgressWidth] = 	\
{								\
    { 0x00,0x63,0xd8,0xf0,0xd8,0x63,0x00 },			\
    { 0x51,0xff,0xff,0xff,0xff,0xff,0x51 },			\
    { 0xae,0xff,0xff,0xff,0xff,0xff,0xae },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xc3,0xff,0xff,0xff,0xff,0xff,0xc3 },			\
    { 0xae,0xff,0xff,0xff,0xff,0xff,0xae },			\
    { 0x54,0xff,0xff,0xff,0xff,0xff,0x54 },			\
    { 0x00,0x66,0xdb,0xf3,0xdb,0x66,0x00 }			\
};

#ifdef KERNEL

#ifdef __cplusplus

void     IOHibernateSystemInit(IOPMrootDomain * rootDomain);

IOReturn IOHibernateSystemSleep(void);
IOReturn IOHibernateSystemHasSlept(void);
IOReturn IOHibernateSystemWake(void);
IOReturn IOHibernateSystemPostWake(void);

#endif /* __cplusplus */

#ifdef _SYS_CONF_H_
typedef void (*kern_get_file_extents_callback_t)(void * ref, uint64_t start, uint64_t size);

struct kern_direct_file_io_ref_t *
kern_open_file_for_direct_io(const char * name, 
			     kern_get_file_extents_callback_t callback, 
			     void * callback_ref,
			     dev_t * device,
                             uint64_t * partitionbase_result,
                             uint64_t * maxiocount_result);
void
kern_close_file_for_direct_io(struct kern_direct_file_io_ref_t * ref);
int
kern_write_file(struct kern_direct_file_io_ref_t * ref, off_t offset, caddr_t addr, vm_size_t len);
int get_kernel_symfile(struct proc *p, char const **symfile);
#endif /* _SYS_CONF_H_ */

hibernate_page_list_t *
hibernate_page_list_allocate(void);

kern_return_t 
hibernate_setup(IOHibernateImageHeader * header,
                        uint32_t free_page_ratio,
                        uint32_t free_page_time,
			hibernate_page_list_t ** page_list_ret,
			hibernate_page_list_t ** page_list_wired_ret,
                        boolean_t * encryptedswap);
kern_return_t 
hibernate_teardown(hibernate_page_list_t * page_list,
                    hibernate_page_list_t * page_list_wired);

kern_return_t 
hibernate_processor_setup(IOHibernateImageHeader * header);

void
hibernate_gobble_pages(uint32_t gobble_count, uint32_t free_page_time);
void
hibernate_free_gobble_pages(void);

void
hibernate_vm_lock(void);
void
hibernate_vm_unlock(void);

// mark pages not to be saved, based on VM system accounting
void
hibernate_page_list_setall(hibernate_page_list_t * page_list,
			   hibernate_page_list_t * page_list_wired,
			   uint32_t * pagesOut);

// mark pages to be saved, or pages not to be saved but available 
// for scratch usage during restore
void
hibernate_page_list_setall_machine(hibernate_page_list_t * page_list,
                                    hibernate_page_list_t * page_list_wired,
                                    uint32_t * pagesOut);

// mark pages not to be saved and not for scratch usage during restore
void
hibernate_page_list_set_volatile( hibernate_page_list_t * page_list,
				  hibernate_page_list_t * page_list_wired,
				  uint32_t * pagesOut);

void
hibernate_page_list_discard(hibernate_page_list_t * page_list);

void
hibernate_set_page_state(hibernate_page_list_t * page_list, hibernate_page_list_t * page_list_wired,
				vm_offset_t ppnum, vm_offset_t count, uint32_t kind);

void 
hibernate_page_bitset(hibernate_page_list_t * list, boolean_t set, uint32_t page);

boolean_t 
hibernate_page_bittst(hibernate_page_list_t * list, uint32_t page);

hibernate_bitmap_t *
hibernate_page_bitmap_pin(hibernate_page_list_t * list, uint32_t * page);

uint32_t
hibernate_page_bitmap_count(hibernate_bitmap_t * bitmap, uint32_t set, uint32_t page);

void 
hibernate_restore_phys_page(uint64_t src, uint64_t dst, uint32_t len, uint32_t procFlags);

void
hibernate_machine_init(void);

uint32_t
hibernate_write_image(void);

long
hibernate_machine_entrypoint(IOHibernateImageHeader * header, void * p2, void * p3, void * p4);
long
hibernate_kernel_entrypoint(IOHibernateImageHeader * header, void * p2, void * p3, void * p4);
void
hibernate_newruntime_map(void * map, vm_size_t map_size, 
			    uint32_t system_table_offset);


extern uint32_t    gIOHibernateState;
extern uint32_t    gIOHibernateMode;
extern uint32_t    gIOHibernateDebugFlags;
extern uint32_t    gIOHibernateFreeTime;	// max time to spend freeing pages (ms)
extern uint8_t     gIOHibernateRestoreStack[];
extern uint8_t     gIOHibernateRestoreStackEnd[];
extern IOHibernateImageHeader *    gIOHibernateCurrentHeader;
extern hibernate_graphics_t *      gIOHibernateGraphicsInfo;
extern hibernate_cryptwakevars_t * gIOHibernateCryptWakeVars;

#define HIBLOG(fmt, args...)	\
    { kprintf(fmt, ## args); printf(fmt, ## args); }

#define HIBPRINT(fmt, args...)	\
    { kprintf(fmt, ## args); }

#endif /* KERNEL */

// gIOHibernateState, kIOHibernateStateKey
enum
{
    kIOHibernateStateInactive            = 0,
    kIOHibernateStateHibernating 	 = 1,	/* writing image */
    kIOHibernateStateWakingFromHibernate = 2	/* booted and restored image */
};

// gIOHibernateMode, kIOHibernateModeKey
enum
{
    kIOHibernateModeOn      = 0x00000001,
    kIOHibernateModeSleep   = 0x00000002,
    kIOHibernateModeEncrypt = 0x00000004,
    kIOHibernateModeDiscardCleanInactive = 0x00000008,
    kIOHibernateModeDiscardCleanActive   = 0x00000010,
    kIOHibernateModeSwitch	= 0x00000020,
    kIOHibernateModeRestart	= 0x00000040
};

// IOHibernateImageHeader.signature
enum
{
    kIOHibernateHeaderSignature        = 0x73696d65,
    kIOHibernateHeaderInvalidSignature = 0x7a7a7a7a
};

// kind for hibernate_set_page_state()
enum
{
    kIOHibernatePageStateFree        = 0,
    kIOHibernatePageStateWiredSave   = 1,
    kIOHibernatePageStateUnwiredSave = 2
};

#define kIOHibernateModeKey		"Hibernate Mode"
#define kIOHibernateFileKey		"Hibernate File"
#define kIOHibernateFreeRatioKey	"Hibernate Free Ratio"
#define kIOHibernateFreeTimeKey		"Hibernate Free Time"

#define kIOHibernateStateKey		"IOHibernateState"
#define kIOHibernateFeatureKey		"Hibernation"
#define kIOHibernatePreviewBufferKey	"IOPreviewBuffer"

#define kIOHibernatePreviewActiveKey	"IOHibernatePreviewActive"
// values for kIOHibernatePreviewActiveKey
enum {
    kIOHibernatePreviewActive  = 0x00000001,
    kIOHibernatePreviewUpdates = 0x00000002
};

#define kIOHibernateBootImageKey	"boot-image"
#define kIOHibernateBootImageKeyKey	"boot-image-key"
#define kIOHibernateBootSignatureKey	"boot-signature"

#define kIOHibernateMemorySignatureKey	  "memory-signature"
#define kIOHibernateMemorySignatureEnvKey "mem-sig"
#define kIOHibernateMachineSignatureKey	  "machine-signature"

#define kIOHibernateRTCVariablesKey	"IOHibernateRTCVariables"

#define kIOHibernateBootSwitchVarsKey			"boot-switch-vars"


#ifdef __cplusplus
}
#endif
