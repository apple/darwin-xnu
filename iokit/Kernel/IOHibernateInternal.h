/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>

#ifdef __cplusplus

enum { kIOHibernateAESKeySize = 128 };	/* bits */

struct IOHibernateVars
{
    hibernate_page_list_t *		page_list;
    hibernate_page_list_t *		page_list_wired;
    class IOBufferMemoryDescriptor *    ioBuffer;
    class IOBufferMemoryDescriptor *    srcBuffer;
    class IOMemoryDescriptor *          previewBuffer;
    OSData *          			previewData;
    OSData *		 		fileExtents;
    OSObject *				saveBootDevice;

    struct IOPolledFileIOVars *		fileVars;
    vm_offset_t				videoMapping;
    vm_size_t				videoAllocSize;
    vm_size_t				videoMapSize;
    uint8_t				haveFastBoot;
    uint8_t				saveBootAudioVolume;
    uint8_t				wiredCryptKey[kIOHibernateAESKeySize / 8];
    uint8_t				cryptKey[kIOHibernateAESKeySize / 8];
};
typedef struct IOHibernateVars IOHibernateVars;


struct IOPolledFileIOVars
{
    struct kern_direct_file_io_ref_t *	fileRef;
    class OSArray *			pollers;
    IOByteCount				blockSize;
    uint8_t *  				buffer;
    IOByteCount 			bufferSize;
    IOByteCount 			bufferLimit;
    IOByteCount 			bufferOffset;
    IOByteCount 			bufferHalf;
    IOByteCount				extentRemaining;
    IOByteCount				lastRead;
    uint64_t				block0;
    uint64_t				position;
    uint64_t				extentPosition;
    uint64_t				encryptStart;
    IOPolledFileExtent * 		extentMap;
    IOPolledFileExtent * 		currentExtent;
    bool				io;
    IOReturn				ioStatus;
};
typedef struct IOPolledFileIOVars IOPolledFileIOVars;

#endif		/* __cplusplus */

enum
{
    kIOHibernateTagSignature = 0x53000000,
    kIOHibernateTagLength    = 0x00001fff,
};

#ifdef __cplusplus
extern "C"
#endif		/* __cplusplus */
uint32_t
hibernate_sum(uint8_t *buf, int32_t len);

extern vm_offset_t sectHIBB;
extern int         sectSizeHIB;
extern vm_offset_t sectDATAB;
extern int         sectSizeDATA;

extern vm_offset_t gIOHibernateWakeMap;	    // ppnum
extern vm_size_t   gIOHibernateWakeMapSize;

