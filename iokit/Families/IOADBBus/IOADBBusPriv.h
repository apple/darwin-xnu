/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
/*
 * Copyright 1996 1995 by Open Software Foundation, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 * 
 */
/*
 * Copyright 1996 1995 by Apple Computer, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * APPLE COMPUTER DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL APPLE COMPUTER BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 */
/*
 * MKLINUX-1.0DR2
 */
/*
 * 18 June 1998 sdouglas
 * Start IOKit version.
 */

#define ADB_DEVICE_COUNT	16

#define ADB_FLAGS_PRESENT   	0x00000001  /* Device is present */
#define ADB_FLAGS_REGISTERED    0x00000002  /* Device has a handler */
#define ADB_FLAGS_UNRESOLVED    0x00000004  /* Device has not been fully probed */

/*
 * ADB Commands
 */

#define ADB_DEVCMD_SELF_TEST        0xff
#define ADB_DEVCMD_CHANGE_ID        0xfe
#define ADB_DEVCMD_CHANGE_ID_AND_ACT    0xfd
#define ADB_DEVCMD_CHANGE_ID_AND_ENABLE 0x00

#ifndef __cplusplus

struct ADBDeviceControl {
    IOADBAddress	address;
    IOADBAddress	defaultAddress;
    UInt8		handlerID;
    UInt8		defaultHandlerID;
    UInt32		flags;
    id			owner;		// here for speed
};

typedef struct ADBDeviceControl ADBDeviceControl;


@class IOADBDevice;

@interface IOADBBus : IODevice <IOADBAutoPollHandler>
{
    IODevice <IOADBController> *	controller;
@public
    ADBDeviceControl *	adbDevices[ ADB_DEVICE_COUNT ];
}

- (IOReturn) probeBus;
- setUpName:(IOADBDevice *)device;

/////// nub -> bus

- (IOReturn) setOwner:owner forDevice:(void *)busRef;

- (IOReturn) flush:(void *)busRef;

- (IOReturn) readRegister:(void *)busRef
                adbRegister:(IOADBRegister)adbRegister
		contents:(UInt8 *)data
		length:(IOByteCount *)length;

- (IOReturn) writeRegister:(void *)busRef
                adbRegister:(IOADBRegister)adbRegister
		contents:(UInt8 *)data
		length:(IOByteCount *)length;

- (IOADBAddress) address:(void *)busRef;

- (IOADBAddress) defaultAddress:(void *)busRef;

- (UInt8) handlerID:(void *)busRef;

- (UInt8) defaultHandlerID:(void *)busRef;

- (IOReturn) setHandlerID:(void *)busRef
		handlerID:(UInt8)handlerID;

@end

@interface IOADBDevice : IODevice <IOADBDevice>
{
    IOADBBus *	bus;
    void *	busRef;
}

- initForBus:(IOADBBus *)bus andBusRef:(void *)busRef;

- (void *) busRef;

@end

#endif
