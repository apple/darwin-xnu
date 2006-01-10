/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */

/*
 * Internal definitions used between the iokit user library and
 * server routines.
 */

#ifndef _IOKIT_IOKITSERVER_H
#define _IOKIT_IOKITSERVER_H

#include <IOKit/IOTypes.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/OSMessageNotification.h>

#ifdef __cplusplus
extern "C" {
#endif
#include <mach/kmod.h>
#ifdef __cplusplus
}
#endif

// IOMakeMatching
/*!
    @enum IOMakeMatching
    @constant kIOServiceMatching
    @constant kIOBSDNameMatching
    @constant kIOOFPathMatching
*/
enum {
    kIOServiceMatching		= 100,
    kIOBSDNameMatching		= 101,
    kIOOFPathMatching		= 102
};

// IOCatalogueSendData
/*!
    @enum IOCatalogueSendData user-client flags.
    @constant kIOCatalogAddDrivers  Signals a call to the addDrivers function in IOCatalogue.
    @constant kIOCatalogAddDriversNoMatch  Signals a call to the addDrivers function in IOCatalogue but does not start a matching thread.
    @constant kIOCatalogRemoveDrivers  Signals a call to the removeDrivers function in IOCatalogue.
    @constant kIOCatalogRemoveDriversNoMatch  Signals a call to the removedrivers function in IOCatalogue but does not start a matching thread. 
    @constant kIOCatalogStartMatching  Signals the IOCatalogue to start an IOService matching thread.
*/
enum {
    kIOCatalogAddDrivers	= 1,
    kIOCatalogAddDriversNoMatch,
    kIOCatalogRemoveDrivers,
    kIOCatalogRemoveDriversNoMatch,
    kIOCatalogStartMatching,
    kIOCatalogRemoveKernelLinker
};

// IOCatalogueGetData
/*!
    @enum IOCatalogueGetData user-client flags
    @constant kIOCatalogGetContents  Returns a snapshot of the database to the caller.
*/
enum {
    kIOCatalogGetContents	  = 1,
    kIOCatalogGetModuleDemandList = 2,
    kIOCatalogGetCacheMissList	  = 3,
    kIOCatalogGetROMMkextList     = 4
};

// IOCatalogueReset
/*!
    @enum IOCatalogueReset user-client flag
    @constant kIOCatalogResetDefault  Removes all entries from IOCatalogue except those used for booting the system.
*/
enum {
    kIOCatalogResetDefault	= 1
};

// IOCatalogueTerminate
/*!
    @enum IOCatalogueTerminate user-client flags.
    @constant kIOCatalogModuleUnload Terminates all services which depend on a particular module and unloads the module.
    @constant kIOCatalogModuleTerminate Terminates all services which depend on a particular module but does not unload the module.
    @constant kIOCatalogServiceTerminate Terminates a particular service by name.
*/
enum {
    kIOCatalogModuleUnload      = 1,
    kIOCatalogModuleTerminate,
    kIOCatalogServiceTerminate
};

enum {
    kIOCatalogMatchIdle      = KMOD_IOKIT_END_RANGE_PACKET - 0x10
};

#endif /* ! _IOKIT_IOKITSERVER_H */

