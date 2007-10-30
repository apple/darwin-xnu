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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 *
 */
 
/*
 * Core IOReturn values. Others may be family defined.
 */

#ifndef __LIBKERN_OSRETURN_H
#define __LIBKERN_OSRETURN_H

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <mach/error.h>

typedef	kern_return_t	OSReturn;

#ifndef sys_libkern
#define sys_libkern		err_system(0x37)
#endif /* sys_libkern */

#define sub_libkern_common	err_sub(0)
#define sub_libkern_metaclass	err_sub(1)
#define sub_libkern_reserved	err_sub(-1)

#define	libkern_common_err(return) \
                                (sys_libkern|sub_libkern_common|(return))
#define	libkern_metaclass_err(return) \
                                (sys_libkern|sub_libkern_metaclass|(return))

#define kOSReturnSuccess         KERN_SUCCESS          // OK
#define kOSReturnError           libkern_common_err(1) // general error


// OSMetaClass subsystem error's
#define kOSMetaClassInternal		libkern_metaclass_err(1)	// runtime internal error
#define kOSMetaClassHasInstances	libkern_metaclass_err(2)	// Can't unload outstanding instances
#define kOSMetaClassNoInit		libkern_metaclass_err(3)	// kmodInitializeLoad wasn't called, runtime internal error
#define kOSMetaClassNoTempData		libkern_metaclass_err(4)	// Allocation failure internal data
#define kOSMetaClassNoDicts		libkern_metaclass_err(5)	// Allocation failure for Metaclass internal dictionaries
#define kOSMetaClassNoKModSet		libkern_metaclass_err(6)	// Allocation failure for internal kmodule set
#define kOSMetaClassNoInsKModSet	libkern_metaclass_err(7)	// Can't insert the KMod set into the module dictionary
#define kOSMetaClassNoSuper		libkern_metaclass_err(8)	// Can't associate a class with its super class
#define kOSMetaClassInstNoSuper		libkern_metaclass_err(9)	// During instance construction can't find a super class
#define kOSMetaClassDuplicateClass	libkern_metaclass_err(10)	// Found class duplicate during module load

__END_DECLS

#endif /* ! __LIBKERN_OSRETURN_H */
