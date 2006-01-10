/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* OSUnserialize.h created by rsulack on Mon 23-Nov-1998 */

#ifndef _OS_OSUNSERIALIZE_H
#define _OS_OSUNSERIALIZE_H

#include <sys/appleapiopts.h>

class OSObject;
class OSString;

/*! @function OSUnserializeXML
    @abstract Recreates an OS Container object from its previously serialized OS Container class instance data.
    @param buffer pointer to buffer containing XML data representing the object to be recreated.
    @param errorString if this is a valid pointer and the XML parser finds a error in buffer, errorString contains text indicating the line number and type of error encountered.
    @result Pointer to the recreated object, or zero on failure. */

extern OSObject* OSUnserializeXML(const char *buffer, OSString **errorString = 0);

#ifdef __APPLE_API_OBSOLETE
extern OSObject* OSUnserialize(const char *buffer, OSString **errorString = 0);
#endif /* __APPLE_API_OBSOLETE */

#endif /* _OS_OSUNSERIALIZE_H */
