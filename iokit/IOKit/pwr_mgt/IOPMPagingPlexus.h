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


#ifndef _IOKIT_IOPMPAGINGPLEXUS_H
#define _IOKIT_IOPMPAGINGPLEXUS_H

#include <IOKit/IOService.h>



/*! @class IOPMPagingPlexus : public IOService
    @abstract 
    @discussion  
*/

class IOPMPagingPlexus : public IOService
{
    OSDeclareDefaultStructors(IOPMPagingPlexus)


protected:

    bool	systemBooting;	// true until preferences received.  Then we act.
    IOLock *	ourLock;
    
public:

    virtual bool start ( IOService * );
    virtual IOReturn setAggressiveness ( unsigned long, unsigned long );
    
protected:

    virtual IOService * findProvider ( IOService * );
    virtual void processSiblings ( IOService * );
    virtual void processChildren ( void );

};

#endif /* ! _IOKIT_IOPMPAGINGPLEXUS_H */

