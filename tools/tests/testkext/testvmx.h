/*
 *  testvmx.h
 *  testkext
 *
 *  Created by Shantonu Sen on 10/24/08.
 *  Copyright 2008 Apple Computer, Inc.. All rights reserved.
 *
 */

#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>

class testvmx : public IOService {
    OSDeclareDefaultStructors(testvmx);
    
    virtual bool start( IOService * provider );
    
    virtual void stop( IOService * provider );
    
};
