/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 *
 *	queueHelpers.cpp
 *
 */
#include <IOKit/scsi/IOSCSIParallelInterface.h>

void IOSCSIParallelDevice::addCommand( queue_head_t *list, IOSCSIParallelCommand *scsiCmd )
{
    scsiCmd->list = list;

    queue_enter( list, scsiCmd, IOSCSIParallelCommand *, nextCommand );
}

void IOSCSIParallelDevice::deleteCommand( queue_head_t *list, IOSCSIParallelCommand *scsiCmd, IOReturn rc = kIOReturnSuccess )
{
    scsiCmd->list = 0;

    if ( rc != kIOReturnSuccess )
    {
        if  ( scsiCmd->results.returnCode == kIOReturnSuccess )
        {    
            scsiCmd->results.returnCode = (IOReturn) rc;
        }
    }
 
    queue_remove( list, scsiCmd, IOSCSIParallelCommand *, nextCommand );
}

IOSCSIParallelCommand *IOSCSIParallelDevice::checkCommand( queue_head_t *list )
{
    if ( queue_empty( list ) == true )
    {
        return 0;
    }

    return (IOSCSIParallelCommand *)queue_first( list );
}


IOSCSIParallelCommand *IOSCSIParallelDevice::getCommand( queue_head_t *list )
{
    IOSCSIParallelCommand	*scsiCmd = 0;

    if ( queue_empty( list ) == false )
    {
        queue_remove_first( list, scsiCmd, IOSCSIParallelCommand *, nextCommand );
        scsiCmd->list = 0;
    }

    return scsiCmd;
}

void IOSCSIParallelDevice::stackCommand( queue_head_t *list, IOSCSIParallelCommand *scsiCmd )
{
    scsiCmd->list = list;

    queue_enter_first( list, scsiCmd, IOSCSIParallelCommand *, nextCommand );
}

void IOSCSIParallelDevice::moveCommand( queue_head_t *fromList, queue_head_t *toList, IOSCSIParallelCommand *scsiCmd, IOReturn rc = kIOReturnSuccess )
{
    if ( rc != kIOReturnSuccess )
    {
        if  ( scsiCmd->results.returnCode == kIOReturnSuccess )
        {    
            scsiCmd->results.returnCode = (IOReturn) rc;
        }
    }

    scsiCmd->list = toList;  

    queue_remove( fromList, scsiCmd, IOSCSIParallelCommand *, nextCommand );
    queue_enter(  toList,   scsiCmd, IOSCSIParallelCommand *, nextCommand );
}

void IOSCSIParallelDevice::moveAllCommands( queue_head_t *fromList, queue_head_t *toList, IOReturn rc = kIOReturnSuccess )
{
    IOSCSIParallelCommand		*scsiCmd;

    if ( queue_empty( fromList ) == true ) return;

    do
    {
        scsiCmd = (IOSCSIParallelCommand *)queue_first( fromList );

        if ( rc != kIOReturnSuccess )
        {
            if  ( scsiCmd->results.returnCode == kIOReturnSuccess )
            {    
                scsiCmd->results.returnCode = (IOReturn) rc;
            }
        }

        scsiCmd->list = toList;  

        queue_remove( fromList, scsiCmd, IOSCSIParallelCommand *, nextCommand );
        queue_enter(  toList,   scsiCmd, IOSCSIParallelCommand *, nextCommand );

    } while( queue_empty( fromList ) == false );
}

bool IOSCSIParallelDevice::findCommand( queue_head_t *list, IOSCSIParallelCommand *findSCSICmd )
{
    IOSCSIParallelCommand		*scsiCmd;

    queue_iterate( list, scsiCmd, IOSCSIParallelCommand *, nextCommand )
    {
        if ( scsiCmd == findSCSICmd )
        {
            return true;
        }
    }
    return false;
}
  
void IOSCSIParallelDevice::purgeAllCommands( queue_head_t *list, IOReturn rc )
{
    IOSCSIParallelCommand		*scsiCmd;

    if ( queue_empty( list ) == true ) return;

    do
    {
        scsiCmd = (IOSCSIParallelCommand *)queue_first( list );

        deleteCommand( list, scsiCmd, rc );
        finishCommand( scsiCmd );

    } while( queue_empty( list ) == false );
}
