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
#include <IOKit/ata/IOATAStandardInterface.h>

void IOATAStandardDevice::addCommand( queue_head_t *list, IOATAStandardCommand *ataCmd )
{
    ataCmd->list = list;

    queue_enter( list, ataCmd, IOATAStandardCommand *, nextCommand );
}

void IOATAStandardDevice::deleteCommand( queue_head_t *list, IOATAStandardCommand *ataCmd, IOReturn rc = kIOReturnSuccess )
{
    ataCmd->list = 0;

    if ( rc != kIOReturnSuccess )
    {
        if  ( ataCmd->results.returnCode == kIOReturnSuccess )
        {    
            ataCmd->results.returnCode = (IOReturn) rc;
        }
    }
 
    queue_remove( list, ataCmd, IOATAStandardCommand *, nextCommand );
}

IOATAStandardCommand *IOATAStandardDevice::checkCommand( queue_head_t *list )
{
    if ( queue_empty( list ) == true )
    {
        return 0;
    }

    return (IOATAStandardCommand *)queue_first( list );
}


IOATAStandardCommand *IOATAStandardDevice::getCommand( queue_head_t *list )
{
    IOATAStandardCommand	*ataCmd = 0;

    if ( queue_empty( list ) == false )
    {
        queue_remove_first( list, ataCmd, IOATAStandardCommand *, nextCommand );
        ataCmd->list = 0;
    }

    return ataCmd;
}

void IOATAStandardDevice::stackCommand( queue_head_t *list, IOATAStandardCommand *ataCmd )
{
    ataCmd->list = list;

    queue_enter_first( list, ataCmd, IOATAStandardCommand *, nextCommand );
}

void IOATAStandardDevice::moveCommand( queue_head_t *fromList, queue_head_t *toList, IOATAStandardCommand *ataCmd, IOReturn rc = kIOReturnSuccess )
{
    if ( rc != kIOReturnSuccess )
    {
        if  ( ataCmd->results.returnCode == kIOReturnSuccess )
        {    
            ataCmd->results.returnCode = (IOReturn) rc;
        }
    }

    ataCmd->list = toList;  

    queue_remove( fromList, ataCmd, IOATAStandardCommand *, nextCommand );
    queue_enter(  toList,   ataCmd, IOATAStandardCommand *, nextCommand );
}

void IOATAStandardDevice::moveAllCommands( queue_head_t *fromList, queue_head_t *toList, IOReturn rc = kIOReturnSuccess )
{
    IOATAStandardCommand		*ataCmd;

    if ( queue_empty( fromList ) == true ) return;

    do
    {
        ataCmd = (IOATAStandardCommand *)queue_first( fromList );

        if ( rc != kIOReturnSuccess )
        {
            if  ( ataCmd->results.returnCode == kIOReturnSuccess )
            {    
                ataCmd->results.returnCode = (IOReturn) rc;
            }
        }

        ataCmd->list = toList;  

        queue_remove( fromList, ataCmd, IOATAStandardCommand *, nextCommand );
        queue_enter(  toList,   ataCmd, IOATAStandardCommand *, nextCommand );

    } while( queue_empty( fromList ) == false );
}

bool IOATAStandardDevice::findCommand( queue_head_t *list, IOATAStandardCommand *findATACmd )
{
    IOATAStandardCommand		*ataCmd;

    queue_iterate( list, ataCmd, IOATAStandardCommand *, nextCommand )
    {
        if ( ataCmd == findATACmd )
        {
            return true;
        }
    }
    return false;
}
  
void IOATAStandardDevice::purgeAllCommands( queue_head_t *list, IOReturn rc )
{
    IOATAStandardCommand		*ataCmd;

    if ( queue_empty( list ) == true ) return;

    do
    {
        ataCmd = (IOATAStandardCommand *)queue_first( list );

        deleteCommand( list, ataCmd, rc );
        finishCommand( ataCmd );

    } while( queue_empty( list ) == false );
}
