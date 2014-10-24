/*
 * Copyright (c) 1998-2011 Apple Inc. All rights reserved.
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
#include <IOKit/IOBSD.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IOCatalogue.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/IOPlatformExpert.h>

extern "C" {

#include <pexpert/pexpert.h>
#include <kern/clock.h>
#include <uuid/uuid.h>
#include <sys/vnode_internal.h>

// how long to wait for matching root device, secs
#if DEBUG
#define ROOTDEVICETIMEOUT       120
#else
#define ROOTDEVICETIMEOUT       60
#endif

extern dev_t mdevadd(int devid, uint64_t base, unsigned int size, int phys);
extern dev_t mdevlookup(int devid);
extern void mdevremoveall(void);
extern void di_root_ramfile(IORegistryEntry * entry);

kern_return_t
IOKitBSDInit( void )
{
    IOService::publishResource("IOBSD");

    return( kIOReturnSuccess );
}

void
IOServicePublishResource( const char * property, boolean_t value )
{
    if ( value)
        IOService::publishResource( property, kOSBooleanTrue );
    else
        IOService::getResourceService()->removeProperty( property );
}

boolean_t
IOServiceWaitForMatchingResource( const char * property, uint64_t timeout )
{
    OSDictionary *	dict = 0;
    IOService *         match = 0;
    boolean_t		found = false;
    
    do {
        
        dict = IOService::resourceMatching( property );
        if( !dict)
            continue;
        match = IOService::waitForMatchingService( dict, timeout );
        if ( match)
            found = true;
        
    } while( false );
    
    if( dict)
        dict->release();
    if( match)
        match->release();
    
    return( found );
}

boolean_t
IOCatalogueMatchingDriversPresent( const char * property )
{
    OSDictionary *	dict = 0;
    OSOrderedSet *	set = 0;
    SInt32		generationCount = 0;
    boolean_t		found = false;
    
    do {
        
        dict = OSDictionary::withCapacity(1);
        if( !dict)
            continue;
        dict->setObject( property, kOSBooleanTrue );
        set = gIOCatalogue->findDrivers( dict, &generationCount );
        if ( set && (set->getCount() > 0))
            found = true;
        
    } while( false );
    
    if( dict)
        dict->release();
    if( set)
        set->release();
    
    return( found );
}

OSDictionary * IOBSDNameMatching( const char * name )
{
    OSDictionary *	dict;
    const OSSymbol *	str = 0;

    do {

	dict = IOService::serviceMatching( gIOServiceKey );
	if( !dict)
	    continue;
        str = OSSymbol::withCString( name );
	if( !str)
	    continue;
        dict->setObject( kIOBSDNameKey, (OSObject *) str );
        str->release();

        return( dict );

    } while( false );

    if( dict)
	dict->release();
    if( str)
	str->release();

    return( 0 );
}

OSDictionary * IOUUIDMatching( void )
{
    return IOService::resourceMatching( "boot-uuid-media" );
}

OSDictionary * IONetworkNamePrefixMatching( const char * prefix )
{
    OSDictionary *	 matching;
    OSDictionary *   propDict = 0;
    const OSSymbol * str      = 0;
	char networkType[128];
	
    do {
        matching = IOService::serviceMatching( "IONetworkInterface" );
        if ( matching == 0 )
            continue;

        propDict = OSDictionary::withCapacity(1);
        if ( propDict == 0 )
            continue;

        str = OSSymbol::withCString( prefix );
        if ( str == 0 )
            continue;

        propDict->setObject( "IOInterfaceNamePrefix", (OSObject *) str );
        str->release();
        str = 0;

		// see if we're contrained to netroot off of specific network type
		if(PE_parse_boot_argn( "network-type", networkType, 128 ))
		{
			str = OSSymbol::withCString( networkType );
			if(str)
			{
				propDict->setObject( "IONetworkRootType", str);
				str->release();
				str = 0;
			}
		}

        if ( matching->setObject( gIOPropertyMatchKey,
                                  (OSObject *) propDict ) != true )
            continue;

        propDict->release();
        propDict = 0;

        return( matching );

    } while ( false );

    if ( matching ) matching->release();
    if ( propDict ) propDict->release();
    if ( str      ) str->release();

    return( 0 );
}

static bool IORegisterNetworkInterface( IOService * netif )
{
    // A network interface is typically named and registered
    // with BSD after receiving a request from a user space
    // "namer". However, for cases when the system needs to
    // root from the network, this registration task must be
    // done inside the kernel and completed before the root
    // device is handed to BSD.

    IOService *    stack;
    OSNumber *     zero    = 0;
    OSString *     path    = 0;
    OSDictionary * dict    = 0;
    char *         pathBuf = 0;
    int            len;
    enum { kMaxPathLen = 512 };

    do {
        stack = IOService::waitForService(
                IOService::serviceMatching("IONetworkStack") );
        if ( stack == 0 ) break;

        dict = OSDictionary::withCapacity(3);
        if ( dict == 0 ) break;

        zero = OSNumber::withNumber((UInt64) 0, 32);
        if ( zero == 0 ) break;

        pathBuf = (char *) IOMalloc( kMaxPathLen );
        if ( pathBuf == 0 ) break;

        len = kMaxPathLen;
        if ( netif->getPath( pathBuf, &len, gIOServicePlane )
             == false ) break;

        path = OSString::withCStringNoCopy( pathBuf );
        if ( path == 0 ) break;

        dict->setObject( "IOInterfaceUnit", zero );
        dict->setObject( kIOPathMatchKey,   path );

        stack->setProperties( dict );
    }
    while ( false );

    if ( zero ) zero->release();
    if ( path ) path->release();
    if ( dict ) dict->release();
    if ( pathBuf ) IOFree(pathBuf, kMaxPathLen);

	return ( netif->getProperty( kIOBSDNameKey ) != 0 );
}

OSDictionary * IOOFPathMatching( const char * path, char * buf, int maxLen )
{
    OSDictionary *	matching = NULL;
    OSString *		str;
    char *		comp;
    int			len;

    do {

	len = strlen( kIODeviceTreePlane ":" );
	maxLen -= len;
	if( maxLen <= 0)
	    continue;

	strlcpy( buf, kIODeviceTreePlane ":", len + 1 );
	comp = buf + len;

	len = strlen( path );
	maxLen -= len;
	if( maxLen <= 0)
	    continue;
	strlcpy( comp, path, len + 1 );

	matching = OSDictionary::withCapacity( 1 );
	if( !matching)
	    continue;

	str = OSString::withCString( buf );
	if( !str)
	    continue;
        matching->setObject( kIOPathMatchKey, str );
	str->release();

	return( matching );

    } while( false );

    if( matching)
        matching->release();

    return( 0 );
}

static int didRam = 0;
enum { kMaxPathBuf = 512, kMaxBootVar = 128 };

kern_return_t IOFindBSDRoot( char * rootName, unsigned int rootNameSize,
				dev_t * root, u_int32_t * oflags )
{
    mach_timespec_t	t;
    IOService *		service;
    IORegistryEntry *	regEntry;
    OSDictionary *	matching = 0;
    OSString *		iostr;
    OSNumber *		off;
    OSData *		data = 0;

    UInt32		flags = 0;
    int			mnr, mjr;
    const char *        mediaProperty = 0;
    char *		rdBootVar;
    char *		str;
    const char *	look = 0;
    int			len;
    bool		debugInfoPrintedOnce = false;
    const char * 	uuidStr = NULL;

    static int		mountAttempts = 0;
				
    int xchar, dchar;
                                    

    if( mountAttempts++)
	IOSleep( 5 * 1000 );

    str = (char *) IOMalloc( kMaxPathBuf + kMaxBootVar );
    if( !str)
	return( kIOReturnNoMemory );
    rdBootVar = str + kMaxPathBuf;

    if (!PE_parse_boot_argn("rd", rdBootVar, kMaxBootVar )
     && !PE_parse_boot_argn("rootdev", rdBootVar, kMaxBootVar ))
	rdBootVar[0] = 0;

    do {
	if( (regEntry = IORegistryEntry::fromPath( "/chosen", gIODTPlane ))) {
	    di_root_ramfile(regEntry);
            data = OSDynamicCast(OSData, regEntry->getProperty( "root-matching" ));
            if (data) {
               matching = OSDynamicCast(OSDictionary, OSUnserializeXML((char *)data->getBytesNoCopy()));
                if (matching) {
                    continue;
                }
            }

	    data = (OSData *) regEntry->getProperty( "boot-uuid" );
	    if( data) {
		uuidStr = (const char*)data->getBytesNoCopy();
		OSString *uuidString = OSString::withCString( uuidStr );

		// match the boot-args boot-uuid processing below
		if( uuidString) {
		    IOLog("rooting via boot-uuid from /chosen: %s\n", uuidStr);
		    IOService::publishResource( "boot-uuid", uuidString );
		    uuidString->release();
		    matching = IOUUIDMatching();
		    mediaProperty = "boot-uuid-media";
		    regEntry->release();
		    continue;
		} else {
		    uuidStr = NULL;
		}
	    }
	    regEntry->release();
	}
    } while( false );

//
//	See if we have a RAMDisk property in /chosen/memory-map.  If so, make it into a device.
//	It will become /dev/mdx, where x is 0-f. 
//

	if(!didRam) {												/* Have we already build this ram disk? */
		didRam = 1;												/* Remember we did this */
		if((regEntry = IORegistryEntry::fromPath( "/chosen/memory-map", gIODTPlane ))) {	/* Find the map node */
			data = (OSData *)regEntry->getProperty("RAMDisk");	/* Find the ram disk, if there */
			if(data) {											/* We found one */
				uintptr_t *ramdParms;
				ramdParms = (uintptr_t *)data->getBytesNoCopy();	/* Point to the ram disk base and size */
				(void)mdevadd(-1, ml_static_ptovirt(ramdParms[0]) >> 12, ramdParms[1] >> 12, 0);	/* Initialize it and pass back the device number */
			}
			regEntry->release();								/* Toss the entry */
		}
	}
	
//
//	Now check if we are trying to root on a memory device
//

	if((rdBootVar[0] == 'm') && (rdBootVar[1] == 'd') && (rdBootVar[3] == 0)) {
		dchar = xchar = rdBootVar[2];							/* Get the actual device */
		if((xchar >= '0') && (xchar <= '9')) xchar = xchar - '0';	/* If digit, convert */
		else {
			xchar = xchar & ~' ';								/* Fold to upper case */
			if((xchar >= 'A') && (xchar <= 'F')) {				/* Is this a valid digit? */
				xchar = (xchar & 0xF) + 9;						/* Convert the hex digit */
				dchar = dchar | ' ';							/* Fold to lower case */
			}
			else xchar = -1;									/* Show bogus */
		}
		if(xchar >= 0) {										/* Do we have a valid memory device name? */
			*root = mdevlookup(xchar);							/* Find the device number */
			if(*root >= 0) {									/* Did we find one? */

				rootName[0] = 'm';								/* Build root name */
				rootName[1] = 'd';								/* Build root name */
				rootName[2] = dchar;							/* Build root name */
				rootName[3] = 0;								/* Build root name */
				IOLog("BSD root: %s, major %d, minor %d\n", rootName, major(*root), minor(*root));
				*oflags = 0;									/* Show that this is not network */
				goto iofrootx;									/* Join common exit... */
			}
			panic("IOFindBSDRoot: specified root memory device, %s, has not been configured\n", rdBootVar);	/* Not there */
		}
	}

      if( (!matching) && rdBootVar[0] ) {
	// by BSD name
	look = rdBootVar;
	if( look[0] == '*')
	    look++;
    
	if ( strncmp( look, "en", strlen( "en" )) == 0 ) {
	    matching = IONetworkNamePrefixMatching( "en" );
	} else if ( strncmp( look, "uuid", strlen( "uuid" )) == 0 ) {
            char *uuid;
            OSString *uuidString;

            uuid = (char *)IOMalloc( kMaxBootVar );
                  
            if ( uuid ) {
                if (!PE_parse_boot_argn( "boot-uuid", uuid, kMaxBootVar )) {
                    panic( "rd=uuid but no boot-uuid=<value> specified" ); 
                } 
                uuidString = OSString::withCString( uuid );
                if ( uuidString ) {
                    IOService::publishResource( "boot-uuid", uuidString );
                    uuidString->release();
                    IOLog( "\nWaiting for boot volume with UUID %s\n", uuid );
                    matching = IOUUIDMatching();
                    mediaProperty = "boot-uuid-media";
                }
                IOFree( uuid, kMaxBootVar );
            }
	} else {
	    matching = IOBSDNameMatching( look );
	}
    }

    if( !matching) {
	OSString * astring;
	// Match any HFS media
	
        matching = IOService::serviceMatching( "IOMedia" );
        astring = OSString::withCStringNoCopy("Apple_HFS");
        if ( astring ) {
            matching->setObject("Content", astring);
            astring->release();
        }
    }

    if( gIOKitDebug & kIOWaitQuietBeforeRoot ) {
    	IOLog( "Waiting for matching to complete\n" );
    	IOService::getPlatform()->waitQuiet();
    }

    if( true && matching) {
        OSSerialize * s = OSSerialize::withCapacity( 5 );

        if( matching->serialize( s )) {
            IOLog( "Waiting on %s\n", s->text() );
            s->release();
        }
    }

    do {
        t.tv_sec = ROOTDEVICETIMEOUT;
        t.tv_nsec = 0;
	matching->retain();
        service = IOService::waitForService( matching, &t );
	if( (!service) || (mountAttempts == 10)) {
            PE_display_icon( 0, "noroot");
            IOLog( "Still waiting for root device\n" );

            if( !debugInfoPrintedOnce) {
                debugInfoPrintedOnce = true;
                if( gIOKitDebug & kIOLogDTree) {
                    IOLog("\nDT plane:\n");
                    IOPrintPlane( gIODTPlane );
                }
                if( gIOKitDebug & kIOLogServiceTree) {
                    IOLog("\nService plane:\n");
                    IOPrintPlane( gIOServicePlane );
                }
                if( gIOKitDebug & kIOLogMemory)
                    IOPrintMemory();
            }
	}
    } while( !service);
    matching->release();

    if ( service && mediaProperty ) {
        service = (IOService *)service->getProperty(mediaProperty);
    }

    mjr = 0;
    mnr = 0;

    // If the IOService we matched to is a subclass of IONetworkInterface,
    // then make sure it has been registered with BSD and has a BSD name
    // assigned.

    if ( service
    &&   service->metaCast( "IONetworkInterface" )
    &&   !IORegisterNetworkInterface( service ) )
    {
        service = 0;
    }

    if( service) {

	len = kMaxPathBuf;
	service->getPath( str, &len, gIOServicePlane );
	IOLog( "Got boot device = %s\n", str );

	iostr = (OSString *) service->getProperty( kIOBSDNameKey );
	if( iostr)
	    strlcpy( rootName, iostr->getCStringNoCopy(), rootNameSize );
	off = (OSNumber *) service->getProperty( kIOBSDMajorKey );
	if( off)
	    mjr = off->unsigned32BitValue();
	off = (OSNumber *) service->getProperty( kIOBSDMinorKey );
	if( off)
	    mnr = off->unsigned32BitValue();

	if( service->metaCast( "IONetworkInterface" ))
	    flags |= 1;

    } else {

	IOLog( "Wait for root failed\n" );
        strlcpy( rootName, "en0", rootNameSize );
        flags |= 1;
    }

    IOLog( "BSD root: %s", rootName );
    if( mjr)
	IOLog(", major %d, minor %d\n", mjr, mnr );
    else
	IOLog("\n");

    *root = makedev( mjr, mnr );
    *oflags = flags;

    IOFree( str,  kMaxPathBuf + kMaxBootVar );

iofrootx:
    if( (gIOKitDebug & (kIOLogDTree | kIOLogServiceTree | kIOLogMemory)) && !debugInfoPrintedOnce) {

	IOService::getPlatform()->waitQuiet();
        if( gIOKitDebug & kIOLogDTree) {
            IOLog("\nDT plane:\n");
            IOPrintPlane( gIODTPlane );
        }
        if( gIOKitDebug & kIOLogServiceTree) {
            IOLog("\nService plane:\n");
            IOPrintPlane( gIOServicePlane );
        }
        if( gIOKitDebug & kIOLogMemory)
            IOPrintMemory();
    }

    return( kIOReturnSuccess );
}

bool IORamDiskBSDRoot(void)
{
    char rdBootVar[kMaxBootVar];
    if (PE_parse_boot_argn("rd", rdBootVar, kMaxBootVar )
     || PE_parse_boot_argn("rootdev", rdBootVar, kMaxBootVar )) {
        if((rdBootVar[0] == 'm') && (rdBootVar[1] == 'd') && (rdBootVar[3] == 0)) {
            return true;
        }
    }
    return false;
}

void IOSecureBSDRoot(const char * rootName)
{
}

void *
IOBSDRegistryEntryForDeviceTree(char * path)
{
    return (IORegistryEntry::fromPath(path, gIODTPlane));
}

void
IOBSDRegistryEntryRelease(void * entry)
{
    IORegistryEntry * regEntry = (IORegistryEntry *)entry;

    if (regEntry)
	regEntry->release();
    return;
}

const void *
IOBSDRegistryEntryGetData(void * entry, char * property_name, 
			  int * packet_length)
{
    OSData *		data;
    IORegistryEntry * 	regEntry = (IORegistryEntry *)entry;

    data = (OSData *) regEntry->getProperty(property_name);
    if (data) {
	*packet_length = data->getLength();
        return (data->getBytesNoCopy());
    }
    return (NULL);
}

kern_return_t IOBSDGetPlatformUUID( uuid_t uuid, mach_timespec_t timeout )
{
    IOService * resources;
    OSString *  string;

    resources = IOService::waitForService( IOService::resourceMatching( kIOPlatformUUIDKey ), ( timeout.tv_sec || timeout.tv_nsec ) ? &timeout : 0 );
    if ( resources == 0 ) return KERN_OPERATION_TIMED_OUT;

    string = ( OSString * ) IOService::getPlatform( )->getProvider( )->getProperty( kIOPlatformUUIDKey );
    if ( string == 0 ) return KERN_NOT_SUPPORTED;

    uuid_parse( string->getCStringNoCopy( ), uuid );

    return KERN_SUCCESS;
}

kern_return_t IOBSDGetPlatformSerialNumber( char *serial_number_str, u_int32_t len )
{
    OSDictionary * platform_dict;
    IOService *platform;
    OSString *  string;

    if (len < 1) {
	    return 0;
    }
    serial_number_str[0] = '\0';

    platform_dict = IOService::serviceMatching( "IOPlatformExpertDevice" );
    if (platform_dict == NULL) {
	    return KERN_NOT_SUPPORTED;
    }

    platform = IOService::waitForService( platform_dict );
    if (platform) {
	    string = ( OSString * ) platform->getProperty( kIOPlatformSerialNumberKey );
	    if ( string == 0 ) {
		    return KERN_NOT_SUPPORTED;
	    } else {
		    strlcpy( serial_number_str, string->getCStringNoCopy( ), len );
	    }
    }
    
    return KERN_SUCCESS;
}

void IOBSDIterateMediaWithContent(const char *content_uuid_cstring, int (*func)(const char *bsd_dev_name, const char *uuid_str, void *arg), void *arg)
{
    OSDictionary *dictionary;
    OSString *content_uuid_string;

    dictionary = IOService::serviceMatching( "IOMedia" );
    if( dictionary ) {
	content_uuid_string = OSString::withCString( content_uuid_cstring );
	if( content_uuid_string ) {
	    IOService *service;
	    OSIterator *iter;

	    dictionary->setObject( "Content", content_uuid_string );
	    dictionary->retain();

	    iter = IOService::getMatchingServices(dictionary);
	    while (iter && (service = (IOService *)iter->getNextObject())) {
		    if( service ) {
			    OSString *iostr = (OSString *) service->getProperty( kIOBSDNameKey );
			    OSString *uuidstr = (OSString *) service->getProperty( "UUID" );
			    const char *uuid;

			    if( iostr) {
				    if (uuidstr) {
					    uuid = uuidstr->getCStringNoCopy();
				    } else {
					    uuid = "00000000-0000-0000-0000-000000000000";
				    }

				    // call the callback
				    if (func && func(iostr->getCStringNoCopy(), uuid, arg) == 0) {
					    break;
				    }
			    }
		    }
	    }
	    if (iter)
		    iter->release();
	    
	    content_uuid_string->release();
	}
	dictionary->release();
    }
}


int IOBSDIsMediaEjectable( const char *cdev_name )
{
    int ret = 0;
    OSDictionary *dictionary;
    OSString *dev_name;

    if (strncmp(cdev_name, "/dev/", 5) == 0) {
	    cdev_name += 5;
    }

    dictionary = IOService::serviceMatching( "IOMedia" );
    if( dictionary ) {
	dev_name = OSString::withCString( cdev_name );
	if( dev_name ) {
	    IOService *service;
	    mach_timespec_t tv = { 5, 0 };    // wait up to "timeout" seconds for the device

	    dictionary->setObject( kIOBSDNameKey, dev_name );
	    dictionary->retain();
	    service = IOService::waitForService( dictionary, &tv );
	    if( service ) {
		OSBoolean *ejectable = (OSBoolean *) service->getProperty( "Ejectable" );

		if( ejectable ) {
			ret = (int)ejectable->getValue();
		}

	    }
	    dev_name->release();
	}
	dictionary->release();
    }

    return ret;
}

} /* extern "C" */
