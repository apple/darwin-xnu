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
#include <IOKit/IOBSD.h>
#include <IOKit/IOLib.h>
#include <IOKit/IOService.h>
#include <IOKit/IODeviceTreeSupport.h>
#include <IOKit/IOKitKeys.h>
#include <IOKit/storage/IOMedia.h>
#include <IOKit/network/IONetworkStack.h>
#include <IOKit/network/IONetworkInterface.h>
#include <IOKit/IOPlatformExpert.h>

#include <sys/disklabel.h>

extern "C" {

#include <pexpert/pexpert.h>
#include <kern/clock.h>

// how long to wait for matching root device, secs
#define ROOTDEVICETIMEOUT	60


kern_return_t
IOKitBSDInit( void )
{
    IOLog("IOKitBSDInit\n");

    IOService::publishResource("IOBSD");
 
    return( kIOReturnSuccess );
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

OSDictionary * IONetworkMatching(  const char * path,
				   char * buf, int maxLen )
{
    OSDictionary *	matching = 0;
    OSDictionary *	dict;
    OSString *		str;
    char *		comp;
    const char *	skip;
    int			len;

    do {

	len = strlen( kIODeviceTreePlane ":" );
	maxLen -= len;
	if( maxLen < 0)
	    continue;

	strcpy( buf, kIODeviceTreePlane ":" );
	comp = buf + len;

        // remove parameters following ':' from the path
        skip = strchr( path, ':');
	if( !skip)
	    continue;

        len = skip - path;
	maxLen -= len;
	if( maxLen < 0)
	    continue;
        strncpy( comp, path, len );
        comp[ len ] = 0;

	matching = IOService::serviceMatching( "IONetworkInterface" );
	if( !matching)
	    continue;
	dict = IOService::addLocation( matching );
	if( !dict)
	    continue;

	str = OSString::withCString( buf );
	if( !str)
	    continue;
        dict->setObject( kIOPathMatchKey, str );
	str->release();

	return( matching );

    } while( false );

    if( matching)
        matching->release();

    return( 0 );
}

OSDictionary * IONetworkNamePrefixMatching( const char * prefix )
{
    OSDictionary *	 matching;
    OSDictionary *   propDict = 0;
    const OSSymbol * str      = 0;

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

        propDict->setObject( kIOInterfaceNamePrefix, (OSObject *) str );
        str->release();
        str = 0;

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

static bool IORegisterNetworkInterface( IONetworkInterface * netif )
{
    IONetworkStack * stack;

    if (( stack = IONetworkStack::getNetworkStack() ))
    {
        stack->registerInterface( netif, netif->getNamePrefix() );
    }

	return ( netif->getProperty( kIOBSDNameKey ) != 0 );
}

static void IORegisterPrimaryNetworkInterface()
{
    IONetworkStack * stack;

    if (( stack = IONetworkStack::getNetworkStack() ))
    {
        stack->registerPrimaryInterface( true );
    }    
}

OSDictionary * IODiskMatching( const char * path, char * buf, int maxLen )
{
    const char * look;
    const char * alias;
    char *       comp;
    long         unit = -1;
    long         partition = -1;
    char         c;

    // scan the tail of the path for "@unit:partition"
    do {
        // Have to get the full path to the controller - an alias may
        // tell us next to nothing, like "hd:8"
        alias = IORegistryEntry::dealiasPath( &path, gIODTPlane );

        look = path + strlen( path);
        c = ':';
        while( look != path) {
            if( *(--look) == c) {
                if( c == ':') {
                    partition = strtol( look + 1, 0, 0 );
                    c = '@';
                } else if( c == '@') {
                    unit = strtol( look + 1, 0, 16 );
                    c = '/';
                } else if( c == '/') {
                    c = 0;
                    break;
                }
            }

	        if( alias && (look == path)) {
                path = alias;
                look = path + strlen( path);
                alias = 0;
            }
        }
        if( c || unit == -1 || partition == -1)
            continue;

        maxLen -= strlen( "{" kIOPathMatchKey "='" kIODeviceTreePlane ":" );
        maxLen -= ( alias ? strlen( alias ) : 0 ) + (look - path);
        maxLen -= strlen( "/@hhhhhhhh:dddddddddd';}" );

        if( maxLen > 0) {
            sprintf( buf, "{" kIOPathMatchKey "='" kIODeviceTreePlane ":" );
            comp = buf + strlen( buf );

            if( alias) {
                strcpy( comp, alias );
                comp += strlen( alias );
            }

            if ( (look - path)) {
                strncpy( comp, path, look - path);
                comp += look - path;
            }

            sprintf( comp, "/@%lx:%ld';}", unit, partition );
        } else
            continue;

        return( OSDynamicCast(OSDictionary, OSUnserialize( buf, 0 )) );

    } while( false );

    return( 0 );
}

OSDictionary * IOOFPathMatching( const char * path, char * buf, int maxLen )
{
    /* need to look up path, get device type,
        call matching help based on device type */

    return( IODiskMatching( path, buf, maxLen ));

}

kern_return_t IOFindBSDRoot( char * rootName,
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
    int			minor, major;
    char *		rdBootVar;
    enum {		kMaxPathBuf = 512, kMaxBootVar = 128 };
    char *		str;
    const char *	look = 0;
    int			len;
    bool		forceNet = false;

    static int		mountAttempts = 0;

    if( mountAttempts++)
	IOSleep( 5 * 1000 );

    str = (char *) IOMalloc( kMaxPathBuf + kMaxBootVar );
    if( !str)
	return( kIOReturnNoMemory );
    rdBootVar = str + kMaxPathBuf;

    if (!PE_parse_boot_arg("rd", rdBootVar )
     && !PE_parse_boot_arg("rootdev", rdBootVar ))
	rdBootVar[0] = 0;

    do {
        if( (regEntry = IORegistryEntry::fromPath( "/chosen", gIODTPlane ))) {
	    data = (OSData *) regEntry->getProperty( "rootpath" );
	    regEntry->release();
	    if( data)
	    continue;
	}
        if( (regEntry = IORegistryEntry::fromPath( "/options", gIODTPlane ))) {
	    data = (OSData *) regEntry->getProperty( "boot-file" );
	    regEntry->release();
	    if( data)
	    continue;
	}
    } while( false );

    if( data)
        look = (const char *) data->getBytesNoCopy();

    if( rdBootVar[0] == '*') {
        look = rdBootVar + 1;
	forceNet = false;
    } else {
        if( (regEntry = IORegistryEntry::fromPath( "/", gIODTPlane ))) {
            forceNet = (0 != regEntry->getProperty( "net-boot" ));
	    regEntry->release();
	}
    }

    if( look) {
	// from OpenFirmware path
	IOLog("From path: \"%s\", ", look);

	if( forceNet || (0 == strncmp( look, "enet", strlen( "enet" ))) )
           matching = IONetworkMatching( look, str, kMaxPathBuf );
        else
            matching = IODiskMatching( look, str, kMaxPathBuf );
    }

    if( (!matching) && rdBootVar[0] ) {
	// by BSD name
	look = rdBootVar;
	if( look[0] == '*')
	    look++;
    
    if ( strncmp( look, "en", strlen( "en" )) == 0 )
        matching = IONetworkNamePrefixMatching( "en" );
    else
        matching = IOBSDNameMatching( look );
    }

    if( !matching) {
        OSString * astring;
	// any UFS
        matching = IOService::serviceMatching( "IOMedia" );
        astring = OSString::withCStringNoCopy("Apple_UFS");
        if ( astring ) {
            matching->setObject(kIOMediaContentKey, astring);
            astring->release();
        }
    }

    if( true && matching) {
        OSSerialize * s = OSSerialize::withCapacity( 5 );

        if( matching->serialize( s )) {
            IOLog( "Waiting on %s\n", s->text() );
            s->release();
        }
    }

    IOService::waitForService(IOService::serviceMatching("IOMediaBSDClient"));

    do {
        t.tv_sec = ROOTDEVICETIMEOUT;
        t.tv_nsec = 0;
	matching->retain();
        service = IOService::waitForService( matching, &t );
	if( (!service) || (mountAttempts == 10)) {
            PE_display_icon( 0, "noroot");
            IOLog( "Still waiting for root device\n" );
	}
    } while( !service);
    matching->release();

    major = 0;
    minor = 0;

    // If the IOService we matched to is a subclass of IONetworkInterface,
    // then make sure it has been registered with BSD and has a BSD name
    // assigned.

    if ( service
    &&   service->metaCast( "IONetworkInterface" )
    &&   !IORegisterNetworkInterface( (IONetworkInterface *) service ) )
    {
        service = 0;
    }
    IORegisterPrimaryNetworkInterface();

    if( service) {

	len = kMaxPathBuf;
	service->getPath( str, &len, gIOServicePlane );
	IOLog( "Got boot device = %s\n", str );

	iostr = (OSString *) service->getProperty( kIOBSDNameKey );
	if( iostr)
	    strcpy( rootName, iostr->getCStringNoCopy() );
	off = (OSNumber *) service->getProperty( kIOBSDMajorKey );
	if( off)
	    major = off->unsigned32BitValue();
	off = (OSNumber *) service->getProperty( kIOBSDMinorKey );
	if( off)
	    minor = off->unsigned32BitValue();

	if( service->metaCast( "IONetworkInterface" ))
	    flags |= 1;

    } else {

	IOLog( "Wait for root failed\n" );
        strcpy( rootName, "en0");
        flags |= 1;
    }

    IOLog( "BSD root: %s", rootName );
    if( major)
	IOLog(", major %d, minor %d\n", major, minor );
    else
	IOLog("\n");

    *root = makedev( major, minor );
    *oflags = flags;

    IOFree( str,  kMaxPathBuf + kMaxBootVar );

    if( gIOKitDebug & (kIOLogDTree | kIOLogServiceTree | kIOLogMemory)) {

	IOSleep(10 * 1000);
//	IOService::getPlatform()->waitQuiet();
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

} /* extern "C" */
