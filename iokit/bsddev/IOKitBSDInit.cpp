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
#include <IOKit/IOPlatformExpert.h>

extern "C" {

#include <pexpert/pexpert.h>
#include <kern/clock.h>

// how long to wait for matching root device, secs
#define ROOTDEVICETIMEOUT	60

extern dev_t mdevadd(int devid, ppnum_t base, unsigned int size, int phys);
extern dev_t mdevlookup(int devid);

kern_return_t
IOKitBSDInit( void )
{
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

OSDictionary * IOUUIDMatching( void )
{
    return IOService::resourceMatching( "boot-uuid-media" );
}


OSDictionary * IOCDMatching( void )
{
    OSDictionary *	dict;
    const OSSymbol *	str;
    
    dict = IOService::serviceMatching( "IOMedia" );
    if( dict == 0 ) {
        IOLog("Unable to find IOMedia\n");
        return 0;
    }
    
    str = OSSymbol::withCString( "CD_ROM_Mode_1" );
    if( str == 0 ) {
        dict->release();
        return 0;
    }
    
    dict->setObject( "Content Hint", (OSObject *)str );
    str->release();        
    return( dict );
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

        propDict->setObject( "IOInterfaceNamePrefix", (OSObject *) str );
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

OSDictionary * IODiskMatching( const char * path, char * buf, int maxLen )
{
    const char * look;
    const char * alias;
    char *       comp;
    long         unit = -1;
    long         partition = -1;
    long		 lun = -1;
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
                    unit = strtol( look + 1, &comp, 16 );

                    if( *comp == ',') {
                        lun = strtol( comp + 1, 0, 16 );
                    }
                    
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
        maxLen -= strlen( "/@hhhhhhhh,hhhhhhhh:dddddddddd';}" );

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
			
			if ( lun != -1 )
			{
				sprintf ( comp, "/@%lx,%lx:%ld';}", unit, lun, partition );
			}
			else
			{
            	sprintf( comp, "/@%lx:%ld';}", unit, partition );
            }
        } else
            continue;
		
        return( OSDynamicCast(OSDictionary, OSUnserialize( buf, 0 )) );

    } while( false );

    return( 0 );
}

OSDictionary * IOOFPathMatching( const char * path, char * buf, int maxLen )
{
    OSDictionary *	matching;
    OSString *		str;
    char *		comp;
    int			len;

    /* need to look up path, get device type,
        call matching help based on device type */

    matching = IODiskMatching( path, buf, maxLen );
    if( matching)
	return( matching );

    do {

	len = strlen( kIODeviceTreePlane ":" );
	maxLen -= len;
	if( maxLen < 0)
	    continue;

	strcpy( buf, kIODeviceTreePlane ":" );
	comp = buf + len;

	len = strlen( path );
	maxLen -= len;
	if( maxLen < 0)
	    continue;
        strncpy( comp, path, len );
        comp[ len ] = 0;

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

IOService * IOFindMatchingChild( IOService * service )
{
    // find a matching child service
    IOService * child = 0;
    OSIterator * iter = service->getClientIterator();
    if ( iter ) {
        while( ( child = (IOService *) iter->getNextObject() ) ) {
            OSDictionary * dict = OSDictionary::withCapacity( 1 );
            if( dict == 0 ) {
                iter->release();
                return 0;
            }
            const OSSymbol * str = OSSymbol::withCString( "Apple_HFS" );
            if( str == 0 ) {
                dict->release();
                iter->release();
                return 0;
            }
            dict->setObject( "Content", (OSObject *)str );
            str->release();
            if ( child->compareProperty( dict, "Content" ) ) {
                dict->release();
                break;
            }
            dict->release();
            IOService * subchild = IOFindMatchingChild( child );
            if ( subchild ) {
                child = subchild;
                break;
            }
        }
        iter->release();
    }
    return child;
}

static int didRam = 0;

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
    UInt32		*ramdParms = 0;

    UInt32		flags = 0;
    int			minor, major;
    bool		findHFSChild = false;
    char *              mediaProperty = 0;
    char *		rdBootVar;
    enum {		kMaxPathBuf = 512, kMaxBootVar = 128 };
    char *		str;
    const char *	look = 0;
    int			len;
    bool		forceNet = false;
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

    if (!PE_parse_boot_arg("rd", rdBootVar )
     && !PE_parse_boot_arg("rootdev", rdBootVar ))
	rdBootVar[0] = 0;

    do {
	if( (regEntry = IORegistryEntry::fromPath( "/chosen", gIODTPlane ))) {
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

	    // else try for an OF Path
	    data = (OSData *) regEntry->getProperty( "rootpath" );
	    regEntry->release();
	    if( data) continue;
	}
        if( (regEntry = IORegistryEntry::fromPath( "/options", gIODTPlane ))) {
	    data = (OSData *) regEntry->getProperty( "boot-file" );
	    regEntry->release();
	    if( data) continue;
	}
    } while( false );

    if( data && !uuidStr)
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



//
//	See if we have a RAMDisk property in /chosen/memory-map.  If so, make it into a device.
//	It will become /dev/mdx, where x is 0-f. 
//

	if(!didRam) {												/* Have we already build this ram disk? */
		didRam = 1;												/* Remember we did this */
		if((regEntry = IORegistryEntry::fromPath( "/chosen/memory-map", gIODTPlane ))) {	/* Find the map node */
			data = (OSData *)regEntry->getProperty("RAMDisk");	/* Find the ram disk, if there */
			if(data) {											/* We found one */

				ramdParms = (UInt32 *)data->getBytesNoCopy();	/* Point to the ram disk base and size */
				(void)mdevadd(-1, ramdParms[0] >> 12, ramdParms[1] >> 12, 0);	/* Initialize it and pass back the device number */
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

    if( look) {
	// from OpenFirmware path
	IOLog("From path: \"%s\", ", look);

        if (!matching) {
            if( forceNet || (0 == strncmp( look, "enet", strlen( "enet" ))) ) {
                matching = IONetworkMatching( look, str, kMaxPathBuf );
            } else {
                matching = IODiskMatching( look, str, kMaxPathBuf );
            }
        }
    }
    
      if( (!matching) && rdBootVar[0] ) {
	// by BSD name
	look = rdBootVar;
	if( look[0] == '*')
	    look++;
    
	if ( strncmp( look, "en", strlen( "en" )) == 0 ) {
	    matching = IONetworkNamePrefixMatching( "en" );
	} else if ( strncmp( look, "cdrom", strlen( "cdrom" )) == 0 ) {
            matching = IOCDMatching();
            findHFSChild = true;
        } else if ( strncmp( look, "uuid", strlen( "uuid" )) == 0 ) {
            char *uuid;
            OSString *uuidString;

            uuid = (char *)IOMalloc( kMaxBootVar );
                  
            if ( uuid ) {
                if (!PE_parse_boot_arg( "boot-uuid", uuid )) {
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
	// any HFS
        matching = IOService::serviceMatching( "IOMedia" );
        astring = OSString::withCStringNoCopy("Apple_HFS");
        if ( astring ) {
            matching->setObject("Content", astring);
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

    if ( service && findHFSChild ) {
        bool waiting = true;
        // wait for children services to finish registering
        while ( waiting ) {
            t.tv_sec = ROOTDEVICETIMEOUT;
            t.tv_nsec = 0;
            if ( service->waitQuiet( &t ) == kIOReturnSuccess ) {
                waiting = false;
            } else {
                IOLog( "Waiting for child registration\n" );
            }
        }
        // look for a subservice with an Apple_HFS child
        IOService * subservice = IOFindMatchingChild( service );
        if ( subservice ) service = subservice;
    } else if ( service && mediaProperty ) {
        service = (IOService *)service->getProperty(mediaProperty);
    }

    major = 0;
    minor = 0;

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

} /* extern "C" */
