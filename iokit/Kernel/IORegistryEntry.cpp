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
 * Copyright (c) 1998 Apple Computer, Inc.  All rights reserved. 
 *
 * HISTORY
 * 12 Nov 98 sdouglas created.
 *
 */

#include <IOKit/IORegistryEntry.h>
#include <libkern/c++/OSContainers.h>
#include <IOKit/IOService.h>
#include <IOKit/IOKitKeys.h>

#include <IOKit/IOLib.h>

#include <IOKit/assert.h>

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define super OSObject

OSDefineMetaClassAndStructors(IORegistryEntry, OSObject)

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

static IORegistryEntry * gRegistryRoot;
static OSDictionary * 	 gIORegistryPlanes;

const OSSymbol * 	gIONameKey;
const OSSymbol * 	gIOLocationKey;

enum {
    kParentSetIndex	= 0,
    kChildSetIndex	= 1,
    kNumSetIndex
};
enum {
    kIOMaxPlaneName	= 32
};

class IORegistryPlane : public OSObject {

    friend class IORegistryEntry;

    OSDeclareAbstractStructors(IORegistryPlane)

    const OSSymbol *	nameKey;
    const OSSymbol *	keys[ kNumSetIndex ];
    const OSSymbol *	pathNameKey;
    const OSSymbol *	pathLocationKey;
    int			reserved[2];

public:
    virtual bool serialize(OSSerialize *s) const;
};

OSDefineMetaClassAndStructors(IORegistryPlane, OSObject)


static IORecursiveLock *	gPropertiesLock;
static SInt32			gIORegistryGenerationCount;

#define UNLOCK	s_lock_done( &gIORegistryLock )
#define RLOCK	s_lock_read( &gIORegistryLock )
#define WLOCK	s_lock_write( &gIORegistryLock );	\
		gIORegistryGenerationCount++
		// make atomic

#define PUNLOCK	IORecursiveLockUnlock( gPropertiesLock )
#define PLOCK	IORecursiveLockLock( gPropertiesLock )

#define IOREGSPLITTABLES

#ifdef IOREGSPLITTABLES
#define registryTable()	fRegistryTable
#else
#define registryTable()	fPropertyTable
#endif

#define DEBUG_FREE	1

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

struct s_lock_t {
	decl_simple_lock_data(,interlock) /* "hardware" interlock field */
	volatile unsigned int
		read_count:16,	/* No. of accepted readers */
		want_upgrade:1,	/* Read-to-write upgrade waiting */
		want_write:1,	/* Writer is waiting, or
				   locked for write */
		waiting:1,	/* Someone is sleeping on lock */
		can_sleep:1;	/* Can attempts to lock go to sleep? */
};

static struct s_lock_t	gIORegistryLock;

/* Time we loop without holding the interlock. 
 * The former is for when we cannot sleep, the latter
 * for when our thread can go to sleep (loop less)
 * we shouldn't retake the interlock at all frequently
 * if we cannot go to sleep, since it interferes with
 * any other processors. In particular, 100 is too small
 * a number for powerpc MP systems because of cache
 * coherency issues and differing lock fetch times between
 * the processors
 */
static unsigned int lock_wait_time[2] = { (unsigned int)-1, 100 } ;
	  
static void
s_lock_init(
	s_lock_t	*l,
	boolean_t	can_sleep)
{
	(void) memset((void *) l, 0, sizeof(s_lock_t));

	simple_lock_init(&l->interlock, 0);
	l->want_write = FALSE;
	l->want_upgrade = FALSE;
	l->read_count = 0;
	l->can_sleep = can_sleep;
}

static void
s_lock_write(
	register s_lock_t	* l)
{
        register int	   i;

	simple_lock(&l->interlock);

	/*
	 *	Try to acquire the want_write bit.
	 */
	while (l->want_write) {

		i = lock_wait_time[l->can_sleep ? 1 : 0];
		if (i != 0) {
			simple_unlock(&l->interlock);
			while (--i != 0 && l->want_write)
				continue;
			simple_lock(&l->interlock);
		}

		if (l->can_sleep && l->want_write) {
			l->waiting = TRUE;
			thread_sleep_simple_lock((event_t) l,
					simple_lock_addr(l->interlock),
					THREAD_UNINT);
			/* interlock relocked */
		}
	}
	l->want_write = TRUE;

	/* Wait for readers (and upgrades) to finish */

	while ((l->read_count != 0) || l->want_upgrade) {

		i = lock_wait_time[l->can_sleep ? 1 : 0];
		if (i != 0) {
			simple_unlock(&l->interlock);
			while (--i != 0 && (l->read_count != 0 ||
					    l->want_upgrade))
				continue;
			simple_lock(&l->interlock);
		}

		if (l->can_sleep && (l->read_count != 0 || l->want_upgrade)) {
			l->waiting = TRUE;
			thread_sleep_simple_lock((event_t) l,
				simple_lock_addr(l->interlock),
				THREAD_UNINT);
			/* interlock relocked */
		}
	}

	simple_unlock(&l->interlock);
}

static void
s_lock_done(
	register s_lock_t	* l)
{
	boolean_t	  do_wakeup = FALSE;

	simple_lock(&l->interlock);

	if (l->read_count != 0) {
		l->read_count -= 1;
	}
	else	{
		if (l->want_upgrade) {
			l->want_upgrade = FALSE;
		}
                else {
                        l->want_write = FALSE;
                }
        }

	/*
	 *	There is no reason to wakeup a waiting thread
	 *	if the read-count is non-zero.  Consider:
	 *		we must be dropping a read lock
	 *		threads are waiting only if one wants a write lock
	 *		if there are still readers, they can't proceed
	 */
	if (l->waiting && (l->read_count == 0)) {
		l->waiting = FALSE;
		do_wakeup = TRUE;
	}

	simple_unlock(&l->interlock);

	if (do_wakeup)
		thread_wakeup((event_t) l);
}

static void
s_lock_read(
	register s_lock_t	* l)
{
	register int	    i;

	simple_lock(&l->interlock);

	while ( l->want_upgrade || ((0 == l->read_count) && l->want_write )) {

		i = lock_wait_time[l->can_sleep ? 1 : 0];

		if (i != 0) {
			simple_unlock(&l->interlock);
			while (--i != 0 && 
                            (l->want_upgrade || ((0 == l->read_count) && l->want_write )))
				continue;
			simple_lock(&l->interlock);
		}

		if (l->can_sleep &&
                    (l->want_upgrade || ((0 == l->read_count) && l->want_write ))) {
			l->waiting = TRUE;
			thread_sleep_simple_lock((event_t) l,
					simple_lock_addr(l->interlock),
					THREAD_UNINT);
			/* interlock relocked */
		}
	}

	l->read_count += 1;
	simple_unlock(&l->interlock);

}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IORegistryEntry * IORegistryEntry::initialize( void )
{
   bool			ok;

    if( !gRegistryRoot) {

        s_lock_init( &gIORegistryLock, true );
	gRegistryRoot = new IORegistryEntry;
	gPropertiesLock = IORecursiveLockAlloc();
	gIORegistryPlanes = OSDictionary::withCapacity( 1 );
        
	assert( gRegistryRoot && gPropertiesLock
		&& gIORegistryPlanes );
        ok = gRegistryRoot->init();

	gIONameKey = OSSymbol::withCStringNoCopy( "IOName" );
	gIOLocationKey = OSSymbol::withCStringNoCopy( "IOLocation" );

	assert( ok && gIONameKey && gIOLocationKey );

	gRegistryRoot->setName( "Root" );
        gRegistryRoot->setProperty( kIORegistryPlanesKey, gIORegistryPlanes );
    }

    return( gRegistryRoot );
}

IORegistryEntry * IORegistryEntry::getRegistryRoot( void )
{
    return( gRegistryRoot );
}

SInt32 IORegistryEntry::getGenerationCount( void )
{
    return( gIORegistryGenerationCount );
}


const IORegistryPlane * IORegistryEntry::makePlane( const char * name )
{
    IORegistryPlane *	plane;
    const OSSymbol *	nameKey;
    const OSSymbol *	parentKey;
    const OSSymbol *	childKey;
    const OSSymbol *	pathNameKey;
    const OSSymbol *	pathLocationKey;
    char		key[ kIOMaxPlaneName + 16 ];
    char *		end;

    strncpy( key, name, kIOMaxPlaneName );
    key[ kIOMaxPlaneName ] = 0;
    end = key + strlen( name );

    nameKey = OSSymbol::withCString( key);

    strcpy( end, "ParentLinks" );
    parentKey = OSSymbol::withCString( key);

    strcpy( end, "ChildLinks" );
    childKey = OSSymbol::withCString( key);

    strcpy( end, "Name" );
    pathNameKey = OSSymbol::withCString( key);

    strcpy( end, "Location" );
    pathLocationKey = OSSymbol::withCString( key);

    plane = new IORegistryPlane;

    if( plane && plane->init()
	&& nameKey && parentKey && childKey
	&& pathNameKey && pathLocationKey ) {

	plane->nameKey = nameKey;
	plane->keys[ kParentSetIndex ] = parentKey;
	plane->keys[ kChildSetIndex ] = childKey;
	plane->pathNameKey = pathNameKey;
	plane->pathLocationKey = pathLocationKey;

	WLOCK;
        gIORegistryPlanes->setObject( nameKey, plane );
	UNLOCK;

    } else {

	if( plane)
	    plane->release();
	if( pathLocationKey)
	    pathLocationKey->release();
	if( pathNameKey)
	    pathNameKey->release();
	if( parentKey)
	    parentKey->release();
	if( childKey)
	    childKey->release();
	if( nameKey)
	    nameKey->release();
	plane = 0;
    }

    return( plane);
}

const IORegistryPlane * IORegistryEntry::getPlane( const char * name )
{
    const IORegistryPlane *	plane;

    RLOCK;
    plane = (const IORegistryPlane *) gIORegistryPlanes->getObject( name );
    UNLOCK;

    return( plane );
}

bool IORegistryPlane::serialize(OSSerialize *s) const
{
    return( nameKey->serialize(s) );
}

enum { kIORegCapacityIncrement = 4 };

bool IORegistryEntry::init( OSDictionary * dict = 0 )
{
    OSString *	prop;

    if( !super::init())
	return( false);

    if( dict) {
	dict->retain();
	if( fPropertyTable)
	    fPropertyTable->release();
	fPropertyTable = dict;

    } else if( !fPropertyTable) {
        fPropertyTable = OSDictionary::withCapacity( kIORegCapacityIncrement );
	if( fPropertyTable)
            fPropertyTable->setCapacityIncrement( kIORegCapacityIncrement );
    }

    if( !fPropertyTable)
        return( false);

#ifdef IOREGSPLITTABLES
    if( !fRegistryTable) {
	fRegistryTable = OSDictionary::withCapacity( kIORegCapacityIncrement );
	if( fRegistryTable)
	    fRegistryTable->setCapacityIncrement( kIORegCapacityIncrement );
    }

    if( (prop = OSDynamicCast( OSString, getProperty( gIONameKey)))) {
        OSSymbol * sym = (OSSymbol *)OSSymbol::withString( prop);
        // ok for OSSymbol too
        setName( sym);
        sym->release();
    }

#endif /* IOREGSPLITTABLES */

    return( true);
}

bool IORegistryEntry::init( IORegistryEntry * old,
				const IORegistryPlane * plane )
{
    OSArray *		all;
    IORegistryEntry *		next;
    unsigned int	index;

    if( !super::init())
	return( false);

    WLOCK;

    fPropertyTable = old->getPropertyTable();
    fPropertyTable->retain();
#ifdef IOREGSPLITTABLES
    fRegistryTable = old->fRegistryTable;
    old->fRegistryTable = OSDictionary::withDictionary( fRegistryTable );
#endif /* IOREGSPLITTABLES */

    old->registryTable()->removeObject( plane->keys[ kParentSetIndex ] );
    old->registryTable()->removeObject( plane->keys[ kChildSetIndex ] );

    all = getParentSetReference( plane );
    if( all) for( index = 0;
              (next = (IORegistryEntry *) all->getObject(index));
              index++ ) {
	    next->makeLink( this, kChildSetIndex, plane );
            next->breakLink( old, kChildSetIndex, plane );
    }

    all = getChildSetReference( plane );
    if( all) for( index = 0;
              (next = (IORegistryEntry *) all->getObject(index));
              index++ ) {
	    next->makeLink( this, kParentSetIndex, plane );
            next->breakLink( old, kParentSetIndex, plane );
    }

    UNLOCK;

    return( true );
}

void IORegistryEntry::free( void )
{

#if DEBUG_FREE
#define msg ": attached at free()"
    char buf[ strlen(msg) + 40 ];

    if( registryTable() && gIOServicePlane) {
        if( getParentSetReference( gIOServicePlane )
            || getChildSetReference( gIOServicePlane )) {

            strncpy( buf, getName(), 32);
            buf[32] = 0;
            strcat( buf, msg );
            IOPanic( buf );
        }
    }
#endif

    if( getPropertyTable())
        getPropertyTable()->release();

#ifdef IOREGSPLITTABLES
    if( registryTable())
        registryTable()->release();
#endif /* IOREGSPLITTABLES */

    super::free();
}

void IORegistryEntry::setPropertyTable( OSDictionary * dict )
{
    if( fPropertyTable)
	fPropertyTable->release();
    if( dict)
	dict->retain();
    fPropertyTable = dict;
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Wrappers to synchronize property table */

#define wrap1(func, type, constant)					\
OSObject *								\
IORegistryEntry::func ## Property( type * aKey) constant		\
{									\
    OSObject *	obj;							\
									\
    PLOCK;								\
    obj = getPropertyTable()->func ## Object( aKey );			\
    PUNLOCK;								\
									\
    return( obj );							\
}

#define wrap2(type, constant)						\
OSObject *								\
IORegistryEntry::copyProperty( type * aKey) constant			\
{									\
    OSObject *	obj;							\
									\
    PLOCK;								\
    obj = getProperty( aKey );						\
    if( obj)								\
        obj->retain();							\
    PUNLOCK;								\
									\
    return( obj );							\
}

#define wrap3(func,type,constant)					\
void									\
IORegistryEntry::func ## Property( type * aKey) constant		\
{									\
    PLOCK;								\
    getPropertyTable()->func ## Object( aKey );				\
    PUNLOCK;								\
}

#define wrap4(type,constant) \
OSObject * \
IORegistryEntry::getProperty( type *                  aKey, \
                              const IORegistryPlane * plane, \
                              IOOptionBits            options ) constant \
{ \
    OSObject * obj = getProperty( aKey ); \
    \
    if ( (0 == obj) && plane && (options & kIORegistryIterateRecursively) ) { \
        IORegistryEntry * entry = (IORegistryEntry *) this; \
        IORegistryIterator * iter; \
        iter = IORegistryIterator::iterateOver( entry, plane, options ); \
        \
        if(iter) { \
            while ( (0 == obj) && (entry = iter->getNextObject()) ) { \
                obj = entry->getProperty( aKey ); \
            } \
            iter->release(); \
        } \
    } \
    \
    return( obj ); \
}

#define wrap5(type,constant) \
OSObject * \
IORegistryEntry::copyProperty( type *                  aKey, \
                              const IORegistryPlane * plane, \
                              IOOptionBits            options ) constant \
{ \
    OSObject * obj = copyProperty( aKey ); \
    \
    if ( (0 == obj) && plane && (options & kIORegistryIterateRecursively) ) { \
        IORegistryEntry * entry = (IORegistryEntry *) this; \
        IORegistryIterator * iter; \
        iter = IORegistryIterator::iterateOver( entry, plane, options ); \
        \
        if(iter) { \
            while ( (0 == obj) && (entry = iter->getNextObject()) ) { \
                obj = entry->copyProperty( aKey ); \
            } \
            iter->release(); \
        } \
    } \
    \
    return( obj ); \
}

bool IORegistryEntry::serializeProperties( OSSerialize * s ) const
{
    bool ok;

//    setProperty( getRetainCount(), 32, "__retain" );

    PLOCK;
    ok = getPropertyTable()->serialize( s );
    PUNLOCK;

    return( ok );
}

OSDictionary * IORegistryEntry::dictionaryWithProperties( void ) const
{
    OSDictionary *	dict;

    PLOCK;
    dict = OSDictionary::withDictionary( getPropertyTable(),
                            getPropertyTable()->getCapacity() );
    PUNLOCK;

    return( dict );
}

IOReturn IORegistryEntry::setProperties( OSObject * properties )
{
    return( kIOReturnUnsupported );
}

wrap1(get, const OSSymbol, const)  // getProperty() definition
wrap1(get, const OSString, const)  // getProperty() definition
wrap1(get, const char, const)      // getProperty() definition

wrap2(const OSSymbol, const)       // copyProperty() definition
wrap2(const OSString, const)       // copyProperty() definition
wrap2(const char, const)      	   // copyProperty() definition

wrap3(remove, const OSSymbol,)     // removeProperty() definition
wrap3(remove, const OSString,)     // removeProperty() definition
wrap3(remove, const char,)         // removeProperty() definition

wrap4(const OSSymbol, const)       // getProperty() w/plane definition
wrap4(const OSString, const)       // getProperty() w/plane definition
wrap4(const char, const)           // getProperty() w/plane definition

wrap5(const OSSymbol, const)       // copyProperty() w/plane definition
wrap5(const OSString, const)       // copyProperty() w/plane definition
wrap5(const char, const)           // copyProperty() w/plane definition


bool
IORegistryEntry::setProperty( const OSSymbol * aKey, OSObject * anObject)
{
    bool ret = false;
    PLOCK;
    ret = getPropertyTable()->setObject( aKey, anObject );
    PUNLOCK;
    
    return ret;
}

bool
IORegistryEntry::setProperty( const OSString * aKey, OSObject * anObject)
{
    bool ret = false;
    PLOCK;
    ret = getPropertyTable()->setObject( aKey, anObject );
    PUNLOCK;

    return ret;
}

bool
IORegistryEntry::setProperty( const char * aKey,  OSObject * anObject)
{
    bool ret = false;
    PLOCK;
    ret = getPropertyTable()->setObject( aKey, anObject );
    PUNLOCK;
    
    return ret;
}

bool
IORegistryEntry::setProperty(const char * aKey, const char * aString)
{
    bool ret = false;
    OSSymbol * aSymbol = (OSSymbol *) OSSymbol::withCString( aString );

    if( aSymbol) {
        PLOCK;
        ret = getPropertyTable()->setObject( aKey, aSymbol );
        PUNLOCK;
        aSymbol->release();
    }
    return( ret );
}

bool
IORegistryEntry::setProperty(const char * aKey, bool aBoolean)
{
    bool ret = false;
    OSBoolean * aBooleanObj = OSBoolean::withBoolean( aBoolean );

    if( aBooleanObj) {
        PLOCK;
        ret = getPropertyTable()->setObject( aKey, aBooleanObj );
        PUNLOCK;
        aBooleanObj->release();
    }
    return( ret );
}

bool
IORegistryEntry::setProperty( const char *       aKey,
                              unsigned long long aValue,
                              unsigned int       aNumberOfBits)
{
    bool ret = false;
    OSNumber * anOffset = OSNumber::withNumber( aValue, aNumberOfBits );

    if( anOffset) {
        PLOCK;
        ret = getPropertyTable()->setObject( aKey, anOffset );
        PUNLOCK;
        anOffset->release();
    }
    return( ret );
}

bool
IORegistryEntry::setProperty( const char *      aKey,
                              void *		bytes,
                              unsigned int      length)
{
    bool ret = false;
    OSData * data = OSData::withBytes( bytes, length );

    if( data) {
        PLOCK;
        ret = getPropertyTable()->setObject( aKey, data );
        PUNLOCK;
        data->release();
    }
    return( ret );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Name, location, paths */

const char * IORegistryEntry::getName( const IORegistryPlane * plane = 0 ) const
{
    OSSymbol *		sym = 0;

    RLOCK;
    if( plane)
	sym = (OSSymbol *) registryTable()->getObject( plane->pathNameKey );
    if( !sym)
	sym = (OSSymbol *) registryTable()->getObject( gIONameKey );
    UNLOCK;

    if( sym)
	return( sym->getCStringNoCopy());
    else
        return( (getMetaClass())->getClassName());
}

const OSSymbol * IORegistryEntry::copyName(
			const IORegistryPlane * plane = 0 ) const
{
    OSSymbol *		sym = 0;

    RLOCK;
    if( plane)
	sym = (OSSymbol *) registryTable()->getObject( plane->pathNameKey );
    if( !sym)
	sym = (OSSymbol *) registryTable()->getObject( gIONameKey );
    if( sym)
	sym->retain();
    UNLOCK;

    if( sym)
	return( sym );
    else
        return( OSSymbol::withCString((getMetaClass())->getClassName()) );
}

const OSSymbol * IORegistryEntry::copyLocation(
			const IORegistryPlane * plane = 0 ) const
{
    OSSymbol *		sym = 0;

    RLOCK;
    if( plane)
	sym = (OSSymbol *) registryTable()->getObject( plane->pathLocationKey );
    if( !sym)
	sym = (OSSymbol *) registryTable()->getObject( gIOLocationKey );
    if( sym)
	sym->retain();
    UNLOCK;

    return( sym );
}

const char * IORegistryEntry::getLocation( const IORegistryPlane * plane = 0 ) const
{
    const OSSymbol *	sym = copyLocation( plane );
    const char *	result = 0;

    if( sym) {
	result = sym->getCStringNoCopy();
	sym->release();
    }

    return( result );
}

void IORegistryEntry::setName( const OSSymbol * name,
                            const IORegistryPlane * plane = 0 )
{
    const OSSymbol *	key;

    if( name) {
        if( plane)
            key = plane->pathNameKey;
        else
            key = gIONameKey;

	WLOCK;
        registryTable()->setObject( key, (OSObject *) name);
	UNLOCK;
    }
}

void IORegistryEntry::setName( const char * name,
                            const IORegistryPlane * plane = 0 )
{
    OSSymbol * sym = (OSSymbol *)OSSymbol::withCString( name );
    if ( sym ) {
        setName( sym, plane );
        sym->release();
    }
}

void IORegistryEntry::setLocation( const OSSymbol * location,
                            const IORegistryPlane * plane = 0 )
{
    const OSSymbol *	key;

    if( location) {
        if( plane)
            key = plane->pathLocationKey;
        else
            key = gIOLocationKey;

	WLOCK;
        registryTable()->setObject( key, (OSObject *) location);
	UNLOCK;
    }
}

void IORegistryEntry::setLocation( const char * location,
                            const IORegistryPlane * plane = 0 )
{
    OSSymbol * sym = (OSSymbol *)OSSymbol::withCString( location );
    if ( sym ) {
        setLocation( sym, plane );
        sym->release();
    }
}

bool
IORegistryEntry::compareName( OSString * name, OSString ** matched = 0 ) const
{
    const OSSymbol *	sym = copyName();
    bool		isEqual;

    isEqual = sym->isEqualTo( name );

    if( isEqual && matched) {
	name->retain();
	*matched = name;
    }

    if( sym)
	sym->release();

    return( isEqual );
}

bool
IORegistryEntry::compareNames( OSObject * names, OSString ** matched = 0 ) const
{
    OSString *		string;
    OSCollection *	collection;
    OSIterator *	iter = 0;
    bool		result = false;

    if( (collection = OSDynamicCast( OSCollection, names))) {
	iter = OSCollectionIterator::withCollection( collection );
	string = 0;
    } else
	string = OSDynamicCast( OSString, names);

    do {
	if( string)
            result = compareName( string, matched );

    } while( (false == result)
	&& iter && (string = OSDynamicCast( OSString, iter->getNextObject())));

    if( iter)
	iter->release();

    return( result);
}


bool IORegistryEntry::getPath(	char * path, int * length,
				const IORegistryPlane * plane ) const
{
    OSArray *		stack;
    IORegistryEntry *	root;
    const IORegistryEntry * entry;
    IORegistryEntry *	parent;
    const OSSymbol *	alias;
    int			index;
    int			len, maxLength, compLen;
    char *		nextComp;
    bool		ok;

   if( !path || !length || !plane)
	return( false);

    len = 0;
    maxLength = *length - 2;
    nextComp = path;

    len = plane->nameKey->getLength();
    if( len >= maxLength)
	return( false);
    strcpy( nextComp, plane->nameKey->getCStringNoCopy());
    nextComp[ len++ ] = ':';
    nextComp += len;

    if( (alias = hasAlias( plane ))) {
	len += alias->getLength();
	ok = (maxLength > len);
	*length = len;
	if( ok)
	    strcpy( nextComp, alias->getCStringNoCopy());
	return( ok );
    }

    entry = this;
    parent = entry->getParentEntry( plane );
    if( !parent)
	// Error if not attached in plane
	return( false);

    stack = OSArray::withCapacity( getDepth( plane ));
    if( !stack)
	return( false);

    RLOCK;

    root = gRegistryRoot->getChildEntry( plane );
    while( parent && (entry != root)) {
	// stop below root
	stack->setObject( (OSObject *) entry );
	entry = parent;
	parent = entry->getParentEntry( plane );
    }

    index = stack->getCount();
    ok = true;

    if( 0 == index) {

        *nextComp++ = '/';
        *nextComp = 0;
        len++;

    } else while( ok && ((--index) >= 0)) {

        entry = (IORegistryEntry *) stack->getObject((unsigned int) index );
        assert( entry );

        if( (alias = entry->hasAlias( plane ))) {
            len = plane->nameKey->getLength() + 1;
            nextComp = path + len;

            compLen = alias->getLength();
            ok = (maxLength > len + compLen);
            if( ok)
                strcpy( nextComp, alias->getCStringNoCopy());
        } else {
            compLen = maxLength - len;
            ok = entry->getPathComponent( nextComp + 1, &compLen, plane );

            if( ok && compLen) {
                compLen++;
                *nextComp = '/';
            }
        }

        if( ok) {
            len += compLen;
            nextComp += compLen;
        }
    }
    *length = len;

    UNLOCK;

    stack->release();

    return( ok );
}

bool IORegistryEntry::getPathComponent( char * path, int * length,
                                        const IORegistryPlane * plane ) const
{
    int			len, locLen, maxLength;
    const char *	compName;
    const char *	loc;
    bool		ok;

    maxLength = *length;

    compName = getName( plane );
    len = strlen( compName );
    if( (loc = getLocation( plane )))
	locLen = 1 + strlen( loc );
    else
	locLen = 0;

    ok = ((len + locLen) < maxLength);
    if( ok) {
        strcpy( path, compName );
	if( loc) {
            path += len;
            len += locLen;
            *path++ = '@';
            strcpy( path, loc );
	}
        *length = len;
    }

    return( ok );
}

const char * IORegistryEntry::matchPathLocation( const char * cmp,
				const IORegistryPlane * plane )
{
    const char	*	str;
    const char	*	result = 0;
    u_quad_t		num1, num2;
    char		c1, c2;

    str = getLocation( plane );
    if( str) {
	c2 = str[0];
	do {
            num1 = strtouq( cmp, (char **) &cmp, 16 );
            if( c2) {
                num2 = strtouq( str, (char **) &str, 16 );
                c2 = str[0];
	    } else
                num2 = 0;

            if( num1 != num2)
                break;

            c1 = *cmp++;

            if( (c2 == ':') && (c2 == c1)) {
                str++;
                continue;
            }

            if( ',' != c1) {
                result = cmp - 1;
                break;
            }

            if( c2) {
                if( c2 != ',')
                    break;
                str++;
            }

        } while( true);
    }

    return( result );
}

IORegistryEntry * IORegistryEntry::getChildFromComponent( const char ** opath,
				const IORegistryPlane * plane )
{
    IORegistryEntry *	entry = 0;
    OSArray *		set;
    unsigned int	index;
    const char *	path;
    const char *	cmp = 0;
    char		c;
    size_t		len;
    const char *	str;

    set = getChildSetReference( plane );
    if( set) {

	path = *opath;

	for( index = 0;
             (entry = (IORegistryEntry *) set->getObject(index));
             index++ ) {

            cmp = path;

            if( *cmp != '@') {
                str = entry->getName( plane );
                len = strlen( str );
                if( strncmp( str, cmp, len ))
                    continue;
                cmp += len;

                c = *cmp;
                if( (c == 0) || (c == '/') || (c == ':'))
                    break;
                if( c != '@')
                    continue;
            }
            cmp++;
            if( (cmp = entry->matchPathLocation( cmp, plane )))
                break;
        }
        if( entry)
            *opath = cmp;
    }

    return( entry );
}

const OSSymbol * IORegistryEntry::hasAlias( const IORegistryPlane * plane,
				char * opath = 0, int * length = 0 ) const
{
    IORegistryEntry *	entry;
    IORegistryEntry *	entry2;
    const OSSymbol *	key;
    const OSSymbol *	bestKey = 0;
    OSIterator *	iter;
    OSData *		data;
    const char * 	path = "/aliases";

    entry = IORegistryEntry::fromPath( path, plane );
    if( entry) {
        RLOCK;
        if( (iter = OSCollectionIterator::withCollection(
				entry->getPropertyTable() ))) {

            while( (key = (OSSymbol *) iter->getNextObject())) {

                data = (OSData *) entry->getProperty( key );
                path = (const char *) data->getBytesNoCopy();
                if( (entry2 = IORegistryEntry::fromPath( path, plane,
						opath, length ))) {
                    if( this == entry2) {
                        if( !bestKey
			 || (bestKey->getLength() > key->getLength()))
                            // pick the smallest alias
                            bestKey = key;
                    }
		    entry2->release();
		}
            }
            iter->release();
        }
	entry->release();
	UNLOCK;
    }
    return( bestKey );
}

const char * IORegistryEntry::dealiasPath(
			const char ** 		opath,
			const IORegistryPlane *	plane )
{
    IORegistryEntry *	entry;
    OSData *		data;
    const char * 	path = *opath;
    const char * 	rpath = 0;
    const char * 	end;
    char		c;
    char		temp[ kIOMaxPlaneName + 1 ];

    if( path[0] == '/')
	return( rpath );

    // check for alias
    end = path;
    while( (c = *end++) && (c != '/') && (c != ':'))
        {}
    end--;
    if( (end - path) < kIOMaxPlaneName) {
        strncpy( temp, path, end - path );
        temp[ end - path ] = 0;

        RLOCK;
        entry = IORegistryEntry::fromPath( "/aliases", plane );
        if( entry) {
            data = (OSData *) entry->getProperty( temp );
            if( data ) {
                rpath = (const char *) data->getBytesNoCopy();
                if( rpath)
                    *opath = end;
            }
	    entry->release();
        }
        UNLOCK;
    }

    return( rpath );
}

IORegistryEntry * IORegistryEntry::fromPath(
                        const char * 		path,
                        const IORegistryPlane * plane = 0,
                        char *			opath = 0,
			int * 			length = 0,
                        IORegistryEntry * 	fromEntry = 0 )
{
    IORegistryEntry *	where = 0;
    IORegistryEntry *	aliasEntry = 0;
    IORegistryEntry *	next;
    const char *	alias;
    const char *	end;
    int			len = 0;
    int			len2;
    char		c;
    char		temp[ kIOMaxPlaneName + 1 ];

    if( 0 == path)
	return( 0 );

    if( 0 == plane) {
	// get plane name
        end = strchr( path, ':' );
	if( end && ((end - path) < kIOMaxPlaneName)) {
	    strncpy( temp, path, end - path );
	    temp[ end - path ] = 0;
            plane = getPlane( temp );
	    path = end + 1;
	}
    }
    if( 0 == plane)
	return( 0 );

    // check for alias
    end = path;
    if( (alias = dealiasPath( &end, plane))) {
        if( length)
            len = *length;
        aliasEntry = IORegistryEntry::fromPath( alias, plane,
                                    opath, &len, fromEntry );
        where = aliasEntry;
        if( where)
            path = end;
        else
            len = 0;
    }

    RLOCK;

    do {
        if( 0 == where) {
            if( (0 == fromEntry) && (*path++ == '/'))
                fromEntry = gRegistryRoot->getChildEntry( plane );
            where = fromEntry;
            if( 0 == where)
                break;
        } else {
            c = *path++;
            if( c != '/') {
                if( c && (c != ':'))	// check valid terminator
                    where = 0;
                break;
            }
        }
        next = where->getChildFromComponent( &path, plane );
        if( next)
            where = next;
    } while( next );

    if( where) {
	// check residual path
	if( where != fromEntry)
            path--;

	if( opath && length) {
            // copy out residual path
	    len2 = len + strlen( path );
	    if( len2 < *length)
                strcpy( opath + len, path );
	    *length = len2;

	} else if( path[0])
	    // no residual path => must be no tail for success
            where = 0;
    }

    if( where)
	where->retain();
    if( aliasEntry)
        aliasEntry->release();

    UNLOCK;

    return( where );
}

IORegistryEntry * IORegistryEntry::childFromPath(
			const char *		path,
                        const IORegistryPlane * plane = 0,
                        char *			opath = 0,
                        int *			len = 0 )
{
    return( IORegistryEntry::fromPath( path, plane, opath, len, this ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define IOLinkIterator OSCollectionIterator

#undef super
#define super OSObject

inline bool IORegistryEntry::arrayMember( OSArray * set,
					  const IORegistryEntry * member,
					unsigned int * index = 0 ) const
{
    int		i;
    OSObject *	probeObject;

    for( i = 0; (probeObject = set->getObject(i)); i++) {
        if (probeObject == (OSObject *) member) {
	    if( index)
                *index = i;
            return( true );
	}
    }
    return( false );
}

bool IORegistryEntry::makeLink( IORegistryEntry * to,
                                unsigned int relation,
                                const IORegistryPlane * plane ) const
{
    OSArray *	links;
    bool	result = false;

    if( (links = (OSArray *)
		registryTable()->getObject( plane->keys[ relation ] ))) {

	result = arrayMember( links, to );
	if( !result)
            result = links->setObject( to );

    } else {

	links = OSArray::withObjects( & (const OSObject *) to, 1, 1 );
	result = (links != 0);
	if( result) {
	    result = registryTable()->setObject( plane->keys[ relation ],
                                          links );
            links->release();
	}
    }

    return( result);
}

void IORegistryEntry::breakLink( IORegistryEntry * to,
                                 unsigned int relation,
                                 const IORegistryPlane * plane ) const
{
    OSArray *		links;
    unsigned int	index;

    if( (links = (OSArray *)
		registryTable()->getObject( plane->keys[ relation ]))) {

	if( arrayMember( links, to, &index )) {
            links->removeObject( index );
	    if( 0 == links->getCount())
                registryTable()->removeObject( plane->keys[ relation ]);
	    }
    }
}


OSArray * IORegistryEntry::getParentSetReference(
				const IORegistryPlane * plane ) const
{
    if( plane)
        return( (OSArray *) registryTable()->getObject(
                            plane->keys[ kParentSetIndex ]));
    else
	return( 0 );
}

OSIterator * IORegistryEntry::getParentIterator(
				const IORegistryPlane * plane ) const
{
    OSArray *		links;
    OSIterator *	iter;

    if( !plane)
	return( 0 );

    RLOCK;
    links = getParentSetReference( plane );
    if( 0 == links)
	links = OSArray::withCapacity( 1 );
    else
	links = OSArray::withArray( links, links->getCount() );
    UNLOCK;

    iter = IOLinkIterator::withCollection( links );

    if( links)
        links->release();

    return( iter );
}

IORegistryEntry * IORegistryEntry::copyParentEntry( const IORegistryPlane * plane ) const
{
    IORegistryEntry *	entry = 0;
    OSArray *		links;

    RLOCK;

    if( (links = getParentSetReference( plane ))) {
        entry = (IORegistryEntry *) links->getObject( 0 );
        entry->retain();
    }

    UNLOCK;

    return( entry);
}

IORegistryEntry * IORegistryEntry::getParentEntry( const IORegistryPlane * plane ) const
{
    IORegistryEntry * entry;

    entry = copyParentEntry( plane );
    if( entry)
        entry->release();

    return( entry );
}

OSArray * IORegistryEntry::getChildSetReference( const IORegistryPlane * plane ) const
{
    if( plane)
        return( (OSArray *) registryTable()->getObject(
                            plane->keys[ kChildSetIndex ]));
    else
	return( 0 );
}

OSIterator * IORegistryEntry::getChildIterator( const IORegistryPlane * plane ) const
{
    OSArray *		links;
    OSIterator *	iter;

    if( !plane)
	return( 0 );

    RLOCK;
    links = getChildSetReference( plane );
    if( 0 == links)
        links = OSArray::withCapacity( 1 );
    else
        links = OSArray::withArray( links, links->getCount() );
    UNLOCK;

    iter = IOLinkIterator::withCollection( links );

    if( links)
        links->release();

    return( iter );
}


IORegistryEntry * IORegistryEntry::copyChildEntry(
				const IORegistryPlane * plane ) const
{
    IORegistryEntry *	entry = 0;
    OSArray *		links;

    RLOCK;

    if( (links = getChildSetReference( plane ))) {
	entry = (IORegistryEntry *) links->getObject( 0 );
        entry->retain();
    }

    UNLOCK;

    return( entry);
}

IORegistryEntry * IORegistryEntry::getChildEntry(
				const IORegistryPlane * plane ) const
{
    IORegistryEntry * entry;

    entry = copyChildEntry( plane );
    if( entry)
        entry->release();
        
    return( entry );
}

void IORegistryEntry::applyToChildren( IORegistryEntryApplierFunction applier,
                                       void * context,
                                       const IORegistryPlane * plane ) const
{
    OSArray *	 	array;
    unsigned int 	index;
    IORegistryEntry *	next;

    if( !plane)
        return;

    RLOCK;
    array = OSArray::withArray( getChildSetReference( plane ));
    UNLOCK;
    if( array) {
        for( index = 0;
             (next = (IORegistryEntry *) array->getObject( index ));
             index++)
            (*applier)(next, context);
        array->release();
    }
}

void IORegistryEntry::applyToParents( IORegistryEntryApplierFunction applier,
                                      void * context,
                                      const IORegistryPlane * plane ) const
{
    OSArray *	 	array;
    unsigned int 	index;
    IORegistryEntry *	next;

    if( !plane)
        return;

    RLOCK;
    array = OSArray::withArray( getParentSetReference( plane ));
    UNLOCK;
    if( array) {
        for( index = 0;
             (next = (IORegistryEntry *) array->getObject( index ));
             index++)
            (*applier)(next, context);
        array->release();
    }
}

bool IORegistryEntry::isChild( IORegistryEntry * child,
                                const IORegistryPlane * plane,
				bool onlyChild = false ) const
{
    OSArray *	links;
    bool	ret = false;

    RLOCK;

    if( (links = getChildSetReference( plane ))) {
	if( (!onlyChild) || (1 == links->getCount()))
            ret = arrayMember( links, child );
    }
    if( ret && (links = child->getParentSetReference( plane )))
	ret = arrayMember( links, this );

    UNLOCK;

    return( ret);
}

bool IORegistryEntry::isParent( IORegistryEntry * parent,
                                const IORegistryPlane * plane,
				bool onlyParent = false ) const

{
    OSArray *	links;
    bool	ret = false;

    RLOCK;

    if( (links = getParentSetReference( plane ))) {
	if( (!onlyParent) || (1 == links->getCount()))
            ret = arrayMember( links, parent );
    }
    if( ret && (links = parent->getChildSetReference( plane )))
	ret = arrayMember( links, this );

    UNLOCK;

    return( ret);
}

bool IORegistryEntry::inPlane( const IORegistryPlane * plane ) const
{
    bool ret;

    RLOCK;

    ret = (0 != getParentSetReference( plane ));

    UNLOCK;

    return( ret );
}

bool IORegistryEntry::attachToParent( IORegistryEntry * parent,
                                const IORegistryPlane * plane )
{
    OSArray *	links;
    bool	ret;
    bool	needParent;

    if( this == parent)
	return( false );

    WLOCK;

    ret = makeLink( parent, kParentSetIndex, plane );

    if( (links = parent->getChildSetReference( plane )))
	needParent = (false == arrayMember( links, this ));
    else
	needParent = true;

//    ret &= parent->makeLink( this, kChildSetIndex, plane );

    UNLOCK;

    if( needParent)
        ret &= parent->attachToChild( this, plane );

    return( ret );
}

bool IORegistryEntry::attachToChild( IORegistryEntry * child,
                                        const IORegistryPlane * plane )
{
    OSArray *	links;
    bool	ret;
    bool	needChild;

    if( this == child)
	return( false );

    WLOCK;

    ret = makeLink( child, kChildSetIndex, plane );

    if( (links = child->getParentSetReference( plane )))
	needChild = (false == arrayMember( links, this ));
    else
	needChild = true;

    UNLOCK;

    if( needChild)
	ret &= child->attachToParent( this, plane );

    return( ret );
}

void IORegistryEntry::detachFromParent( IORegistryEntry * parent,
                                const IORegistryPlane * plane )
{
    OSArray *	links;
    bool	needParent;

    WLOCK;

    parent->retain();

    breakLink( parent, kParentSetIndex, plane );

    if( (links = parent->getChildSetReference( plane )))
	needParent = arrayMember( links, this );
    else
	needParent = false;

//    parent->breakLink( this, kChildSetIndex, plane );

    UNLOCK;

    if( needParent)
	parent->detachFromChild( this, plane );

    parent->release();
}

void IORegistryEntry::detachFromChild( IORegistryEntry * child,
                                const IORegistryPlane * plane )
{
    OSArray *		links;
    bool	needChild;

    WLOCK;

    child->retain();

    breakLink( child, kChildSetIndex, plane );

    if( (links = child->getParentSetReference( plane )))
	needChild = arrayMember( links, this );
    else
	needChild = false;

    UNLOCK;

    if( needChild)
	child->detachFromParent( this, plane );

    child->release();
}

void IORegistryEntry::detachAbove( const IORegistryPlane * plane )
{
    IORegistryEntry *	parent;

    retain();
    while( (parent = getParentEntry( plane )))
	detachFromParent( parent, plane );
    release();
}

void IORegistryEntry::detachAll( const IORegistryPlane * plane )
{
    OSOrderedSet *		all;
    IORegistryEntry *		next;
    IORegistryIterator *	regIter;

    regIter = IORegistryIterator::iterateOver( this, plane, true );
    if( 0 == regIter)
	return;
    all = regIter->iterateAll();
    regIter->release();

    detachAbove( plane );
    if( all) {
	while( (next = (IORegistryEntry *) all->getLastObject())) {

            next->retain();
            all->removeObject(next);

            next->detachAbove( plane );
            next->release();
        }
        all->release();
    }
}

unsigned int IORegistryEntry::getDepth( const IORegistryPlane * plane ) const
{
    unsigned int		depth = 1;
    OSArray *			parents;
    unsigned int 		oneDepth, maxParentDepth, count;
    IORegistryEntry *		one;
    const IORegistryEntry *	next;
    unsigned int		index;

    RLOCK;

    next = this;
    while( (parents = next->getParentSetReference( plane ))) {

	count = parents->getCount();
	if( 0 == count)
	    break;
	if( 1 == count) {
            depth++;
            next = (IORegistryEntry *) parents->getObject( 0 );
	} else {
	    // painful
	    maxParentDepth = 0;
	    for( index = 0;
		 (one = (IORegistryEntry *) parents->getObject( index ));
		 index++ ) {
                oneDepth = one->getDepth( plane );
                if( oneDepth > maxParentDepth)
                    maxParentDepth = oneDepth;
            }
            depth += maxParentDepth;
	    break;
	}
    }

    UNLOCK;

    return( depth);
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#undef super
#define super OSIterator

OSDefineMetaClassAndStructors(IORegistryIterator, OSIterator)

enum { kIORegistryIteratorInvalidFlag = 0x80000000 };

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IORegistryIterator *
IORegistryIterator::iterateOver( IORegistryEntry * root,
                                 const IORegistryPlane * plane,
                                 IOOptionBits options = 0 )
{
    IORegistryIterator *	create;

    if( 0 == root)
	return( 0);
    if( 0 == plane)
	return( 0);

    create = new IORegistryIterator;
    if( create) {
        if( create->init()) {

            root->retain();
            create->root = root;
            create->where = &create->start;
            create->start.current = root;
            create->plane = plane;
            create->options = options & ~kIORegistryIteratorInvalidFlag;

	} else {
	    create->release();
	    create = 0;
	}
    }
    return( create);
}

IORegistryIterator *
IORegistryIterator::iterateOver( const IORegistryPlane * plane,
				 IOOptionBits options = 0 )
{
    return( iterateOver( gRegistryRoot, plane, options ));
}

bool IORegistryIterator::isValid( void )
{
    bool		ok;
    IORegCursor *	next;

    next = where;

    RLOCK;

    ok = (0 == (kIORegistryIteratorInvalidFlag & options));

    while( ok && next) {
	if( where->iter)
            ok = where->iter->isValid();
	next = next->next;
    }
    UNLOCK;

    return( ok);
}

void IORegistryIterator::enterEntry( const IORegistryPlane * enterPlane )
{
    IORegCursor *	prev;

    prev = where;
    where = (IORegCursor *) IOMalloc( sizeof( IORegCursor));
    assert( where);

    if( where) {
        where->iter = 0;
        where->next = prev;
        where->current = prev->current;
        plane = enterPlane;
    }
}

void IORegistryIterator::enterEntry( void )
{
    enterEntry( plane );
}

bool IORegistryIterator::exitEntry( void )
{
    IORegCursor *	gone;

    if( where->iter) {
	where->iter->release();
	where->iter = 0;
        if( where->current)// && (where != &start))
            where->current->release();
    }

    if( where != &start) {
	gone = where;
        where = gone->next;
        IOFree( gone, sizeof( IORegCursor));
	return( true);

    } else
        return( false);
}

void IORegistryIterator::reset( void )
{
    while( exitEntry())
	{}

    if( done) {
	done->release();
	done = 0;
    }

    where->current = root;
    options &= ~kIORegistryIteratorInvalidFlag;
}

void IORegistryIterator::free( void )
{
    reset();

    if( root)
        root->release();

    super::free();
}


IORegistryEntry * IORegistryIterator::getNextObjectFlat( void )
{
    IORegistryEntry * 	next = 0;
    OSArray *		links = 0;

    RLOCK;

    if( (0 == where->iter)) {
	// just entered - create new iter
	if( isValid()
        &&  where->current
        &&  (links = ( (options & kIORegistryIterateParents) ?
                        where->current->getParentSetReference( plane ) :
                        where->current->getChildSetReference( plane ) )) )

            where->iter = OSCollectionIterator::withCollection( links );

    } else
	// next sibling - release current
        if( where->current)
            where->current->release();

    if( where->iter) {

        next = (IORegistryEntry *) where->iter->getNextObject();

        if( next)
            next->retain();
        else if( !where->iter->isValid())
            options |= kIORegistryIteratorInvalidFlag;
    }

    where->current = next;

    UNLOCK;

    return( next);
}

IORegistryEntry * IORegistryIterator::getNextObjectRecursive( void )
{
    IORegistryEntry *	next;

    do
        next = getNextObjectFlat();
    while( (0 == next) && exitEntry());

    if( next) {
	if( 0 == done)
            done = OSOrderedSet::withCapacity( 10 );
	if( done->setObject((OSObject *) next)) {
       	    // done set didn't contain this one, so recurse
            enterEntry();
	}
    }
    return( next);
}

IORegistryEntry * IORegistryIterator::getNextObject( void )
{
    if( options & kIORegistryIterateRecursively)
	return( getNextObjectRecursive());
    else
	return( getNextObjectFlat());
}

IORegistryEntry * IORegistryIterator::getCurrentEntry( void )
{
    if( isValid())
	return( where->current);
    else
	return( 0);
}

OSOrderedSet * IORegistryIterator::iterateAll( void )
{
    reset();
    while( getNextObjectRecursive())
        {}
    if( done)
        done->retain();
    return( done);
}

OSMetaClassDefineReservedUsed(IORegistryEntry, 0);
OSMetaClassDefineReservedUsed(IORegistryEntry, 1);
OSMetaClassDefineReservedUsed(IORegistryEntry, 2);
OSMetaClassDefineReservedUsed(IORegistryEntry, 3);
OSMetaClassDefineReservedUsed(IORegistryEntry, 4);

OSMetaClassDefineReservedUnused(IORegistryEntry, 5);
OSMetaClassDefineReservedUnused(IORegistryEntry, 6);
OSMetaClassDefineReservedUnused(IORegistryEntry, 7);
OSMetaClassDefineReservedUnused(IORegistryEntry, 8);
OSMetaClassDefineReservedUnused(IORegistryEntry, 9);
OSMetaClassDefineReservedUnused(IORegistryEntry, 10);
OSMetaClassDefineReservedUnused(IORegistryEntry, 11);
OSMetaClassDefineReservedUnused(IORegistryEntry, 12);
OSMetaClassDefineReservedUnused(IORegistryEntry, 13);
OSMetaClassDefineReservedUnused(IORegistryEntry, 14);
OSMetaClassDefineReservedUnused(IORegistryEntry, 15);
OSMetaClassDefineReservedUnused(IORegistryEntry, 16);
OSMetaClassDefineReservedUnused(IORegistryEntry, 17);
OSMetaClassDefineReservedUnused(IORegistryEntry, 18);
OSMetaClassDefineReservedUnused(IORegistryEntry, 19);
OSMetaClassDefineReservedUnused(IORegistryEntry, 20);
OSMetaClassDefineReservedUnused(IORegistryEntry, 21);
OSMetaClassDefineReservedUnused(IORegistryEntry, 22);
OSMetaClassDefineReservedUnused(IORegistryEntry, 23);
OSMetaClassDefineReservedUnused(IORegistryEntry, 24);
OSMetaClassDefineReservedUnused(IORegistryEntry, 25);
OSMetaClassDefineReservedUnused(IORegistryEntry, 26);
OSMetaClassDefineReservedUnused(IORegistryEntry, 27);
OSMetaClassDefineReservedUnused(IORegistryEntry, 28);
OSMetaClassDefineReservedUnused(IORegistryEntry, 29);
OSMetaClassDefineReservedUnused(IORegistryEntry, 30);
OSMetaClassDefineReservedUnused(IORegistryEntry, 31);

/* inline function implementation */
OSDictionary * IORegistryEntry::getPropertyTable( void ) const
{ return(fPropertyTable); }
