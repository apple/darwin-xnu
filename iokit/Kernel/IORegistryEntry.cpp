/*
 * Copyright (c) 1998-2006 Apple Computer, Inc. All rights reserved.
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

#define kIORegPlaneParentSuffix		"ParentLinks"
#define kIORegPlaneChildSuffix		"ChildLinks"
#define kIORegPlaneNameSuffix		"Name"
#define kIORegPlaneLocationSuffix	"Location"

#define kIORegPlaneParentSuffixLen	(sizeof(kIORegPlaneParentSuffix) - 1)
#define kIORegPlaneChildSuffixLen	(sizeof(kIORegPlaneChildSuffix) - 1)
#define kIORegPlaneNameSuffixLen	(sizeof(kIORegPlaneNameSuffix) - 1)
#define kIORegPlaneLocationSuffixLen	(sizeof(kIORegPlaneLocationSuffix) - 1)

static IORegistryEntry * gRegistryRoot;
static OSDictionary * 	 gIORegistryPlanes;

const OSSymbol * 	gIONameKey;
const OSSymbol * 	gIOLocationKey;
const OSSymbol * 	gIORegistryEntryIDKey;

enum {
    kParentSetIndex	= 0,
    kChildSetIndex	= 1,
    kNumSetIndex
};
enum {
    kIOMaxPlaneName	= 32
};

enum { kIORegistryIDReserved = (1ULL << 32) + 255 };

static uint64_t gIORegistryLastID = kIORegistryIDReserved;

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

#define UNLOCK	lck_rw_done( &gIORegistryLock )
#define RLOCK	lck_rw_lock_shared( &gIORegistryLock )
#define WLOCK	lck_rw_lock_exclusive( &gIORegistryLock );	\
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

lck_rw_t	gIORegistryLock;
lck_grp_t       *gIORegistryLockGrp;
lck_grp_attr_t  *gIORegistryLockGrpAttr;
lck_attr_t      *gIORegistryLockAttr;


/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

IORegistryEntry * IORegistryEntry::initialize( void )
{
   bool			ok;

    if( !gRegistryRoot) {


	gIORegistryLockGrpAttr = lck_grp_attr_alloc_init();
	//lck_grp_attr_setstat(gIORegistryLockGrpAttr);
	gIORegistryLockGrp = lck_grp_alloc_init("IORegistryLock",  gIORegistryLockGrpAttr);
	gIORegistryLockAttr = lck_attr_alloc_init();
	lck_attr_rw_shared_priority(gIORegistryLockAttr);
	//lck_attr_setdebug(gIORegistryLockAttr);
	lck_rw_init( &gIORegistryLock, gIORegistryLockGrp, gIORegistryLockAttr);

	gRegistryRoot = new IORegistryEntry;
	gPropertiesLock = IORecursiveLockAlloc();
	gIORegistryPlanes = OSDictionary::withCapacity( 1 );
        
	assert( gRegistryRoot && gPropertiesLock
		&& gIORegistryPlanes );
        ok = gRegistryRoot->init();

	if (ok)
	    gRegistryRoot->reserved->fRegistryEntryID = ++gIORegistryLastID;

	gIONameKey = OSSymbol::withCStringNoCopy( "IOName" );
	gIOLocationKey = OSSymbol::withCStringNoCopy( "IOLocation" );
	gIORegistryEntryIDKey = OSSymbol::withCStringNoCopy( kIORegistryEntryIDKey );

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

    strlcpy( key, name, kIOMaxPlaneName + 1 );
    end = key + strlen( key );

    nameKey = OSSymbol::withCString( key);

    strlcpy( end, kIORegPlaneParentSuffix, kIORegPlaneParentSuffixLen + 1 );
    parentKey = OSSymbol::withCString( key);

    strlcpy( end, kIORegPlaneChildSuffix, kIORegPlaneChildSuffixLen + 1 );
    childKey = OSSymbol::withCString( key);

    strlcpy( end, kIORegPlaneNameSuffix, kIORegPlaneNameSuffixLen + 1 );
    pathNameKey = OSSymbol::withCString( key);

    strlcpy( end, kIORegPlaneLocationSuffix, kIORegPlaneLocationSuffixLen + 1 );
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

bool IORegistryEntry::init( OSDictionary * dict )
{
    OSString *	prop;

    if( !super::init())
	return( false);

    if (!reserved)
    {
	reserved = IONew(ExpansionData, 1);
	if (!reserved)
	    return (false);
	bzero(reserved, sizeof(ExpansionData));
    }
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

    reserved = old->reserved;
    old->reserved = NULL;

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
    if( registryTable() && gIOServicePlane) {
        if( getParentSetReference( gIOServicePlane )
            || getChildSetReference( gIOServicePlane )) {
            panic("%s: attached at free()", getName());
        }
    }
#endif

    if( getPropertyTable())
        getPropertyTable()->release();

#ifdef IOREGSPLITTABLES
    if( registryTable())
        registryTable()->release();
#endif /* IOREGSPLITTABLES */

    if (reserved)
	IODelete(reserved, ExpansionData, 1);

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
//    setProperty( getRetainCount(), 32, "__retain" );

    PLOCK;
    OSCollection *snapshotProperties = getPropertyTable()->copyCollection();
    PUNLOCK;

    bool ok =  snapshotProperties->serialize( s );
    snapshotProperties->release();
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

wrap2(const OSSymbol, const)       // copyProperty() definition
wrap2(const OSString, const)       // copyProperty() definition
wrap2(const char, const)      	   // copyProperty() definition

wrap4(const OSSymbol, const)       // getProperty() w/plane definition
wrap4(const OSString, const)       // getProperty() w/plane definition
wrap4(const char, const)           // getProperty() w/plane definition

wrap5(const OSSymbol, const)       // copyProperty() w/plane definition
wrap5(const OSString, const)       // copyProperty() w/plane definition
wrap5(const char, const)           // copyProperty() w/plane definition


OSObject *
IORegistryEntry::getProperty( const OSSymbol * aKey) const
{
    OSObject * obj;

    PLOCK;
    obj = getPropertyTable()->getObject( aKey );
    PUNLOCK;

    return( obj );
}

void
IORegistryEntry::removeProperty( const OSSymbol * aKey)
{
    PLOCK;
    getPropertyTable()->removeObject( aKey );
    PUNLOCK;
}

bool
IORegistryEntry::setProperty( const OSSymbol * aKey, OSObject * anObject)
{
    bool ret = false;

    // If we are inserting a collection class and the current entry
    // is attached into the registry (inPlane()) then mark the collection
    // as immutable.
    OSCollection *coll = OSDynamicCast(OSCollection, anObject);
    bool makeImmutable = (coll && inPlane());

    PLOCK;
    if( makeImmutable )
	coll->setOptions( OSCollection::kMASK, OSCollection::kImmutable );

    ret = getPropertyTable()->setObject( aKey, anObject );
    PUNLOCK;
    
    return ret;
}

IOReturn IORegistryEntry::
runPropertyAction(Action inAction, OSObject *target,
	void *arg0, void *arg1, void *arg2, void *arg3)
{
    IOReturn res;

    // closeGate is recursive so don't worry if we already hold the lock.
    PLOCK;
    res = (*inAction)(target, arg0, arg1, arg2, arg3);
    PUNLOCK;

    return res;
}

OSObject *
IORegistryEntry::getProperty( const OSString * aKey) const
{
    const OSSymbol * tmpKey = OSSymbol::withString( aKey );
    OSObject * obj = getProperty( tmpKey );

    tmpKey->release();
    return( obj );
}

OSObject *
IORegistryEntry::getProperty( const char * aKey) const
{
    const OSSymbol * tmpKey = OSSymbol::withCString( aKey );
    OSObject * obj = getProperty( tmpKey );

    tmpKey->release();
    return( obj );
}


void
IORegistryEntry::removeProperty( const OSString * aKey)
{
    const OSSymbol * tmpKey = OSSymbol::withString( aKey );
    removeProperty( tmpKey );
    tmpKey->release();
}

void
IORegistryEntry::removeProperty( const char * aKey)
{
    const OSSymbol * tmpKey = OSSymbol::withCString( aKey );
    removeProperty( tmpKey );
    tmpKey->release();
}

bool
IORegistryEntry::setProperty( const OSString * aKey, OSObject * anObject)
{
    const OSSymbol * tmpKey = OSSymbol::withString( aKey );
    bool ret = setProperty( tmpKey, anObject );

    tmpKey->release();
    return ret;
}

bool
IORegistryEntry::setProperty( const char * aKey,  OSObject * anObject)
{
    const OSSymbol * tmpKey = OSSymbol::withCString( aKey );
    bool ret = setProperty( tmpKey, anObject );

    tmpKey->release();
    return ret;
}

bool
IORegistryEntry::setProperty(const char * aKey, const char * aString)
{
    bool ret = false;
    OSSymbol * aSymbol = (OSSymbol *) OSSymbol::withCString( aString );

    if( aSymbol) {
        const OSSymbol * tmpKey = OSSymbol::withCString( aKey );
        ret = setProperty( tmpKey, aSymbol );

        tmpKey->release();
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
        const OSSymbol * tmpKey = OSSymbol::withCString( aKey );
        ret = setProperty( tmpKey, aBooleanObj );

        tmpKey->release();
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
        const OSSymbol * tmpKey = OSSymbol::withCString( aKey );
        ret = setProperty( tmpKey, anOffset );

        tmpKey->release();
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
        const OSSymbol * tmpKey = OSSymbol::withCString( aKey );
        ret = setProperty( tmpKey, data );

        tmpKey->release();
        data->release();
    }
    return( ret );
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

/* Name, location, paths */

const char * IORegistryEntry::getName( const IORegistryPlane * plane ) const
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
			const IORegistryPlane * plane ) const
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
			const IORegistryPlane * plane ) const
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

const char * IORegistryEntry::getLocation( const IORegistryPlane * plane ) const
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
                            const IORegistryPlane * plane )
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
                            const IORegistryPlane * plane )
{
    OSSymbol * sym = (OSSymbol *)OSSymbol::withCString( name );
    if ( sym ) {
        setName( sym, plane );
        sym->release();
    }
}

void IORegistryEntry::setLocation( const OSSymbol * location,
                            const IORegistryPlane * plane )
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
                            const IORegistryPlane * plane )
{
    OSSymbol * sym = (OSSymbol *)OSSymbol::withCString( location );
    if ( sym ) {
        setLocation( sym, plane );
        sym->release();
    }
}

bool
IORegistryEntry::compareName( OSString * name, OSString ** matched ) const
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
IORegistryEntry::compareNames( OSObject * names, OSString ** matched ) const
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
    int			len, maxLength, compLen, aliasLen;
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
    strlcpy( nextComp, plane->nameKey->getCStringNoCopy(), len + 1);
    nextComp[ len++ ] = ':';
    nextComp += len;

    if( (alias = hasAlias( plane ))) {
	aliasLen = alias->getLength();
	len += aliasLen;
	ok = (maxLength > len);
	*length = len;
	if( ok)
	    strlcpy( nextComp, alias->getCStringNoCopy(), aliasLen + 1);
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
            ok = (maxLength > (len + compLen));
            if( ok)
                strlcpy( nextComp, alias->getCStringNoCopy(), compLen + 1);
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

    ok = ((len + locLen + 1) < maxLength);
    if( ok) {
        strlcpy( path, compName, len + 1 );
	if( loc) {
            path += len;
            len += locLen;
            *path++ = '@';
            strlcpy( path, loc, locLen );
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
    char		lastPathChar, lastLocationChar;

    str = getLocation( plane );
    if( str) {
	lastPathChar = cmp[0];
	lastLocationChar = str[0];
	do {
            if( lastPathChar) {
                num1 = strtouq( cmp, (char **) &cmp, 16 );
                lastPathChar = *cmp++;
	    } else
                num1 = 0;

            if( lastLocationChar) {
                num2 = strtouq( str, (char **) &str, 16 );
                lastLocationChar = *str++;
	    } else
                num2 = 0;

            if( num1 != num2)
                break;

	    if (!lastPathChar && !lastLocationChar) {
                result = cmp - 1;
                break;
            }

            if( (',' != lastPathChar) && (':' != lastPathChar))
		lastPathChar = 0;

	    if (lastPathChar && lastLocationChar && (lastPathChar != lastLocationChar))
                break;

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
				char * opath, int * length ) const
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
        strlcpy( temp, path, end - path + 1 );

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
                        const IORegistryPlane * plane,
                        char *			opath,
			int * 			length,
                        IORegistryEntry * 	fromEntry )
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
	    strlcpy( temp, path, end - path + 1 );
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
	    len2 = strlen( path );
	    if( (len + len2) < *length)
                strlcpy( opath + len, path, len2 + 1 );
	    *length = (len + len2);

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
                        const IORegistryPlane * plane,
                        char *			opath,
                        int *			len )
{
    return( IORegistryEntry::fromPath( path, plane, opath, len, this ));
}

/* * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * * */

#define IOLinkIterator OSCollectionIterator

#undef super
#define super OSObject

inline bool IORegistryEntry::arrayMember( OSArray * set,
					  const IORegistryEntry * member,
					unsigned int * index ) const
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

	links = OSArray::withObjects( (const OSObject **) &to, 1, 1 );
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
				bool onlyChild ) const
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
				bool onlyParent ) const

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

    if( plane)
	ret = (0 != getParentSetReference( plane ));
    else {

	// Check to see if this is in any plane.  If it is in a plane
	// then the registryTable will contain a key with the ParentLinks
	// suffix.  When we iterate over the keys looking for that suffix
	ret = false;

	OSCollectionIterator *iter =
	    OSCollectionIterator::withCollection( registryTable());
	if( iter) {
	    const OSSymbol *key;

            while( (key = (OSSymbol *) iter->getNextObject()) ) {
		size_t keysuffix;

		// Get a pointer to this keys suffix
		keysuffix = key->getLength();
		if (keysuffix <= kIORegPlaneParentSuffixLen)
		    continue;
		keysuffix -= kIORegPlaneParentSuffixLen;
		if( !strncmp(key->getCStringNoCopy() + keysuffix, 
				kIORegPlaneParentSuffix, 
				kIORegPlaneParentSuffixLen + 1) ) {
		    ret = true;
		    break;
		}
            }
            iter->release();
        }
    }

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

    if (!reserved->fRegistryEntryID)
	reserved->fRegistryEntryID = ++gIORegistryLastID;

    ret = makeLink( parent, kParentSetIndex, plane );

    if( (links = parent->getChildSetReference( plane )))
	needParent = (false == arrayMember( links, this ));
    else
	needParent = true;

    UNLOCK;

    PLOCK;

    // Mark any collections in the property list as immutable
    OSDictionary *ptable = getPropertyTable();
    OSCollectionIterator *iter =
	OSCollectionIterator::withCollection( ptable );
    if( iter) {
	const OSSymbol *key;

	while( (key = (OSSymbol *) iter->getNextObject( ))) {
	    // Is object for key a collection?
	    OSCollection *coll =
		OSDynamicCast( OSCollection, ptable->getObject( key ));

	    if( coll) {
		// Yup so mark it as immutable
		coll->setOptions( OSCollection::kMASK,
				  OSCollection::kImmutable );
	    }
	}
	iter->release();
    }

    PUNLOCK;

    if( needParent)
        ret &= parent->attachToChild( this, plane );

    return( ret );
}

uint64_t IORegistryEntry::getRegistryEntryID( void )
{
    if (reserved)
	return (reserved->fRegistryEntryID);
    else
	return (0);
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
                                 IOOptionBits options )
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
				 IOOptionBits options )
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
    where = (IORegCursor *) IOMalloc( sizeof(IORegCursor));
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
        IOFree( gone, sizeof(IORegCursor));
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

#if __LP64__
OSMetaClassDefineReservedUnused(IORegistryEntry, 0);
OSMetaClassDefineReservedUnused(IORegistryEntry, 1);
OSMetaClassDefineReservedUnused(IORegistryEntry, 2);
OSMetaClassDefineReservedUnused(IORegistryEntry, 3);
OSMetaClassDefineReservedUnused(IORegistryEntry, 4);
OSMetaClassDefineReservedUnused(IORegistryEntry, 5);
#else
OSMetaClassDefineReservedUsed(IORegistryEntry, 0);
OSMetaClassDefineReservedUsed(IORegistryEntry, 1);
OSMetaClassDefineReservedUsed(IORegistryEntry, 2);
OSMetaClassDefineReservedUsed(IORegistryEntry, 3);
OSMetaClassDefineReservedUsed(IORegistryEntry, 4);
OSMetaClassDefineReservedUsed(IORegistryEntry, 5);
#endif
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
