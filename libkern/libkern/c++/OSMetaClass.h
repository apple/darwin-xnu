/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
#ifndef _LIBKERN_OSMETACLASS_H
#define _LIBKERN_OSMETACLASS_H

#include <sys/types.h>

#include <libkern/OSReturn.h>

class OSMetaClass;
class OSObject;
class OSString;
class OSSymbol;
class OSDictionary;
class OSSerialize;

#if __GNUC__ < 3
#define APPLE_KEXT_COMPATIBILITY
#else
#define APPLE_KEXT_COMPATIBILITY __attribute__ ((apple_kext_compatibility))
#endif

class OSMetaClassBase
{
public:
/*! @function OSTypeAlloc
    @abstract Allocate an instance of the desired object.
    @discussion The OSTypeAlloc macro can be used to break the binary compatibility difficulties presented by new.  The problem is that C++ compiles the knowledge of the size of the class into the cade calling new.  If you use the alloc code however the class size is determined by the callee not the caller.
    @param type Name of the desired type to be created.
    @result 'this' if object cas been successfully created.
*/
#define OSTypeAlloc(type)	((type *) ((type::metaClass)->alloc()))

/*! @function OSTypeID
    @abstract Given the name of a class return it's typeID
    @param type Name of the desired type, eg. OSObject.
    @result A unique Type ID for the class.
*/
#define OSTypeID(type)	(type::metaClass)

/*! @function OSTypeIDInst
    @abstract Given a pointer to an object return it's typeID
    @param typeinst An instance of an OSObject subclass.
    @result The typeID, ie. OSMetaClass *.
*/
#define OSTypeIDInst(typeinst)	((typeinst)->getMetaClass())

/*! @function OSDynamicCast
    @abstract Roughly analogous to (type *) inst, but check if valid first.
    @discussion OSDynamicCast is an attempt to implement a rudimentary equivalent to rtti's dynamic_cast<T> operator.  Embedded-C++ doesn't allow the use of rtti.  OSDynamicCast is build on the OSMetaClass mechanism.  Note it is safe to call this with a 0 parameter.  
    @param type name of desired class name.  Notice that it is assumed that you desire to cast to a pointer to an object of this type.	Also type qualifiers, like const, are not recognized and will cause an, usually obscure, compile error.
    @param inst Pointer to object that you wish to attempt to type cast.  May be 0.
    @result inst if object non-zero and it is of the desired type, otherwise 0.
*/
#define OSDynamicCast(type, inst)	\
    ((type *) OSMetaClassBase::safeMetaCast((inst), OSTypeID(type)))

/*! @function OSCheckTypeInst
    @abstract Is the target object a subclass of the reference object?
    @param typeinst Reference instance of an object, desired type.
    @param inst Instance of object to check for type compatibility.
    @result false if typeinst or inst are 0 or inst is not a subclass of typeinst's class. true otherwise.
*/
#define OSCheckTypeInst(typeinst, inst) \
    OSMetaClassBase::checkTypeInst(inst, typeinst)
    

protected:
    OSMetaClassBase();
    virtual ~OSMetaClassBase();

private:
    // Disable copy constructors of OSMetaClassBase based objects
/*! @function operator =
    @abstract Disable implicit copy constructor by making private
    @param src Reference to source object that isn't allowed to be copied
*/
    void operator =(OSMetaClassBase &src);

/*! @function OSMetaClassBase
    @abstract Disable implicit copy constructor by making private
    @param src Reference to source object that isn't allowed to be copied
*/
    OSMetaClassBase(OSMetaClassBase &src);

public:
/*! @function release
    @abstract Primary implementation of the release mechanism.
    @discussion  If $link retainCount <= the when argument then call $link free().  This indirect implementation of $link release allows the developer to break reference circularity.  An example of this sort of problem is a parent/child mutual reference, either the parent or child can implement: void release() { release(2); } thus breaking the cirularity. 
    @param when When retainCount == when then call free(). */
    virtual void release(int when) const = 0;

/*! @function getRetainCount
    @abstract How many times has this object been retained?
    @result Current retain count
*/
    virtual int getRetainCount() const = 0;

/*! @function retain
    @abstract Retain a reference in this object.
*/
    virtual void retain() const = 0;
/*! @function release
    @abstract Release a reference to this object
*/
    virtual void release() const = 0;

/*! @function serialize
    @abstract 
    @discussion 
    @param s
    @result 
*/
    virtual bool serialize(OSSerialize *s) const = 0;

    virtual const OSMetaClass * getMetaClass() const = 0;

/*! @function isEqualTo
    @abstract Is this == anObj?
    @discussion OSMetaClassBase::isEqualTo implements this as a shallow pointer comparison.  The OS container classes do a more meaningful comparison.  Your mileage may vary.
    @param anObj Object to compare 'this' to.
    @result true if the objects are equivalent, false otherwise.
*/
    virtual bool isEqualTo(const OSMetaClassBase *anObj) const;

/*! @function metaCast
    @abstract Check to see if this object is or inherits from the given type.
    @discussion This function is the guts of the OSMetaClass system.  IODynamicCast, qv, is implemented using this function.
    @param toMeta Pointer to a constant OSMetaClass for the desired target type.
    @result 'this' if object is of desired type, otherwise 0.
*/
    OSMetaClassBase *metaCast(const OSMetaClass *toMeta) const;


/*! @function metaCast
    @abstract See OSMetaClassBase::metaCast(const OSMetaClass *)
    @param toMeta OSSymbol of the desired class' name.
    @result 'this' if object is of desired type, otherwise 0.
*/
    OSMetaClassBase *metaCast(const OSSymbol *toMeta) const;

/*! @function metaCast
    @abstract See OSMetaClassBase::metaCast(const OSMetaClass *)
    @param toMeta OSString of the desired class' name.
    @result 'this' if object is of desired type, otherwise 0.
*/
    OSMetaClassBase *metaCast(const OSString *toMeta) const;

/*! @function metaCast
    @abstract See OSMetaClassBase::metaCast(const OSMetaClass *)
    @param toMeta const char * C String of the desired class' name.
    @result 'this' if object is of desired type, otherwise 0.
*/
    OSMetaClassBase *metaCast(const char *toMeta) const;

    // Helper inlines for runtime type preprocessor macros
    static OSMetaClassBase *
    safeMetaCast(const OSMetaClassBase *me, const OSMetaClass *toType);

    static bool
    checkTypeInst(const OSMetaClassBase *inst, const OSMetaClassBase *typeinst);

public:

/*! @function taggedRetain
    @abstract Retain a tagged reference in this object.
*/
    // WAS: virtual void _RESERVEDOSMetaClassBase0();
    virtual void taggedRetain(const void *tag = 0) const = 0;

/*! @function taggedRelease
    @abstract Release a tagged reference to this object
*/
    // WAS:  virtual void _RESERVEDOSMetaClassBase1();
    virtual void taggedRelease(const void *tag = 0) const = 0;

protected:
/*! @function taggedRelease
    @abstract Release a tagged reference to this object and free if retainCount == when on entry
*/
    // WAS:  virtual void _RESERVEDOSMetaClassBase2();
    virtual void taggedRelease(const void *tag, const int when) const = 0;

private:
    // Virtual Padding
    virtual void _RESERVEDOSMetaClassBase3();
    virtual void _RESERVEDOSMetaClassBase4();
    virtual void _RESERVEDOSMetaClassBase5();
    virtual void _RESERVEDOSMetaClassBase6();
    virtual void _RESERVEDOSMetaClassBase7();
} APPLE_KEXT_COMPATIBILITY;

/*!
    @class OSMetaClass : OSMetaClassBase
    @abstract An instance of a OSMetaClass represents one class then the kernel's runtime type information system is aware of.
*/
class OSMetaClass : private OSMetaClassBase
{

private:
    // Can never be allocated must be created at compile time
    static void *operator new(size_t size);

    struct ExpansionData { };
    
/*! @var reserved Reserved for future use.  (Internal use only)  */
    ExpansionData *reserved;

/*! @var superClass Handle to the superclass' meta class. */
    const OSMetaClass *superClassLink;

/*! @var className OSSymbol of the class' name. */
    const OSSymbol *className;

/*! @var classSize How big is a single instancde of this class. */
    unsigned int classSize;

/*! @var instanceCount Roughly number of instances of the object.  Used primarily as a code in use flag. */
    mutable unsigned int instanceCount;

/*! @function OSMetaClass
    @abstract Private the default constructor */
    OSMetaClass();

    // Called by postModLoad
/*! @function logError
    @abstract Given an error code log an error string using printf */
    static void logError(OSReturn result);

/*! @function getMetaClassWithName
    @abstract Lookup a meta-class in the runtime type information system
    @param name Name of the desired class's meta-class. 
    @result pointer to a meta-class object if found, 0 otherwise. */

    static const OSMetaClass *getMetaClassWithName(const OSSymbol *name);

protected:
/*! @function retain
    @abstract Implement abstract but should no dynamic allocation is allowed */
    virtual void retain() const;

/*! @function release
    @abstract Implement abstract but should no dynamic allocation is allowed */
    virtual void release() const;

/*! @function release
    @abstract Implement abstract but should no dynamic allocation is allowed 
    @param when ignored. */
    virtual void release(int when) const;

/*! @function taggedRetain
    @abstract Retain a tagged reference in this object.
*/
    virtual void taggedRetain(const void *tag = 0) const;

/*! @function release
    @abstract Release a tagged reference to this object
*/
    virtual void taggedRelease(const void *tag = 0) const;

/*! @function release
    @abstract Release a tagged reference to this object
*/
    virtual void taggedRelease(const void *tag, const int when) const;

/*! @function getRetainCount
    @abstract Implement abstract but should no dynamic allocation is allowed */
    virtual int getRetainCount() const;

    virtual const OSMetaClass * getMetaClass() const;

/*! @function OSMetaClass
    @abstract Constructor for OSMetaClass objects
    @discussion This constructor is protected and cannot not be used to instantiate an OSMetaClass object, i.e. OSMetaClass is an abstract class.  This function stores the currently constructing OSMetaClass instance away for later processing.  See preModLoad and postModLoad.
    @param inClassName cString of the name of the class this meta-class represents.
    @param inSuperClassName cString of the name of the super class.
    @param inClassSize sizeof the class. */
    OSMetaClass(const char *inClassName,
		const OSMetaClass *inSuperClass,
		unsigned int inClassSize);

/*! @function ~OSMetaClass
    @abstract Destructor for OSMetaClass objects
    @discussion If this function is called it means that the object code that implemented this class is actually in the process of unloading.  The destructor removes all reference's to the subclass from the runtime type information system. */
    virtual ~OSMetaClass();

    // Needs to be overriden as NULL as all OSMetaClass objects are allocated
    // statically at compile time, don't accidently try to free them.
    void operator delete(void *mem, size_t size) { };

public:
    static const OSMetaClass * const metaClass;

/*! @function preModLoad
    @abstract Prepare the runtime type system for the load of a module.
    @discussion Prepare the runtime type information system for the loading of new all meta-classes constructed between now and the next postModLoad.  preModLoad grab's a lock so that the runtime type information system loading can be protected, the lock is released by the postModLoad function.  Any OSMetaClass that is constructed between the bracketing pre and post calls will be assosiated with the module name.
    @param kmodName globally unique cString name of the kernel module being loaded. 
    @result If success full return a handle to be used in later calls 0 otherwise. */
    static void *preModLoad(const char *kmodName);

/*! @function failModLoad
    @abstract Record an error during the loading of an kernel module.
    @discussion As constructor's can't return errors nor can they through exceptions in embedded-c++ an indirect error mechanism is necessary.  Check mod load returns a bool to indicate the current error state of the runtime type information system.  During object construction a call to failModLoad will cause an error code to be recorded.  Once an error has been set the continuing construction will be ignored until the end of the pre/post load.
    @param error Code of the error. */
    static void failModLoad(OSReturn error);

/*! @function checkModLoad
    @abstract Check if the current load attempt is still OK.
    @param loadHandle Handle returned when a successful call to preModLoad is made.
    @result true if no error's are outstanding and the system is primed to recieve more objects. */
    static bool checkModLoad(void *loadHandle);

/*! @function postModLoad
    @abstract Finish postprocessing on a kernel module's meta-classes.
    @discussion As the order of static object construction is undefined it is necessary to process the constructors in two phases.  These phases rely on global information that is created be the preparation step, preModLoad, which also guarantees single threading between multiple modules.  Phase one was the static construction of each meta-class object one by one withing the context prepared by the preModLoad call.  postModLoad is the second phase of processing.  Inserts links all of the super class inheritance chains up, inserts the meta-classes into the global register of classes and records for each meta-class which kernel module caused it's construction.  Finally it cleans up the temporary storage and releases the single threading lock and returns whatever error has been recorded in during the construction phase or the post processing phase. 
    @param loadHandle Handle returned when a successful call to preModLoad is made.
    @result Error code of the first error encountered. */
    static OSReturn postModLoad(void *loadHandle);

/*! @function modHasInstance
    @abstract Do any of the objects represented by OSMetaClass and associated with the given kernel module name have instances?
    @discussion Check all meta-classes associated with the module name and check their instance counts.  This function is used to check to see if a module can be unloaded.  Obviously if an instance is still outstanding it isn't safe to unload the code that relies on that object.
    @param kmodName cString of the kernel module name.
    @result true if there are any current instances of any class in the module.
*/
    static bool modHasInstance(const char *kmodName);

/*! @function reportModInstances
    @abstract Log any object that has instances in a module.
    @discussion When a developer ask for a module to be unloaded but the unload fails due to outstanding instances.  This function will report which classes still have instances.  It is intended mostly for developers to find problems with unloading classes and will be called automatically by 'verbose' unloads.
    @param kmodName cString of the kernel module name. */
    static void reportModInstances(const char *kmodName);

/*! @function considerUnloads
    @abstract Schedule module unloading.
    @discussion Schedule unused modules to be unloaded; called when IOKit matching goes idle. */

    static void considerUnloads();

/*! @function allocClassWithName
    @abstract Lookup a meta-class in the runtime type information system and return the results of an alloc call.
    @param name Name of the desired class. 
    @result pointer to an new object, 0 if not found or so memory. */
    static OSObject *allocClassWithName(const OSSymbol *name);

/*! @function allocClassWithName
    @abstract Lookup a meta-class in the runtime type information system and return the results of an alloc call.
    @param name Name of the desired class. 
    @result pointer to an new object, 0 if not found or so memory. */
    static OSObject *allocClassWithName(const OSString *name);

/*! @function allocClassWithName
    @abstract Lookup a meta-class in the runtime type information system and return the results of an alloc call.
    @param name Name of the desired class. 
    @result pointer to an new object, 0 if not found or so memory. */
    static OSObject *allocClassWithName(const char *name);

/*! @function checkMetaCastWithName
    @abstract Introspect an objects inheritance tree looking for a class of the given name.  Basis of MacOSX's kernel dynamic casting mechanism.
    @param name Name of the desired class or super class. 
    @param in object to be introspected. 
    @result in parameter if cast valid, 0 otherwise. */
    static OSMetaClassBase *
	checkMetaCastWithName(const OSSymbol *name, const OSMetaClassBase *in);

/*! @function checkMetaCastWithName
    @abstract Introspect an objects inheritance tree looking for a class of the given name.  Basis of MacOSX's kernel dynamic casting mechanism.
    @param name Name of the desired class or super class.
    @param in object to be introspected.
    @result in parameter if cast valid, 0 otherwise. */
    static OSMetaClassBase *
	checkMetaCastWithName(const OSString *name, const OSMetaClassBase *in);

/*! @function checkMetaCastWithName
    @abstract Introspect an objects inheritance tree looking for a class of the given name.  Basis of MacOSX's kernel dynamic casting mechanism.
    @param name Name of the desired class or super class.
    @param in object to be introspected.
    @result in parameter if cast valid, 0 otherwise. */
    static OSMetaClassBase *
	checkMetaCastWithName(const char *name, const OSMetaClassBase *in);


/*! @function instanceConstructed
    @abstract Counts the instances of the class behind this metaclass.
    @discussion Every non-abstract class that inherits from OSObject has a default constructor that calls it's own meta-class' instanceConstructed function.  This constructor is defined by the OSDefineMetaClassAndStructors macro (qv) that all OSObject subclasses must use.  Also if the instance count goes from 0 to 1, ie the first instance, then increment the instance count of the super class */
    void instanceConstructed() const;

/*! @function instanceDestructed
    @abstract Removes one instance of the class behind this metaclass.
    @discussion OSObject's free function calls this method just before it does a 'delete this' on itself.  If the instance count transitions from 1 to 0, i.e. the last object, then one instance of the superclasses is also removed. */
    void instanceDestructed() const;


/*! @function checkMetaCast
    @abstract Ask a OSMetaClass instance if the given object is either an instance of it or an instance of a subclass of it.
    @param check Pointer of object to introspect.
    @result check parameter if cast valid, 0 otherwise. */
    OSMetaClassBase *checkMetaCast(const OSMetaClassBase *check) const;


/*! @function getInstanceCount
    @abstract How many instances of the class have been created.
    @result Count of the number of instances. */
    unsigned int getInstanceCount() const;


/*! @function getSuperClass
    @abstract 'Get'ter for the super class.
    @result Pointer to superclass, chain ends with 0 for OSObject. */
    const OSMetaClass *getSuperClass() const;

/*! @function getClassName
    @abstract 'Get'ter for class name.
    @result cString of the class name. */
    const char *getClassName() const;

/*! @function getClassSize
    @abstract 'Get'ter for sizeof(class).
    @result sizeof of class that this OSMetaClass instance represents. */
    unsigned int getClassSize() const;

/*! @function alloc
    @abstract Allocate an instance of the class that this OSMetaClass instance represents.
    @discussion This alloc function is analogous to the old ObjC class alloc method.  Typically not used by clients as the static function allocClassWithName is more generally useful.  Infact that function is implemented in terms of this  virtual function.  All subclass's of OSMetaClass must implement this function but that is what the OSDefineMetaClassAndStructor's families of macros does for the developer automatically. 
    @result Pointer to a new object with a retain count of 1. */
    virtual OSObject *alloc() const = 0;

/*! @function OSDeclareCommonStructors
    @abstract Basic helper macro for the OSDeclare for Default and Abstract macros, qv.  DO NOT USE.
    @param className Name of class. NO QUOTES. */
#define OSDeclareCommonStructors(className)				\
    private:								\
	static const OSMetaClass * const superClass;			\
    public:								\
	static const OSMetaClass * const metaClass;			\
        static class MetaClass : public OSMetaClass {			\
        public:								\
            MetaClass();						\
            virtual OSObject *alloc() const;				\
        } gMetaClass;							\
        friend class className ::MetaClass;				\
        virtual const OSMetaClass * getMetaClass() const;		\
    protected:								\
	className (const OSMetaClass *);				\
	virtual ~ className ()


/*! @function OSDeclareDefaultStructors
    @abstract One of the macro's used in the class declaration of all subclasses of OSObject, declares runtime type information data and interfaces. 
    @discussion Macro used in the class declaration all subclasses of OSObject, declares runtime type information data and interfaces.  By convention it should be 'called' immediately after the opening brace in a class declaration.  It leaves the current privacy state as 'protected:'.
    @param className Name of class. NO QUOTES. */
#define OSDeclareDefaultStructors(className)				\
	OSDeclareCommonStructors(className);				\
    public:								\
	className ();							\
    protected:


/*! @function OSDeclareAbstractStructors
    @abstract One of the macro's used in the class declaration of all subclasses of OSObject, declares runtime type information data and interfaces. 
    @discussion This macro is used when the class being declared has one or more '= 0' pure virtual methods and thus it is illegal to create an instance of this class.  It leaves the current privacy state as 'protected:'.
    @param className Name of class. NO QUOTES. */
#define OSDeclareAbstractStructors(className)				\
	OSDeclareCommonStructors(className);				\
    private:								\
	className (); /* Make primary constructor private in abstract */ \
    protected:

/*! @function OSDefineMetaClassWithInit
    @abstract Basic helper macro for the OSDefineMetaClass for the default and Abstract macros, qv.  DO NOT USE.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS.
    @param init Name of a function to call after the OSMetaClass is constructed. */
#define OSDefineMetaClassWithInit(className, superClassName, init)	\
    /* Class global data */						\
    className ::MetaClass className ::gMetaClass;			\
    const OSMetaClass * const className ::metaClass = 			\
        & className ::gMetaClass;					\
    const OSMetaClass * const className ::superClass = 			\
        & superClassName ::gMetaClass;					\
    /* Class member functions */					\
    className :: className(const OSMetaClass *meta)			\
	    : superClassName (meta) { }					\
    className ::~ className() { }					\
    const OSMetaClass * className ::getMetaClass() const		\
        { return &gMetaClass; }						\
    /* The ::MetaClass constructor */					\
    className ::MetaClass::MetaClass()					\
        : OSMetaClass(#className, className::superClass, sizeof(className)) \
        { init; }

/*! @function OSDefineAbstractStructors
    @abstract Basic helper macro for the OSDefineMetaClass for the default and Abstract macros, qv.  DO NOT USE.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS. */
#define OSDefineAbstractStructors(className, superClassName)		\
    OSObject * className ::MetaClass::alloc() const { return 0; }

/*! @function OSDefineDefaultStructors
    @abstract Basic helper macro for the OSDefineMetaClass for the default and Abstract macros, qv.  DO NOT USE.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS. */
#define OSDefineDefaultStructors(className, superClassName)		\
    OSObject * className ::MetaClass::alloc() const			\
	{ return new className; }					\
    className :: className () : superClassName (&gMetaClass)		\
	{ gMetaClass.instanceConstructed(); }


/*! @function OSDefineMetaClassAndAbstractStructorsWithInit
    @abstract Primary definition macro for all abstract classes that a subclasses of OSObject.
    @discussion Define an OSMetaClass subclass and the primary constructors and destructors for a subclass of OSObject that is an abstract class.  In general this 'function' is 'called' at the top of the file just before the first function is implemented for a particular class.  Once the OSMetaClass has been constructed, at load time, call the init routine.  NB you can not rely on the order of execution of the init routines.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS.
    @param init Name of a function to call after the OSMetaClass is constructed. */
#define OSDefineMetaClassAndAbstractStructorsWithInit(className, superClassName, init) \
    OSDefineMetaClassWithInit(className, superClassName, init)		\
    OSDefineAbstractStructors(className, superClassName)

/*! @function OSDefineMetaClassAndStructorsWithInit
    @abstract See OSDefineMetaClassAndStructors
    @discussion Define an OSMetaClass subclass and the primary constructors and destructors for a subclass of OSObject that isn't an abstract class.  In general this 'function' is 'called' at the top of the file just before the first function is implemented for a particular class.  Once the OSMetaClass has been constructed, at load time, call the init routine.  NB you can not rely on the order of execution of the init routines.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS.
    @param init Name of a function to call after the OSMetaClass is constructed. */
#define OSDefineMetaClassAndStructorsWithInit(className, superClassName, init) \
    OSDefineMetaClassWithInit(className, superClassName, init)		\
    OSDefineDefaultStructors(className, superClassName)

/* Helpers */
/*! @function OSDefineMetaClass
    @abstract Define an OSMetaClass instance, used for backward compatiblility only.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS. */
#define OSDefineMetaClass(className, superClassName)			\
    OSDefineMetaClassWithInit(className, superClassName, )

/*! @function OSDefineMetaClassAndStructors
    @abstract Define an OSMetaClass subclass and the runtime system routines.
    @discussion Define an OSMetaClass subclass and the primary constructors and destructors for a subclass of OSObject that isn't an abstract class.  In general this 'function' is 'called' at the top of the file just before the first function is implemented for a particular class.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS. */
#define OSDefineMetaClassAndStructors(className, superClassName)	\
    OSDefineMetaClassAndStructorsWithInit(className, superClassName, )

/*! @function OSDefineMetaClassAndAbstractStructors
    @abstract Define an OSMetaClass subclass and the runtime system routines.
    @discussion Define an OSMetaClass subclass and the primary constructors and destructors for a subclass of OSObject that is an abstract class.  In general this 'function' is 'called' at the top of the file just before the first function is implemented for a particular class.
    @param className Name of class. NO QUOTES and NO MACROS.
    @param superClassName Name of super class. NO QUOTES and NO MACROS. */
#define OSDefineMetaClassAndAbstractStructors(className, superClassName) \
    OSDefineMetaClassAndAbstractStructorsWithInit (className, superClassName, )

    // Dynamic vtable patchup support routines and types
    void reservedCalled(int ind) const;

#define OSMetaClassDeclareReservedUnused(classname, index)		\
    private:								\
        virtual void _RESERVED ## classname ## index ()

#define OSMetaClassDeclareReservedUsed(classname, index)

#define OSMetaClassDefineReservedUnused(classname, index)		\
void classname ::_RESERVED ## classname ## index () 			\
    { gMetaClass.reservedCalled(index); }

#define OSMetaClassDefineReservedUsed(classname, index)

    // IOKit debug internal routines.
    static void printInstanceCounts();
    static void serializeClassDictionary(OSDictionary *dict);

private:
    // Obsolete APIs
    static OSDictionary *getClassDictionary();
    virtual bool serialize(OSSerialize *s) const;

    // Virtual Padding functions for MetaClass's
    OSMetaClassDeclareReservedUnused(OSMetaClass, 0);
    OSMetaClassDeclareReservedUnused(OSMetaClass, 1);
    OSMetaClassDeclareReservedUnused(OSMetaClass, 2);
    OSMetaClassDeclareReservedUnused(OSMetaClass, 3);
    OSMetaClassDeclareReservedUnused(OSMetaClass, 4);
    OSMetaClassDeclareReservedUnused(OSMetaClass, 5);
    OSMetaClassDeclareReservedUnused(OSMetaClass, 6);
    OSMetaClassDeclareReservedUnused(OSMetaClass, 7);
};

#endif /* !_LIBKERN_OSMETACLASS_H */
