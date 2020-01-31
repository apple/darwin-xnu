/*
 * runtime.c
 * libclosure
 *
 * Copyright (c) 2008-2010 Apple Inc. All rights reserved.
 *
 * @APPLE_LLVM_LICENSE_HEADER@
 */


#ifndef KERNEL

#include "Block_private.h"
#include <stdio.h>
#include <stdlib.h>
#include <dlfcn.h>
#include <os/assumes.h>

#else /* !KERNEL */

#include <libkern/Block_private.h>
#include <libkern/OSRuntime.h>

#define malloc(s)  kern_os_malloc((s))
#define free(a)    kern_os_free((a))

#endif /* KERNEL */

#include <string.h>
#include <stdint.h>
#ifndef os_assumes
#define os_assumes(_x) (_x)
#endif
#ifndef os_assert
#define os_assert(_x) assert(_x)
#endif

#if TARGET_OS_WIN32
#define _CRT_SECURE_NO_WARNINGS 1
#include <windows.h>
static __inline bool
OSAtomicCompareAndSwapLong(long oldl, long newl, long volatile *dst)
{
	// fixme barrier is overkill -- see objc-os.h
	long original = InterlockedCompareExchange(dst, newl, oldl);
	return original == oldl;
}

static __inline bool
OSAtomicCompareAndSwapInt(int oldi, int newi, int volatile *dst)
{
	// fixme barrier is overkill -- see objc-os.h
	int original = InterlockedCompareExchange(dst, newi, oldi);
	return original == oldi;
}
#else
#define OSAtomicCompareAndSwapLong(_Old, _New, _Ptr) __sync_bool_compare_and_swap(_Ptr, _Old, _New)
#define OSAtomicCompareAndSwapInt(_Old, _New, _Ptr) __sync_bool_compare_and_swap(_Ptr, _Old, _New)
#endif


/*******************************************************************************
 *  Internal Utilities
 ********************************************************************************/

static int32_t
latching_incr_int(volatile int32_t *where)
{
	while (1) {
		int32_t old_value = *where;
		if ((old_value & BLOCK_REFCOUNT_MASK) == BLOCK_REFCOUNT_MASK) {
			return BLOCK_REFCOUNT_MASK;
		}
		if (OSAtomicCompareAndSwapInt(old_value, old_value + 2, where)) {
			return old_value + 2;
		}
	}
}

static bool
latching_incr_int_not_deallocating(volatile int32_t *where)
{
	while (1) {
		int32_t old_value = *where;
		if (old_value & BLOCK_DEALLOCATING) {
			// if deallocating we can't do this
			return false;
		}
		if ((old_value & BLOCK_REFCOUNT_MASK) == BLOCK_REFCOUNT_MASK) {
			// if latched, we're leaking this block, and we succeed
			return true;
		}
		if (OSAtomicCompareAndSwapInt(old_value, old_value + 2, where)) {
			// otherwise, we must store a new retained value without the deallocating bit set
			return true;
		}
	}
}


// return should_deallocate?
static bool
latching_decr_int_should_deallocate(volatile int32_t *where)
{
	while (1) {
		int32_t old_value = *where;
		if ((old_value & BLOCK_REFCOUNT_MASK) == BLOCK_REFCOUNT_MASK) {
			return false; // latched high
		}
		if ((old_value & BLOCK_REFCOUNT_MASK) == 0) {
			return false; // underflow, latch low
		}
		int32_t new_value = old_value - 2;
		bool result = false;
		if ((old_value & (BLOCK_REFCOUNT_MASK | BLOCK_DEALLOCATING)) == 2) {
			new_value = old_value - 1;
			result = true;
		}
		if (OSAtomicCompareAndSwapInt(old_value, new_value, where)) {
			return result;
		}
	}
}


/**************************************************************************
 *  Framework callback functions and their default implementations.
 ***************************************************************************/
#if !TARGET_OS_WIN32
#pragma mark Framework Callback Routines
#endif

static void
_Block_retain_object_default(const void *ptr __unused)
{
}

static void
_Block_release_object_default(const void *ptr __unused)
{
}

static void
_Block_destructInstance_default(const void *aBlock __unused)
{
}

static void (*_Block_retain_object)(const void *ptr) = _Block_retain_object_default;
static void (*_Block_release_object)(const void *ptr) = _Block_release_object_default;
static void (*_Block_destructInstance) (const void *aBlock) = _Block_destructInstance_default;


/**************************************************************************
 *  Callback registration from ObjC runtime and CoreFoundation
 ***************************************************************************/

void
_Block_use_RR2(const Block_callbacks_RR *callbacks)
{
	_Block_retain_object = callbacks->retain;
	_Block_release_object = callbacks->release;
	_Block_destructInstance = callbacks->destructInstance;
}

/****************************************************************************
 *  Accessors for block descriptor fields
 *****************************************************************************/
#if 0
static struct Block_descriptor_1 *
_Block_descriptor_1(struct Block_layout *aBlock)
{
	return aBlock->descriptor;
}
#endif

static struct Block_descriptor_2 *
_Block_descriptor_2(struct Block_layout *aBlock)
{
	if (!(aBlock->flags & BLOCK_HAS_COPY_DISPOSE)) {
		return NULL;
	}
	uint8_t *desc = (uint8_t *)aBlock->descriptor;
	desc += sizeof(struct Block_descriptor_1);
	return __IGNORE_WCASTALIGN((struct Block_descriptor_2 *)desc);
}

static struct Block_descriptor_3 *
_Block_descriptor_3(struct Block_layout *aBlock)
{
	if (!(aBlock->flags & BLOCK_HAS_SIGNATURE)) {
		return NULL;
	}
	uint8_t *desc = (uint8_t *)aBlock->descriptor;
	desc += sizeof(struct Block_descriptor_1);
	if (aBlock->flags & BLOCK_HAS_COPY_DISPOSE) {
		desc += sizeof(struct Block_descriptor_2);
	}
	return __IGNORE_WCASTALIGN((struct Block_descriptor_3 *)desc);
}

static void
_Block_call_copy_helper(void *result, struct Block_layout *aBlock)
{
	struct Block_descriptor_2 *desc = _Block_descriptor_2(aBlock);
	if (!desc) {
		return;
	}

	(*desc->copy)(result, aBlock); // do fixup
}

static void
_Block_call_dispose_helper(struct Block_layout *aBlock)
{
	struct Block_descriptor_2 *desc = _Block_descriptor_2(aBlock);
	if (!desc) {
		return;
	}

	(*desc->dispose)(aBlock);
}

/*******************************************************************************
 *  Internal Support routines for copying
 ********************************************************************************/

#if !TARGET_OS_WIN32
#pragma mark Copy/Release support
#endif

// Copy, or bump refcount, of a block.  If really copying, call the copy helper if present.
void *
_Block_copy(const void *arg)
{
	struct Block_layout *aBlock;

	if (!arg) {
		return NULL;
	}

	// The following would be better done as a switch statement
	aBlock = (struct Block_layout *)arg;
	if (aBlock->flags & BLOCK_NEEDS_FREE) {
		// latches on high
		latching_incr_int(&aBlock->flags);
		return aBlock;
	} else if (aBlock->flags & BLOCK_IS_GLOBAL) {
		return aBlock;
	} else {
		// Its a stack block.  Make a copy.
		struct Block_layout *result = (typeof(result))malloc(aBlock->descriptor->size);
		if (!result) {
			return NULL;
		}
		memmove(result, aBlock, aBlock->descriptor->size); // bitcopy first
#if __has_feature(ptrauth_calls)
		// Resign the invoke pointer as it uses address authentication.
		result->invoke = aBlock->invoke;
#endif
		// reset refcount
		result->flags &= ~(BLOCK_REFCOUNT_MASK | BLOCK_DEALLOCATING); // XXX not needed
		result->flags |= BLOCK_NEEDS_FREE | 2; // logical refcount 1
		_Block_call_copy_helper(result, aBlock);
		// Set isa last so memory analysis tools see a fully-initialized object.
		result->isa = _NSConcreteMallocBlock;
		return result;
	}
}


// Runtime entry points for maintaining the sharing knowledge of byref data blocks.

// A closure has been copied and its fixup routine is asking us to fix up the reference to the shared byref data
// Closures that aren't copied must still work, so everyone always accesses variables after dereferencing the forwarding ptr.
// We ask if the byref pointer that we know about has already been copied to the heap, and if so, increment and return it.
// Otherwise we need to copy it and update the stack forwarding pointer
static struct Block_byref *
_Block_byref_copy(const void *arg)
{
	struct Block_byref *src = (struct Block_byref *)arg;

	if ((src->forwarding->flags & BLOCK_REFCOUNT_MASK) == 0) {
		// src points to stack
		struct Block_byref *copy = (struct Block_byref *)malloc(src->size);
		copy->isa = NULL;
		// byref value 4 is logical refcount of 2: one for caller, one for stack
		copy->flags = src->flags | BLOCK_BYREF_NEEDS_FREE | 4;
		copy->forwarding = copy; // patch heap copy to point to itself
		src->forwarding = copy; // patch stack to point to heap copy
		copy->size = src->size;

		if (src->flags & BLOCK_BYREF_HAS_COPY_DISPOSE) {
			// Trust copy helper to copy everything of interest
			// If more than one field shows up in a byref block this is wrong XXX
			struct Block_byref_2 *src2 = (struct Block_byref_2 *)(src + 1);
			struct Block_byref_2 *copy2 = (struct Block_byref_2 *)(copy + 1);
			copy2->byref_keep = src2->byref_keep;
			copy2->byref_destroy = src2->byref_destroy;

			if (src->flags & BLOCK_BYREF_LAYOUT_EXTENDED) {
				struct Block_byref_3 *src3 = (struct Block_byref_3 *)(src2 + 1);
				struct Block_byref_3 *copy3 = (struct Block_byref_3*)(copy2 + 1);
				copy3->layout = src3->layout;
			}

			(*src2->byref_keep)(copy, src);
		} else {
			// Bitwise copy.
			// This copy includes Block_byref_3, if any.
			memmove(copy + 1, src + 1, src->size - sizeof(*src));
		}
	}
	// already copied to heap
	else if ((src->forwarding->flags & BLOCK_BYREF_NEEDS_FREE) == BLOCK_BYREF_NEEDS_FREE) {
		latching_incr_int(&src->forwarding->flags);
	}

	return src->forwarding;
}

static void
_Block_byref_release(const void *arg)
{
	struct Block_byref *byref = (struct Block_byref *)arg;

	// dereference the forwarding pointer since the compiler isn't doing this anymore (ever?)
	byref = byref->forwarding;

	if (byref->flags & BLOCK_BYREF_NEEDS_FREE) {
		__assert_only int32_t refcount = byref->flags & BLOCK_REFCOUNT_MASK;
		os_assert(refcount);
		if (latching_decr_int_should_deallocate(&byref->flags)) {
			if (byref->flags & BLOCK_BYREF_HAS_COPY_DISPOSE) {
				struct Block_byref_2 *byref2 = (struct Block_byref_2 *)(byref + 1);
				(*byref2->byref_destroy)(byref);
			}
			free(byref);
		}
	}
}


/************************************************************
 *
 * API supporting SPI
 * _Block_copy, _Block_release, and (old) _Block_destroy
 *
 ***********************************************************/

#if !TARGET_OS_WIN32
#pragma mark SPI/API
#endif


// API entry point to release a copied Block
void
_Block_release(const void *arg)
{
	struct Block_layout *aBlock = (struct Block_layout *)arg;
	if (!aBlock) {
		return;
	}
	if (aBlock->flags & BLOCK_IS_GLOBAL) {
		return;
	}
	if (!(aBlock->flags & BLOCK_NEEDS_FREE)) {
		return;
	}

	if (latching_decr_int_should_deallocate(&aBlock->flags)) {
		_Block_call_dispose_helper(aBlock);
		_Block_destructInstance(aBlock);
		free(aBlock);
	}
}

bool
_Block_tryRetain(const void *arg)
{
	struct Block_layout *aBlock = (struct Block_layout *)arg;
	return latching_incr_int_not_deallocating(&aBlock->flags);
}

bool
_Block_isDeallocating(const void *arg)
{
	struct Block_layout *aBlock = (struct Block_layout *)arg;
	return (aBlock->flags & BLOCK_DEALLOCATING) != 0;
}


/************************************************************
 *
 * SPI used by other layers
 *
 ***********************************************************/

size_t
Block_size(void *aBlock)
{
	return ((struct Block_layout *)aBlock)->descriptor->size;
}

bool
_Block_use_stret(void *aBlock)
{
	struct Block_layout *layout = (struct Block_layout *)aBlock;

	int requiredFlags = BLOCK_HAS_SIGNATURE | BLOCK_USE_STRET;
	return (layout->flags & requiredFlags) == requiredFlags;
}

// Checks for a valid signature, not merely the BLOCK_HAS_SIGNATURE bit.
bool
_Block_has_signature(void *aBlock)
{
	return _Block_signature(aBlock) ? true : false;
}

const char *
_Block_signature(void *aBlock)
{
	struct Block_descriptor_3 *desc3 = _Block_descriptor_3((struct Block_layout *)aBlock);
	if (!desc3) {
		return NULL;
	}

	return desc3->signature;
}

const char *
_Block_layout(void *aBlock)
{
	// Don't return extended layout to callers expecting old GC layout
	struct Block_layout *layout = (struct Block_layout *)aBlock;
	if (layout->flags & BLOCK_HAS_EXTENDED_LAYOUT) {
		return NULL;
	}

	struct Block_descriptor_3 *desc3 = _Block_descriptor_3((struct Block_layout *)aBlock);
	if (!desc3) {
		return NULL;
	}

	return desc3->layout;
}

const char *
_Block_extended_layout(void *aBlock)
{
	// Don't return old GC layout to callers expecting extended layout
	struct Block_layout *layout = (struct Block_layout *)aBlock;
	if (!(layout->flags & BLOCK_HAS_EXTENDED_LAYOUT)) {
		return NULL;
	}

	struct Block_descriptor_3 *desc3 = _Block_descriptor_3((struct Block_layout *)aBlock);
	if (!desc3) {
		return NULL;
	}

	// Return empty string (all non-object bytes) instead of NULL
	// so callers can distinguish "empty layout" from "no layout".
	if (!desc3->layout) {
		return "";
	} else {
		return desc3->layout;
	}
}

#if !TARGET_OS_WIN32
#pragma mark Compiler SPI entry points
#endif


/*******************************************************
 *
 *  Entry points used by the compiler - the real API!
 *
 *
 *  A Block can reference four different kinds of things that require help when the Block is copied to the heap.
 *  1) C++ stack based objects
 *  2) References to Objective-C objects
 *  3) Other Blocks
 *  4) __block variables
 *
 *  In these cases helper functions are synthesized by the compiler for use in Block_copy and Block_release, called the copy and dispose helpers.  The copy helper emits a call to the C++ const copy constructor for C++ stack based objects and for the rest calls into the runtime support function _Block_object_assign.  The dispose helper has a call to the C++ destructor for case 1 and a call into _Block_object_dispose for the rest.
 *
 *  The flags parameter of _Block_object_assign and _Block_object_dispose is set to
 * BLOCK_FIELD_IS_OBJECT (3), for the case of an Objective-C Object,
 * BLOCK_FIELD_IS_BLOCK (7), for the case of another Block, and
 * BLOCK_FIELD_IS_BYREF (8), for the case of a __block variable.
 *  If the __block variable is marked weak the compiler also or's in BLOCK_FIELD_IS_WEAK (16)
 *
 *  So the Block copy/dispose helpers should only ever generate the four flag values of 3, 7, 8, and 24.
 *
 *  When  a __block variable is either a C++ object, an Objective-C object, or another Block then the compiler also generates copy/dispose helper functions.  Similarly to the Block copy helper, the "__block" copy helper (formerly and still a.k.a. "byref" copy helper) will do a C++ copy constructor (not a const one though!) and the dispose helper will do the destructor.  And similarly the helpers will call into the same two support functions with the same values for objects and Blocks with the additional BLOCK_BYREF_CALLER (128) bit of information supplied.
 *
 *  So the __block copy/dispose helpers will generate flag values of 3 or 7 for objects and Blocks respectively, with BLOCK_FIELD_IS_WEAK (16) or'ed as appropriate and always 128 or'd in, for the following set of possibilities:
 *   __block id                   128+3       (0x83)
 *   __block (^Block)             128+7       (0x87)
 *   __weak __block id            128+3+16    (0x93)
 *   __weak __block (^Block)      128+7+16    (0x97)
 *
 *
 ********************************************************/

//
// When Blocks or Block_byrefs hold objects then their copy routine helpers use this entry point
// to do the assignment.
//
void
_Block_object_assign(void *destArg, const void *object, const int flags)
{
	const void **dest = (const void **)destArg;
	switch (os_assumes(flags & BLOCK_ALL_COPY_DISPOSE_FLAGS)) {
	case BLOCK_FIELD_IS_OBJECT:
		/*******
		 *  id object = ...;
		 *  [^{ object; } copy];
		 ********/

		_Block_retain_object(object);
		*dest = object;
		break;

	case BLOCK_FIELD_IS_BLOCK:
		/*******
		 *  void (^object)(void) = ...;
		 *  [^{ object; } copy];
		 ********/

		*dest = _Block_copy(object);
		break;

	case BLOCK_FIELD_IS_BYREF | BLOCK_FIELD_IS_WEAK:
	case BLOCK_FIELD_IS_BYREF:
		/*******
		 *  // copy the onstack __block container to the heap
		 *  // Note this __weak is old GC-weak/MRC-unretained.
		 *  // ARC-style __weak is handled by the copy helper directly.
		 *  __block ... x;
		 *  __weak __block ... x;
		 *  [^{ x; } copy];
		 ********/

		*dest = _Block_byref_copy(object);
		break;

	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_OBJECT:
	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_BLOCK:
		/*******
		 *  // copy the actual field held in the __block container
		 *  // Note this is MRC unretained __block only.
		 *  // ARC retained __block is handled by the copy helper directly.
		 *  __block id object;
		 *  __block void (^object)(void);
		 *  [^{ object; } copy];
		 ********/

		*dest = object;
		break;

	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_OBJECT | BLOCK_FIELD_IS_WEAK:
	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_BLOCK  | BLOCK_FIELD_IS_WEAK:
		/*******
		 *  // copy the actual field held in the __block container
		 *  // Note this __weak is old GC-weak/MRC-unretained.
		 *  // ARC-style __weak is handled by the copy helper directly.
		 *  __weak __block id object;
		 *  __weak __block void (^object)(void);
		 *  [^{ object; } copy];
		 ********/

		*dest = object;
		break;

	default:
		break;
	}
}

// When Blocks or Block_byrefs hold objects their destroy helper routines call this entry point
// to help dispose of the contents
void
_Block_object_dispose(const void *object, const int flags)
{
	switch (os_assumes(flags & BLOCK_ALL_COPY_DISPOSE_FLAGS)) {
	case BLOCK_FIELD_IS_BYREF | BLOCK_FIELD_IS_WEAK:
	case BLOCK_FIELD_IS_BYREF:
		// get rid of the __block data structure held in a Block
		_Block_byref_release(object);
		break;
	case BLOCK_FIELD_IS_BLOCK:
		_Block_release(object);
		break;
	case BLOCK_FIELD_IS_OBJECT:
		_Block_release_object(object);
		break;
	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_OBJECT:
	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_BLOCK:
	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_OBJECT | BLOCK_FIELD_IS_WEAK:
	case BLOCK_BYREF_CALLER | BLOCK_FIELD_IS_BLOCK  | BLOCK_FIELD_IS_WEAK:
		break;
	default:
		break;
	}
}


// Workaround for <rdar://26015603> dylib with no __DATA segment fails to rebase
__attribute__((used))
static int let_there_be_data = 42;

#undef malloc
#undef free
