/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* IOArray.h created by rsulack on Thu 11-Sep-1997 */

#include <libkern/c++/OSCollectionIterator.h>
#include <libkern/c++/OSCollection.h>
#include <libkern/c++/OSArray.h>
#include <libkern/c++/OSLib.h>

#define super OSIterator

OSDefineMetaClassAndStructors(OSCollectionIterator, OSIterator)

bool
OSCollectionIterator::initWithCollection(const OSCollection *inColl)
{
	if (!super::init() || !inColl) {
		return false;
	}

	inColl->retain();
	collection = inColl;
	collIterator = NULL;
	initialUpdateStamp = 0;
	valid = false;

	return true;
}

OSCollectionIterator *
OSCollectionIterator::withCollection(const OSCollection *inColl)
{
	OSCollectionIterator *me = new OSCollectionIterator;

	if (me && !me->initWithCollection(inColl)) {
		me->release();
		return NULL;
	}

	return me;
}

void
OSCollectionIterator::free()
{
	if (collIterator) {
		kfree(collIterator, collection->iteratorSize());
		OSCONTAINER_ACCUMSIZE(-((size_t) collection->iteratorSize()));
		collIterator = NULL;
	}

	if (collection) {
		collection->release();
		collection = NULL;
	}

	super::free();
}

void
OSCollectionIterator::reset()
{
	valid = false;

	if (!collIterator) {
		collIterator = (void *)kalloc_container(collection->iteratorSize());
		OSCONTAINER_ACCUMSIZE(collection->iteratorSize());
		if (!collIterator) {
			return;
		}
	}

	if (!collection->initIterator(collIterator)) {
		return;
	}

	initialUpdateStamp = collection->updateStamp;
	valid = true;
}

bool
OSCollectionIterator::isValid()
{
	if (!collIterator) {
		collIterator = (void *)kalloc_container(collection->iteratorSize());
		OSCONTAINER_ACCUMSIZE(collection->iteratorSize());
		if (!collection->initIterator(collIterator)) {
			return false;
		}
		initialUpdateStamp = collection->updateStamp;
		valid = true;
	} else if (!valid || collection->updateStamp != initialUpdateStamp) {
		return false;
	}

	return true;
}

OSObject *
OSCollectionIterator::getNextObject()
{
	OSObject *retObj;
	bool retVal;

	if (!isValid()) {
		return NULL;
	}

	retVal = collection->getNextObjectForIterator(collIterator, &retObj);
	return (retVal)? retObj : NULL;
}
