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
 * AppleBPF.cpp - BPF driver class implementation.
 *
 */

// Need to check with Simon on User/Client interface and how to do
// PostLoad, and check on IOBSD (IONeededResource)

#include <assert.h>
#include <IOKit/IOLib.h>
#include "AppleBPF.h"

extern "C" {
#include <sys/time.h>
#include <net/bpf.h>
#include <net/bpfdesc.h>
#include <sys/malloc.h>
}

//------------------------------------------------------------------------

#define super IOService
OSDefineMetaClassAndStructors(AppleBPF, IOService);

//------------------------------------------------------------------------


// -----------------------------------------------------------------------
//
// This is the first method to be called when an object of this class is 
// instantiated.
// 
bool AppleBPF::init(OSDictionary * properties)
{
	if (!super::init(properties))
	{	IOLog("BPF: super init failed\n");
		return false;
	}
	
	// Do class specific initialization here. Probably not necessary for
	// this driver.

//	IOLog("BPF: super init succeeded\n");
	return true;	// return 'true' for success, 'false' for failure.
}

// -----------------------------------------------------------------------
//
// The driver has been matched, start it up. Do most initialization and
// resource allocation here.
//
bool AppleBPF::start(IOService * provider)
{	int i;
	OSNumber *val;
	extern struct bpf_d     *bpf_dtab;
	extern int nbpfilter;

	if (!super::start(provider))
	{	IOLog("BPF: super start failed\n");
		return false;
	}

	val = OSDynamicCast(OSNumber, getObject("IODevCount"));
	if (val == 0)
		nbpfilter = DEFAULT_BPF_DEV_COUNT;
	else
		nbpfilter = val->unsigned32BitValue();

//	bpfops.bpf_tap = bpf_tap;
//	bpfops.bpf_mtap = bpf_mtap;

	bpf_dtab = (struct bpf_d *)IOMalloc(sizeof (struct bpf_d) * nbpfilter);
	if (bpf_dtab == NULL)
	{	IOLog("%s: couldn't get memory for descriptor table\n",
		      getName());
		return false;
	}

	/*
	 * Mark all the descriptors free
	 */
	for (i = 0; i < nbpfilter; ++i)
	    D_MARKFREE(&bpf_dtab[i]);

//	IOLog("AppleBPF::start() called\n");

	return true;	// return 'true' for success, 'false' for failure.
}

// -----------------------------------------------------------------------
//
// Release all resources before the driver goes away.
//
void AppleBPF::stop(IOService * provider)
{	extern struct bpf_d     *bpf_dtab;
	extern int nbpfilter;
 
	IOFree((void *)bpf_dtab, sizeof (struct bpf_d) * nbpfilter);
}
