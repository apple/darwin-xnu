/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#include "kpi_interfacefilter.h"

#include <sys/malloc.h>
#include <sys/param.h>
#include <sys/socket.h>
#include <sys/kern_event.h>
#include <net/dlil.h>

errno_t
iflt_attach(
	ifnet_t interface,
	const struct iff_filter *filter,
	interface_filter_t *filter_ref)
{
	if (interface == NULL) return ENOENT;
		
	return dlil_attach_filter(interface, filter, filter_ref);
}

void
iflt_detach(
	interface_filter_t filter_ref)
{
	dlil_detach_filter(filter_ref);
}
