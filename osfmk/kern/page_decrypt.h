/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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

#ifndef _KERN_PAGE_DECRYPT_H
#define _KERN_PAGE_DECRYPT_H

typedef	int	  (*dsmos_page_transform_hook_t) (const void*,void*);
extern	void	dsmos_page_transform_hook(dsmos_page_transform_hook_t hook,
					  void (*commpage_setup_dsmos_blob)(void**, int));	/* exported */

extern	int		dsmos_page_transform(const void*,void*);

#endif	/* _KERN_PAGE_DECRYPT_H */
