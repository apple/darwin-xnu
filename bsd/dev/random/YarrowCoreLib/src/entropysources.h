/*
 * Copyright (c) 1999, 2000-2001 Apple Computer, Inc. All rights reserved.
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

/* entropysources.h */
/* This files contain the defination of the entropy sources */

#ifndef __YARROW_ENTROPY_SOURCES_H__
#define __YARROW_ENTROPY_SOURCES_H__

#if		defined(macintosh) || defined(__APPLE__)
/* 
 * In our implementation, all sources are user sources.
 */
enum entropy_sources {
	ENTROPY_SOURCES = 0
};
#else
enum entropy_sources {
	KEYTIMESOURCE = 0,
	MOUSETIMESOURCE,
	MOUSEMOVESOURCE,
	SLOWPOLLSOURCE,
	ENTROPY_SOURCES,	/* Leave as second to last source */
	MSG_CLOSE_PIPE		/* Leave as last source */
};
#endif

#endif
