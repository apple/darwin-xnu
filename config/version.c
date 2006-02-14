/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
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

/* version.c
 * This file is a C source template for version.c, which is generated
 * on every make of xnu.  This template is processed by the script
 * xnu/config/newvers.pl based on the version information in the file
 * xnu/config/MasterVersion.
 */

#include <libkern/version.h>

const char version[] = OSTYPE " Kernel Version ###KERNEL_VERSION_LONG###: ###KERNEL_BUILD_DATE###; ###KERNEL_BUILDER###:###KERNEL_BUILD_OBJROOT###";
const int  version_major = VERSION_MAJOR;
const int  version_minor = VERSION_MINOR;
const int  version_revision = VERSION_REVISION;
const int  version_stage = VERSION_STAGE;
const int  version_prerelease_level = VERSION_PRERELEASE_LEVEL;
const char version_variant[] = VERSION_VARIANT;
const char osbuilder[] = "###KERNEL_BUILDER###";
const char osrelease[] = OSRELEASE;
const char ostype[] = OSTYPE;

