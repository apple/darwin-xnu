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


/* This list is used in IOStartIOKit.cpp to declare fake kmod_info
 * structs for kext dependencies that are built into the kernel.
 * Empty version strings get replaced with osrelease at runtime.
 */
const char * gIOKernelKmods =
"{"
   "'com.apple.kernel'                         = '';"
   "'com.apple.kpi.bsd'                        = '';"
   "'com.apple.kpi.iokit'                      = '';"
   "'com.apple.kpi.libkern'                    = '';"
   "'com.apple.kpi.mach'                       = '';"
   "'com.apple.kpi.unsupported'                = '';"
   "'com.apple.iokit.IONVRAMFamily'            = '';"
   "'com.apple.driver.AppleNMI'                = '';"
   "'com.apple.iokit.IOSystemManagementFamily' = '';"
   "'com.apple.iokit.ApplePlatformFamily'      = '';"
   "'com.apple.kernel.6.0'                     = '7.9.9';"
   "'com.apple.kernel.bsd'                     = '7.9.9';"
   "'com.apple.kernel.iokit'                   = '7.9.9';"
   "'com.apple.kernel.libkern'                 = '7.9.9';"
   "'com.apple.kernel.mach'                    = '7.9.9';"
"}";


const char * gIOKernelConfigTables =
"("
"   {"
"     'IOClass'         = IOPanicPlatform;"
"     'IOProviderClass' = IOPlatformExpertDevice;"
"     'IOProbeScore'    = '-1';"
"   }"
#ifdef PPC
"   ,"
"   {"
"       'IOClass'               = AppleCPU;"
"       'IOProviderClass'       = IOPlatformDevice;"
"       'IONameMatch'           = 'cpu';"
"       'IOProbeScore'          = 100:32;"
"   },"
"   {"
"       'IOClass'              = AppleNMI;"
"       'IOProviderClass'      = AppleMacIODevice;"
"       'IONameMatch'          = 'programmer-switch';"
"   },"
"   {"
"       'IOClass'               = AppleNVRAM;"
"       'IOProviderClass'       = AppleMacIODevice;"
"       'IONameMatch'           = nvram;"
"   }"
#endif /* PPC */
")";

