/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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


/* This list is used in IOStartIOKit.cpp to declare fake kmod_info
 * structs for kext dependencies that are built into the kernel.
 */
const char * gIOKernelKmods =
"{"
"   'com.apple.kernel'                         = '7.2';"
"   'com.apple.kpi.bsd'                        = '7.2';"
"   'com.apple.kpi.iokit'                      = '7.2';"
"   'com.apple.kpi.libkern'                    = '7.2';"
"   'com.apple.kpi.mach'                       = '7.2';"
"   'com.apple.iokit.IONVRAMFamily'            = '7.2';"
"   'com.apple.driver.AppleNMI'                = '7.2';"
"   'com.apple.iokit.IOSystemManagementFamily' = '7.2';"
"   'com.apple.iokit.ApplePlatformFamily'      = '7.2';"
"   'com.apple.kernel.6.0'                     = '6.9.9';"
"   'com.apple.kernel.bsd'                     = '6.9.9';"
"   'com.apple.kernel.iokit'                   = '6.9.9';"
"   'com.apple.kernel.libkern'                 = '6.9.9';"
"   'com.apple.kernel.mach'                    = '6.9.9';"
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
#ifdef i386
"   ,"
"   {"
"       'IOClass'           = AppleIntelClock;"
"       'IOProviderClass'   = IOPlatformDevice;"
"       'IONameMatch'       = intel-clock;"
"   }"
#endif /* i386 */
")";

