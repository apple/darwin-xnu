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
 * See the SystemKEXT project for fuller information on these
 * fake or pseudo-kexts, including their compatible versions.
 */
const char * gIOKernelKmods =
"{
    'com.apple.kernel'                         = '6.0';
    'com.apple.kernel.bsd'                     = '6.0';
    'com.apple.kernel.iokit'                   = '6.0';
    'com.apple.kernel.libkern'                 = '6.0';
    'com.apple.kernel.mach'                    = '6.0';
    'com.apple.iokit.IOADBFamily'              = '1.1';
    'com.apple.iokit.IONVRAMFamily'            = '1.1';
    'com.apple.iokit.IOSystemManagementFamily' = '1.1';
    'com.apple.iokit.ApplePlatformFamily'      = '1.0';
    'com.apple.driver.AppleNMI'                = '1.0';
}";


const char * gIOKernelConfigTables =
"(
    {
      'IOClass'         = IOPanicPlatform;
      'IOProviderClass' = IOPlatformExpertDevice;
      'IOProbeScore'    = '-1';
    }
"
#ifdef PPC
"   ,
    {
	'IOClass'		= AppleCPU;
	'IOProviderClass'	= IOPlatformDevice;
        'IONameMatch'		= 'cpu';
	'IOProbeScore'		= 100:32;
    },
    {
        'IOClass'              = AppleNMI;
        'IOProviderClass'      = AppleMacIODevice;
        'IONameMatch'          = 'programmer-switch';
    },
    {
        'IOClass'		= AppleNVRAM;
        'IOProviderClass'	= AppleMacIODevice;
        'IONameMatch'		= nvram;
    }, 
    {   
        'IOClass'               = IOPMUADBController;
        'IOProviderClass'       = AppleMacIODevice;
        'IONameMatch'           = adb;
    }
"
#endif /* PPC */
#ifdef i386
"   ,
    {
       'IOClass'           = AppleI386PlatformExpert;
       'IOProviderClass'   = IOPlatformExpertDevice;
       'top-level'         = "
    /* set of dicts to make into nubs */
    "[
       { IOName = cpu; },
       { IOName = intel-pic; },
       { IOName = intel-clock; }, 
       { IOName = ps2controller; },
       { IOName = pci; },
       { IOName = display; 'AAPL,boot-display' = Yes; }
    ];
    },
    {
       'IOClass'           = AppleI386CPU;
       'IOProviderClass'   = IOPlatformDevice;
       'IONameMatch'       = cpu;
       'IOProbeScore'      = 100:32;
    },
    {
       'IOClass'           = AppleIntelClassicPIC;
       'IOProviderClass'   = IOPlatformDevice;
       'IONameMatch'       = intel-pic;
    },
    {
       'IOClass'           = AppleIntelClock;
       'IOProviderClass'   = IOPlatformDevice;
       'IONameMatch'       = intel-clock;
    }
"
#endif /* i386 */
")";

