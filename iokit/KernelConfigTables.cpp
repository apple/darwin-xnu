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
    'com.apple.kernel'                         = '5.4';
    'com.apple.kernel.bsd'                     = '5.4';
    'com.apple.kernel.iokit'                   = '5.4';
    'com.apple.kernel.libkern'                 = '5.4';
    'com.apple.kernel.mach'                    = '5.4';
    'com.apple.iokit.IOADBFamily'              = '1.1';
    'com.apple.iokit.IOSystemManagementFamily' = '1.1';
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
"
#if 0
"
    {
        'IOClass'		= PowerSurgePE;
        'IOProviderClass'	= IOPlatformExpertDevice;
        'IONameMatch'		= ('AAPL,7300', 'AAPL,7500', 'AAPL,8500', 'AAPL,9500');
        'IOProbeScore'		= 10000:32;
    },
"
#endif
"
"
#if 0
"
    {
        'IOClass'		= PowerStarPE;
        'IOProviderClass'	= IOPlatformExpertDevice;
        'IONameMatch'		= ('AAPL,3400/2400', 'AAPL,3500');
        'IOProbeScore'		= 10000:32;
    },
"
#endif
"
    {
        'IOClass'		= GossamerPE;
        'IOProviderClass'	= IOPlatformExpertDevice;
	'IONameMatch'		= ('AAPL,Gossamer', 'AAPL,PowerMac G3', 'AAPL,PowerBook1998', 'iMac,1', 'PowerMac1,1', 'PowerMac1,2', 'PowerBook1,1');
	'IOProbeScore'		= 10000:32;
    },
    {
	'IOClass'		= GossamerCPU;
	'IOProviderClass'	= IOPlatformDevice;
        'IONameMatch'		= 'cpu';
	'IOProbeScore'		= 1000:32;
    },
"
#if 0
"
    {
        'IOClass'         	= PowerExpressPE;
        'IOProviderClass'	= IOPlatformExpertDevice;
	'IONameMatch'		= 'AAPL,9700';
	'IOProbeScore'		= 10000:32;
	'senses'		= <00000000 00000000 00000000 00000000 "
                                  "00000000 00000000 00000000 00000000 "
                                  "00000000 00000000 00000000 00000000 "
                                  "00000000 00000000 00000000 00000000 "
                                  "00000000 00000000 00000000 00000000 "
                                  "00000000 00000000 00000000 00000000 "
                                  "00000000 00000000 00000001 00000001 "
                                  "00000001 00000001 00000001 00000001 "
                                  "00000001 00000001 00000001 00000001 "
                                  "00000001 00000001>;
    },
"
#endif
#if 0
"
    {
        'IOClass'		= GrandCentral;
        'IOProviderClass'	= IOPCIDevice;
        'IONameMatch'		= gc;
	'IOProbeScore'		= 2000:32;
    },
"
#endif
"
    {
        'IOClass'		= OHare;
        'IOProviderClass'	= IOPCIDevice;
        'IONameMatch'		= ('ohare', 'pci106b,7');
    },
    {
        'IOClass'              = AppleNMI;
        'IOProviderClass'      = AppleMacIODevice;
        'IONameMatch'          = 'programmer-switch';
    },
    {
        'IOClass'		= AppleCuda;
        'IOProviderClass'	= AppleVIADevice;
        'IONameMatch'		= cuda;
    },"
#if 0
" {
        'IOClass'		= ApplePMU;
        'IOProviderClass'	= AppleVIADevice;
        'IONameMatch'		= pmu;
    },"
#endif
    "{   
        'IOClass'               = IOPMUADBController;
        'IOProviderClass'       = AppleMacIODevice;
        'IONameMatch'           = adb;
    }, 
    {
        'IOClass'		= AppleNVRAM;
        'IOProviderClass'	= AppleMacIODevice;
        'IONameMatch'		= nvram;
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
    },
    {
       'IOClass'           = AppleATAPIIX;
       'IOProviderClass'   = IOPCIDevice;
       'IOPCIMatch'        = '0x12308086 0x70108086 0x71118086 0x24118086 0x24218086 0x244a8086 0x244b8086';
       'IOMatchCategory'   = AppleATAPIIXChannel0;
    },
    {
       'IOClass'           = AppleATAPIIX;
       'IOProviderClass'   = IOPCIDevice;
       'IOPCIMatch'        = '0x12308086 0x70108086 0x71118086 0x24118086 0x24218086 0x244a8086 0x244b8086';
       'IOMatchCategory'   = AppleATAPIIXChannel1;
    }
"
#endif /* i386 */
")";

