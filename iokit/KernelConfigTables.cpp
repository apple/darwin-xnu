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
    'com.apple.kernel'                         = '1.3.2';
    'com.apple.kernel.bsd'                     = '1.0.2';
    'com.apple.kernel.iokit'                   = '1.0.2';
    'com.apple.kernel.libkern'                 = '1.0.2';
    'com.apple.kernel.mach'                    = '1.0.2';
    'com.apple.iokit.IOADBFamily'              = '1.0.2';
    'com.apple.iokit.IOCDStorageFamily'        = '1.0.2';
    'com.apple.iokit.IODVDStorageFamily'       = '1.0.2';
    'com.apple.iokit.IOGraphicsFamily'         = '1.0.2';
    'com.apple.iokit.IOHIDSystem'              = '1.0.2';
    'com.apple.iokit.IONDRVSupport'            = '1.0.2';
    'com.apple.iokit.IONetworkingFamily'       = '1.0.2';
    'com.apple.iokit.IOPCIFamily'              = '1.0.2';
    'com.apple.iokit.IOStorageFamily'          = '1.0.2';
    'com.apple.iokit.IOSystemManagementFamily' = '1.0.2';
}";


const char * gIOKernelConfigTables =
"(
    {
      'IOClass'         = IOPanicPlatform;
      'IOProviderClass' = IOPlatformExpertDevice;
      'IOProbeScore'    = '-1';
    },
    {
	'IOClass'		= IOHIDSystem;
	'IOProviderClass'	= IOResources;
	'IOResourceMatch'	= IOKit;
	'IOMatchCategory'	= IOHID;
    },
    {
	'IOClass'		= IOBSDConsole;
	'IOProviderClass'	= IOResources;
	'IOResourceMatch'	= IOBSD;
	'IOMatchCategory'	= IOBSDConsole;
    },
    {
	'IOClass'		= IODisplayWrangler;
	'IOProviderClass'	= IOResources;
	'IOResourceMatch'	= IOKit;
	'IOMatchCategory'	= IOGraphics;
    },
    {
	'IOClass'		= IOApplePartitionScheme;
	'IOProviderClass'	= IOMedia;
	'IOProbeScore'		= 2000:32;
	'IOMatchCategory'	= IOStorage;
	'IOPropertyMatch'	=
	{
		'Whole'	= .true.;
	};
	'Content Mask'		= 'Apple_partition_scheme';
    },
    {
	'IOClass'		= IOApplePartitionScheme;
	'IOProviderClass'	= IOMedia;
	'IOProbeScore'		= 2000:32;
	'IOMatchCategory'	= IOStorage;
	'IOPropertyMatch'	=
	{
		'Content Hint'	= 'CD_ROM_Mode_1';
	};
	'Content Mask'		= 'Apple_partition_scheme';
    },
    {
	'IOClass'		= IOApplePartitionScheme;
	'IOProviderClass'	= IOMedia;
	'IOProbeScore'		= 2000:32;
	'IOMatchCategory'	= IOStorage;
	'IOPropertyMatch'	=
	{
		'Content Hint'	= 'CD_ROM_Mode_2_Form_1';
	};
	'Content Mask'		= 'Apple_partition_scheme';
    },
    {
	'IOClass'		= IONeXTPartitionScheme;
	'IOProviderClass'	= IOMedia;
	'IOProbeScore'		= 1000:32;
	'IOMatchCategory'	= IOStorage;
	'IOPropertyMatch'	=
	{
		'Whole'	= .true.;
	};
	'Content Mask'		= 'NeXT_partition_scheme';
	'Content Table'		=
	{
	    '4.4BSD' = 'Apple_UFS';
	    '4.1BSD' = 'Unknown';
	    '4.2BSD' = 'Unknown';
	    '4.4LFS' = 'Unknown';
	};
    },
    {
	'IOClass'		= IONeXTPartitionScheme;
	'IOProviderClass'	= IOMedia;
	'IOProbeScore'		= 1000:32;
	'IOMatchCategory'	= IOStorage;
	'IOPropertyMatch'	=
	{
		'Content Hint'	= 'CD_ROM_Mode_1';
	};
	'Content Mask'		= 'NeXT_partition_scheme';
	'Content Table'		=
	{
	    '4.4BSD' = 'Apple_UFS';
	    '4.1BSD' = 'Unknown';
	    '4.2BSD' = 'Unknown';
	    '4.4LFS' = 'Unknown';
	};
    },
    {
	'IOClass'		= IONeXTPartitionScheme;
	'IOProviderClass'	= IOMedia;
	'IOProbeScore'		= 1000:32;
	'IOMatchCategory'	= IOStorage;
	'IOPropertyMatch'	=
	{
		'Content Hint'	= 'Apple_Rhapsody_UFS';
	};
	'Content Mask'		= 'NeXT_partition_scheme';
	'Content Table'		=
	{
	    '4.4BSD' = 'Apple_UFS';
	    '4.1BSD' = 'Unknown';
	    '4.2BSD' = 'Unknown';
	    '4.4LFS' = 'Unknown';
	};
    },
    {
	'IOClass'		= IOFDiskPartitionScheme;
	'IOProviderClass'	= IOMedia;
	'IOProbeScore'		= 3000:32;
	'IOMatchCategory'	= IOStorage;
	'IOPropertyMatch'	=
	{
		'Whole'	= .true.;
	};
	'Content Mask'		= 'FDisk_partition_scheme';
	'Content Table'		=
	{
	    '0x01' = 'DOS_FAT_12';
	    '0x04' = 'DOS_FAT_16_S';
	    '0x05' = 'DOS_Extended';
	    '0x06' = 'DOS_FAT_16';
	    '0x07' = 'Windows_NTFS';
	    '0x0A' = 'Boot_Manager';
	    '0x0B' = 'DOS_FAT_32';
	    '0x0C' = 'Windows_FAT_32';
	    '0x0E' = 'Windows_FAT_16';
	    '0x0F' = 'Windows_Extended';
	    '0x11' = 'DOS_FAT_12_Hidden';
	    '0x14' = 'DOS_FAT_16_S_Hidden';
	    '0x16' = 'DOS_FAT_16_Hidden';
	    '0x17' = 'Windows_NTFS_Hidden';
	    '0x1B' = 'DOS_FAT_32_Hidden';
	    '0x1C' = 'Windows_FAT_32_Hidden';
	    '0x1E' = 'Windows_FAT_16_Hidden';
	    '0x63' = 'UNIX';
	    '0x82' = 'Linux_Swap';
	    '0x83' = 'Linux_Ext2FS';
	    '0x84' = 'Hibernation';
	    '0x85' = 'Linux_Extended';
	    '0x86' = 'Windows_FAT_16_FT';
	    '0x87' = 'Windows_NTFS_FT';
	    '0xA5' = 'FreeBSD';
	    '0xA6' = 'OpenBSD';
	    '0xA7' = 'NeXTSTEP';
	    '0xA8' = 'Apple_UFS';
	    '0xA9' = 'NetBSD';
	    '0xAB' = 'Apple_Boot';
	    '0xAF' = 'Apple_HFS';
	    '0xB7' = 'BSDI';
	    '0xB8' = 'BSDI_Swap';
	    '0xC6' = 'Windows_FAT_16_FT_Corrupt';
	    '0xC7' = 'Windows_NTFS_FT_Corrupt';
	    '0xEB' = 'BeOS';
	    '0xF2' = 'DOS_Secondary';
	    '0xFD' = 'Linux_RAID';
	};
    },
    {
	'IOClass'		= IOCDPartitionScheme;
	'IOProviderClass'	= IOCDMedia;
	'IOMatchCategory'	= IOStorage;
	'Content Mask'		= 'CD_partition_scheme';
	'Content Table'		=
	{
	    '0x01' = 'CD_DA';
	    '0x02' = 'CD_ROM_Mode_1';
	    '0x03' = 'CD_ROM_Mode_2';
	    '0x04' = 'CD_ROM_Mode_2_Form_1';
	    '0x05' = 'CD_ROM_Mode_2_Form_2';
	};
    },
    {
	'IOClass'		= IOMediaBSDClient;
	'IOProviderClass'	= IOResources;
	'IOMatchCategory'	= IOMediaBSDClient;
	'IOResourceMatch'	= IOBSD;
    },
    {
	'IOClass'		= AppleDDCDisplay;
	'IOProviderClass'	= IODisplayConnect;
	'IOProbeScore'		= 2000:32;
	appleDDC		=   <00000082 00ff2140 0000008c 00043147 "
                                    "00000096 00053140 00000098 0003314c "
                                    "0000009a 0002314f 0000009c 00ff3159 "
                                    "000000aa 000d494f 000000b4 0001fffc "
                                    "000000b6 00004540 000000b8 000f454c "
                                    "000000ba 000e454f 000000bc 00ff4559 "
                                    "000000be 000b6140 000000c8 000a614a "
                                    "000000cc 0009614f 000000d0 00ff6159 "
                                    "000000d2 00ff614f 000000dc 0017ffc4 "
                                    "000000fa 00ff814f 00000104 00ff8180 "
                                    "00000106 0008818f 0000010c 00ff8199 "
                                    "00000118 00ffa940 0000011a 00ffa945 "
                                    "0000011c 00ffa94a 0000011e 00ffa94f "
                                    "00000120 00ffa954 00000121 00ffa959 "
                                    "00000128 00ffc140 0000012a 00ffc14f "
                                    "0000012c 00ffc940 0000012e 00ffc94f "
                                    "00000130 00ffd140 00000132 00ffd14f "
                                    "000001fe 00ffd1c0 00000208 00ffd1cc>;
        overrides		= ( { ID = 0x06105203:32;
					additions = <0000010c>; },
				    { ID = 0x0610049c:32;
					deletions = <000000b6>; },
				    { ID = 0x0610059c:32;
					deletions = <000000b6>; },
				    { ID = 0x0610069c:32;
					deletions = <000000b6>; },
				    { ID = 0x0610079c:32;
					deletions = <000000b6>; },
				    { ID = 0x0610089c:32;
					deletions = <000000b6>; },
				    { ID = 0x06101092:32;
					additions = <00000121>; },
				    { ID = 0x0610029d:32;
					additions = <0000009e>; } );
    },
    {
	'IOClass'		= AppleG3SeriesDisplay;
	'IOProviderClass'	= IODisplayConnect;
	'IOProbeScore'		= 1500:32;
    },
    {
	'IOClass'		= AppleSenseDisplay;
	'IOProviderClass'	= IODisplayConnect;
	'IOProbeScore'		= 1000:32;
    },
    {
	'IOClass'		= AppleNoSenseDisplay;
	'IOProviderClass'	= IODisplayConnect;
	'IOProbeScore'		= 500:32;
    },
    {
	'IOClass'		= IOBlockStorageDriver;
	'IOProviderClass'	= IOBlockStorageDevice;
	'IOPropertyMatch'	=
	{
		'device-type'	= 'Generic';
	};
    },
    {
	'IOClass'		= IOSCSIHDDrive;
	'IOProviderClass'	= IOSCSIDevice;
    },
    {
	'IOClass'		= IOCDBlockStorageDriver;
	'IOProviderClass'	= IOCDBlockStorageDevice;
	'IOPropertyMatch'	=
	{
		'device-type'	= 'CDROM';
	};
    },
    {
	'IOClass'		= IOSCSICDDrive;
	'IOProviderClass'	= IOSCSIDevice;
    },
    {
	'IOClass'		= IODVDBlockStorageDriver;
	'IOProviderClass'	= IODVDBlockStorageDevice;
	'IOPropertyMatch'	=
	{
		'device-type'	= 'DVD';
	};
    },
    {
	'IOClass'		= IOSCSIDVDDrive;
	'IOProviderClass'	= IOSCSIDevice;
    },
"
#if defined(__i386__)
"
    {
       'IOClass'           = IOATAHDDrive;
       'IOProviderClass'   = IOATADevice;
    },
    {
       'IOClass'           = IOATAPIHDDrive;
       'IOProviderClass'   = IOATADevice;
    },
    {
       'IOClass'           = IOATAPICDDrive;
       'IOProviderClass'   = IOATADevice;
    },
    {
       'IOClass'           = IOATAPIDVDDrive;
       'IOProviderClass'   = IOATADevice;
    },
"
#endif
"
    {
        'IOClass'          = IONetworkStack;
        'IOProviderClass'  = IOResources;
        'IOResourceMatch'  = IOBSD;
        'IOMatchCategory'  = IONetworkStack;
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
"
    {
	'IOClass'		= AppleGracklePCI;
	'IOProviderClass'	= IOPlatformDevice;
	'IONameMatch'		= ('grackle', 'MOT,PPC106');
    },
    {
	'IOClass'		= AppleMacRiscPCI;
	'IOProviderClass'	= IOPlatformDevice;
	'IONameMatch'		= ('bandit', 'uni-north');
    },
    {
	'IOClass'		= AppleMacRiscAGP;
	'IOProviderClass'	= IOPlatformDevice;
	'IONameMatch'		= 'uni-north';
	'IOProbeScore'		= 1000:32;
	'IOAGPFlags'		= 1:32;
    },
    {
	'IOClass'		= AppleMacRiscVCI;
	'IOProviderClass'	= IOPlatformDevice;
	'IONameMatch'		= chaos;
    },
    {
	'IOClass'		= IOPCI2PCIBridge;
	'IOProviderClass'	= IOPCIDevice;
	'IONameMatch'		= 'pci-bridge';
    },
    {
	'IOClass'		= IOPCI2PCIBridge;
	'IOProviderClass'	= IOPCIDevice;
        'IOPCIMatch'           = '0x00261011';
    },
"
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
    },
    {
	'IOClass'		= IOADBBus;
	'IOProviderClass'	= IOADBController;
    },
  {
      'IOClass'			= AppleADBKeyboard;
      'IOProviderClass'		= IOADBDevice;
      'ADB Match'		= '2';
  },
  {
      'IOClass'			= AppleADBButtons;
      'IOProviderClass'		= IOADBDevice;
      'ADB Match'		= '7';
  },
    {
	'IOClass'		= AppleADBMouseType1;
	'IOProviderClass'	= IOADBDevice;
	'ADB Match'		= '3';
	'IOProbeScore'		= 5000:32;
    },
    {
	'IOClass'		= AppleADBMouseType2;
	'IOProviderClass'	= IOADBDevice;
	'ADB Match'		= '3';
	'IOProbeScore'		= 10000:32;
    },
    {
	'IOClass'		= AppleADBMouseType4;
	'IOProviderClass'	= IOADBDevice;
	'ADB Match'		= '3-01';
	'IOProbeScore'		= 20000:32;
        'accltpad'		= <"
                                "0000b000"
                                "74706164000700000000000100010000"
                                "00010000000020000005000123c60001"
                                "00000002fe3c0003800000055719000b"
                                "000000082ebf001a0000000a3ff1002e"
                                "0000000050000005000123c600010000"
                                "0002de8a000410000005682c000fe000"
                                "00081ebf00226000000a1f680037e000"
                                "000080000007000123c6000100000001"
                                "c378000280000002ac150004a0000004"
                                "5402000dc00000061285001bb0000007"
                                "e68b002d1000000a44eb004a90000000"
                                "b000000900012429000100000001b37c"
                                "0002800000025e5f000580000003bf2c"
                                "000f00000004bc350017a00000061e38"
                                "0027b00000075d4500385000000899a2"
                                "004bb000000a91050066b0000000e000"
                                "000a00011855000130000001b2280002"
                                "f000000253690006a00000036f4a0010"
                                "d00000046aab001f100000054aab002d"
                                "500000062555003f400000071aab0051"
                                "c00000089aab00663000000a8aab007d"
                                "700000010000000b0001185500013000"
                                "0001b228000310000002536900071000"
                                "00032f4a001180000003acfb001c8800"
                                "00043aab0028e0000004caab00384000"
                                "000555550048f00000063aab005c9000"
                                "0007aaab00731000000a3aab008b7000"
                                ">;
    },
    {
	'IOClass'		= IONDRVFramebuffer;
	'IOProviderClass'	= IOPCIDevice;
	'IONameMatch'		= display;
	'IOProbeScore'		= 20000:32;
	'IOMatchCategory'	= IOFramebuffer;
    },
    {
	'IOClass'		= IONDRVFramebuffer;
	'IOProviderClass'	= IOPlatformDevice;
	'IONameMatch'		= display;
	'IOProbeScore'		= 20000:32;
	'IOMatchCategory'	= IOFramebuffer;
    },
    {
	'IOClass'		= IOBootFramebuffer;
	'IOProviderClass'	= IOPCIDevice;
	'IONameMatch'		= display;
	'IOMatchCategory'	= IOFramebuffer;
    },
    {
	'IOClass'		= AppleADBDisplay;
	'IOProbeScore'		= 1000:32;
	'IOProviderClass'	= IOADBDevice;
	'ADB Match'		= '*-c0';
	modes850		=   <000000dc 0000008c 0000009a 0000009e "
                                    "000000aa 000000d2 000000d0 000000fa "
                                    "00000106 0000010c 00000118 0000011a "
                                    "0000011c 0000011e>;
	modes750		=   <000000dc 0000008c 000000aa 000000d2 "
                                    "000000fa 00000106 00000118>;
	modesStudio		=   <000000d2 0000008c 000000aa>;
	adb2Modes		= modes750;
	adb3Modes		= modes850;
	adb4Modes		= modes850;
	adb5Modes		= modes750;
	adb6Modes		= modesStudio;
    },
    {
	'IOClass'           = BMacEnet;
	'IOProviderClass'   = AppleMacIODevice;
	'IONameMatch'       = ('bmac', 'bmac+');
    },
"
#if 0
"
    {
        'IOClass'         	= Sym8xxSCSIController;
        'IOProviderClass'	= IOPCIDevice;
        'IONameMatch'		= ('apple53C8xx', 'Apple53C875Card', 'ATTO,ExpressPCIProLVD', 'ATTO,ExpressPCIProUL2D', 'ATTO,ExpressPCIProUL3D');
    },
"
#endif
"
"
#if 0
"
    {
	'IOClass'           = MaceEnet;
	'IOProviderClass'   = AppleMacIODevice;
	'IONameMatch'       = mace;
    },
    {
        'IOClass'           = Intel82557;
        'IOProviderClass'   = IOPCIDevice;
        'IOPCIMatch'        = '0x12298086';
        'IODefaultMedium'   = '00000020';
        'Flow Control'      = .true.;
        'Verbose'           = .false.;
    },
"
#endif /* 0 */
"
    {
        'IOClass'           = IOKDP;
        'IOProviderClass'   = IOKernelDebugger;
        'IOMatchCategory'   = IOKDP;
        'IOEnableKDP'       = .true.;
        'IODriverMatch'     =
        {
            'IOClass'  = ('BMacEnet', 'UniNEnet', 'MaceEnet');
        };
        'IODriverNubMatch'  =
        {
            'built-in' = <>;
        };
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
       'IOClass'           = AppleI386PCI;
       'IOProviderClass'   = IOPlatformDevice;
       'IONameMatch'       = pci;
    },
    {
       'IOClass'           = ApplePS2Controller;
       'IOProviderClass'   = IOPlatformDevice;
       'IONameMatch'       = ps2controller;
    },
    {
       'IOClass'           = ApplePS2Keyboard;
       'IOProviderClass'   = ApplePS2KeyboardDevice;
    },
    {
       'IOClass'           = ApplePS2Mouse;
       'IOProviderClass'   = ApplePS2MouseDevice;
    },
    {
       'IOClass'           = IOBootFramebuffer;
       'IOProviderClass'   = IOPlatformDevice;
       'IONameMatch'       = display;
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
    },
    {
        'IOClass'		   = IOPCI2PCIBridge;
        'IOProviderClass'  = IOPCIDevice;
        'IOPCIClassMatch'  = '0x06040000&0xffff0000';
    },
    {
       'IOClass'           = Intel82557;
       'IOProviderClass'   = IOPCIDevice;
       'IOPCIMatch'        = '0x12298086';
       'IODefaultMedium'   = '00000020';
       'Flow Control'      = .true.;
       'Verbose'           = .false.;
    },
    {
        'IOClass'          = IOKDP;
        'IOProviderClass'  = IOKernelDebugger;
        'IOMatchCategory'  = IOKDP;
        'IOEnableKDP'      = .true.;
        'IODriverMatch'    =
        {
            'IOClass'  = ('Intel82557', 'DEC21x4');
        };
        'IODriverNubMatch' =
        {
        };
    }
"
#endif /* i386 */
")";
