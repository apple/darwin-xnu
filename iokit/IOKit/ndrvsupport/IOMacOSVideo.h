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
     File:       Video.h
 
     Contains:   Video Driver Interfaces.
 
     Copyright:  (c) 1986-2000 by Apple Computer, Inc., all rights reserved
 
     Bugs?:      For bug reports, consult the following page on
                 the World Wide Web:
 
                     http://developer.apple.com/bugreporter/
 
*/
#ifndef __IOMACOSVIDEO__
#define __IOMACOSVIDEO__

#ifdef IOKIT

#define PRAGMA_STRUCT_ALIGN 1
#define FOUR_CHAR_CODE(x)           (x)
#include <IOKit/ndrvsupport/IOMacOSTypes.h>

#else /* IOKIT */

#ifndef __QUICKDRAW__
#include <Quickdraw.h>
#endif

#endif /* IOKIT */

#if PRAGMA_ONCE
#pragma once
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if PRAGMA_IMPORT
#pragma import on
#endif

#if PRAGMA_STRUCT_ALIGN
    #pragma options align=mac68k
#elif PRAGMA_STRUCT_PACKPUSH
    #pragma pack(push, 2)
#elif PRAGMA_STRUCT_PACK
    #pragma pack(2)
#endif

enum {
    mBaseOffset                 = 1,                            /*Id of mBaseOffset.*/
    mRowBytes                   = 2,                            /*Video sResource parameter Id's */
    mBounds                     = 3,                            /*Video sResource parameter Id's */
    mVersion                    = 4,                            /*Video sResource parameter Id's */
    mHRes                       = 5,                            /*Video sResource parameter Id's */
    mVRes                       = 6,                            /*Video sResource parameter Id's */
    mPixelType                  = 7,                            /*Video sResource parameter Id's */
    mPixelSize                  = 8,                            /*Video sResource parameter Id's */
    mCmpCount                   = 9,                            /*Video sResource parameter Id's */
    mCmpSize                    = 10,                           /*Video sResource parameter Id's */
    mPlaneBytes                 = 11,                           /*Video sResource parameter Id's */
    mVertRefRate                = 14,                           /*Video sResource parameter Id's */
    mVidParams                  = 1,                            /*Video parameter block id.*/
    mTable                      = 2,                            /*Offset to the table.*/
    mPageCnt                    = 3,                            /*Number of pages*/
    mDevType                    = 4,                            /*Device Type*/
    oneBitMode                  = 128,                          /*Id of OneBitMode Parameter list.*/
    twoBitMode                  = 129,                          /*Id of TwoBitMode Parameter list.*/
    fourBitMode                 = 130,                          /*Id of FourBitMode Parameter list.*/
    eightBitMode                = 131                           /*Id of EightBitMode Parameter list.*/
};

enum {
    sixteenBitMode              = 132,                          /*Id of SixteenBitMode Parameter list.*/
    thirtyTwoBitMode            = 133,                          /*Id of ThirtyTwoBitMode Parameter list.*/
    firstVidMode                = 128,                          /*The new, better way to do the above. */
    secondVidMode               = 129,                          /* QuickDraw only supports six video */
    thirdVidMode                = 130,                          /* at this time.      */
    fourthVidMode               = 131,
    fifthVidMode                = 132,
    sixthVidMode                = 133,
    spGammaDir                  = 64,
    spVidNamesDir               = 65
};


/* csTimingFormat values in VDTimingInfo */
/* look in the declaration rom for timing info */
enum {
    kDeclROMtables              = FOUR_CHAR_CODE('decl'),
    kDetailedTimingFormat       = FOUR_CHAR_CODE('arba')        /* Timing is a detailed timing*/
};

/* Size of a block of EDID (Extended Display Identification Data) */
enum {
    kDDCBlockSize               = 128
};

/* ddcBlockType constants*/
enum {
    kDDCBlockTypeEDID           = 0                             /* EDID block type. */
};

/* ddcFlags constants*/
enum {
    kDDCForceReadBit            = 0,                            /* Force a new read of the EDID. */
    kDDCForceReadMask           = (1 << kDDCForceReadBit)       /* Mask for kddcForceReadBit. */
};


/* Timing mode constants for Display Manager MultiMode support
    Corresponding   .h equates are in Video.h
                    .a equates are in Video.a
                    .r equates are in DepVideoEqu.r
    
    The second enum is the old names (for compatibility).
    The first enum is the new names.
*/
enum {
    timingInvalid               = 0,                            /*    Unknown timing... force user to confirm. */
    timingInvalid_SM_T24        = 8,                            /*    Work around bug in SM Thunder24 card.*/
    timingApple_FixedRateLCD    = 42,                           /*    Lump all fixed-rate LCDs into one category.*/
    timingApple_512x384_60hz    = 130,                          /*  512x384  (60 Hz) Rubik timing. */
    timingApple_560x384_60hz    = 135,                          /*  560x384  (60 Hz) Rubik-560 timing. */
    timingApple_640x480_67hz    = 140,                          /*  640x480  (67 Hz) HR timing. */
    timingApple_640x400_67hz    = 145,                          /*  640x400  (67 Hz) HR-400 timing. */
    timingVESA_640x480_60hz     = 150,                          /*  640x480  (60 Hz) VGA timing. */
    timingVESA_640x480_72hz     = 152,                          /*  640x480  (72 Hz) VGA timing. */
    timingVESA_640x480_75hz     = 154,                          /*  640x480  (75 Hz) VGA timing. */
    timingVESA_640x480_85hz     = 158,                          /*  640x480  (85 Hz) VGA timing. */
    timingGTF_640x480_120hz     = 159,                          /*  640x480  (120 Hz) VESA Generalized Timing Formula */
    timingApple_640x870_75hz    = 160,                          /*  640x870  (75 Hz) FPD timing.*/
    timingApple_640x818_75hz    = 165,                          /*  640x818  (75 Hz) FPD-818 timing.*/
    timingApple_832x624_75hz    = 170,                          /*  832x624  (75 Hz) GoldFish timing.*/
    timingVESA_800x600_56hz     = 180,                          /*  800x600  (56 Hz) SVGA timing. */
    timingVESA_800x600_60hz     = 182,                          /*  800x600  (60 Hz) SVGA timing. */
    timingVESA_800x600_72hz     = 184,                          /*  800x600  (72 Hz) SVGA timing. */
    timingVESA_800x600_75hz     = 186,                          /*  800x600  (75 Hz) SVGA timing. */
    timingVESA_800x600_85hz     = 188,                          /*  800x600  (85 Hz) SVGA timing. */
    timingVESA_1024x768_60hz    = 190,                          /* 1024x768  (60 Hz) VESA 1K-60Hz timing. */
    timingVESA_1024x768_70hz    = 200,                          /* 1024x768  (70 Hz) VESA 1K-70Hz timing. */
    timingVESA_1024x768_75hz    = 204,                          /* 1024x768  (75 Hz) VESA 1K-75Hz timing (very similar to timingApple_1024x768_75hz). */
    timingVESA_1024x768_85hz    = 208,                          /* 1024x768  (85 Hz) VESA timing. */
    timingApple_1024x768_75hz   = 210,                          /* 1024x768  (75 Hz) Apple 19" RGB. */
    timingApple_1152x870_75hz   = 220,                          /* 1152x870  (75 Hz) Apple 21" RGB. */
    timingAppleNTSC_ST          = 230,                          /*  512x384  (60 Hz, interlaced, non-convolved). */
    timingAppleNTSC_FF          = 232,                          /*  640x480  (60 Hz, interlaced, non-convolved). */
    timingAppleNTSC_STconv      = 234,                          /*  512x384  (60 Hz, interlaced, convolved). */
    timingAppleNTSC_FFconv      = 236,                          /*  640x480  (60 Hz, interlaced, convolved). */
    timingApplePAL_ST           = 238,                          /*  640x480  (50 Hz, interlaced, non-convolved). */
    timingApplePAL_FF           = 240,                          /*  768x576  (50 Hz, interlaced, non-convolved). */
    timingApplePAL_STconv       = 242,                          /*  640x480  (50 Hz, interlaced, convolved). */
    timingApplePAL_FFconv       = 244,                          /*  768x576  (50 Hz, interlaced, convolved). */
    timingVESA_1280x960_75hz    = 250,                          /* 1280x960  (75 Hz) */
    timingVESA_1280x960_60hz    = 252,                          /* 1280x960  (60 Hz) */
    timingVESA_1280x960_85hz    = 254,                          /* 1280x960  (85 Hz) */
    timingVESA_1280x1024_60hz   = 260,                          /* 1280x1024 (60 Hz) */
    timingVESA_1280x1024_75hz   = 262,                          /* 1280x1024 (75 Hz) */
    timingVESA_1280x1024_85hz   = 268,                          /* 1280x1024 (85 Hz) */
    timingVESA_1600x1200_60hz   = 280,                          /* 1600x1200 (60 Hz) VESA timing. */
    timingVESA_1600x1200_65hz   = 282,                          /* 1600x1200 (65 Hz) VESA timing. */
    timingVESA_1600x1200_70hz   = 284,                          /* 1600x1200 (70 Hz) VESA timing. */
    timingVESA_1600x1200_75hz   = 286,                          /* 1600x1200 (75 Hz) VESA timing (pixel clock is 189.2 Mhz dot clock). */
    timingVESA_1600x1200_80hz   = 288,                          /* 1600x1200 (80 Hz) VESA timing (pixel clock is 216>? Mhz dot clock) - proposed only. */
    timingVESA_1600x1200_85hz   = 289,                          /* 1600x1200 (85 Hz) VESA timing (pixel clock is 229.5 Mhz dot clock). */
    timingVESA_1792x1344_60hz   = 296,                          /* 1792x1344 (60 Hz) VESA timing (204.75 Mhz dot clock). */
    timingVESA_1792x1344_75hz   = 298,                          /* 1792x1344 (75 Hz) VESA timing (261.75 Mhz dot clock). */
    timingVESA_1856x1392_60hz   = 300,                          /* 1856x1392 (60 Hz) VESA timing (218.25 Mhz dot clock). */
    timingVESA_1856x1392_75hz   = 302,                          /* 1856x1392 (75 Hz) VESA timing (288 Mhz dot clock). */
    timingVESA_1920x1440_60hz   = 304,                          /* 1920x1440 (60 Hz) VESA timing (234 Mhz dot clock). */
    timingVESA_1920x1440_75hz   = 306,                          /* 1920x1440 (75 Hz) VESA timing (297 Mhz dot clock). */
    timingSMPTE240M_60hz        = 400,                          /* 60Hz V, 33.75KHz H, interlaced timing, 16:9 aspect, typical resolution of 1920x1035. */
    timingFilmRate_48hz         = 410,                          /* 48Hz V, 25.20KHz H, non-interlaced timing, typical resolution of 640x480. */
    timingSony_1600x1024_76hz   = 500,                          /* 1600x1024 (76 Hz) Sony timing (pixel clock is 170.447 Mhz dot clock). */
    timingSony_1920x1080_60hz   = 510,                          /* 1920x1080 (60 Hz) Sony timing (pixel clock is 159.84 Mhz dot clock). */
    timingSony_1920x1080_72hz   = 520,                          /* 1920x1080 (72 Hz) Sony timing (pixel clock is 216.023 Mhz dot clock). */
    timingSony_1920x1200_76hz   = 540,                          /* 1900x1200 (76 Hz) Sony timing (pixel clock is 243.20 Mhz dot clock). */
    timingApple_0x0_0hz_Offline = 550                           /* Indicates that this timing will take the display off-line and remove it from the system. */
};


/* Deprecated timing names.*/
enum {
    timingApple12               = timingApple_512x384_60hz,
    timingApple12x              = timingApple_560x384_60hz,
    timingApple13               = timingApple_640x480_67hz,
    timingApple13x              = timingApple_640x400_67hz,
    timingAppleVGA              = timingVESA_640x480_60hz,
    timingApple15               = timingApple_640x870_75hz,
    timingApple15x              = timingApple_640x818_75hz,
    timingApple16               = timingApple_832x624_75hz,
    timingAppleSVGA             = timingVESA_800x600_56hz,
    timingApple1Ka              = timingVESA_1024x768_60hz,
    timingApple1Kb              = timingVESA_1024x768_70hz,
    timingApple19               = timingApple_1024x768_75hz,
    timingApple21               = timingApple_1152x870_75hz,
    timingSony_1900x1200_74hz   = 530,                          /* 1900x1200 (74 Hz) Sony timing (pixel clock is 236.25 Mhz dot clock). */
    timingSony_1900x1200_76hz   = timingSony_1920x1200_76hz     /* 1900x1200 (76 Hz) Sony timing (pixel clock is 245.48 Mhz dot clock). */
};

/* csConnectFlags values in VDDisplayConnectInfo */
enum {
    kAllModesValid              = 0,                            /* All modes not trimmed by primary init are good close enough to try */
    kAllModesSafe               = 1,                            /* All modes not trimmed by primary init are know to be safe */
    kReportsTagging             = 2,                            /* Can detect tagged displays (to identify smart monitors) */
    kHasDirectConnection        = 3,                            /* True implies that driver can talk directly to device (e.g. serial data link via sense lines) */
    kIsMonoDev                  = 4,                            /* Says whether there's an RGB (0) or Monochrome (1) connection. */
    kUncertainConnection        = 5,                            /* There may not be a display (no sense lines?). */
    kTaggingInfoNonStandard     = 6,                            /* Set when csConnectTaggedType/csConnectTaggedData are non-standard (i.e., not the Apple CRT sense codes). */
    kReportsDDCConnection       = 7,                            /* Card can do ddc (set kHasDirectConnect && kHasDDCConnect if you actually found a ddc display). */
    kHasDDCConnection           = 8,                            /* Card has ddc connect now. */
    kConnectionInactive         = 9,                            /* Set when the connection is NOT currently active (generally used in a multiconnection environment). */
    kDependentConnection        = 10,                           /* Set when some ascpect of THIS connection depends on another (will generally be set in a kModeSimulscan environment). */
    kBuiltInConnection          = 11,                           /* Set when connection is KNOWN to be built-in (this is not the same as kHasDirectConnection). */
    kOverrideConnection         = 12,                           /* Set when the reported connection is not the true one, but is one that has been forced through a SetConnection call */
    kFastCheckForDDC            = 13,                           /* Set when all 3 are true: 1) sense codes indicate DDC display could be attached 2) attempted fast check 3) DDC failed */
    kReportsHotPlugging         = 14                            /* Detects and reports hot pluggging on connector (via VSL also implies DDC will be up to date w/o force read) */
};


/* csDisplayType values in VDDisplayConnectInfo */
enum {
    kUnknownConnect             = 1,                            /* Not sure how we'll use this, but seems like a good idea. */
    kPanelConnect               = 2,                            /* For use with fixed-in-place LCD panels. */
    kPanelTFTConnect            = 2,                            /* Alias for kPanelConnect */
    kFixedModeCRTConnect        = 3,                            /*  For use with fixed-mode (i.e., very limited range) displays. */
    kMultiModeCRT1Connect       = 4,                            /* 320x200 maybe, 12" maybe, 13" (default), 16" certain, 19" maybe, 21" maybe */
    kMultiModeCRT2Connect       = 5,                            /* 320x200 maybe, 12" maybe, 13" certain, 16" (default), 19" certain, 21" maybe */
    kMultiModeCRT3Connect       = 6,                            /* 320x200 maybe, 12" maybe, 13" certain, 16" certain, 19" default, 21" certain */
    kMultiModeCRT4Connect       = 7,                            /* Expansion to large multi mode (not yet used) */
    kModelessConnect            = 8,                            /* Expansion to modeless model (not yet used) */
    kFullPageConnect            = 9,                            /* 640x818 (to get 8bpp in 512K case) and 640x870 (these two only) */
    kVGAConnect                 = 10,                           /* 640x480 VGA default -- question everything else */
    kNTSCConnect                = 11,                           /* NTSC ST (default), FF, STconv, FFconv */
    kPALConnect                 = 12,                           /* PAL ST (default), FF, STconv, FFconv */
    kHRConnect                  = 13,                           /* Straight-6 connect -- 640x480 and 640x400 (to get 8bpp in 256K case) (these two only) */
    kPanelFSTNConnect           = 14,                           /* For use with fixed-in-place LCD FSTN (aka "Supertwist") panels */
    kMonoTwoPageConnect         = 15,                           /* 1152x870 Apple color two-page display */
    kColorTwoPageConnect        = 16,                           /* 1152x870 Apple B&W two-page display */
    kColor16Connect             = 17,                           /* 832x624 Apple B&W two-page display */
    kColor19Connect             = 18,                           /* 1024x768 Apple B&W two-page display */
    kGenericCRT                 = 19,                           /* Indicates nothing except that connection is CRT in nature. */
    kGenericLCD                 = 20,                           /* Indicates nothing except that connection is LCD in nature. */
    kDDCConnect                 = 21,                           /* DDC connection, always set kHasDDCConnection */
    kNoConnect                  = 22                            /* No display is connected - load sensing or similar level of hardware detection is assumed (used by resident drivers that support hot plugging when nothing is currently connected) */
};

/* csTimingFlags values in VDTimingInfoRec */
enum {
    kModeValid                  = 0,                            /* Says that this mode should NOT be trimmed. */
    kModeSafe                   = 1,                            /* This mode does not need confirmation */
    kModeDefault                = 2,                            /* This is the default mode for this type of connection */
    kModeShowNow                = 3,                            /* This mode should always be shown (even though it may require a confirm) */
    kModeNotResize              = 4,                            /* This mode should not be used to resize the display (eg. mode selects a different connector on card) */
    kModeRequiresPan            = 5,                            /* This mode has more pixels than are actually displayed */
    kModeInterlaced             = 6,                            /* This mode is interlaced (single pixel lines look bad). */
    kModeShowNever              = 7,                            /* This mode should not be shown in the user interface. */
    kModeSimulscan              = 8,                            /* Indicates that more than one display connection can be driven from a single framebuffer controller. */
    kModeNotPreset              = 9,                            /* Indicates that the timing is not a factory preset for the current display (geometry may need correction) */
    kModeBuiltIn                = 10,                           /* Indicates that the display mode is for the built-in connect only (on multiconnect devices like the PB 3400) Only the driver is quieried */
    kModeStretched              = 11                            /* Indicates that the display mode will be stretched/distorted to match the display aspect ratio */
};

/* csDepthFlags in VDVideoParametersInfoRec */
enum {
    kDepthDependent             = 0                             /* Says that this depth mode may cause dependent changes in other framebuffers (and . */
};

/* csResolutionFlags bit flags for VDResolutionInfoRec */
enum {
    kResolutionHasMultipleDepthSizes = 0                        /* Says that this mode has different csHorizontalPixels, csVerticalLines at different depths (usually slightly larger at lower depths) */
};


enum {
                                                                /*    Power Mode constants for VDPowerStateRec.powerState.  Note the numeric order does not match the power state order */
    kAVPowerOff                 = 0,                            /* Power fully off*/
    kAVPowerStandby             = 1,
    kAVPowerSuspend             = 2,
    kAVPowerOn                  = 3,
    kHardwareSleep              = 128,
    kHardwareWake               = 129,
    kHardwareWakeFromSuspend    = 130,
    kHardwareWakeToDoze         = 131,
    kHardwareWakeToDozeFromSuspend = 132
};

enum {
                                                                /*    Power Mode masks and bits for VDPowerStateRec.powerFlags.  */
    kPowerStateNeedsRefresh     = 0,                            /* When leaving this power mode, a display will need refreshing   */
    kPowerStateSleepAwareBit    = 1,                            /* if gestaltPCCardDockingSelectorFix, Docking mgr checks this bit before checking kPowerStateSleepAllowedBit */
    kPowerStateSleepForbiddenBit = 2,                           /* if kPowerStateSleepAwareBit, Docking mgr checks this bit before sleeping */
    kPowerStateSleepCanPowerOffBit = 3,                         /* supports power down sleep (ie PCI power off)*/
    kPowerStateSleepNoDPMSBit   = 4,                            /* Bug #2425210.  Do not use DPMS with this display.*/
    kPowerStateSleepWaketoDozeBit = 5,                          /* Supports Wake to Doze */
    kPowerStateNeedsRefreshMask = (1L << kPowerStateNeedsRefresh),
    kPowerStateSleepAwareMask   = (1L << kPowerStateSleepAwareBit),
    kPowerStateSleepForbiddenMask = (1L << kPowerStateSleepForbiddenBit),
    kPowerStateSleepCanPowerOffMask = (1L << kPowerStateSleepCanPowerOffBit),
    kPowerStateSleepNoDPMSMask  = (1L << kPowerStateSleepNoDPMSBit),
    kPowerStateSleepWaketoDozeMask = (1L << kPowerStateSleepWaketoDozeBit)
};


enum {
                                                                /* Control Codes */
    cscReset                    = 0,
    cscKillIO                   = 1,
    cscSetMode                  = 2,
    cscSetEntries               = 3,
    cscSetGamma                 = 4,
    cscGrayPage                 = 5,
    cscGrayScreen               = 5,
    cscSetGray                  = 6,
    cscSetInterrupt             = 7,
    cscDirectSetEntries         = 8,
    cscSetDefaultMode           = 9,
    cscSwitchMode               = 10,
    cscSetSync                  = 11,
    cscSavePreferredConfiguration = 16,
    cscSetHardwareCursor        = 22,
    cscDrawHardwareCursor       = 23,
    cscSetConvolution           = 24,
    cscSetPowerState            = 25,
    cscPrivateControlCall       = 26,                           /* Takes a VDPrivateSelectorDataRec*/
    cscSetMultiConnect          = 28,                           /* From a GDI point of view, this call should be implemented completely in the HAL and not at all in the core.*/
    cscSetClutBehavior          = 29,                           /* Takes a VDClutBehavior */
    cscSetDetailedTiming        = 31,                           /* Takes a VDDetailedTimingPtr */
    cscDoCommunication          = 33,                           /* Takes a VDCommunicationPtr */
    cscUnusedCall               = 127                           /* This call used to expend the scrn resource.  Its imbedded data contains more control info */
};

enum {
                                                                /* Status Codes */
    cscGetMode                  = 2,
    cscGetEntries               = 3,
    cscGetPageCnt               = 4,
    cscGetPages                 = 4,                            /* This is what C&D 2 calls it. */
    cscGetPageBase              = 5,
    cscGetBaseAddr              = 5,                            /* This is what C&D 2 calls it. */
    cscGetGray                  = 6,
    cscGetInterrupt             = 7,
    cscGetGamma                 = 8,
    cscGetDefaultMode           = 9,
    cscGetCurMode               = 10,
    cscGetSync                  = 11,
    cscGetConnection            = 12,                           /* Return information about the connection to the display */
    cscGetModeTiming            = 13,                           /* Return timing info for a mode */
    cscGetModeBaseAddress       = 14,                           /* Return base address information about a particular mode */
    cscGetScanProc              = 15,                           /* QuickTime scan chasing routine */
    cscGetPreferredConfiguration = 16,
    cscGetNextResolution        = 17,
    cscGetVideoParameters       = 18,
    cscGetGammaInfoList         = 20,
    cscRetrieveGammaTable       = 21,
    cscSupportsHardwareCursor   = 22,
    cscGetHardwareCursorDrawState = 23,
    cscGetConvolution           = 24,
    cscGetPowerState            = 25,
    cscPrivateStatusCall        = 26,                           /* Takes a VDPrivateSelectorDataRec*/
    cscGetDDCBlock              = 27,                           /* Takes a VDDDCBlockRec  */
    cscGetMultiConnect          = 28,                           /* From a GDI point of view, this call should be implemented completely in the HAL and not at all in the core.*/
    cscGetClutBehavior          = 29,                           /* Takes a VDClutBehavior */
    cscGetTimingRanges          = 30,                           /* Takes a VDDisplayTimingRangePtr */
    cscGetDetailedTiming        = 31,                           /* Takes a VDDetailedTimingPtr */
    cscGetCommunicationInfo     = 32                            /* Takes a VDCommunicationInfoPtr */
};

/* Bit definitions for the Get/Set Sync call*/
enum {
    kDisableHorizontalSyncBit   = 0,
    kDisableVerticalSyncBit     = 1,
    kDisableCompositeSyncBit    = 2,
    kEnableSyncOnBlue           = 3,
    kEnableSyncOnGreen          = 4,
    kEnableSyncOnRed            = 5,
    kNoSeparateSyncControlBit   = 6,
    kTriStateSyncBit            = 7,
    kHorizontalSyncMask         = 0x01,
    kVerticalSyncMask           = 0x02,
    kCompositeSyncMask          = 0x04,
    kDPMSSyncMask               = 0x07,
    kTriStateSyncMask           = 0x80,
    kSyncOnBlueMask             = 0x08,
    kSyncOnGreenMask            = 0x10,
    kSyncOnRedMask              = 0x20,
    kSyncOnMask                 = 0x38
};

enum {
                                                                /*    Power Mode constants for translating DPMS modes to Get/SetSync calls.  */
    kDPMSSyncOn                 = 0,
    kDPMSSyncStandby            = 1,
    kDPMSSyncSuspend            = 2,
    kDPMSSyncOff                = 7
};

/* Bit definitions for the Get/Set Convolution call*/
enum {
    kConvolved                  = 0,
    kLiveVideoPassThru          = 1,
    kConvolvedMask              = 0x01,
    kLiveVideoPassThruMask      = 0x02
};



struct VPBlock {
    long                            vpBaseOffset;               /*Offset to page zero of video RAM (From minorBaseOS).*/
    short                           vpRowBytes;                 /*Width of each row of video memory.*/
    Rect                            vpBounds;                   /*BoundsRect for the video display (gives dimensions).*/
    short                           vpVersion;                  /*PixelMap version number.*/
    short                           vpPackType;
    long                            vpPackSize;
    long                            vpHRes;                     /*Horizontal resolution of the device (pixels per inch).*/
    long                            vpVRes;                     /*Vertical resolution of the device (pixels per inch).*/
    short                           vpPixelType;                /*Defines the pixel type.*/
    short                           vpPixelSize;                /*Number of bits in pixel.*/
    short                           vpCmpCount;                 /*Number of components in pixel.*/
    short                           vpCmpSize;                  /*Number of bits per component*/
    long                            vpPlaneBytes;               /*Offset from one plane to the next.*/
};
typedef struct VPBlock                  VPBlock;
typedef VPBlock *                       VPBlockPtr;

struct VDEntryRecord {
    Ptr                             csTable;                    /*(long) pointer to color table entry=value, r,g,b:INTEGER*/
};
typedef struct VDEntryRecord            VDEntryRecord;

typedef VDEntryRecord *                 VDEntRecPtr;
/* Parm block for SetGray control call */

struct VDGrayRecord {
    Boolean                         csMode;                     /*Same as GDDevType value (0=color, 1=mono)*/
    SInt8                           filler;
};
typedef struct VDGrayRecord             VDGrayRecord;

typedef VDGrayRecord *                  VDGrayPtr;
/* Parm block for SetInterrupt call */

struct VDFlagRecord {
    SInt8                           csMode;
    SInt8                           filler;
};
typedef struct VDFlagRecord             VDFlagRecord;

typedef VDFlagRecord *                  VDFlagRecPtr;
/* Parm block for SetEntries control call */

struct VDSetEntryRecord {
    ColorSpec *                     csTable;                    /*Pointer to an array of color specs*/
    short                           csStart;                    /*Which spec in array to start with, or -1*/
    short                           csCount;                    /*Number of color spec entries to set*/
};
typedef struct VDSetEntryRecord         VDSetEntryRecord;

typedef VDSetEntryRecord *              VDSetEntryPtr;
/* Parm block for SetGamma control call */

struct VDGammaRecord {
    Ptr                             csGTable;                   /*pointer to gamma table*/
};
typedef struct VDGammaRecord            VDGammaRecord;

typedef VDGammaRecord *                 VDGamRecPtr;

struct VDBaseAddressInfoRec {
    long                            csDevData;                  /* LONGINT - (long) timing mode */
    long                            csDevBase;                  /* LONGINT - (long) base address of the mode */
    short                           csModeReserved;             /* INTEGER - (short) will some day be the depth */
    long                            csModeBase;                 /* LONGINT - (long) reserved */
};
typedef struct VDBaseAddressInfoRec     VDBaseAddressInfoRec;

typedef VDBaseAddressInfoRec *          VDBaseAddressInfoPtr;

struct VDSwitchInfoRec {
    unsigned short                  csMode;                     /*(word) mode depth*/
    unsigned long                   csData;                     /*(long) functional sResource of mode*/
    unsigned short                  csPage;                     /*(word) page to switch in*/
    Ptr                             csBaseAddr;                 /*(long) base address of page (return value)*/
    unsigned long                   csReserved;                 /*(long) Reserved (set to 0) */
};
typedef struct VDSwitchInfoRec          VDSwitchInfoRec;

typedef VDSwitchInfoRec *               VDSwitchInfoPtr;

struct VDTimingInfoRec {
    unsigned long                   csTimingMode;               /* LONGINT - (long) timing mode (a la InitGDevice) */
    unsigned long                   csTimingReserved;           /* LONGINT - (long) reserved */
    unsigned long                   csTimingFormat;             /* LONGINT - (long) what format is the timing info */
    unsigned long                   csTimingData;               /* LONGINT - (long) data supplied by driver */
    unsigned long                   csTimingFlags;              /* LONGINT - (long) mode within device */
};
typedef struct VDTimingInfoRec          VDTimingInfoRec;

typedef VDTimingInfoRec *               VDTimingInfoPtr;

struct VDDisplayConnectInfoRec {
    unsigned short                  csDisplayType;              /* INTEGER - (word) Type of display connected */
    unsigned char                   csConnectTaggedType;        /* BYTE - type of tagging */
    unsigned char                   csConnectTaggedData;        /* BYTE - tagging data */
    unsigned long                   csConnectFlags;             /* LONGINT - (long) tell us about the connection */
    unsigned long                   csDisplayComponent;         /* LONGINT - (long) if the card has a direct connection to the display, it returns the display component here (FUTURE) */
    unsigned long                   csConnectReserved;          /* LONGINT - (long) reserved */
};
typedef struct VDDisplayConnectInfoRec  VDDisplayConnectInfoRec;

typedef VDDisplayConnectInfoRec *       VDDisplayConnectInfoPtr;

struct VDMultiConnectInfoRec {
    unsigned long                   csDisplayCountOrNumber;     /* For GetMultiConnect, returns count n of 1..n connections; otherwise, indicates the ith connection.*/
    VDDisplayConnectInfoRec         csConnectInfo;              /* Standard VDDisplayConnectionInfo for connection i.*/
};
typedef struct VDMultiConnectInfoRec    VDMultiConnectInfoRec;

typedef VDMultiConnectInfoRec *         VDMultiConnectInfoPtr;
/* RawSenseCode
    This abstract data type is not exactly abstract.  Rather, it is merely enumerated constants
    for the possible raw sense code values when 'standard' sense code hardware is implemented.

    For 'standard' sense code hardware, the raw sense is obtained as follows:
        o Instruct the frame buffer controller NOT to actively drive any of the monitor sense lines
        o Read the state of the monitor sense lines 2, 1, and 0.  (2 is the MSB, 0 the LSB)

    IMPORTANT Note: 
    When the 'kTaggingInfoNonStandard' bit of 'csConnectFlags' is FALSE, then these constants 
    are valid 'csConnectTaggedType' values in 'VDDisplayConnectInfo' 

*/
typedef unsigned char                   RawSenseCode;
enum {
    kRSCZero                    = 0,
    kRSCOne                     = 1,
    kRSCTwo                     = 2,
    kRSCThree                   = 3,
    kRSCFour                    = 4,
    kRSCFive                    = 5,
    kRSCSix                     = 6,
    kRSCSeven                   = 7
};


/* ExtendedSenseCode
    This abstract data type is not exactly abstract.  Rather, it is merely enumerated constants
    for the values which are possible when the extended sense algorithm is applied to hardware
    which implements 'standard' sense code hardware.

    For 'standard' sense code hardware, the extended sense code algorithm is as follows:
    (Note:  as described here, sense line 'A' corresponds to '2', 'B' to '1', and 'C' to '0')
        o Drive sense line 'A' low and read the values of 'B' and 'C'.  
        o Drive sense line 'B' low and read the values of 'A' and 'C'.
        o Drive sense line 'C' low and read the values of 'A' and 'B'.

    In this way, a six-bit number of the form BC/AC/AB is generated. 

    IMPORTANT Note: 
    When the 'kTaggingInfoNonStandard' bit of 'csConnectFlags' is FALSE, then these constants 
    are valid 'csConnectTaggedData' values in 'VDDisplayConnectInfo' 

*/
typedef unsigned char                   ExtendedSenseCode;
enum {
    kESCZero21Inch              = 0x00,                         /* 21" RGB                     */
    kESCOnePortraitMono         = 0x14,                         /* Portrait Monochrome              */
    kESCTwo12Inch               = 0x21,                         /* 12" RGB                    */
    kESCThree21InchRadius       = 0x31,                         /* 21" RGB (Radius)               */
    kESCThree21InchMonoRadius   = 0x34,                         /* 21" Monochrome (Radius)           */
    kESCThree21InchMono         = 0x35,                         /* 21" Monochrome               */
    kESCFourNTSC                = 0x0A,                         /* NTSC                     */
    kESCFivePortrait            = 0x1E,                         /* Portrait RGB              */
    kESCSixMSB1                 = 0x03,                         /* MultiScan Band-1 (12" thru 1Six")  */
    kESCSixMSB2                 = 0x0B,                         /* MultiScan Band-2 (13" thru 19")       */
    kESCSixMSB3                 = 0x23,                         /* MultiScan Band-3 (13" thru 21")       */
    kESCSixStandard             = 0x2B,                         /* 13"/14" RGB or 12" Monochrome   */
    kESCSevenPAL                = 0x00,                         /* PAL                        */
    kESCSevenNTSC               = 0x14,                         /* NTSC                     */
    kESCSevenVGA                = 0x17,                         /* VGA                        */
    kESCSeven16Inch             = 0x2D,                         /* 16" RGB (GoldFish)               */
    kESCSevenPALAlternate       = 0x30,                         /* PAL (Alternate)                */
    kESCSeven19Inch             = 0x3A,                         /* Third-Party 19"                 */
    kESCSevenDDC                = 0x3E,                         /* DDC display                   */
    kESCSevenNoDisplay          = 0x3F                          /* No display connected           */
};

/* DepthMode
    This abstract data type is used to to reference RELATIVE pixel depths.
    Its definition is largely derived from its past usage, analogous to 'xxxVidMode'

    Bits per pixel DOES NOT directly map to 'DepthMode'  For example, on some
    graphics hardware, 'kDepthMode1' may represent 1 BPP, whereas on other
    hardware, 'kDepthMode1' may represent 8BPP.

    DepthMode IS considered to be ordinal, i.e., operations such as <, >, ==, etc.
    behave as expected.  The values of the constants which comprise the set are such
    that 'kDepthMode4 < kDepthMode6' behaves as expected.
*/
typedef unsigned short                  DepthMode;
enum {
    kDepthMode1                 = 128,
    kDepthMode2                 = 129,
    kDepthMode3                 = 130,
    kDepthMode4                 = 131,
    kDepthMode5                 = 132,
    kDepthMode6                 = 133
};

enum {
    kFirstDepthMode             = 128,                          /* These constants are obsolete, and just included    */
    kSecondDepthMode            = 129,                          /* for clients that have converted to the above     */
    kThirdDepthMode             = 130,                          /* kDepthModeXXX constants.                */
    kFourthDepthMode            = 131,
    kFifthDepthMode             = 132,
    kSixthDepthMode             = 133
};



struct VDPageInfo {
    short                           csMode;                     /*(word) mode within device*/
    long                            csData;                     /*(long) data supplied by driver*/
    short                           csPage;                     /*(word) page to switch in*/
    Ptr                             csBaseAddr;                 /*(long) base address of page*/
};
typedef struct VDPageInfo               VDPageInfo;

typedef VDPageInfo *                    VDPgInfoPtr;

struct VDSizeInfo {
    short                           csHSize;                    /*(word) desired/returned h size*/
    short                           csHPos;                     /*(word) desired/returned h position*/
    short                           csVSize;                    /*(word) desired/returned v size*/
    short                           csVPos;                     /*(word) desired/returned v position*/
};
typedef struct VDSizeInfo               VDSizeInfo;

typedef VDSizeInfo *                    VDSzInfoPtr;

struct VDSettings {
    short                           csParamCnt;                 /*(word) number of params*/
    short                           csBrightMax;                /*(word) max brightness*/
    short                           csBrightDef;                /*(word) default brightness*/
    short                           csBrightVal;                /*(word) current brightness*/
    short                           csCntrstMax;                /*(word) max contrast*/
    short                           csCntrstDef;                /*(word) default contrast*/
    short                           csCntrstVal;                /*(word) current contrast*/
    short                           csTintMax;                  /*(word) max tint*/
    short                           csTintDef;                  /*(word) default tint*/
    short                           csTintVal;                  /*(word) current tint*/
    short                           csHueMax;                   /*(word) max hue*/
    short                           csHueDef;                   /*(word) default hue*/
    short                           csHueVal;                   /*(word) current hue*/
    short                           csHorizDef;                 /*(word) default horizontal*/
    short                           csHorizVal;                 /*(word) current horizontal*/
    short                           csHorizMax;                 /*(word) max horizontal*/
    short                           csVertDef;                  /*(word) default vertical*/
    short                           csVertVal;                  /*(word) current vertical*/
    short                           csVertMax;                  /*(word) max vertical*/
};
typedef struct VDSettings               VDSettings;
typedef VDSettings *                    VDSettingsPtr;

struct VDDefMode {
    UInt8                           csID;
    SInt8                           filler;
};
typedef struct VDDefMode                VDDefMode;
typedef VDDefMode *                     VDDefModePtr;

struct VDSyncInfoRec {
    UInt8                           csMode;
    UInt8                           csFlags;
};
typedef struct VDSyncInfoRec            VDSyncInfoRec;

typedef VDSyncInfoRec *                 VDSyncInfoPtr;
typedef UInt32                          AVIDType;
typedef AVIDType                        DisplayIDType;
typedef UInt32                          DisplayModeID;
typedef UInt32                          VideoDeviceType;
typedef UInt32                          GammaTableID;
/*
   All displayModeID values from 0x80000000 to 0xFFFFFFFF and 0x00
   are reserved for Apple Computer.
*/
/* Constants for the cscGetNextResolution call */
enum {
    kDisplayModeIDCurrent       = 0x00,                         /* Reference the Current DisplayModeID */
    kDisplayModeIDInvalid       = (long)0xFFFFFFFF,             /* A bogus DisplayModeID in all cases */
    kDisplayModeIDFindFirstResolution = (long)0xFFFFFFFE,       /* Used in cscGetNextResolution to reset iterator */
    kDisplayModeIDNoMoreResolutions = (long)0xFFFFFFFD,         /* Used in cscGetNextResolution to indicate End Of List */
    kDisplayModeIDFindFirstProgrammable = (long)0xFFFFFFFC,     /* Used in cscGetNextResolution to find unused programmable timing */
    kDisplayModeIDBootProgrammable = (long)0xFFFFFFFB,          /* This is the ID given at boot time by the OF driver to a programmable timing */
    kDisplayModeIDReservedBase  = (long)0x80000000              /* Lowest (unsigned) DisplayModeID reserved by Apple */
};

/* Constants for the GetGammaInfoList call */
enum {
    kGammaTableIDFindFirst      = (long)0xFFFFFFFE,             /* Get the first gamma table ID */
    kGammaTableIDNoMoreTables   = (long)0xFFFFFFFD,             /* Used to indicate end of list */
    kGammaTableIDSpecific       = 0x00                          /* Return the info for the given table id */
};

/* Constants for GetMultiConnect call*/
enum {
    kGetConnectionCount         = (long)0xFFFFFFFF,             /* Used to get the number of possible connections in a "multi-headed" framebuffer environment.*/
    kActivateConnection         = (0 << kConnectionInactive),   /* Used for activating a connection (csConnectFlags value).*/
    kDeactivateConnection       = (1 << kConnectionInactive)    /* Used for deactivating a connection (csConnectFlags value.)*/
};

/* VDCommunicationRec.csBusID values*/
enum {
    kVideoDefaultBus            = 0
};


/* VDCommunicationInfoRec.csBusType values*/
enum {
    kVideoBusTypeInvalid        = 0,
    kVideoBusTypeI2C            = 1
};


/* VDCommunicationRec.csSendType and VDCommunicationRec.csReplyType values*/
enum {
    kVideoNoTransactionType     = 0,                            /* No transaction*/
    kVideoSimpleI2CType         = 1,                            /* Simple I2C message*/
    kVideoDDCciReplyType        = 2                             /* DDC/ci message (with imbedded length)*/
};




struct VDResolutionInfoRec {
    DisplayModeID                   csPreviousDisplayModeID;    /* ID of the previous resolution in a chain */
    DisplayModeID                   csDisplayModeID;            /* ID of the next resolution */
    unsigned long                   csHorizontalPixels;         /* # of pixels in a horizontal line at the max depth */
    unsigned long                   csVerticalLines;            /* # of lines in a screen at the max depth */
    Fixed                           csRefreshRate;              /* Vertical Refresh Rate in Hz */
    DepthMode                       csMaxDepthMode;             /* 0x80-based number representing max bit depth */
    unsigned long                   csResolutionFlags;          /* Reserved - flag bits */
    unsigned long                   csReserved;                 /* Reserved */
};
typedef struct VDResolutionInfoRec      VDResolutionInfoRec;

typedef VDResolutionInfoRec *           VDResolutionInfoPtr;

struct VDVideoParametersInfoRec {
    DisplayModeID                   csDisplayModeID;            /* the ID of the resolution we want info on */
    DepthMode                       csDepthMode;                /* The bit depth we want the info on (0x80 based) */
    VPBlockPtr                      csVPBlockPtr;               /* Pointer to a video parameter block */
    unsigned long                   csPageCount;                /* Number of pages supported by the resolution */
    VideoDeviceType                 csDeviceType;               /* Device Type:  Direct, Fixed or CLUT; */
    UInt32                          csDepthFlags;               /* Flags */
};
typedef struct VDVideoParametersInfoRec VDVideoParametersInfoRec;

typedef VDVideoParametersInfoRec *      VDVideoParametersInfoPtr;

struct VDGammaInfoRec {
    GammaTableID                    csLastGammaID;              /* the ID of the previous gamma table */
    GammaTableID                    csNextGammaID;              /* the ID of the next gamma table */
    Ptr                             csGammaPtr;                 /* Ptr to a gamma table data */
    unsigned long                   csReserved;                 /* Reserved */
};
typedef struct VDGammaInfoRec           VDGammaInfoRec;

typedef VDGammaInfoRec *                VDGammaInfoPtr;

struct VDGetGammaListRec {
    GammaTableID                    csPreviousGammaTableID;     /* ID of the previous gamma table */
    GammaTableID                    csGammaTableID;             /* ID of the gamma table following csPreviousDisplayModeID */
    unsigned long                   csGammaTableSize;           /* Size of the gamma table in bytes */
    char *                          csGammaTableName;           /* Gamma table name (c-string) */
};
typedef struct VDGetGammaListRec        VDGetGammaListRec;

typedef VDGetGammaListRec *             VDGetGammaListPtr;

struct VDRetrieveGammaRec {
    GammaTableID                    csGammaTableID;             /* ID of gamma table to retrieve */
    GammaTbl *                      csGammaTablePtr;            /* Location to copy desired gamma to */
};
typedef struct VDRetrieveGammaRec       VDRetrieveGammaRec;

typedef VDRetrieveGammaRec *            VDRetrieveGammaPtr;

struct VDSetHardwareCursorRec {
    void *                          csCursorRef;                /* reference to cursor data */
    UInt32                          csReserved1;                /* reserved for future use */
    UInt32                          csReserved2;                /* should be ignored */
};
typedef struct VDSetHardwareCursorRec   VDSetHardwareCursorRec;

typedef VDSetHardwareCursorRec *        VDSetHardwareCursorPtr;

struct VDDrawHardwareCursorRec {
    SInt32                          csCursorX;                  /* x coordinate */
    SInt32                          csCursorY;                  /* y coordinate */
    UInt32                          csCursorVisible;            /* true if cursor is must be visible */
    UInt32                          csReserved1;                /* reserved for future use */
    UInt32                          csReserved2;                /* should be ignored */
};
typedef struct VDDrawHardwareCursorRec  VDDrawHardwareCursorRec;

typedef VDDrawHardwareCursorRec *       VDDrawHardwareCursorPtr;

struct VDSupportsHardwareCursorRec {
    UInt32                          csSupportsHardwareCursor;
                                                                /* true if hardware cursor is supported */
    UInt32                          csReserved1;                /* reserved for future use */
    UInt32                          csReserved2;                /* must be zero */
};
typedef struct VDSupportsHardwareCursorRec VDSupportsHardwareCursorRec;

typedef VDSupportsHardwareCursorRec *   VDSupportsHardwareCursorPtr;

struct VDHardwareCursorDrawStateRec {
    SInt32                          csCursorX;                  /* x coordinate */
    SInt32                          csCursorY;                  /* y coordinate */
    UInt32                          csCursorVisible;            /* true if cursor is visible */
    UInt32                          csCursorSet;                /* true if cursor successfully set by last set control call */
    UInt32                          csReserved1;                /* reserved for future use */
    UInt32                          csReserved2;                /* must be zero */
};
typedef struct VDHardwareCursorDrawStateRec VDHardwareCursorDrawStateRec;

typedef VDHardwareCursorDrawStateRec *  VDHardwareCursorDrawStatePtr;

struct VDConvolutionInfoRec {
    DisplayModeID                   csDisplayModeID;            /* the ID of the resolution we want info on */
    DepthMode                       csDepthMode;                /* The bit depth we want the info on (0x80 based) */
    unsigned long                   csPage;
    UInt32                          csFlags;
    UInt32                          csReserved;
};
typedef struct VDConvolutionInfoRec     VDConvolutionInfoRec;

typedef VDConvolutionInfoRec *          VDConvolutionInfoPtr;

struct VDPowerStateRec {
    unsigned long                   powerState;
    unsigned long                   powerFlags;

    unsigned long                   powerReserved1;
    unsigned long                   powerReserved2;
};
typedef struct VDPowerStateRec          VDPowerStateRec;

typedef VDPowerStateRec *               VDPowerStatePtr;
/*
    Private Data to video drivers.
    
    In versions of MacOS with multiple address spaces (System 8), the OS 
    must know the extent of parameters in order to move them between the caller
    and driver.  The old private-selector model for video drivers does not have
    this information so:
    
    For post-7.x Systems private calls should be implemented using the cscPrivateCall
*/

struct VDPrivateSelectorDataRec {
    LogicalAddress                  privateParameters;          /* Caller's parameters*/
    ByteCount                       privateParametersSize;      /* Size of data sent from caller to driver*/
    LogicalAddress                  privateResults;             /* Caller's return area. Can be nil, or same as privateParameters.*/
    ByteCount                       privateResultsSize;         /* Size of data driver returns to caller. Can be nil, or same as privateParametersSize.*/
};
typedef struct VDPrivateSelectorDataRec VDPrivateSelectorDataRec;


struct VDPrivateSelectorRec {
    UInt32                          reserved;                   /* Reserved (set to 0). */
    VDPrivateSelectorDataRec        data[1];
};
typedef struct VDPrivateSelectorRec     VDPrivateSelectorRec;

struct VDDDCBlockRec {
    UInt32                          ddcBlockNumber;             /* Input -- DDC EDID (Extended Display Identification Data) number (1-based) */
    ResType                         ddcBlockType;               /* Input -- DDC block type (EDID/VDIF) */
    UInt32                          ddcFlags;                   /* Input -- DDC Flags*/
    UInt32                          ddcReserved;                /* Reserved */
    Byte                            ddcBlockData[128];          /* Output -- DDC EDID/VDIF data (kDDCBlockSize) */
};
typedef struct VDDDCBlockRec            VDDDCBlockRec;

typedef VDDDCBlockRec *                 VDDDCBlockPtr;

enum {
                                                                /* timingSyncConfiguration*/
    kSyncInterlaceMask          = (1 << 7),
    kSyncAnalogCompositeMask    = 0,
    kSyncAnalogCompositeSerrateMask = (1 << 2),
    kSyncAnalogCompositeRGBSyncMask = (1 << 1),
    kSyncAnalogBipolarMask      = (1 << 3),
    kSyncAnalogBipolarSerrateMask = (1 << 2),
    kSyncAnalogBipolarSRGBSyncMask = (1 << 1),
    kSyncDigitalCompositeMask   = (1 << 4),
    kSyncDigitalCompositeSerrateMask = (1 << 2),
    kSyncDigitalCompositeMatchHSyncMask = (1 << 2),
    kSyncDigitalSeperateMask    = (1 << 4) + (1 << 3),
    kSyncDigitalVSyncPositiveMask = (1 << 2),
    kSyncDigitalHSyncPositiveMask = (1 << 1)
};




struct VDDisplayTimingRangeRec {
    UInt32                          csRangeSize;                /* Init to sizeof(VDDisplayTimingRangeRec) */
    UInt32                          csRangeType;                /* Init to 0 */
    UInt32                          csRangeVersion;             /* Init to 0 */
    UInt32                          csRangeReserved;            /* Init to 0 */

    UInt32                          csRangeBlockIndex;          /* Requested block (first index is 0)*/
    UInt32                          csRangeGroup;               /* set to 0 */
    UInt32                          csRangeBlockCount;          /* # blocks */
    UInt32                          csRangeFlags;               /* dependent video */

    UInt64                          csMinPixelClock;            /* Min dot clock in Hz */
    UInt64                          csMaxPixelClock;            /* Max dot clock in Hz */

    UInt32                          csMaxPixelError;            /* Max dot clock error */
    UInt32                          csTimingRangeSyncFlags;
    UInt32                          csTimingRangeSignalLevels;
    UInt32                          csReserved0;

    UInt32                          csMinFrameRate;             /* Hz */
    UInt32                          csMaxFrameRate;             /* Hz */
    UInt32                          csMinLineRate;              /* Hz */
    UInt32                          csMaxLineRate;              /* Hz */


    UInt32                          csMaxHorizontalTotal;       /* Clocks - Maximum total (active + blanking) */
    UInt32                          csMaxVerticalTotal;         /* Clocks - Maximum total (active + blanking) */
    UInt32                          csMaxTotalReserved1;        /* Reserved */
    UInt32                          csMaxTotalReserved2;        /* Reserved */



                                                                /* Some cards require that some timing elements*/
                                                                /* be multiples of a "character size" (often 8*/
                                                                /* clocks).  The "xxxxCharSize" fields document*/
                                                                /* those requirements.*/


    UInt8                           csCharSizeHorizontalActive; /* Character size */
    UInt8                           csCharSizeHorizontalBlanking; /* Character size */
    UInt8                           csCharSizeHorizontalSyncOffset; /* Character size */
    UInt8                           csCharSizeHorizontalSyncPulse; /* Character size */

    UInt8                           csCharSizeVerticalActive;   /* Character size */
    UInt8                           csCharSizeVerticalBlanking; /* Character size */
    UInt8                           csCharSizeVerticalSyncOffset; /* Character size */
    UInt8                           csCharSizeVerticalSyncPulse; /* Character size */

    UInt8                           csCharSizeHorizontalBorderLeft; /* Character size */
    UInt8                           csCharSizeHorizontalBorderRight; /* Character size */
    UInt8                           csCharSizeVerticalBorderTop; /* Character size */
    UInt8                           csCharSizeVerticalBorderBottom; /* Character size */

    UInt8                           csCharSizeHorizontalTotal;  /* Character size for active + blanking */
    UInt8                           csCharSizeVerticalTotal;    /* Character size for active + blanking */
    UInt16                          csCharSizeReserved1;        /* Reserved (Init to 0) */


    UInt32                          csMinHorizontalActiveClocks;
    UInt32                          csMaxHorizontalActiveClocks;
    UInt32                          csMinHorizontalBlankingClocks;
    UInt32                          csMaxHorizontalBlankingClocks;

    UInt32                          csMinHorizontalSyncOffsetClocks;
    UInt32                          csMaxHorizontalSyncOffsetClocks;
    UInt32                          csMinHorizontalPulseWidthClocks;
    UInt32                          csMaxHorizontalPulseWidthClocks;

    UInt32                          csMinVerticalActiveClocks;
    UInt32                          csMaxVerticalActiveClocks;
    UInt32                          csMinVerticalBlankingClocks;
    UInt32                          csMaxVerticalBlankingClocks;

    UInt32                          csMinVerticalSyncOffsetClocks;
    UInt32                          csMaxVerticalSyncOffsetClocks;
    UInt32                          csMinVerticalPulseWidthClocks;
    UInt32                          csMaxVerticalPulseWidthClocks;


    UInt32                          csMinHorizontalBorderLeft;
    UInt32                          csMaxHorizontalBorderLeft;
    UInt32                          csMinHorizontalBorderRight;
    UInt32                          csMaxHorizontalBorderRight;

    UInt32                          csMinVerticalBorderTop;
    UInt32                          csMaxVerticalBorderTop;
    UInt32                          csMinVerticalBorderBottom;
    UInt32                          csMaxVerticalBorderBottom;

    UInt32                          csReserved1;                /* Reserved (Init to 0)*/
    UInt32                          csReserved2;                /* Reserved (Init to 0)*/
    UInt32                          csReserved3;                /* Reserved (Init to 0)*/
    UInt32                          csReserved4;                /* Reserved (Init to 0)*/

    UInt32                          csReserved5;                /* Reserved (Init to 0)*/
    UInt32                          csReserved6;                /* Reserved (Init to 0)*/
    UInt32                          csReserved7;                /* Reserved (Init to 0)*/
    UInt32                          csReserved8;                /* Reserved (Init to 0)*/
};
typedef struct VDDisplayTimingRangeRec  VDDisplayTimingRangeRec;

typedef VDDisplayTimingRangeRec *       VDDisplayTimingRangePtr;

enum {
                                                                /* csDisplayModeState*/
    kDMSModeReady               = 0,                            /* Display Mode ID is configured and ready*/
    kDMSModeNotReady            = 1,                            /* Display Mode ID is is being programmed*/
    kDMSModeFree                = 2                             /* Display Mode ID is not associated with a timing*/
};


/* Video driver Errors -10930 to -10959 */
enum {
    kTimingChangeRestrictedErr  = -10930,
    kVideoI2CReplyPendingErr    = -10931,
    kVideoI2CTransactionErr     = -10932,
    kVideoI2CBusyErr            = -10933,
    kVideoI2CTransactionTypeErr = -10934,
    kVideoBufferSizeErr         = -10935
};


enum {
                                                                /* csTimingRangeSignalLevels*/
    kRangeSupportsSignal_0700_0300_Bit = 0,
    kRangeSupportsSignal_0714_0286_Bit = 1,
    kRangeSupportsSignal_1000_0400_Bit = 2,
    kRangeSupportsSignal_0700_0000_Bit = 3,
    kRangeSupportsSignal_0700_0300_Mask = (1 << kRangeSupportsSignal_0700_0300_Bit),
    kRangeSupportsSignal_0714_0286_Mask = (1 << kRangeSupportsSignal_0714_0286_Bit),
    kRangeSupportsSignal_1000_0400_Mask = (1 << kRangeSupportsSignal_1000_0400_Bit),
    kRangeSupportsSignal_0700_0000_Mask = (1 << kRangeSupportsSignal_0700_0000_Bit)
};


enum {
                                                                /* csSignalConfig*/
    kDigitalSignalBit           = 0,                            /* Do not set.  Mac OS does not currently support arbitrary digital timings*/
    kAnalogSetupExpectedBit     = 1,                            /* Analog displays - display expects a blank-to-black setup or pedestal.  See VESA signal standards.*/
    kDigitalSignalMask          = (1 << kDigitalSignalBit),
    kAnalogSetupExpectedMask    = (1 << kAnalogSetupExpectedBit)
};


enum {
                                                                /* csSignalLevels for analog*/
    kAnalogSignalLevel_0700_0300 = 0,
    kAnalogSignalLevel_0714_0286 = 1,
    kAnalogSignalLevel_1000_0400 = 2,
    kAnalogSignalLevel_0700_0000 = 3
};


enum {
                                                                /* csTimingRangeSyncFlags*/
    kRangeSupportsSeperateSyncsBit = 0,
    kRangeSupportsSyncOnGreenBit = 1,
    kRangeSupportsCompositeSyncBit = 2,
    kRangeSupportsVSyncSerrationBit = 3,
    kRangeSupportsSeperateSyncsMask = (1 << kRangeSupportsSeperateSyncsBit),
    kRangeSupportsSyncOnGreenMask = (1 << kRangeSupportsSyncOnGreenBit),
    kRangeSupportsCompositeSyncMask = (1 << kRangeSupportsCompositeSyncBit),
    kRangeSupportsVSyncSerrationMask = (1 << kRangeSupportsVSyncSerrationBit)
};



enum {
                                                                /* csHorizontalSyncConfig and csVerticalSyncConfig*/
    kSyncPositivePolarityBit    = 0,                            /* Digital separate sync polarity for analog interfaces (0 => negative polarity)*/
    kSyncPositivePolarityMask   = (1 << kSyncPositivePolarityBit)
};




/* For timings with kDetailedTimingFormat.*/

struct VDDetailedTimingRec {
    UInt32                          csTimingSize;               /* Init to sizeof(VDDetailedTimingRec)*/
    UInt32                          csTimingType;               /* Init to 0*/
    UInt32                          csTimingVersion;            /* Init to 0*/
    UInt32                          csTimingReserved;           /* Init to 0*/

    DisplayModeID                   csDisplayModeID;            /* Init to 0*/
    UInt32                          csDisplayModeSeed;          /* */
    UInt32                          csDisplayModeState;         /* Display Mode state*/
    UInt32                          csDisplayModeAlias;         /* Mode to use when programmed.*/

    UInt32                          csSignalConfig;
    UInt32                          csSignalLevels;

    UInt64                          csPixelClock;               /* Hz*/

    UInt64                          csMinPixelClock;            /* Hz - With error what is slowest actual clock */
    UInt64                          csMaxPixelClock;            /* Hz - With error what is fasted actual clock */


    UInt32                          csHorizontalActive;         /* Pixels*/
    UInt32                          csHorizontalBlanking;       /* Pixels*/
    UInt32                          csHorizontalSyncOffset;     /* Pixels*/
    UInt32                          csHorizontalSyncPulseWidth; /* Pixels*/

    UInt32                          csVerticalActive;           /* Lines*/
    UInt32                          csVerticalBlanking;         /* Lines*/
    UInt32                          csVerticalSyncOffset;       /* Lines*/
    UInt32                          csVerticalSyncPulseWidth;   /* Lines*/

    UInt32                          csHorizontalBorderLeft;     /* Pixels*/
    UInt32                          csHorizontalBorderRight;    /* Pixels*/
    UInt32                          csVerticalBorderTop;        /* Lines*/
    UInt32                          csVerticalBorderBottom;     /* Lines*/

    UInt32                          csHorizontalSyncConfig;
    UInt32                          csHorizontalSyncLevel;      /* Future use (init to 0)*/
    UInt32                          csVerticalSyncConfig;
    UInt32                          csVerticalSyncLevel;        /* Future use (init to 0)*/

    UInt32                          csReserved1;                /* Init to 0*/
    UInt32                          csReserved2;                /* Init to 0*/
    UInt32                          csReserved3;                /* Init to 0*/
    UInt32                          csReserved4;                /* Init to 0*/

    UInt32                          csReserved5;                /* Init to 0*/
    UInt32                          csReserved6;                /* Init to 0*/
    UInt32                          csReserved7;                /* Init to 0*/
    UInt32                          csReserved8;                /* Init to 0*/
};
typedef struct VDDetailedTimingRec      VDDetailedTimingRec;

typedef VDDetailedTimingRec *           VDDetailedTimingPtr;
typedef UInt32                          VDClutBehavior;
typedef VDClutBehavior *                VDClutBehaviorPtr;
enum {
    kSetClutAtSetEntries        = 0,                            /* SetEntries behavior is to update clut during SetEntries call*/
    kSetClutAtVBL               = 1                             /* SetEntries behavior is to upate clut at next vbl*/
};



struct VDCommunicationRec {
    SInt32                          csBusID;                    /* kVideoDefaultBus for single headed cards.*/
    UInt32                          csReserved0;                /* Always zero*/
    UInt32                          csReserved1;                /* Always zero*/
    UInt32                          csReserved2;                /* Always zero*/

    UInt32                          csSendAddress;              /* Usually I2C address (eg 0x6E)*/
    UInt32                          csSendType;                 /* See kVideoSimpleI2CType etc.*/
    LogicalAddress                  csSendBuffer;               /* Pointer to the send buffer*/
    ByteCount                       csSendSize;                 /* Number of bytes to send*/

    UInt32                          csReplyAddress;             /* Address from which to read (eg 0x6F for kVideoDDCciReplyType I2C address)*/
    UInt32                          csReplyType;                /* See kVideoDDCciReplyType etc.*/
    LogicalAddress                  csReplyBuffer;              /* Pointer to the reply buffer*/
    ByteCount                       csReplySize;                /* Max bytes to reply (size of csReplyBuffer)*/

    UInt32                          csReserved3;
    UInt32                          csReserved4;
    UInt32                          csReserved5;                /* Always zero*/
    UInt32                          csReserved6;                /* Always zero*/
};
typedef struct VDCommunicationRec       VDCommunicationRec;

typedef VDCommunicationRec *            VDCommunicationPtr;

struct VDCommunicationInfoRec {
    SInt32                          csBusID;                    /* kVideoDefaultBus for single headed cards. */
    UInt32                          csBusType;                  /* See kVideoBusI2C etc.*/
    SInt32                          csMinBus;                   /* Minimum bus (usually kVideoDefaultBus).  Used to probe additional busses*/
    SInt32                          csMaxBus;                   /* Max bus (usually kVideoDefaultBus).  Used to probe additional busses*/

    UInt32                          csSupportedTypes;           /* Bit field for first 32 supported transaction types.  Eg. 0x07 => support for kVideoNoTransactionType, kVideoSimpleI2CType and kVideoDDCciReplyType.*/
    UInt32                          csReserved1;                /* Always zero*/
    UInt32                          csReserved2;                /* Always zero*/
    UInt32                          csReserved3;                /* Always zero*/

    UInt32                          csReserved4;                /* Always zero*/
    UInt32                          csReserved5;                /* Always zero*/
    UInt32                          csReserved6;                /* Always zero*/
    UInt32                          csReserved7;                /* Always zero*/
};
typedef struct VDCommunicationInfoRec   VDCommunicationInfoRec;

typedef VDCommunicationInfoRec *        VDCommunicationInfoPtr;

#if PRAGMA_STRUCT_ALIGN
    #pragma options align=reset
#elif PRAGMA_STRUCT_PACKPUSH
    #pragma pack(pop)
#elif PRAGMA_STRUCT_PACK
    #pragma pack()
#endif

#ifdef PRAGMA_IMPORT_OFF
#pragma import off
#elif PRAGMA_IMPORT
#pragma import reset
#endif

#ifdef __cplusplus
}
#endif

#endif /* __IOMACOSVIDEO__ */

