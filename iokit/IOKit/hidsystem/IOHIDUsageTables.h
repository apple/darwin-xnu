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
#ifndef _IOHIDUSAGETABLES_H
#define _IOHIDUSAGETABLES_H

/* ******************************************************************************************
 * HID Usage Tables
 *
 * The following constants are from the USB 'HID Usage Tables' specification, revision 1.1rc3
 * ****************************************************************************************** */


/* Usage Pages */
enum
{
	kHIDPage_Undefined	= 0x00,
	kHIDPage_GenericDesktop	= 0x01,
	kHIDPage_Simulation	= 0x02,
	kHIDPage_VR	= 0x03,
	kHIDPage_Sport	= 0x04,
	kHIDPage_Game	= 0x05,
	/* Reserved 0x06 */
	kHIDPage_KeyboardOrKeypad	= 0x07,	/* USB Device Class Definition for Human Interface Devices (HID). Note: the usage type for all key codes is Selector (Sel). */
	kHIDPage_LEDs	= 0x08,
	kHIDPage_Button	= 0x09,
	kHIDPage_Ordinal	= 0x0A,
	kHIDPage_Telephony	= 0x0B,
	kHIDPage_Consumer	= 0x0C,
	kHIDPage_Digitizer	= 0x0D,
	/* Reserved 0x0E */
	kHIDPage_PID	= 0x0F,	/* USB Physical Interface Device definitions for force feedback and related devices. */
	kHIDPage_Unicode	= 0x10,
	/* Reserved 0x11 - 0x13 */
	kHIDPage_AlphanumericDisplay	= 0x14,
	/* Reserved 0x15 - 0x7F */
	/* Monitor 0x80 - 0x83	 USB Device Class Definition for Monitor Devices */
	/* Power 0x84 - 0x87	 USB Device Class Definition for Power Devices */
	/* Reserved 0x88 - 0x8B */
	kHIDPage_BarCodeScanner	= 0x8C,	/* (Point of Sale) USB Device Class Definition for Bar Code Scanner Devices */
	kHIDPage_Scale	= 0x8D,	/* (Point of Sale) USB Device Class Definition for Scale Devices */
	/* ReservedPointofSalepages 0x8E - 0x8F */
	kHIDPage_CameraControl	= 0x90,	/* USB Device Class Definition for Image Class Devices */
	kHIDPage_Arcade	= 0x91,	/* OAAF Definitions for arcade and coinop related Devices */
	/* Reserved 0x92 - 0xFEFF */
	/* VendorDefined 0xFF00 - 0xFFFF */
	kHIDPage_VendorDefinedStart	= 0xFF00,
};

/* Undefined Usage for all usage pages */
enum
{
	kHIDUsage_Undefined	= 0x00
};

/* GenericDesktop Page (0x01) */
enum
{
	kHIDUsage_GD_Pointer	= 0x01,	/* Physical Collection */
	kHIDUsage_GD_Mouse	= 0x02,	/* Application Collection */
	/* 0x03 Reserved */
	kHIDUsage_GD_Joystick	= 0x04,	/* Application Collection */
	kHIDUsage_GD_GamePad	= 0x05,	/* Application Collection */
	kHIDUsage_GD_Keyboard	= 0x06,	/* Application Collection */
	kHIDUsage_GD_Keypad	= 0x07,	/* Application Collection */
	kHIDUsage_GD_MultiAxisController	= 0x08,	/* Application Collection */
	/* 0x09 - 0x2F Reserved */
	kHIDUsage_GD_X	= 0x30,	/* Dynamic Value */
	kHIDUsage_GD_Y	= 0x31,	/* Dynamic Value */
	kHIDUsage_GD_Z	= 0x32,	/* Dynamic Value */
	kHIDUsage_GD_Rx	= 0x33,	/* Dynamic Value */
	kHIDUsage_GD_Ry	= 0x34,	/* Dynamic Value */
	kHIDUsage_GD_Rz	= 0x35,	/* Dynamic Value */
	kHIDUsage_GD_Slider	= 0x36,	/* Dynamic Value */
	kHIDUsage_GD_Dial	= 0x37,	/* Dynamic Value */
	kHIDUsage_GD_Wheel	= 0x38,	/* Dynamic Value */
	kHIDUsage_GD_Hatswitch	= 0x39,	/* Dynamic Value */
	kHIDUsage_GD_CountedBuffer	= 0x3A,	/* Logical Collection */
	kHIDUsage_GD_ByteCount	= 0x3B,	/* Dynamic Value */
	kHIDUsage_GD_MotionWakeup	= 0x3C,	/* One-Shot Control */
	kHIDUsage_GD_Start	= 0x3D,	/* On/Off Control */
	kHIDUsage_GD_Select	= 0x3E,	/* On/Off Control */
	/* 0x3F Reserved */
	kHIDUsage_GD_Vx	= 0x40,	/* Dynamic Value */
	kHIDUsage_GD_Vy	= 0x41,	/* Dynamic Value */
	kHIDUsage_GD_Vz	= 0x42,	/* Dynamic Value */
	kHIDUsage_GD_Vbrx	= 0x43,	/* Dynamic Value */
	kHIDUsage_GD_Vbry	= 0x44,	/* Dynamic Value */
	kHIDUsage_GD_Vbrz	= 0x45,	/* Dynamic Value */
	kHIDUsage_GD_Vno	= 0x46,	/* Dynamic Value */
	/* 0x47 - 0x7F Reserved */
	kHIDUsage_GD_SystemControl	= 0x80,	/* Application Collection */
	kHIDUsage_GD_SystemPowerDown	= 0x81,	/* One-Shot Control */
	kHIDUsage_GD_SystemSleep	= 0x82,	/* One-Shot Control */
	kHIDUsage_GD_SystemWakeUp	= 0x83,	/* One-Shot Control */
	kHIDUsage_GD_SystemContextMenu	= 0x84,	/* One-Shot Control */
	kHIDUsage_GD_SystemMainMenu	= 0x85,	/* One-Shot Control */
	kHIDUsage_GD_SystemAppMenu	= 0x86,	/* One-Shot Control */
	kHIDUsage_GD_SystemMenuHelp	= 0x87,	/* One-Shot Control */
	kHIDUsage_GD_SystemMenuExit	= 0x88,	/* One-Shot Control */
	kHIDUsage_GD_SystemMenu	= 0x89,	/* Selector */
	kHIDUsage_GD_SystemMenuRight	= 0x8A,	/* Re-Trigger Control */
	kHIDUsage_GD_SystemMenuLeft	= 0x8B,	/* Re-Trigger Control */
	kHIDUsage_GD_SystemMenuUp	= 0x8C,	/* Re-Trigger Control */
	kHIDUsage_GD_SystemMenuDown	= 0x8D,	/* Re-Trigger Control */
	/* 0x8E - 0x8F Reserved */
	kHIDUsage_GD_DPadUp	= 0x90,	/* On/Off Control */
	kHIDUsage_GD_DPadDown	= 0x91,	/* On/Off Control */
	kHIDUsage_GD_DPadRight	= 0x92,	/* On/Off Control */
	kHIDUsage_GD_DPadLeft	= 0x93,	/* On/Off Control */
	/* 0x94 - 0xFFFF Reserved */
	kHIDUsage_GD_Reserved = 0xFFFF,
};

/* Simulation Page (0x02) */
/* This section provides detailed descriptions of the usages employed by simulation devices. */
enum
{
	kHIDUsage_Sim_FlightSimulationDevice	= 0x01,	/* Application Collection */
	kHIDUsage_Sim_AutomobileSimulationDevice	= 0x02,	/* Application Collection */
	kHIDUsage_Sim_TankSimulationDevice	= 0x03,	/* Application Collection */
	kHIDUsage_Sim_SpaceshipSimulationDevice	= 0x04,	/* Application Collection */
	kHIDUsage_Sim_SubmarineSimulationDevice	= 0x05,	/* Application Collection */
	kHIDUsage_Sim_SailingSimulationDevice	= 0x06,	/* Application Collection */
	kHIDUsage_Sim_MotorcycleSimulationDevice	= 0x07,	/* Application Collection */
	kHIDUsage_Sim_SportsSimulationDevice	= 0x08,	/* Application Collection */
	kHIDUsage_Sim_AirplaneSimulationDevice	= 0x09,	/* Application Collection */
	kHIDUsage_Sim_HelicopterSimulationDevice	= 0x0A,	/* Application Collection */
	kHIDUsage_Sim_MagicCarpetSimulationDevice	= 0x0B,	/* Application Collection */
	kHIDUsage_Sim_BicycleSimulationDevice	= 0x0C,	/* Application Collection */
	/* 0x0D - 0x1F Reserved */
	kHIDUsage_Sim_FlightControlStick	= 0x20,	/* Application Collection */
	kHIDUsage_Sim_FlightStick	= 0x21,	/* Application Collection */
	kHIDUsage_Sim_CyclicControl	= 0x22,	/* Physical Collection */
	kHIDUsage_Sim_CyclicTrim	= 0x23,	/* Physical Collection */
	kHIDUsage_Sim_FlightYoke	= 0x24,	/* Application Collection */
	kHIDUsage_Sim_TrackControl	= 0x25,	/* Physical Collection */
	/* 0x26 - 0xAF Reserved */
	kHIDUsage_Sim_Aileron	= 0xB0,	/* Dynamic Value */
	kHIDUsage_Sim_AileronTrim	= 0xB1,	/* Dynamic Value */
	kHIDUsage_Sim_AntiTorqueControl	= 0xB2,	/* Dynamic Value */
	kHIDUsage_Sim_AutopilotEnable	= 0xB3,	/* On/Off Control */
	kHIDUsage_Sim_ChaffRelease	= 0xB4,	/* One-Shot Control */
	kHIDUsage_Sim_CollectiveControl	= 0xB5,	/* Dynamic Value */
	kHIDUsage_Sim_DiveBrake	= 0xB6,	/* Dynamic Value */
	kHIDUsage_Sim_ElectronicCountermeasures	= 0xB7,	/* On/Off Control */
	kHIDUsage_Sim_Elevator	= 0xB8,	/* Dynamic Value */
	kHIDUsage_Sim_ElevatorTrim	= 0xB9,	/* Dynamic Value */
	kHIDUsage_Sim_Rudder	= 0xBA,	/* Dynamic Value */
	kHIDUsage_Sim_Throttle	= 0xBB,	/* Dynamic Value */
	kHIDUsage_Sim_FlightCommunications	= 0xBC,	/* On/Off Control */
	kHIDUsage_Sim_FlareRelease	= 0xBD,	/* One-Shot Control */
	kHIDUsage_Sim_LandingGear	= 0xBE,	/* On/Off Control */
	kHIDUsage_Sim_ToeBrake	= 0xBF,	/* Dynamic Value */
	kHIDUsage_Sim_Trigger	= 0xC0,	/* Momentary Control */
	kHIDUsage_Sim_WeaponsArm	= 0xC1,	/* On/Off Control */
	kHIDUsage_Sim_Weapons	= 0xC2,	/* Selector */
	kHIDUsage_Sim_WingFlaps	= 0xC3,	/* Dynamic Value */
	kHIDUsage_Sim_Accelerator	= 0xC4,	/* Dynamic Value */
	kHIDUsage_Sim_Brake	= 0xC5,	/* Dynamic Value */
	kHIDUsage_Sim_Clutch	= 0xC6,	/* Dynamic Value */
	kHIDUsage_Sim_Shifter	= 0xC7,	/* Dynamic Value */
	kHIDUsage_Sim_Steering	= 0xC8,	/* Dynamic Value */
	kHIDUsage_Sim_TurretDirection	= 0xC9,	/* Dynamic Value */
	kHIDUsage_Sim_BarrelElevation	= 0xCA,	/* Dynamic Value */
	kHIDUsage_Sim_DivePlane	= 0xCB,	/* Dynamic Value */
	kHIDUsage_Sim_Ballast	= 0xCC,	/* Dynamic Value */
	kHIDUsage_Sim_BicycleCrank	= 0xCD,	/* Dynamic Value */
	kHIDUsage_Sim_HandleBars	= 0xCE,	/* Dynamic Value */
	kHIDUsage_Sim_FrontBrake	= 0xCF,	/* Dynamic Value */
	kHIDUsage_Sim_RearBrake	= 0xD0,	/* Dynamic Value */
	/* 0xD1 - 0xFFFF Reserved */
	kHIDUsage_Sim_Reserved = 0xFFFF,
};

/* VR Page (0x03) */
/* Virtual Reality controls depend on designators to identify the individual controls. Most of the following are */
/* usages are applied to the collections of entities that comprise the actual device. */
enum
{
	kHIDUsage_VR_Belt	= 0x01,	/* Application Collection */
	kHIDUsage_VR_BodySuit	= 0x02,	/* Application Collection */
	kHIDUsage_VR_Flexor	= 0x03,	/* Physical Collection */
	kHIDUsage_VR_Glove	= 0x04,	/* Application Collection */
	kHIDUsage_VR_HeadTracker	= 0x05,	/* Physical Collection */
	kHIDUsage_VR_HeadMountedDisplay	= 0x06,	/* Application Collection */
	kHIDUsage_VR_HandTracker	= 0x07,	/* Application Collection */
	kHIDUsage_VR_Oculometer	= 0x08,	/* Application Collection */
	kHIDUsage_VR_Vest	= 0x09,	/* Application Collection */
	kHIDUsage_VR_AnimatronicDevice	= 0x0A,	/* Application Collection */
	/* 0x0B - 0x1F Reserved */
	kHIDUsage_VR_StereoEnable	= 0x20,	/* On/Off Control */
	kHIDUsage_VR_DisplayEnable	= 0x21,	/* On/Off Control */
	/* 0x22 - 0xFFFF Reserved */
	kHIDUsage_VR_Reserved = 0xFFFF,
};

/* Sport Page (0x04) */
enum
{
	kHIDUsage_Sprt_BaseballBat	= 0x01,	/* Application Collection */
	kHIDUsage_Sprt_GolfClub	= 0x02,	/* Application Collection */
	kHIDUsage_Sprt_RowingMachine	= 0x03,	/* Application Collection */
	kHIDUsage_Sprt_Treadmill	= 0x04,	/* Application Collection */
	/* 0x05 - 0x2F Reserved */
	kHIDUsage_Sprt_Oar	= 0x30,	/* Dynamic Value */
	kHIDUsage_Sprt_Slope	= 0x31,	/* Dynamic Value */
	kHIDUsage_Sprt_Rate	= 0x32,	/* Dynamic Value */
	kHIDUsage_Sprt_StickSpeed	= 0x33,	/* Dynamic Value */
	kHIDUsage_Sprt_StickFaceAngle	= 0x34,	/* Dynamic Value */
	kHIDUsage_Sprt_StickHeelOrToe	= 0x35,	/* Dynamic Value */
	kHIDUsage_Sprt_StickFollowThrough	= 0x36,	/* Dynamic Value */
	kHIDUsage_Sprt_StickTempo	= 0x37,	/* Dynamic Value */
	kHIDUsage_Sprt_StickType	= 0x38,	/* Named Array */
	kHIDUsage_Sprt_StickHeight	= 0x39,	/* Dynamic Value */
	/* 0x3A - 0x4F Reserved */
	kHIDUsage_Sprt_Putter	= 0x50,	/* Selector */
	kHIDUsage_Sprt_1Iron	= 0x51,	/* Selector */
	kHIDUsage_Sprt_2Iron	= 0x52,	/* Selector */
	kHIDUsage_Sprt_3Iron	= 0x53,	/* Selector */
	kHIDUsage_Sprt_4Iron	= 0x54,	/* Selector */
	kHIDUsage_Sprt_5Iron	= 0x55,	/* Selector */
	kHIDUsage_Sprt_6Iron	= 0x56,	/* Selector */
	kHIDUsage_Sprt_7Iron	= 0x57,	/* Selector */
	kHIDUsage_Sprt_8Iron	= 0x58,	/* Selector */
	kHIDUsage_Sprt_9Iron	= 0x59,	/* Selector */
	kHIDUsage_Sprt_10Iron	= 0x5A,	/* Selector */
	kHIDUsage_Sprt_11Iron	= 0x5B,	/* Selector */
	kHIDUsage_Sprt_SandWedge	= 0x5C,	/* Selector */
	kHIDUsage_Sprt_LoftWedge	= 0x5D,	/* Selector */
	kHIDUsage_Sprt_PowerWedge	= 0x5E,	/* Selector */
	kHIDUsage_Sprt_1Wood	= 0x5F,	/* Selector */
	kHIDUsage_Sprt_3Wood	= 0x60,	/* Selector */
	kHIDUsage_Sprt_5Wood	= 0x61,	/* Selector */
	kHIDUsage_Sprt_7Wood	= 0x62,	/* Selector */
	kHIDUsage_Sprt_9Wood	= 0x63,	/* Selector */
	/* 0x64 - 0xFFFF Reserved */
	kHIDUsage_Sprt_Reserved = 0xFFFF,
};

/* Game Page (0x05) */
enum
{
	kHIDUsage_Game_3DGameController	= 0x01,	/* Application Collection */
	kHIDUsage_Game_PinballDevice	= 0x02,	/* Application Collection */
	kHIDUsage_Game_GunDevice	= 0x03,	/* Application Collection */
	/* 0x04 - 0x1F Reserved */
	kHIDUsage_Game_PointofView	= 0x20,	/* Physical Collection */
	kHIDUsage_Game_TurnRightOrLeft	= 0x21,	/* Dynamic Value */
	kHIDUsage_Game_PitchUpOrDown	= 0x22,	/* Dynamic Value */
	kHIDUsage_Game_RollRightOrLeft	= 0x23,	/* Dynamic Value */
	kHIDUsage_Game_MoveRightOrLeft	= 0x24,	/* Dynamic Value */
	kHIDUsage_Game_MoveForwardOrBackward	= 0x25,	/* Dynamic Value */
	kHIDUsage_Game_MoveUpOrDown	= 0x26,	/* Dynamic Value */
	kHIDUsage_Game_LeanRightOrLeft	= 0x27,	/* Dynamic Value */
	kHIDUsage_Game_LeanForwardOrBackward	= 0x28,	/* Dynamic Value */
	kHIDUsage_Game_HeightOfPOV	= 0x29,	/* Dynamic Value */
	kHIDUsage_Game_Flipper	= 0x2A,	/* Momentary Control */
	kHIDUsage_Game_SecondaryFlipper	= 0x2B,	/* Momentary Control */
	kHIDUsage_Game_Bump	= 0x2C,	/* Momentary Control */
	kHIDUsage_Game_NewGame	= 0x2D,	/* One-Shot Control */
	kHIDUsage_Game_ShootBall	= 0x2E,	/* One-Shot Control */
	kHIDUsage_Game_Player	= 0x2F,	/* One-Shot Control */
	kHIDUsage_Game_GunBolt	= 0x30,	/* On/Off Control */
	kHIDUsage_Game_GunClip	= 0x31,	/* On/Off Control */
	kHIDUsage_Game_Gun	= 0x32,	/* Selector */
	kHIDUsage_Game_GunSingleShot	= 0x33,	/* Selector */
	kHIDUsage_Game_GunBurst	= 0x34,	/* Selector */
	kHIDUsage_Game_GunAutomatic	= 0x35,	/* Selector */
	kHIDUsage_Game_GunSafety	= 0x36,	/* On/Off Control */
	kHIDUsage_Game_GamepadFireOrJump	= 0x37,	/* Logical Collection */
	kHIDUsage_Game_GamepadTrigger	= 0x39,	/* Logical Collection */
	/* 0x3A - 0xFFFF Reserved */
	kHIDUsage_Game_Reserved = 0xFFFF,
};

/* KeyboardOrKeypad Page (0x07) */
/* This section is the Usage Page for key codes to be used in implementing a USB keyboard. A Boot Keyboard (84-, 101- or 104-key) should at a minimum support all associated usage codes as indicated in the “Boot” */
/* column below. */
/* The usage type of all key codes is Selectors (Sel), except for the modifier keys Keyboard Left Control (0x224) to Keyboard Right GUI (0x231) which are Dynamic Flags (DV). */
/* Note: A general note on Usages and languages: Due to the variation of keyboards from language to language, it is not feasible to specify exact key mappings for every language. Where this list is not specific for a key function in a language, the closest equivalent key position should be used, so that a keyboard may be modified for a different language by simply printing different keycaps. One example is the Y key on a North American keyboard. In Germany this is typically Z. Rather than changing the keyboard firmware to put the Z Usage into that place in the descriptor list, the vendor should use the Y Usage on both the North American and German keyboards. This continues to be the existing practice in the industry, in order to minimize the number of changes to the electronics to accommodate otherlanguages. */
enum
{
	kHIDUsage_KeyboardErrorRollOver	= 0x01,	/* ErrorRollOver */
	kHIDUsage_KeyboardPOSTFail	= 0x02,	/* POSTFail */
	kHIDUsage_KeyboardErrorUndefined	= 0x03,	/* ErrorUndefined */
	kHIDUsage_KeyboardA	= 0x04,	/* a or A */
	kHIDUsage_KeyboardB	= 0x05,	/* b or B */
	kHIDUsage_KeyboardC	= 0x06,	/* c or C */
	kHIDUsage_KeyboardD	= 0x07,	/* d or D */
	kHIDUsage_KeyboardE	= 0x08,	/* e or E */
	kHIDUsage_KeyboardF	= 0x09,	/* f or F */
	kHIDUsage_KeyboardG	= 0x0A,	/* g or G */
	kHIDUsage_KeyboardH	= 0x0B,	/* h or H */
	kHIDUsage_KeyboardI	= 0x0C,	/* i or I */
	kHIDUsage_KeyboardJ	= 0x0D,	/* j or J */
	kHIDUsage_KeyboardK	= 0x0E,	/* k or K */
	kHIDUsage_KeyboardL	= 0x0F,	/* l or L */
	kHIDUsage_KeyboardM	= 0x10,	/* m or M */
	kHIDUsage_KeyboardN	= 0x11,	/* n or N */
	kHIDUsage_KeyboardO	= 0x12,	/* o or O */
	kHIDUsage_KeyboardP	= 0x13,	/* p or P */
	kHIDUsage_KeyboardQ	= 0x14,	/* q or Q */
	kHIDUsage_KeyboardR	= 0x15,	/* r or R */
	kHIDUsage_KeyboardS	= 0x16,	/* s or S */
	kHIDUsage_KeyboardT	= 0x17,	/* t or T */
	kHIDUsage_KeyboardU	= 0x18,	/* u or U */
	kHIDUsage_KeyboardV	= 0x19,	/* v or V */
	kHIDUsage_KeyboardW	= 0x1A,	/* w or W */
	kHIDUsage_KeyboardX	= 0x1B,	/* x or X */
	kHIDUsage_KeyboardY	= 0x1C,	/* y or Y */
	kHIDUsage_KeyboardZ	= 0x1D,	/* z or Z */
	kHIDUsage_Keyboard1	= 0x1E,	/* 1 or ! */
	kHIDUsage_Keyboard2	= 0x1F,	/* 2 or @ */
	kHIDUsage_Keyboard3	= 0x20,	/* 3 or # */
	kHIDUsage_Keyboard4	= 0x21,	/* 4 or $ */
	kHIDUsage_Keyboard5	= 0x22,	/* 5 or % */
	kHIDUsage_Keyboard6	= 0x23,	/* 6 or ^ */
	kHIDUsage_Keyboard7	= 0x24,	/* 7 or & */
	kHIDUsage_Keyboard8	= 0x25,	/* 8 or * */
	kHIDUsage_Keyboard9	= 0x26,	/* 9 or ( */
	kHIDUsage_Keyboard0	= 0x27,	/* 0 or ) */
	kHIDUsage_KeyboardReturnOrEnter	= 0x28,	/* Return (Enter) */
	kHIDUsage_KeyboardEscape	= 0x29,	/* Escape */
	kHIDUsage_KeyboardDeleteOrBackspace	= 0x2A,	/* Delete (Backspace) */
	kHIDUsage_KeyboardTab	= 0x2B,	/* Tab */
	kHIDUsage_KeyboardSpacebar	= 0x2C,	/* Spacebar */
	kHIDUsage_KeyboardHyphen	= 0x2D,	/* - or _ */
	kHIDUsage_KeyboardEqualSign	= 0x2E,	/* = or + */
	kHIDUsage_KeyboardOpenBracket	= 0x2F,	/* [ or { */
	kHIDUsage_KeyboardCloseBracket	= 0x30,	/* ] or } */
	kHIDUsage_KeyboardBackslash	= 0x31,	/* \ or | */
	kHIDUsage_KeyboardNonUSPound	= 0x32,	/* Non-US # or _ */
	kHIDUsage_KeyboardSemicolon	= 0x33,	/* ; or : */
	kHIDUsage_KeyboardQuote	= 0x34,	/* ' or " */
	kHIDUsage_KeyboardGraveAccentAndTilde	= 0x35,	/* Grave Accent and Tilde */
	kHIDUsage_KeyboardComma	= 0x36,	/* , or < */
	kHIDUsage_KeyboardPeriod	= 0x37,	/* . or > */
	kHIDUsage_KeyboardSlash	= 0x38,	/* / or ? */
	kHIDUsage_KeyboardCapsLock	= 0x39,	/* Caps Lock */
	kHIDUsage_KeyboardF1	= 0x3A,	/* F1 */
	kHIDUsage_KeyboardF2	= 0x3B,	/* F2 */
	kHIDUsage_KeyboardF3	= 0x3C,	/* F3 */
	kHIDUsage_KeyboardF4	= 0x3D,	/* F4 */
	kHIDUsage_KeyboardF5	= 0x3E,	/* F5 */
	kHIDUsage_KeyboardF6	= 0x3F,	/* F6 */
	kHIDUsage_KeyboardF7	= 0x40,	/* F7 */
	kHIDUsage_KeyboardF8	= 0x41,	/* F8 */
	kHIDUsage_KeyboardF9	= 0x42,	/* F9 */
	kHIDUsage_KeyboardF10	= 0x43,	/* F10 */
	kHIDUsage_KeyboardF11	= 0x44,	/* F11 */
	kHIDUsage_KeyboardF12	= 0x45,	/* F12 */
	kHIDUsage_KeyboardPrintScreen	= 0x46,	/* Print Screen */
	kHIDUsage_KeyboardScrollLock	= 0x47,	/* Scroll Lock */
	kHIDUsage_KeyboardPause	= 0x48,	/* Pause */
	kHIDUsage_KeyboardInsert	= 0x49,	/* Insert */
	kHIDUsage_KeyboardHome	= 0x4A,	/* Home */
	kHIDUsage_KeyboardPageUp	= 0x4B,	/* Page Up */
	kHIDUsage_KeyboardDeleteForward	= 0x4C,	/* Delete Forward */
	kHIDUsage_KeyboardEnd	= 0x4D,	/* End */
	kHIDUsage_KeyboardPageDown	= 0x4E,	/* Page Down */
	kHIDUsage_KeyboardRightArrow	= 0x4F,	/* Right Arrow */
	kHIDUsage_KeyboardLeftArrow	= 0x50,	/* Left Arrow */
	kHIDUsage_KeyboardDownArrow	= 0x51,	/* Down Arrow */
	kHIDUsage_KeyboardUpArrow	= 0x52,	/* Up Arrow */
	kHIDUsage_KeypadNumLock	= 0x53,	/* Keypad NumLock or Clear */
	kHIDUsage_KeypadSlash	= 0x54,	/* Keypad / */
	kHIDUsage_KeypadAsterisk	= 0x55,	/* Keypad * */
	kHIDUsage_KeypadHyphen	= 0x56,	/* Keypad - */
	kHIDUsage_KeypadPlus	= 0x57,	/* Keypad + */
	kHIDUsage_KeypadEnter	= 0x58,	/* Keypad Enter */
	kHIDUsage_Keypad1	= 0x59,	/* Keypad 1 or End */
	kHIDUsage_Keypad2	= 0x5A,	/* Keypad 2 or Down Arrow */
	kHIDUsage_Keypad3	= 0x5B,	/* Keypad 3 or Page Down */
	kHIDUsage_Keypad4	= 0x5C,	/* Keypad 4 or Left Arrow */
	kHIDUsage_Keypad5	= 0x5D,	/* Keypad 5 */
	kHIDUsage_Keypad6	= 0x5E,	/* Keypad 6 or Right Arrow */
	kHIDUsage_Keypad7	= 0x5F,	/* Keypad 7 or Home */
	kHIDUsage_Keypad8	= 0x60,	/* Keypad 8 or Up Arrow */
	kHIDUsage_Keypad9	= 0x61,	/* Keypad 9 or Page Up */
	kHIDUsage_Keypad0	= 0x62,	/* Keypad 0 or Insert */
	kHIDUsage_KeypadPeriod	= 0x63,	/* Keypad . or Delete */
	kHIDUsage_KeyboardNonUSBackslash	= 0x64,	/* Non-US \ or | */
	kHIDUsage_KeyboardApplication	= 0x65,	/* Application */
	kHIDUsage_KeyboardPower	= 0x66,	/* Power */
	kHIDUsage_KeypadEqualSign	= 0x67,	/* Keypad = */
	kHIDUsage_KeyboardF13	= 0x68,	/* F13 */
	kHIDUsage_KeyboardF14	= 0x69,	/* F14 */
	kHIDUsage_KeyboardF15	= 0x6A,	/* F15 */
	kHIDUsage_KeyboardF16	= 0x6B,	/* F16 */
	kHIDUsage_KeyboardF17	= 0x6C,	/* F17 */
	kHIDUsage_KeyboardF18	= 0x6D,	/* F18 */
	kHIDUsage_KeyboardF19	= 0x6E,	/* F19 */
	kHIDUsage_KeyboardF20	= 0x6F,	/* F20 */
	kHIDUsage_KeyboardF21	= 0x70,	/* F21 */
	kHIDUsage_KeyboardF22	= 0x71,	/* F22 */
	kHIDUsage_KeyboardF23	= 0x72,	/* F23 */
	kHIDUsage_KeyboardF24	= 0x73,	/* F24 */
	kHIDUsage_KeyboardExecute	= 0x74,	/* Execute */
	kHIDUsage_KeyboardHelp	= 0x75,	/* Help */
	kHIDUsage_KeyboardMenu	= 0x76,	/* Menu */
	kHIDUsage_KeyboardSelect	= 0x77,	/* Select */
	kHIDUsage_KeyboardStop	= 0x78,	/* Stop */
	kHIDUsage_KeyboardAgain	= 0x79,	/* Again */
	kHIDUsage_KeyboardUndo	= 0x7A,	/* Undo */
	kHIDUsage_KeyboardCut	= 0x7B,	/* Cut */
	kHIDUsage_KeyboardCopy	= 0x7C,	/* Copy */
	kHIDUsage_KeyboardPaste	= 0x7D,	/* Paste */
	kHIDUsage_KeyboardFind	= 0x7E,	/* Find */
	kHIDUsage_KeyboardMute	= 0x7F,	/* Mute */
	kHIDUsage_KeyboardVolumeUp	= 0x80,	/* Volume Up */
	kHIDUsage_KeyboardVolumeDown	= 0x81,	/* Volume Down */
	kHIDUsage_KeyboardLockingCapsLock	= 0x82,	/* Locking Caps Lock */
	kHIDUsage_KeyboardLockingNumLock	= 0x83,	/* Locking Num Lock */
	kHIDUsage_KeyboardLockingScrollLock	= 0x84,	/* Locking Scroll Lock */
	kHIDUsage_KeypadComma	= 0x85,	/* Keypad Comma */
	kHIDUsage_KeypadEqualSignAS400	= 0x86,	/* Keypad Equal Sign for AS/400 */
	kHIDUsage_KeyboardInternational1	= 0x87,	/* International1 */
	kHIDUsage_KeyboardInternational2	= 0x88,	/* International2 */
	kHIDUsage_KeyboardInternational3	= 0x89,	/* International3 */
	kHIDUsage_KeyboardInternational4	= 0x8A,	/* International4 */
	kHIDUsage_KeyboardInternational5	= 0x8B,	/* International5 */
	kHIDUsage_KeyboardInternational6	= 0x8C,	/* International6 */
	kHIDUsage_KeyboardInternational7	= 0x8D,	/* International7 */
	kHIDUsage_KeyboardInternational8	= 0x8E,	/* International8 */
	kHIDUsage_KeyboardInternational9	= 0x8F,	/* International9 */
	kHIDUsage_KeyboardLANG1	= 0x90,	/* LANG1 */
	kHIDUsage_KeyboardLANG2	= 0x91,	/* LANG2 */
	kHIDUsage_KeyboardLANG3	= 0x92,	/* LANG3 */
	kHIDUsage_KeyboardLANG4	= 0x93,	/* LANG4 */
	kHIDUsage_KeyboardLANG5	= 0x94,	/* LANG5 */
	kHIDUsage_KeyboardLANG6	= 0x95,	/* LANG6 */
	kHIDUsage_KeyboardLANG7	= 0x96,	/* LANG7 */
	kHIDUsage_KeyboardLANG8	= 0x97,	/* LANG8 */
	kHIDUsage_KeyboardLANG9	= 0x98,	/* LANG9 */
	kHIDUsage_KeyboardAlternateErase	= 0x99,	/* AlternateErase */
	kHIDUsage_KeyboardSysReqOrAttention	= 0x9A,	/* SysReq/Attention */
	kHIDUsage_KeyboardCancel	= 0x9B,	/* Cancel */
	kHIDUsage_KeyboardClear	= 0x9C,	/* Clear */
	kHIDUsage_KeyboardPrior	= 0x9D,	/* Prior */
	kHIDUsage_KeyboardReturn	= 0x9E,	/* Return */
	kHIDUsage_KeyboardSeparator	= 0x9F,	/* Separator */
	kHIDUsage_KeyboardOut	= 0xA0,	/* Out */
	kHIDUsage_KeyboardOper	= 0xA1,	/* Oper */
	kHIDUsage_KeyboardClearOrAgain	= 0xA2,	/* Clear/Again */
	kHIDUsage_KeyboardCrSelOrProps	= 0xA3,	/* CrSel/Props */
	kHIDUsage_KeyboardExSel	= 0xA4,	/* ExSel */
	/* 0xA5-0xDF Reserved */
	kHIDUsage_KeyboardLeftControl	= 0xE0,	/* Left Control */
	kHIDUsage_KeyboardLeftShift	= 0xE1,	/* Left Shift */
	kHIDUsage_KeyboardLeftAlt	= 0xE2,	/* Left Alt */
	kHIDUsage_KeyboardLeftGUI	= 0xE3,	/* Left GUI */
	kHIDUsage_KeyboardRightControl	= 0xE4,	/* Right Control */
	kHIDUsage_KeyboardRightShift	= 0xE5,	/* Right Shift */
	kHIDUsage_KeyboardRightAlt	= 0xE6,	/* Right Alt */
	kHIDUsage_KeyboardRightGUI	= 0xE7,	/* Right GUI */
	/* 0xE8-0xFFFF Reserved */
	kHIDUsage_Keyboard_Reserved = 0xFFFF,
};

/* LEDs Page (0x08) */
/* An LED or indicator is implemented as an On/Off Control (OOF) using the “Single button toggle” mode, where a value of 1 will turn on the indicator, and a value of 0 will turn it off. The exceptions are described below. */
enum
{
	kHIDUsage_LED_NumLock	= 0x01,	/* On/Off Control */
	kHIDUsage_LED_CapsLock	= 0x02,	/* On/Off Control */
	kHIDUsage_LED_ScrollLock	= 0x03,	/* On/Off Control */
	kHIDUsage_LED_Compose	= 0x04,	/* On/Off Control */
	kHIDUsage_LED_Kana	= 0x05,	/* On/Off Control */
	kHIDUsage_LED_Power	= 0x06,	/* On/Off Control */
	kHIDUsage_LED_Shift	= 0x07,	/* On/Off Control */
	kHIDUsage_LED_DoNotDisturb	= 0x08,	/* On/Off Control */
	kHIDUsage_LED_Mute	= 0x09,	/* On/Off Control */
	kHIDUsage_LED_ToneEnable	= 0x0A,	/* On/Off Control */
	kHIDUsage_LED_HighCutFilter	= 0x0B,	/* On/Off Control */
	kHIDUsage_LED_LowCutFilter	= 0x0C,	/* On/Off Control */
	kHIDUsage_LED_EqualizerEnable	= 0x0D,	/* On/Off Control */
	kHIDUsage_LED_SoundFieldOn	= 0x0E,	/* On/Off Control */
	kHIDUsage_LED_SurroundOn	= 0x0F,	/* On/Off Control */
	kHIDUsage_LED_Repeat	= 0x10,	/* On/Off Control */
	kHIDUsage_LED_Stereo	= 0x11,	/* On/Off Control */
	kHIDUsage_LED_SamplingRateDetect	= 0x12,	/* On/Off Control */
	kHIDUsage_LED_Spinning	= 0x13,	/* On/Off Control */
	kHIDUsage_LED_CAV	= 0x14,	/* On/Off Control */
	kHIDUsage_LED_CLV	= 0x15,	/* On/Off Control */
	kHIDUsage_LED_RecordingFormatDetect	= 0x16,	/* On/Off Control */
	kHIDUsage_LED_OffHook	= 0x17,	/* On/Off Control */
	kHIDUsage_LED_Ring	= 0x18,	/* On/Off Control */
	kHIDUsage_LED_MessageWaiting	= 0x19,	/* On/Off Control */
	kHIDUsage_LED_DataMode	= 0x1A,	/* On/Off Control */
	kHIDUsage_LED_BatteryOperation	= 0x1B,	/* On/Off Control */
	kHIDUsage_LED_BatteryOK	= 0x1C,	/* On/Off Control */
	kHIDUsage_LED_BatteryLow	= 0x1D,	/* On/Off Control */
	kHIDUsage_LED_Speaker	= 0x1E,	/* On/Off Control */
	kHIDUsage_LED_HeadSet	= 0x1F,	/* On/Off Control */
	kHIDUsage_LED_Hold	= 0x20,	/* On/Off Control */
	kHIDUsage_LED_Microphone	= 0x21,	/* On/Off Control */
	kHIDUsage_LED_Coverage	= 0x22,	/* On/Off Control */
	kHIDUsage_LED_NightMode	= 0x23,	/* On/Off Control */
	kHIDUsage_LED_SendCalls	= 0x24,	/* On/Off Control */
	kHIDUsage_LED_CallPickup	= 0x25,	/* On/Off Control */
	kHIDUsage_LED_Conference	= 0x26,	/* On/Off Control */
	kHIDUsage_LED_StandBy	= 0x27,	/* On/Off Control */
	kHIDUsage_LED_CameraOn	= 0x28,	/* On/Off Control */
	kHIDUsage_LED_CameraOff	= 0x29,	/* On/Off Control */
	kHIDUsage_LED_OnLine	= 0x2A,	/* On/Off Control */
	kHIDUsage_LED_OffLine	= 0x2B,	/* On/Off Control */
	kHIDUsage_LED_Busy	= 0x2C,	/* On/Off Control */
	kHIDUsage_LED_Ready	= 0x2D,	/* On/Off Control */
	kHIDUsage_LED_PaperOut	= 0x2E,	/* On/Off Control */
	kHIDUsage_LED_PaperJam	= 0x2F,	/* On/Off Control */
	kHIDUsage_LED_Remote	= 0x30,	/* On/Off Control */
	kHIDUsage_LED_Forward	= 0x31,	/* On/Off Control */
	kHIDUsage_LED_Reverse	= 0x32,	/* On/Off Control */
	kHIDUsage_LED_Stop	= 0x33,	/* On/Off Control */
	kHIDUsage_LED_Rewind	= 0x34,	/* On/Off Control */
	kHIDUsage_LED_FastForward	= 0x35,	/* On/Off Control */
	kHIDUsage_LED_Play	= 0x36,	/* On/Off Control */
	kHIDUsage_LED_Pause	= 0x37,	/* On/Off Control */
	kHIDUsage_LED_Record	= 0x38,	/* On/Off Control */
	kHIDUsage_LED_Error	= 0x39,	/* On/Off Control */
	kHIDUsage_LED_Usage	= 0x3A,	/* Selector */
	kHIDUsage_LED_UsageInUseIndicator	= 0x3B,	/* Usage Switch */
	kHIDUsage_LED_UsageMultiModeIndicator	= 0x3C,	/* Usage Modifier */
	kHIDUsage_LED_IndicatorOn	= 0x3D,	/* Selector */
	kHIDUsage_LED_IndicatorFlash	= 0x3E,	/* Selector */
	kHIDUsage_LED_IndicatorSlowBlink	= 0x3F,	/* Selector */
	kHIDUsage_LED_IndicatorFastBlink	= 0x40,	/* Selector */
	kHIDUsage_LED_IndicatorOff	= 0x41,	/* Selector */
	kHIDUsage_LED_FlashOnTime	= 0x42,	/* Dynamic Value */
	kHIDUsage_LED_SlowBlinkOnTime	= 0x43,	/* Dynamic Value */
	kHIDUsage_LED_SlowBlinkOffTime	= 0x44,	/* Dynamic Value */
	kHIDUsage_LED_FastBlinkOnTime	= 0x45,	/* Dynamic Value */
	kHIDUsage_LED_FastBlinkOffTime	= 0x46,	/* Dynamic Value */
	kHIDUsage_LED_UsageIndicatorColor	= 0x47,	/* Usage Modifier */
	kHIDUsage_LED_IndicatorRed	= 0x48,	/* Selector */
	kHIDUsage_LED_IndicatorGreen	= 0x49,	/* Selector */
	kHIDUsage_LED_IndicatorAmber	= 0x4A,	/* Selector */
	kHIDUsage_LED_GenericIndicator	= 0x4B,	/* On/Off Control */
	kHIDUsage_LED_SystemSuspend	= 0x4C,	/* On/Off Control */
	kHIDUsage_LED_ExternalPowerConnected	= 0x4D,	/* On/Off Control */
	/* 0x4E - 0xFFFF Reserved */
	kHIDUsage_LED_Reserved = 0xFFFF,
};

/* Button Page (0x09) */
/* The Button page is the first place an application should look for user selection controls. System graphical user interfaces typically employ a pointer and a set of hierarchical selectors to select, move and otherwise manipulate their environment. For these purposes the following assignment of significance can be applied to the Button usages: */
/* • Button 1, Primary Button. Used for object selecting, dragging, and double click activation. On MacOS, this is the only button. Microsoft operating systems call this a logical left button, because it */
/* is not necessarily physically located on the left of the pointing device. */
/* • Button 2, Secondary Button. Used by newer graphical user interfaces to browse object properties. Exposed by systems to applications that typically assign application-specific functionality. */
/* • Button 3, Tertiary Button. Optional control. Exposed to applications, but seldom assigned functionality due to prevalence of two- and one-button devices. */
/* • Buttons 4 -55. As the button number increases, its significance as a selector decreases. */
/* In many ways the assignment of button numbers is similar to the assignment of Effort in Physical descriptors. Button 1 would be used to define the button a finger rests on when the hand is in the “at rest” position, that is, virtually no effort is required by the user to activate the button. Button values increment as the finger has to stretch to reach a control. See Section 6.2.3, “Physical Descriptors,” in the HID Specification for methods of further qualifying buttons. */
enum
{
	kHIDUsage_Button_1	= 0x01,	/* (primary/trigger) */
	kHIDUsage_Button_2	= 0x02,	/* (secondary) */
	kHIDUsage_Button_3	= 0x03,	/* (tertiary) */
	kHIDUsage_Button_4	= 0x04, /* 4th button */
	/* ... */
	kHIDUsage_Button_65535	= 0xFFFF,
};

/* Ordinal Page (0x0A) */
/* The Ordinal page allows multiple instances of a control or sets of controls to be declared without requiring individual enumeration in the native usage page. For example, it is not necessary to declare usages of Pointer 1, Pointer 2, and so forth on the Generic Desktop page. When parsed, the ordinal instance number is, in essence, concatenated to the usages attached to the encompassing collection to create Pointer 1, Pointer 2, and so forth. */
/* For an example, see Section A.5, “Multiple Instances of a Control,” in Appendix A, “Usage Examples.” By convention, an Ordinal collection is placed inside the collection for which it is declaring multiple instances. */
/* Instances do not have to be identical. */
enum
{
	/* 0x00 Reserved */
	kHIDUsage_Ord_Instance1	= 0x01,	/* Usage Modifier */
	kHIDUsage_Ord_Instance2	= 0x02,	/* Usage Modifier */
	kHIDUsage_Ord_Instance3	= 0x03,	/* Usage Modifier */
	kHIDUsage_Ord_Instance4	= 0x04,	/* Usage Modifier */
	kHIDUsage_Ord_Instance65535	= 0xFFFF,	/* Usage Modifier */
};

/* Telephony Page (0x0B) */
/* This usage page defines the keytop and control usages for telephony devices. */
/* Indicators on a phone are handled by wrapping them in LED: Usage In Use Indicator and LED: Usage Selected Indicator usages. For example, a message-indicator LED would be identified by a Telephony: Message usage declared as a Feature or Output in a LED: Usage In Use Indicator collection. */
/* See Section 14, “Consumer Page (0x0C),” for audio volume and tone controls. */
enum
{
	kHIDUsage_Tfon_Phone	= 0x01,	/* Application Collection */
	kHIDUsage_Tfon_AnsweringMachine	= 0x02,	/* Application Collection */
	kHIDUsage_Tfon_MessageControls	= 0x03,	/* Logical Collection */
	kHIDUsage_Tfon_Handset	= 0x04,	/* Logical Collection */
	kHIDUsage_Tfon_Headset	= 0x05,	/* Logical Collection */
	kHIDUsage_Tfon_TelephonyKeyPad	= 0x06,	/* Named Array */
	kHIDUsage_Tfon_ProgrammableButton	= 0x07,	/* Named Array */
	/* 0x08 - 0x1F Reserved */
	kHIDUsage_Tfon_HookSwitch	= 0x20,	/* On/Off Control */
	kHIDUsage_Tfon_Flash	= 0x21,	/* Momentary Control */
	kHIDUsage_Tfon_Feature	= 0x22,	/* One-Shot Control */
	kHIDUsage_Tfon_Hold	= 0x23,	/* On/Off Control */
	kHIDUsage_Tfon_Redial	= 0x24,	/* One-Shot Control */
	kHIDUsage_Tfon_Transfer	= 0x25,	/* One-Shot Control */
	kHIDUsage_Tfon_Drop	= 0x26,	/* One-Shot Control */
	kHIDUsage_Tfon_Park	= 0x27,	/* On/Off Control */
	kHIDUsage_Tfon_ForwardCalls	= 0x28,	/* On/Off Control */
	kHIDUsage_Tfon_AlternateFunction	= 0x29,	/* Momentary Control */
	kHIDUsage_Tfon_Line	= 0x2A,	/* One-Shot Control */
	kHIDUsage_Tfon_SpeakerPhone	= 0x2B,	/* On/Off Control */
	kHIDUsage_Tfon_Conference	= 0x2C,	/* On/Off Control */
	kHIDUsage_Tfon_RingEnable	= 0x2D,	/* On/Off Control */
	kHIDUsage_Tfon_Ring	= 0x2E,	/* Selector */
	kHIDUsage_Tfon_PhoneMute	= 0x2F,	/* On/Off Control */
	kHIDUsage_Tfon_CallerID	= 0x30,	/* Momentary Control */
	/* 0x31 - 0x4F Reserved */
	kHIDUsage_Tfon_SpeedDial	= 0x50,	/* One-Shot Control */
	kHIDUsage_Tfon_StoreNumber	= 0x51,	/* One-Shot Control */
	kHIDUsage_Tfon_RecallNumber	= 0x52,	/* One-Shot Control */
	kHIDUsage_Tfon_PhoneDirectory	= 0x53,	/* On/Off Control */
	/* 0x54 - 0x6F Reserved */
	kHIDUsage_Tfon_VoiceMail	= 0x70,	/* On/Off Control */
	kHIDUsage_Tfon_ScreenCalls	= 0x71,	/* On/Off Control */
	kHIDUsage_Tfon_DoNotDisturb	= 0x72,	/* On/Off Control */
	kHIDUsage_Tfon_Message	= 0x73,	/* One-Shot Control */
	kHIDUsage_Tfon_AnswerOnOrOff	= 0x74,	/* On/Off Control */
	/* 0x75 - 0x8F Reserved */
	kHIDUsage_Tfon_InsideDialTone	= 0x90,	/* Momentary Control */
	kHIDUsage_Tfon_OutsideDialTone	= 0x91,	/* Momentary Control */
	kHIDUsage_Tfon_InsideRingTone	= 0x92,	/* Momentary Control */
	kHIDUsage_Tfon_OutsideRingTone	= 0x93,	/* Momentary Control */
	kHIDUsage_Tfon_PriorityRingTone	= 0x94,	/* Momentary Control */
	kHIDUsage_Tfon_InsideRingback	= 0x95,	/* Momentary Control */
	kHIDUsage_Tfon_PriorityRingback	= 0x96,	/* Momentary Control */
	kHIDUsage_Tfon_LineBusyTone	= 0x97,	/* Momentary Control */
	kHIDUsage_Tfon_ReorderTone	= 0x98,	/* Momentary Control */
	kHIDUsage_Tfon_CallWaitingTone	= 0x99,	/* Momentary Control */
	kHIDUsage_Tfon_ConfirmationTone1	= 0x9A,	/* Momentary Control */
	kHIDUsage_Tfon_ConfirmationTone2	= 0x9B,	/* Momentary Control */
	kHIDUsage_Tfon_TonesOff	= 0x9C,	/* On/Off Control */
	kHIDUsage_Tfon_OutsideRingback	= 0x9D,	/* Momentary Control */
	/* 0x9E - 0xAF Reserved */
	kHIDUsage_Tfon_PhoneKey0	= 0xB0,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey1	= 0xB1,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey2	= 0xB2,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey3	= 0xB3,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey4	= 0xB4,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey5	= 0xB5,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey6	= 0xB6,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey7	= 0xB7,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey8	= 0xB8,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKey9	= 0xB9,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKeyStar	= 0xBA,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKeyPound	= 0xBB,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKeyA	= 0xBC,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKeyB	= 0xBD,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKeyC	= 0xBE,	/* Selector/One-Shot Control */
	kHIDUsage_Tfon_PhoneKeyD	= 0xBF,	/* Selector/One-Shot Control */
	/* 0xC0 - 0xFFFF Reserved */
	kHIDUsage_TFon_Reserved = 0xFFFF,
};

/* Consumer Page (0x0C) */
/* All controls on the Consumer page are application-specific. That is, they affect a specific device, not the system as a whole. */
enum
{
	kHIDUsage_Csmr_ConsumerControl	= 0x01,	/* Application Collection */
	kHIDUsage_Csmr_NumericKeyPad	= 0x02,	/* Named Array */
	kHIDUsage_Csmr_ProgrammableButtons	= 0x03,	/* Named Array */
	/* 0x03 - 0x1F Reserved */
	kHIDUsage_Csmr_Plus10	= 0x20,	/* One-Shot Control */
	kHIDUsage_Csmr_Plus100	= 0x21,	/* One-Shot Control */
	kHIDUsage_Csmr_AMOrPM	= 0x22,	/* One-Shot Control */
	/* 0x23 - 0x3F Reserved */
	kHIDUsage_Csmr_Power	= 0x30,	/* On/Off Control */
	kHIDUsage_Csmr_Reset	= 0x31,	/* One-Shot Control */
	kHIDUsage_Csmr_Sleep	= 0x32,	/* One-Shot Control */
	kHIDUsage_Csmr_SleepAfter	= 0x33,	/* One-Shot Control */
	kHIDUsage_Csmr_SleepMode	= 0x34,	/* Re-Trigger Control */
	kHIDUsage_Csmr_Illumination	= 0x35,	/* On/Off Control */
	kHIDUsage_Csmr_FunctionButtons	= 0x36,	/* Named Array */
	/* 0x37 - 0x3F Reserved */
	kHIDUsage_Csmr_Menu	= 0x40,	/* On/Off Control */
	kHIDUsage_Csmr_MenuPick	= 0x41,	/* One-Shot Control */
	kHIDUsage_Csmr_MenuUp	= 0x42,	/* One-Shot Control */
	kHIDUsage_Csmr_MenuDown	= 0x43,	/* One-Shot Control */
	kHIDUsage_Csmr_MenuLeft	= 0x44,	/* One-Shot Control */
	kHIDUsage_Csmr_MenuRight	= 0x45,	/* One-Shot Control */
	kHIDUsage_Csmr_MenuEscape	= 0x46,	/* One-Shot Control */
	kHIDUsage_Csmr_MenuValueIncrease	= 0x47,	/* One-Shot Control */
	kHIDUsage_Csmr_MenuValueDecrease	= 0x48,	/* One-Shot Control */
	/* 0x49 - 0x5F Reserved */
	kHIDUsage_Csmr_DataOnScreen	= 0x60,	/* On/Off Control */
	kHIDUsage_Csmr_ClosedCaption	= 0x61,	/* On/Off Control */
	kHIDUsage_Csmr_ClosedCaptionSelect	= 0x62,	/* Selector */
	kHIDUsage_Csmr_VCROrTV	= 0x63,	/* On/Off Control */
	kHIDUsage_Csmr_BroadcastMode	= 0x64,	/* One-Shot Control */
	kHIDUsage_Csmr_Snapshot	= 0x65,	/* One-Shot Control */
	kHIDUsage_Csmr_Still	= 0x66,	/* One-Shot Control */
	/* 0x67 - 0x7F Reserved */
	kHIDUsage_Csmr_Selection	= 0x80,	/* Named Array */
	kHIDUsage_Csmr_Assign	= 0x81,	/* Selector */
	kHIDUsage_Csmr_ModeStep	= 0x82,	/* One-Shot Control */
	kHIDUsage_Csmr_RecallLast	= 0x83,	/* One-Shot Control */
	kHIDUsage_Csmr_EnterChannel	= 0x84,	/* One-Shot Control */
	kHIDUsage_Csmr_OrderMovie	= 0x85,	/* One-Shot Control */
	kHIDUsage_Csmr_Channel	= 0x86,	/* Linear Control */
	kHIDUsage_Csmr_MediaSelection	= 0x87,	/* Selector */
	kHIDUsage_Csmr_MediaSelectComputer	= 0x88,	/* Selector */
	kHIDUsage_Csmr_MediaSelectTV	= 0x89,	/* Selector */
	kHIDUsage_Csmr_MediaSelectWWW	= 0x8A,	/* Selector */
	kHIDUsage_Csmr_MediaSelectDVD	= 0x8B,	/* Selector */
	kHIDUsage_Csmr_MediaSelectTelephone	= 0x8C,	/* Selector */
	kHIDUsage_Csmr_MediaSelectProgramGuide	= 0x8D,	/* Selector */
	kHIDUsage_Csmr_MediaSelectVideoPhone	= 0x8E,	/* Selector */
	kHIDUsage_Csmr_MediaSelectGames	= 0x8F,	/* Selector */
	kHIDUsage_Csmr_MediaSelectMessages	= 0x90,	/* Selector */
	kHIDUsage_Csmr_MediaSelectCD	= 0x91,	/* Selector */
	kHIDUsage_Csmr_MediaSelectVCR	= 0x92,	/* Selector */
	kHIDUsage_Csmr_MediaSelectTuner	= 0x93,	/* Selector */
	kHIDUsage_Csmr_Quit	= 0x94,	/* One-Shot Control */
	kHIDUsage_Csmr_Help	= 0x95,	/* On/Off Control */
	kHIDUsage_Csmr_MediaSelectTape	= 0x96,	/* Selector */
	kHIDUsage_Csmr_MediaSelectCable	= 0x97,	/* Selector */
	kHIDUsage_Csmr_MediaSelectSatellite	= 0x98,	/* Selector */
	kHIDUsage_Csmr_MediaSelectSecurity	= 0x99,	/* Selector */
	kHIDUsage_Csmr_MediaSelectHome	= 0x9A,	/* Selector */
	kHIDUsage_Csmr_MediaSelectCall	= 0x9B,	/* Selector */
	kHIDUsage_Csmr_ChannelIncrement	= 0x9C,	/* One-Shot Control */
	kHIDUsage_Csmr_ChannelDecrement	= 0x9D,	/* One-Shot Control */
	kHIDUsage_Csmr_Media	= 0x9E,	/* Selector */
	/* 0x9F Reserved */
	kHIDUsage_Csmr_VCRPlus	= 0xA0,	/* One-Shot Control */
	kHIDUsage_Csmr_Once	= 0xA1,	/* One-Shot Control */
	kHIDUsage_Csmr_Daily	= 0xA2,	/* One-Shot Control */
	kHIDUsage_Csmr_Weekly	= 0xA3,	/* One-Shot Control */
	kHIDUsage_Csmr_Monthly	= 0xA4,	/* One-Shot Control */
	/* 0xA5 - 0xAF Reserved */
	kHIDUsage_Csmr_Play	= 0xB0,	/* On/Off Control */
	kHIDUsage_Csmr_Pause	= 0xB1,	/* On/Off Control */
	kHIDUsage_Csmr_Record	= 0xB2,	/* On/Off Control */
	kHIDUsage_Csmr_FastForward	= 0xB3,	/* On/Off Control */
	kHIDUsage_Csmr_Rewind	= 0xB4,	/* On/Off Control */
	kHIDUsage_Csmr_ScanNextTrack	= 0xB5,	/* One-Shot Control */
	kHIDUsage_Csmr_ScanPreviousTrack	= 0xB6,	/* One-Shot Control */
	kHIDUsage_Csmr_Stop	= 0xB7,	/* One-Shot Control */
	kHIDUsage_Csmr_Eject	= 0xB8,	/* One-Shot Control */
	kHIDUsage_Csmr_RandomPlay	= 0xB9,	/* On/Off Control */
	kHIDUsage_Csmr_SelectDisc	= 0xBA,	/* Named Array */
	kHIDUsage_Csmr_EnterDisc	= 0xBB,	/* Momentary Control */
	kHIDUsage_Csmr_Repeat	= 0xBC,	/* One-Shot Control */
	kHIDUsage_Csmr_Tracking	= 0xBD,	/* Linear Control */
	kHIDUsage_Csmr_TrackNormal	= 0xBE,	/* One-Shot Control */
	kHIDUsage_Csmr_SlowTracking	= 0xBF,	/* Linear Control */
	kHIDUsage_Csmr_FrameForward	= 0xC0,	/* Re-Trigger Control */
	kHIDUsage_Csmr_FrameBack	= 0xC1,	/* Re-Trigger Control */
	kHIDUsage_Csmr_Mark	= 0xC2,	/* One-Shot Control */
	kHIDUsage_Csmr_ClearMark	= 0xC3,	/* One-Shot Control */
	kHIDUsage_Csmr_RepeatFromMark	= 0xC4,	/* On/Off Control */
	kHIDUsage_Csmr_ReturnToMark	= 0xC5,	/* One-Shot Control */
	kHIDUsage_Csmr_SearchMarkForward	= 0xC6,	/* One-Shot Control */
	kHIDUsage_Csmr_SearchMarkBackwards	= 0xC7,	/* One-Shot Control */
	kHIDUsage_Csmr_CounterReset	= 0xC8,	/* One-Shot Control */
	kHIDUsage_Csmr_ShowCounter	= 0xC9,	/* One-Shot Control */
	kHIDUsage_Csmr_TrackingIncrement	= 0xCA,	/* Re-Trigger Control */
	kHIDUsage_Csmr_TrackingDecrement	= 0xCB,	/* Re-Trigger Control */
	kHIDUsage_Csmr_StopOrEject	= 0xCC,	/* One-Shot Control */
	kHIDUsage_Csmr_PlayOrPause	= 0xCD,	/* One-Shot Control */
	kHIDUsage_Csmr_PlayOrSkip	= 0xCE,	/* One-Shot Control */
	/* 0xCF - 0xDF Reserved */
	kHIDUsage_Csmr_Volume	= 0xE0,	/* Linear Control */
	kHIDUsage_Csmr_Balance	= 0xE1,	/* Linear Control */
	kHIDUsage_Csmr_Mute	= 0xE2,	/* On/Off Control */
	kHIDUsage_Csmr_Bass	= 0xE3,	/* Linear Control */
	kHIDUsage_Csmr_Treble	= 0xE4,	/* Linear Control */
	kHIDUsage_Csmr_BassBoost	= 0xE5,	/* On/Off Control */
	kHIDUsage_Csmr_SurroundMode	= 0xE6,	/* One-Shot Control */
	kHIDUsage_Csmr_Loudness	= 0xE7,	/* On/Off Control */
	kHIDUsage_Csmr_MPX	= 0xE8,	/* On/Off Control */
	kHIDUsage_Csmr_VolumeIncrement	= 0xE9,	/* Re-Trigger Control */
	kHIDUsage_Csmr_VolumeDecrement	= 0xEA,	/* Re-Trigger Control */
	/* 0xEB - 0xEF Reserved */
	kHIDUsage_Csmr_Speed	= 0xF0,	/* Selector */
	kHIDUsage_Csmr_PlaybackSpeed	= 0xF1,	/* Named Array */
	kHIDUsage_Csmr_StandardPlay	= 0xF2,	/* Selector */
	kHIDUsage_Csmr_LongPlay	= 0xF3,	/* Selector */
	kHIDUsage_Csmr_ExtendedPlay	= 0xF4,	/* Selector */
	kHIDUsage_Csmr_Slow	= 0xF5,	/* One-Shot Control */
	/* 0xF6 - 0xFF Reserved */
	kHIDUsage_Csmr_FanEnable	= 0x100,	/* On/Off Control */
	kHIDUsage_Csmr_FanSpeed	= 0x101,	/* Linear Control */
	kHIDUsage_Csmr_LightEnable	= 0x102,	/* On/Off Control */
	kHIDUsage_Csmr_LightIlluminationLevel	= 0x103,	/* Linear Control */
	kHIDUsage_Csmr_ClimateControlEnable	= 0x104,	/* On/Off Control */
	kHIDUsage_Csmr_RoomTemperature	= 0x105,	/* Linear Control */
	kHIDUsage_Csmr_SecurityEnable	= 0x106,	/* On/Off Control */
	kHIDUsage_Csmr_FireAlarm	= 0x107,	/* One-Shot Control */
	kHIDUsage_Csmr_PoliceAlarm	= 0x108,	/* One-Shot Control */
	/* 0x109 - 0x14F Reserved */
	kHIDUsage_Csmr_BalanceRight	= 0x150,	/* Re-Trigger Control */
	kHIDUsage_Csmr_BalanceLeft	= 0x151,	/* Re-Trigger Control */
	kHIDUsage_Csmr_BassIncrement	= 0x152,	/* Re-Trigger Control */
	kHIDUsage_Csmr_BassDecrement	= 0x153,	/* Re-Trigger Control */
	kHIDUsage_Csmr_TrebleIncrement	= 0x154,	/* Re-Trigger Control */
	kHIDUsage_Csmr_TrebleDecrement	= 0x155,	/* Re-Trigger Control */
	/* 0x156 - 0x15F Reserved */
	kHIDUsage_Csmr_SpeakerSystem	= 0x160,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelLeft	= 0x161,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelRight	= 0x162,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelCenter	= 0x163,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelFront	= 0x164,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelCenterFront	= 0x165,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelSide	= 0x166,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelSurround	= 0x167,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelLowFrequencyEnhancement	= 0x168,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelTop	= 0x169,	/* Logical Collection */
	kHIDUsage_Csmr_ChannelUnknown	= 0x16A,	/* Logical Collection */
	/* 0x16B - 0x16F Reserved */
	kHIDUsage_Csmr_SubChannel	= 0x170,	/* Linear Control */
	kHIDUsage_Csmr_SubChannelIncrement	= 0x171,	/* One-Shot Control */
	kHIDUsage_Csmr_SubChannelDecrement	= 0x172,	/* One-Shot Control */
	kHIDUsage_Csmr_AlternateAudioIncrement	= 0x173,	/* One-Shot Control */
	kHIDUsage_Csmr_AlternateAudioDecrement	= 0x174,	/* One-Shot Control */
	/* 0x175 - 0x17F Reserved */
	kHIDUsage_Csmr_ApplicationLaunchButtons	= 0x180,	/* Named Array */
	kHIDUsage_Csmr_ALLaunchButtonConfigurationTool	= 0x181,	/* Selector */
	kHIDUsage_Csmr_ALProgrammableButtonConfiguration	= 0x182,	/* Selector */
	kHIDUsage_Csmr_ALConsumerControlConfiguration	= 0x183,	/* Selector */
	kHIDUsage_Csmr_ALWordProcessor	= 0x184,	/* Selector */
	kHIDUsage_Csmr_ALTextEditor	= 0x185,	/* Selector */
	kHIDUsage_Csmr_ALSpreadsheet	= 0x186,	/* Selector */
	kHIDUsage_Csmr_ALGraphicsEditor	= 0x187,	/* Selector */
	kHIDUsage_Csmr_ALPresentationApp	= 0x188,	/* Selector */
	kHIDUsage_Csmr_ALDatabaseApp	= 0x189,	/* Selector */
	kHIDUsage_Csmr_ALEmailReader	= 0x18A,	/* Selector */
	kHIDUsage_Csmr_ALNewsreader	= 0x18B,	/* Selector */
	kHIDUsage_Csmr_ALVoicemail	= 0x18C,	/* Selector */
	kHIDUsage_Csmr_ALContactsOrAddressBook	= 0x18D,	/* Selector */
	kHIDUsage_Csmr_ALCalendarOrSchedule	= 0x18E,	/* Selector */
	kHIDUsage_Csmr_ALTaskOrProjectManager	= 0x18F,	/* Selector */
	kHIDUsage_Csmr_ALLogOrJournalOrTimecard	= 0x190,	/* Selector */
	kHIDUsage_Csmr_ALCheckbookOrFinance	= 0x191,	/* Selector */
	kHIDUsage_Csmr_ALCalculator	= 0x192,	/* Selector */
	kHIDUsage_Csmr_ALAOrVCaptureOrPlayback	= 0x193,	/* Selector */
	kHIDUsage_Csmr_ALLocalMachineBrowser	= 0x194,	/* Selector */
	kHIDUsage_Csmr_ALLANOrWANBrowser	= 0x195,	/* Selector */
	kHIDUsage_Csmr_ALInternetBrowser	= 0x196,	/* Selector */
	kHIDUsage_Csmr_ALRemoteNetworkingOrISPConnect	= 0x197,	/* Selector */
	kHIDUsage_Csmr_ALNetworkConference	= 0x198,	/* Selector */
	kHIDUsage_Csmr_ALNetworkChat	= 0x199,	/* Selector */
	kHIDUsage_Csmr_ALTelephonyOrDialer	= 0x19A,	/* Selector */
	kHIDUsage_Csmr_ALLogon	= 0x19B,	/* Selector */
	kHIDUsage_Csmr_ALLogoff	= 0x19C,	/* Selector */
	kHIDUsage_Csmr_ALLogonOrLogoff	= 0x19D,	/* Selector */
	kHIDUsage_Csmr_ALTerminalLockOrScreensaver	= 0x19E,	/* Selector */
	kHIDUsage_Csmr_ALControlPanel	= 0x19F,	/* Selector */
	kHIDUsage_Csmr_ALCommandLineProcessorOrRun	= 0x1A0,	/* Selector */
	kHIDUsage_Csmr_ALProcessOrTaskManager	= 0x1A1,	/* Selector */
	kHIDUsage_Csmr_AL	= 0x1A2,	/* Selector */
	kHIDUsage_Csmr_ALNextTaskOrApplication	= 0x143,	/* Selector */
	kHIDUsage_Csmr_ALPreviousTaskOrApplication	= 0x1A4,	/* Selector */
	kHIDUsage_Csmr_ALPreemptiveHaltTaskOrApplication	= 0x1A5,	/* Selector */
	/* 0x1A6 - 0x1FF Reserved */
	kHIDUsage_Csmr_GenericGUIApplicationControls	= 0x200,	/* Named Array */
	kHIDUsage_Csmr_ACNew	= 0x201,	/* Selector */
	kHIDUsage_Csmr_ACOpen	= 0x202,	/* Selector */
	kHIDUsage_Csmr_ACClose	= 0x203,	/* Selector */
	kHIDUsage_Csmr_ACExit	= 0x204,	/* Selector */
	kHIDUsage_Csmr_ACMaximize	= 0x205,	/* Selector */
	kHIDUsage_Csmr_ACMinimize	= 0x206,	/* Selector */
	kHIDUsage_Csmr_ACSave	= 0x207,	/* Selector */
	kHIDUsage_Csmr_ACPrint	= 0x208,	/* Selector */
	kHIDUsage_Csmr_ACProperties	= 0x209,	/* Selector */
	kHIDUsage_Csmr_ACUndo	= 0x21A,	/* Selector */
	kHIDUsage_Csmr_ACCopy	= 0x21B,	/* Selector */
	kHIDUsage_Csmr_ACCut	= 0x21C,	/* Selector */
	kHIDUsage_Csmr_ACPaste	= 0x21D,	/* Selector */
	kHIDUsage_Csmr_AC	= 0x21E,	/* Selector */
	kHIDUsage_Csmr_ACFind	= 0x21F,	/* Selector */
	kHIDUsage_Csmr_ACFindandReplace	= 0x220,	/* Selector */
	kHIDUsage_Csmr_ACSearch	= 0x221,	/* Selector */
	kHIDUsage_Csmr_ACGoTo	= 0x222,	/* Selector */
	kHIDUsage_Csmr_ACHome	= 0x223,	/* Selector */
	kHIDUsage_Csmr_ACBack	= 0x224,	/* Selector */
	kHIDUsage_Csmr_ACForward	= 0x225,	/* Selector */
	kHIDUsage_Csmr_ACStop	= 0x226,	/* Selector */
	kHIDUsage_Csmr_ACRefresh	= 0x227,	/* Selector */
	kHIDUsage_Csmr_ACPreviousLink	= 0x228,	/* Selector */
	kHIDUsage_Csmr_ACNextLink	= 0x229,	/* Selector */
	kHIDUsage_Csmr_ACBookmarks	= 0x22A,	/* Selector */
	kHIDUsage_Csmr_ACHistory	= 0x22B,	/* Selector */
	kHIDUsage_Csmr_ACSubscriptions	= 0x22C,	/* Selector */
	kHIDUsage_Csmr_ACZoomIn	= 0x22D,	/* Selector */
	kHIDUsage_Csmr_ACZoomOut	= 0x22E,	/* Selector */
	kHIDUsage_Csmr_ACZoom	= 0x22F,	/* Selector */
	kHIDUsage_Csmr_ACFullScreenView	= 0x230,	/* Selector */
	kHIDUsage_Csmr_ACNormalView	= 0x231,	/* Selector */
	kHIDUsage_Csmr_ACViewToggle	= 0x232,	/* Selector */
	kHIDUsage_Csmr_ACScrollUp	= 0x233,	/* Selector */
	kHIDUsage_Csmr_ACScrollDown	= 0x234,	/* Selector */
	kHIDUsage_Csmr_ACScroll	= 0x235,	/* Selector */
	kHIDUsage_Csmr_ACPanLeft	= 0x236,	/* Selector */
	kHIDUsage_Csmr_ACPanRight	= 0x237,	/* Selector */
	kHIDUsage_Csmr_ACPan	= 0x238,	/* Selector */
	kHIDUsage_Csmr_ACNewWindow	= 0x239,	/* Selector */
	kHIDUsage_Csmr_ACTileHorizontally	= 0x23A,	/* Selector */
	kHIDUsage_Csmr_ACTileVertically	= 0x23B,	/* Selector */
	kHIDUsage_Csmr_ACFormat	= 0x23C,	/* Selector */
	/* 0x23D - 0xFFFF Reserved */
	kHIDUsage_Csmr_Reserved = 0xFFFF,
};

/* Digitizer Page (0x0D) */
/* This section provides detailed descriptions of the usages employed by Digitizer Devices. */
enum
{
	kHIDUsage_Dig_Digitizer	= 0x01,	/* Application Collection */
	kHIDUsage_Dig_Pen	= 0x02,	/* Application Collection */
	kHIDUsage_Dig_LightPen	= 0x03,	/* Application Collection */
	kHIDUsage_Dig_TouchScreen	= 0x04,	/* Application Collection */
	kHIDUsage_Dig_TouchPad	= 0x05,	/* Application Collection */
	kHIDUsage_Dig_WhiteBoard	= 0x06,	/* Application Collection */
	kHIDUsage_Dig_CoordinateMeasuringMachine	= 0x07,	/* Application Collection */
	kHIDUsage_Dig_3DDigitizer	= 0x08,	/* Application Collection */
	kHIDUsage_Dig_StereoPlotter	= 0x09,	/* Application Collection */
	kHIDUsage_Dig_ArticulatedArm	= 0x0A,	/* Application Collection */
	kHIDUsage_Dig_Armature	= 0x0B,	/* Application Collection */
	kHIDUsage_Dig_MultiplePointDigitizer	= 0x0C,	/* Application Collection */
	kHIDUsage_Dig_FreeSpaceWand	= 0x0D,	/* Application Collection */
	/* 0x0E - 0x1F Reserved */
	kHIDUsage_Dig_Stylus	= 0x20,	/* Logical Collection */
	kHIDUsage_Dig_Puck	= 0x21,	/* Logical Collection */
	kHIDUsage_Dig_Finger	= 0x22,	/* Logical Collection */
	/* 0x23 - 0x2F Reserved */
	kHIDUsage_Dig_TipPressure	= 0x30,	/* Dynamic Value */
	kHIDUsage_Dig_BarrelPressure	= 0x31,	/* Dynamic Value */
	kHIDUsage_Dig_InRange	= 0x32,	/* Momentary Control */
	kHIDUsage_Dig_Touch	= 0x33,	/* Momentary Control */
	kHIDUsage_Dig_Untouch	= 0x34,	/* One-Shot Control */
	kHIDUsage_Dig_Tap	= 0x35,	/* One-Shot Control */
	kHIDUsage_Dig_Quality	= 0x36,	/* Dynamic Value */
	kHIDUsage_Dig_DataValid	= 0x37,	/* Momentary Control */
	kHIDUsage_Dig_TransducerIndex	= 0x38,	/* Dynamic Value */
	kHIDUsage_Dig_TabletFunctionKeys	= 0x39,	/* Logical Collection */
	kHIDUsage_Dig_ProgramChangeKeys	= 0x3A,	/* Logical Collection */
	kHIDUsage_Dig_BatteryStrength	= 0x3B,	/* Dynamic Value */
	kHIDUsage_Dig_Invert	= 0x3C,	/* Momentary Control */
	kHIDUsage_Dig_XTilt	= 0x3D,	/* Dynamic Value */
	kHIDUsage_Dig_YTilt	= 0x3E,	/* Dynamic Value */
	kHIDUsage_Dig_Azimuth	= 0x3F,	/* Dynamic Value */
	kHIDUsage_Dig_Altitude	= 0x40,	/* Dynamic Value */
	kHIDUsage_Dig_Twist	= 0x41,	/* Dynamic Value */
	kHIDUsage_Dig_TipSwitch	= 0x42,	/* Momentary Control */
	kHIDUsage_Dig_SecondaryTipSwitch	= 0x43,	/* Momentary Control */
	kHIDUsage_Dig_BarrelSwitch	= 0x44,	/* Momentary Control */
	kHIDUsage_Dig_Eraser	= 0x45,	/* Momentary Control */
	kHIDUsage_Dig_TabletPick	= 0x46,	/* Momentary Control */
	/* 0x47 - 0xFFFF Reserved */
	kHIDUsage_Dig_Reserved = 0xFFFF,
};

/* AlphanumericDisplay Page (0x14) */
/* The Alphanumeric Display page is intended for use by simple alphanumeric displays that are used on consumer devices. */
enum
{
	kHIDUsage_AD_AlphanumericDisplay	= 0x01,	/* Application Collection */
	/* 0x02 - 0x1F Reserved */
	kHIDUsage_AD_DisplayAttributesReport	= 0x20,	/* Logical Collection */
	kHIDUsage_AD_ASCIICharacterSet	= 0x21,	/* Static Flag */
	kHIDUsage_AD_DataReadBack	= 0x22,	/* Static Flag */
	kHIDUsage_AD_FontReadBack	= 0x23,	/* Static Flag */
	kHIDUsage_AD_DisplayControlReport	= 0x24,	/* Logical Collection */
	kHIDUsage_AD_ClearDisplay	= 0x25,	/* Dynamic Flag */
	kHIDUsage_AD_DisplayEnable	= 0x26,	/* Dynamic Flag */
	kHIDUsage_AD_ScreenSaverDelay	= 0x27,	/* Static Value */
	kHIDUsage_AD_ScreenSaverEnable	= 0x28,	/* Dynamic Flag */
	kHIDUsage_AD_VerticalScroll	= 0x29,	/* Static Flag */
	kHIDUsage_AD_HorizontalScroll	= 0x2A,	/* Static Flag */
	kHIDUsage_AD_CharacterReport	= 0x2B,	/* Logical Collection */
	kHIDUsage_AD_DisplayData	= 0x2C,	/* Dynamic Value */
	kHIDUsage_AD_DisplayStatus	= 0x2D,	/* Logical Collection */
	kHIDUsage_AD_StatNotReady	= 0x2E,	/* Selector */
	kHIDUsage_AD_StatReady	= 0x2F,	/* Selector */
	kHIDUsage_AD_ErrNotaloadablecharacter	= 0x30,	/* Selector */
	kHIDUsage_AD_ErrFontdatacannotberead	= 0x31,	/* Selector */
	kHIDUsage_AD_CursorPositionReport	= 0x32,	/* Logical Collection */
	kHIDUsage_AD_Row	= 0x33,	/* Dynamic Value */
	kHIDUsage_AD_Column	= 0x34,	/* Dynamic Value */
	kHIDUsage_AD_Rows	= 0x35,	/* Static Value */
	kHIDUsage_AD_Columns	= 0x36,	/* Static Value */
	kHIDUsage_AD_CursorPixelPositioning	= 0x37,	/* Static Flag */
	kHIDUsage_AD_CursorMode	= 0x38,	/* Dynamic Flag */
	kHIDUsage_AD_CursorEnable	= 0x39,	/* Dynamic Flag */
	kHIDUsage_AD_CursorBlink	= 0x3A,	/* Dynamic Flag */
	kHIDUsage_AD_FontReport	= 0x3B,	/* Logical Collection */
	kHIDUsage_AD_FontData	= 0x3C,	/* Buffered Byte */
	kHIDUsage_AD_CharacterWidth	= 0x3D,	/* Static Value */
	kHIDUsage_AD_CharacterHeight	= 0x3E,	/* Static Value */
	kHIDUsage_AD_CharacterSpacingHorizontal	= 0x3F,	/* Static Value */
	kHIDUsage_AD_CharacterSpacingVertical	= 0x40,	/* Static Value */
	kHIDUsage_AD_UnicodeCharacterSet	= 0x41,	/* Static Flag */
	/* 0x42 - 0xFFFF Reserved */
	kHIDUsage_AD_Reserved = 0xFFFF,
};

#endif /* _IOHIDUSAGETABLES_H */
