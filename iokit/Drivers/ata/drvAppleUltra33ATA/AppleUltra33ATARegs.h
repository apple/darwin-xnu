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
 *	PCI Control registers for Cmd646X chipset 
 *
 */
enum Ultra646RegsValues
{
    kUltra646CFR				= 0x50,		/* Configuration */
    kUltra646CFR_DSA1				= 0x40,
    kUltra646CFR_IDEIntPRI			= 0x04,

    kUltra646CNTRL				= 0x51,		/* Drive 0/1 Control Register */
    kUltra646CNTRL_Drive1ReadAhead		= 0x80,
    kUltra646CNTRL_Drive0ReadAhead		= 0x40,
    kUltra646CNTRL_EnableSDY			= 0x08,
    kUltra646CNTRL_EnablePRI			= 0x04,

    kUltra646CMDTIM				= 0x52,		/* Task file timing (all drives) */
    kUltra646CMDTIM_Drive01CmdActive		= 0xF0,
    kUltra646CMDTIM_Drive01CmdRecovery		= 0x0F,

    kUltra646ARTTIM0				= 0x53,		/* Drive 0 Address Setup */
    kUltra646ARTTIM0_Drive0AddrSetup		= 0xC0,

    kUltra646DRWTIM0				= 0x54,		/* Drive 0 Data Read/Write - DACK Time	*/
    kUltra646DRWTIM0_Drive0DataActive		= 0xF0,
    kUltra646DRWTIM0_Drive0DataRecovery		= 0x0F,

    kUltra646ARTTIM1				= 0x55,		/* Drive 1 Address Setup */
    kUltra646ARTTIM1_Drive1AddrSetup		= 0xC0,

    kUltra646DRWTIM1				= 0x56,		/* Drive 1 Data Read/Write - DACK Time */
    kUltra646DRWTIM1_Drive1DataActive		= 0xF0,
    kUltra646DRWTIM1_Drive1DataRecover		= 0x0F,

    kUltra646ARTTIM23				= 0x57,		/* Drive 2/3 Control/Status */
    kUltra646ARTTIM23_AddrSetup			= 0xC0,
    kUltra646ARTTIM23_IDEIntSDY			= 0x10,
    kUltra646ARTTIM23_Drive3ReadAhead		= 0x08,
    kUltra646ARTTIM23_Drive2ReadAhead		= 0x04,

    kUltra646DRWTIM2				= 0x58,		/* Drive 2 Read/Write - DACK Time */
    kUltra646DRWTIM2_Drive2DataActive		= 0xF0,	
    kUltra646DRWTIM2_Drive2DataRecovery		= 0x0F,

    kUltra646BRST				= 0x59,		/* Read Ahead Count */

    kUltra646DRWTIM3				= 0x5B,		/* Drive 3 Read/Write - DACK Time */
    kUltra646DRWTIM3_Drive3DataActive		= 0xF0,
    kUltra646DRWTIM3_Drive3DataRecover		= 0x0F,

    kUltra646BMIDECR0				= 0x70,		/* BusMaster Command Register - Primary */
    kUltra646BMIDECR0_PCIWritePRI		= 0x08,
    kUltra646BMIDECR0_StartDMAPRI		= 0x01,

    kUltra646MRDMODE				= 0x71,		/* DMA Master Read Mode Select */
    kUltra646MRDMODE_PCIReadMask		= 0x03,
    kUltra646MRDMODE_PCIRead			= 0x00,
    kUltra646MRDMODE_PCIReadMultiple		= 0x01,
    kUltra646MRDMODE_IDEIntPRI			= 0x04,
    kUltra646MRDMODE_IDEIntSDY			= 0x08,
    kUltra646MRDMODE_IntEnablePRI		= 0x10,
    kUltra646MRDMODE_IntEnableSDY		= 0x20,
    kUltra646MRDMODE_ResetAll			= 0x40,

    kUltra646BMIDESR0				= 0x72,		/* BusMaster Status Register - Primary */
    kUltra646BMIDESR0_Simplex			= 0x80,
    kUltra646BMIDESR0_Drive1DMACap		= 0x40,
    kUltra646BMIDESR0_Drive0DMACap		= 0x20,
    kUltra646BMIDESR0_DMAIntPRI			= 0x04,
    kUltra646BMIDESR0_DMAErrorPRI		= 0x02,
    kUltra646BMIDESR0_DMAActivePRI		= 0x01,

    kUltra646UDIDETCR0				= 0x73,		/* Ultra DMA Timing Control Register - Primary */
    kUltra646UDIDETCR0_Drive1UDMACycleTime	= 0xC0,
    kUltra646UDIDETCR0_Drive0UDMACycleTime	= 0x30,
    kUltra646UDIDETCR0_Drive1UDMAEnable		= 0x02,
    kUltra646UDIDETCR0_Drive0UDMAEnable		= 0x01,

    kUltra646DTPR0				= 0x74,		/* Descriptor Table Pointer - Primary */

    kUltra646BMIDECR1				= 0x78,		/* BusMaster Command Register - Secondary */
    kUltra646BMIDECR1_PCIWriteSDY		= 0x08,
    kUltra646BMIDECR1_StartDMASDY		= 0x01,

    kUltra646BMIDESR1				= 0x7A,		/* BusMaster Status Register - Secondary */
    kUltra646BMIDESR1_Simplex			= 0x80,
    kUltra646BMIDESR1_Drive3DMACap		= 0x40,
    kUltra646BMIDESR1_Drive2DMACap		= 0x20,
    kUltra646BMIDESR1_DMAIntSDY			= 0x04,
    kUltra646BMIDESR1_DMAErrorSDY		= 0x02,
    kUltra646BMIDESR1_DMAActiveSDY		= 0x01,

    kUltra646UDIDETCR1				= 0x7B,		/* Ultra DMA Timing Control Register - Secondary */
    kUltra646UDIDETCR1_Drive3UDMACycleTime	= 0xC0,
    kUltra646UDIDETCR1_Drive2UDMACycleTime	= 0x30,
    kUltra646UDIDETCR1_Drive3UDMAEnable		= 0x02,
    kUltra646UDIDETCR1_Drive2UDMAEnable		= 0x01,

    kUltra646DTPR1				= 0x7C,		/* Descriptor Table Pointer - Secondary */
};

typedef struct
{
    UInt32    		cntrlReg;
    UInt32		arttimReg;
    UInt32		cmdtimReg;
    UInt32		drwtimRegPIO;
    UInt32		drwtimRegDMA;
    UInt32		udidetcrReg;
} Ultra646Regs;       


typedef struct
{
    UInt32		start;
    UInt32		length;
} Ultra646Descriptor;   


#define IDE_SYSCLK_NS		30
