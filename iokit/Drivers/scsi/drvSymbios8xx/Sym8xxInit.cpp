/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/* Sym8xxInit.m created by russb2 on Sat 30-May-1998 */

/*-----------------------------------------------------------------------------*
 * This module contains initialization routines for the driver.
 *
 * Driver initialization consists of:
 * 
 * - Doing PCI bus initialization for the script engine PCI device.
 * - Setting up shared communication areas in system memory between the script
 *   and the driver.
 * - Copying the script program into the script engine on-board ram, applying 
 *   script relocation fixups as required.
 * - Setting the initial register values for the script engine.
 * - Setting up driver related storage and interfacing with driverKit.
 *
 *-----------------------------------------------------------------------------*/

/*
 * This define causes Sym8xxScript.h to include the script instructions and
 * relocation tables. Normally without this define we only will get #define
 * values for interfacing with the script.
 */
#define INCL_SCRIPT_TEXT

#include "Sym8xxController.h"

#define super	IOSCSIParallelController

OSDefineMetaClassAndStructors( Sym8xxSCSIController, IOSCSIParallelController )	;

/*-----------------------------------------------------------------------------*
 * This structure contains most of the inital register settings for
 * the script engine. See Sym8xxRegs.h for the actual initialization
 * values.
 *
 *-----------------------------------------------------------------------------*/
typedef struct ChipInitRegs
{
    UInt32		regNum;
    UInt32		regSize;
    UInt32		regValue;

} ChipInitRegs;

static ChipInitRegs 	Sym8xxInitRegs[] =
{
	{ SCNTL0,	SCNTL0_SIZE,	SCNTL0_INIT 	},
	{ SCNTL1,	SCNTL1_SIZE,    SCNTL1_INIT	},
        { SCNTL2,	SCNTL2_SIZE,	SCNTL2_INIT	},
        { SCNTL3,     	SCNTL3_SIZE,	SCNTL3_INIT_875	},
        { SXFER,	SXFER_SIZE, 	SXFER_INIT	},
        { SDID,		SDID_SIZE,	SDID_INIT	},
        { GPREG,	GPREG_SIZE,	GPREG_INIT	},
        { SFBR,		SFBR_SIZE,	SFBR_INIT	},
        { SOCL, 	SOCL_SIZE,	SOCL_INIT	},
        { DSA,		DSA_SIZE,	DSA_INIT	},
        { ISTAT,	ISTAT_SIZE,	ISTAT_INIT	},
        { TEMP,		TEMP_SIZE,	TEMP_INIT	},
        { CTEST0,	CTEST0_SIZE,	CTEST0_INIT	},
        { CTEST3,	CTEST3_SIZE,	CTEST3_INIT_A	},
        { CTEST4,	CTEST4_SIZE,	CTEST4_INIT	},
        { CTEST5,	CTEST5_SIZE,	CTEST5_INIT_A_revB},
        { DBC,		DBC_SIZE,	DBC_INIT	},
        { DCMD,		DCMD_SIZE,	DCMD_INIT	},
        { DNAD,		DNAD_SIZE,	DNAD_INIT	},
	{ DSPS,		DSPS_SIZE,	DSPS_INIT	},
	{ SCRATCHA,	SCRATCHA_SIZE,	SCRATCHA_INIT	},
        { DMODE,	DMODE_SIZE,	DMODE_INIT_A	},
        { DIEN,		DIEN_SIZE,	DIEN_INIT	},
        { DWT,		DWT_SIZE,	DWT_INIT	},
        { DCNTL,	DCNTL_SIZE,	DCNTL_INIT_A 	},
        { SIEN,		SIEN_SIZE,	SIEN_INIT	},
        { SLPAR,	SLPAR_SIZE,	SLPAR_INIT	},
        { MACNTL,	MACNTL_SIZE,	MACNTL_INIT	},
        { GPCNTL,	GPCNTL_SIZE,	GPCNTL_INIT	},
        { STIME0,	STIME0_SIZE,	STIME0_INIT	},
        { STIME1,	STIME1_SIZE,	STIME1_INIT	},
        { RESPID0,	RESPID0_SIZE,   RESPID0_INIT	},
        { RESPID1,    	RESPID1_SIZE,   RESPID1_INIT	},
        { STEST2,	STEST2_SIZE,	STEST2_INIT	},
        { STEST3,	STEST3_SIZE,	STEST3_INIT	},
        { SODL,		SODL_SIZE,	SODL_INIT	},
        { SCRATCHB,	SCRATCHB_SIZE,	SCRATCHB_INIT	}
};

/*-----------------------------------------------------------------------------*
 *  
 *
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::configure( IOService *forProvider, SCSIControllerInfo *controllerInfo )
{
    provider = (IOPCIDevice *)forProvider;

    if ( Sym8xxInit() == false )
    {
        return false;
    }

    initialReset = true;

    Sym8xxSCSIBusReset( 0 );
    IOSleep(3000);

    controllerInfo->initiatorId			= 7;

    controllerInfo->maxTargetsSupported		= 16;
    controllerInfo->maxLunsSupported		= 8;

    controllerInfo->minTransferPeriodpS		= (chipId == kChipIdSym875) ? 50000 : 0;
    controllerInfo->maxTransferOffset		= (chipId == kChipIdSym875) ? 16    : 0;
    controllerInfo->maxTransferWidth		= 2;

    controllerInfo->maxCommandsPerController	= 0;
    controllerInfo->maxCommandsPerTarget	= 0;
    controllerInfo->maxCommandsPerLun		= 0;

    controllerInfo->tagAllocationMethod		= kTagAllocationPerController;
    controllerInfo->maxTags			= 128;

    controllerInfo->commandPrivateDataSize	= sizeof( SRB );
    controllerInfo->targetPrivateDataSize	= 0;
    controllerInfo->lunPrivateDataSize		= 0;

    controllerInfo->disableCancelCommands	= false;

    return true;
}


/*-----------------------------------------------------------------------------*
 * Script Initialization
 *
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::Sym8xxInit()
{
    /*
     * Perform PCI related initialization
     */
    if ( Sym8xxInitPCI() == false )
    { 
        return false;
    }

    /*
     * Allocate/initialize driver resources
     */
    if ( Sym8xxInitVars() == false )
    {
        return false;
    }

    /*
     * Initialize the script engine registers
     */
    if ( Sym8xxInitChip() == false )
    {
        return false;
    }

    /* 
     * Apply fixups to script and copy script to script engine's on-board ram
     */
    if ( Sym8xxInitScript() == false )
    {
        return false;
    }

    getWorkLoop()->enableAllInterrupts();

    /*
     * Start script execution
     */
    Sym8xxWriteRegs( chipBaseAddr, DSP, DSP_SIZE, (UInt32) &chipRamAddrPhys[Ent_select_phase] );

    return true;
}

/*-----------------------------------------------------------------------------*
 * Script engine PCI initialization
 *
 * This routine determines the chip version/revision, enables the chip address
 * ranges and allocates a virtual mapping to the script engine's registers and
 * on-board ram.
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::Sym8xxInitPCI()
{
    unsigned long	pciReg0, pciReg8;
    UInt32		chipRev;
    UInt32		n;
    UInt32		ramReg;
    OSString		*matchEntry;


    /*
     * Determine the number of memory ranges for the PCI device.
     * 
     * The hardware implementation may or may not have a ROM present
     * accounting for the difference in the number of ranges.
     */
    n = provider->getDeviceMemoryCount();
    if ( !( n == 3  ||  n == 4 )  )
    {
        return false;
    }

    /*
     * Determine the hardware version. Check the deviceID and
     * RevID in the PCI config regs.
     */
    pciReg0 = provider->configRead32( 0x00 );
    pciReg8 = provider->configRead32( 0x08 ); 

    chipId  = pciReg0 >> 16;
    chipRev = pciReg8 & 0xff;

//    IOLog( "SCSI(Symbios8xx): Chip Id = %04x Chip rev = %02x\n\r", chipId, chipRev );


    ioMapRegs = provider->mapDeviceMemoryWithRegister( 0x14 );
    if ( ioMapRegs == 0 )
    {
        return false;
    }

    switch ( chipId )
    {
        case kChipIdSym875:
            ramReg = 0x18;
            break;

        case kChipIdSym895:
        case kChipIdSym896:
        case kChipIdSym1010:
            ramReg = 0x1C;
            break;

        default:
            ramReg = 0x1C;
    }

    ioMapRam = provider->mapDeviceMemoryWithRegister( ramReg );
    if ( ioMapRam == 0 )
    {
        return false;
    }

    /*
     * Assume 80Mhz external clock rate for motherboard 875 implementations
     * and 40Mhz for others.
     */
    matchEntry = OSDynamicCast( OSString, getProperty( gIONameMatchedKey ) );
    if ( matchEntry == 0 )
    {
        IOLog("SCSI(Sym8xx): Cannot obtain matching property.\n");
        return false;
    }

    if ( matchEntry->isEqualTo( "apple53C8xx" ) == true )
    {
      chipClockRate = CLK_80MHz;
    }
    else
    {
      chipClockRate = CLK_40MHz;
    }

    /*
     * BUS MASTER, MEM I/O Space, MEM WR & INV
     */
    provider->configWrite32( 0x04, 0x16 );

    /*
     *  set Latency to Max , cache 32
     */
    provider->configWrite32( 0x0C, 0x2008 );

    /*
     * get chip register block mapped into pci memory
     */
    chipBaseAddr        = (UInt8 *)ioMapRegs->getVirtualAddress();
    chipBaseAddrPhys 	= (UInt8 *)ioMapRegs->getPhysicalAddress();

//  kprintf( "SCSI(Symbios8xx): Chip Base addr = %08x(p) %08x(v)\n\r", 
//	     (UInt32)chipBaseAddrPhys, (UInt32)chipBaseAddr );

    chipRamAddr        = (UInt8 *)ioMapRam->getVirtualAddress();
    chipRamAddrPhys    = (UInt8 *)ioMapRam->getPhysicalAddress();

//  kprintf( "SCSI(Symbios8xx): Chip Ram  addr = %08x(p) %08x(v)\n\r",  
//           (UInt32)chipRamAddrPhys,  (UInt32)chipRamAddr );

    /*
     * Attach interrupt
     */
    interruptEvent = IOInterruptEventSource::interruptEventSource(
            (OSObject *)             this,
            (IOInterruptEventAction) &Sym8xxSCSIController::interruptOccurred,
            (IOService *)            provider,
            (int)                    0 );

    if ( interruptEvent == NULL )
    {
        return false;
    }

    getWorkLoop()->addEventSource( interruptEvent );
 
    interruptEvent->enable();

    /*
     * 
     */
    memoryCursor = IOBigMemoryCursor::withSpecification( 16*1024*1024, 0xffffffff );
    if ( memoryCursor == NULL )
    {
        return false;
    }



    return true;
}

/*-----------------------------------------------------------------------------*
 * This routine allocates/initializes shared memory for communication between 
 * the script and the driver. In addition other driver resources semaphores, 
 * queues are initialized here.
 *
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::Sym8xxInitVars()
{
    UInt32			i;

    adapter = (AdapterInterface *)IOMallocContiguous( page_size, page_size, (IOPhysicalAddress *)&adapterPhys );
    if ( adapter == 0 )
    {
        return false;
    }
    bzero( adapter, page_size );

    /*
     * We keep two copies of the Nexus pointer array. One contains physical addresses and
     * is located in the script/driver shared storage. The other copy holds the corresponding
     * virtual addresses to the active Nexus structures and is located in the drivers instance
     * data.
     * Both tables can be accessed through indirect pointers in the script/driver communication
     * area. This is the preferred method to access these arrays.
     */ 
    adapter->nexusPtrsVirt = (Nexus **)nexusArrayVirt;
    adapter->nexusPtrsPhys = (Nexus **)adapter->nexusArrayPhys;

    for (i=0; i < MAX_SCSI_TAG; i ++ )
    {
        adapter->nexusPtrsVirt[i] = (Nexus *) -1;
        adapter->nexusPtrsPhys[i] = (Nexus *) -1;
    }
 
    /*
     * The script/driver communication area also contains a 16-entry table clock
     * settings for each target.
     */ 
    for (i=0; i < MAX_SCSI_TARGETS; i++ )
    {
        adapter->targetClocks[i].scntl3Reg = SCNTL3_INIT_875;
    }


    return true;
}


/*-----------------------------------------------------------------------------*
 * This routine makes a temporary copy of the script program, applies script fixups,
 * initializes the script local data table at the top of the script image, and
 * copies the modified script image to the script engine's on-board ram.
 *
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::Sym8xxInitScript()
{
    UInt32	 	i;
    UInt32		scriptPgm[sizeof(BSC_SCRIPT)/sizeof(UInt32)];

    /*
     * Make a copy of the script
     */
    bcopy( BSC_SCRIPT, scriptPgm, sizeof(scriptPgm) );
    bzero( scriptPgm, R_ld_size );

    /*
     * Apply fixups to the script copy
     */
    for ( i=0; i < sizeof(Rel_Patches)/sizeof(UInt32); i++ )
    {
        scriptPgm[Rel_Patches[i]] += (UInt32)chipRamAddrPhys;
    }
    for ( i=0; i < sizeof(LABELPATCHES)/sizeof(UInt32); i++ )
    {
        scriptPgm[LABELPATCHES[i]] += (UInt32)chipRamAddrPhys;
    }
 
    /*
     * Initialize the script working variables with pointers to the script/driver
     * communications area.
     */
    scriptPgm[R_ld_sched_mlbx_base_adr >> 2] 	= (UInt32)&adapterPhys->schedMailBox;
    scriptPgm[R_ld_nexus_array_base >> 2]    	= (UInt32)&adapterPhys->nexusArrayPhys;
    scriptPgm[R_ld_device_table_base_adr >> 2] 	= (UInt32)&adapterPhys->targetClocks;

    /*
     * Load the script image into the script engine's on-board ram.
     */
    Sym8xxLoadScript( (UInt32 *)scriptPgm, sizeof(scriptPgm)/sizeof(UInt32) );

    return true;
}


/*-----------------------------------------------------------------------------*
 * This routine transfers the script program image into the script engine's
 * on-board ram
 *
 *-----------------------------------------------------------------------------*/
void Sym8xxSCSIController::Sym8xxLoadScript( UInt32 *scriptPgm,  UInt32 scriptWords )
{
    UInt32			i;
    volatile UInt32		*ramPtr = (volatile UInt32 *)chipRamAddr;

    for ( i = 0; i < scriptWords; i++ )
    {
        ramPtr[i] = OSSwapHostToLittleInt32(scriptPgm[i]);
    }
}

/*-----------------------------------------------------------------------------*
 * This routine initializes the script engine's register block.
 *
 *-----------------------------------------------------------------------------*/
bool Sym8xxSCSIController::Sym8xxInitChip()
{
    UInt32			i;

    /*
     * Reset the script engine
     */
    Sym8xxWriteRegs( chipBaseAddr, ISTAT, ISTAT_SIZE, RST );
    IODelay( 25 );
    Sym8xxWriteRegs( chipBaseAddr, ISTAT, ISTAT_SIZE, ISTAT_INIT );
  
    /*
     * Load our canned register values into the script engine
     */
    for ( i = 0; i < sizeof(Sym8xxInitRegs)/sizeof(ChipInitRegs); i++ )
    {
        Sym8xxWriteRegs( chipBaseAddr, Sym8xxInitRegs[i].regNum, Sym8xxInitRegs[i].regSize, Sym8xxInitRegs[i].regValue );
        IODelay( 10 );
    }

    /*
     * For hardware implementations that have a 40Mhz SCLK input, we enable the chip's on-board
     * clock doubler to bring the clock rate upto 80Mhz which is required for Ultra-SCSI timings.
     */
    if ( chipClockRate == CLK_40MHz )
    {
        /*
         *   Clock doubler setup for 875 (rev 3 and above).
         */
        /* set clock doubler enabler bit */
        Sym8xxWriteRegs( chipBaseAddr, STEST1, STEST1_SIZE, STEST1_INIT | DBLEN);
        IODelay(30);  
        /* halt scsi clock */
        Sym8xxWriteRegs( chipBaseAddr, STEST3, STEST3_SIZE, STEST3_INIT | HSC );
        IODelay(10);
        Sym8xxWriteRegs( chipBaseAddr, SCNTL3, SCNTL3_SIZE, SCNTL3_INIT_875);
        IODelay(10);
        /* set clock doubler select bit */
        Sym8xxWriteRegs( chipBaseAddr, STEST1, STEST1_SIZE, STEST1_INIT | DBLEN | DBLSEL);
        IODelay(10);
        /* clear hold on scsi clock */
        Sym8xxWriteRegs( chipBaseAddr, STEST3, STEST3_SIZE, STEST3_INIT);
    }

    /*  
     * Set our host-adapter ID in the script engine's registers
     */
    initiatorID = kHostAdapterSCSIId;

    if ( initiatorID > 7 )
    {
        Sym8xxWriteRegs( chipBaseAddr, RESPID1, RESPID1_SIZE, 1 << (initiatorID-8));
    }
    else
    {
        Sym8xxWriteRegs( chipBaseAddr, RESPID0, RESPID0_SIZE, 1 << initiatorID);
    }

    Sym8xxWriteRegs( chipBaseAddr, SCID, SCID_SIZE, SCID_INIT | initiatorID );

    return true;
}


