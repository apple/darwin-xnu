/******************************************************************************
 *
 * Name: actbl.h - Basic ACPI Table Definitions
 *       $Revision: 1.7 $
 *
 *****************************************************************************/

/******************************************************************************
 *
 * 1. Copyright Notice
 *
 * Some or all of this work - Copyright (c) 1999 - 2006, Intel Corp.
 * All rights reserved.
 *
 * 2. License
 *
 * 2.1. This is your license from Intel Corp. under its intellectual property
 * rights.  You may have additional license terms from the party that provided
 * you this software, covering your right to use that party's intellectual
 * property rights.
 *
 * 2.2. Intel grants, free of charge, to any person ("Licensee") obtaining a
 * copy of the source code appearing in this file ("Covered Code") an
 * irrevocable, perpetual, worldwide license under Intel's copyrights in the
 * base code distributed originally by Intel ("Original Intel Code") to copy,
 * make derivatives, distribute, use and display any portion of the Covered
 * Code in any form, with the right to sublicense such rights; and
 *
 * 2.3. Intel grants Licensee a non-exclusive and non-transferable patent
 * license (with the right to sublicense), under only those claims of Intel
 * patents that are infringed by the Original Intel Code, to make, use, sell,
 * offer to sell, and import the Covered Code and derivative works thereof
 * solely to the minimum extent necessary to exercise the above copyright
 * license, and in no event shall the patent license extend to any additions
 * to or modifications of the Original Intel Code.  No other license or right
 * is granted directly or by implication, estoppel or otherwise;
 *
 * The above copyright and patent license is granted only if the following
 * conditions are met:
 *
 * 3. Conditions
 *
 * 3.1. Redistribution of Source with Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification with rights to further distribute source must include
 * the above Copyright Notice, the above License, this list of Conditions,
 * and the following Disclaimer and Export Compliance provision.  In addition,
 * Licensee must cause all Covered Code to which Licensee contributes to
 * contain a file documenting the changes Licensee made to create that Covered
 * Code and the date of any change.  Licensee must include in that file the
 * documentation of any changes made by any predecessor Licensee.  Licensee
 * must include a prominent statement that the modification is derived,
 * directly or indirectly, from Original Intel Code.
 *
 * 3.2. Redistribution of Source with no Rights to Further Distribute Source.
 * Redistribution of source code of any substantial portion of the Covered
 * Code or modification without rights to further distribute source must
 * include the following Disclaimer and Export Compliance provision in the
 * documentation and/or other materials provided with distribution.  In
 * addition, Licensee may not authorize further sublicense of source of any
 * portion of the Covered Code, and must include terms to the effect that the
 * license from Licensee to its licensee is limited to the intellectual
 * property embodied in the software Licensee provides to its licensee, and
 * not to intellectual property embodied in modifications its licensee may
 * make.
 *
 * 3.3. Redistribution of Executable. Redistribution in executable form of any
 * substantial portion of the Covered Code or modification must reproduce the
 * above Copyright Notice, and the following Disclaimer and Export Compliance
 * provision in the documentation and/or other materials provided with the
 * distribution.
 *
 * 3.4. Intel retains all right, title, and interest in and to the Original
 * Intel Code.
 *
 * 3.5. Neither the name Intel nor any other trademark owned or controlled by
 * Intel shall be used in advertising or otherwise to promote the sale, use or
 * other dealings in products derived from or relating to the Covered Code
 * without prior written authorization from Intel.
 *
 * 4. Disclaimer and Export Compliance
 *
 * 4.1. INTEL MAKES NO WARRANTY OF ANY KIND REGARDING ANY SOFTWARE PROVIDED
 * HERE.  ANY SOFTWARE ORIGINATING FROM INTEL OR DERIVED FROM INTEL SOFTWARE
 * IS PROVIDED "AS IS," AND INTEL WILL NOT PROVIDE ANY SUPPORT,  ASSISTANCE,
 * INSTALLATION, TRAINING OR OTHER SERVICES.  INTEL WILL NOT PROVIDE ANY
 * UPDATES, ENHANCEMENTS OR EXTENSIONS.  INTEL SPECIFICALLY DISCLAIMS ANY
 * IMPLIED WARRANTIES OF MERCHANTABILITY, NONINFRINGEMENT AND FITNESS FOR A
 * PARTICULAR PURPOSE.
 *
 * 4.2. IN NO EVENT SHALL INTEL HAVE ANY LIABILITY TO LICENSEE, ITS LICENSEES
 * OR ANY OTHER THIRD PARTY, FOR ANY LOST PROFITS, LOST DATA, LOSS OF USE OR
 * COSTS OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES, OR FOR ANY INDIRECT,
 * SPECIAL OR CONSEQUENTIAL DAMAGES ARISING OUT OF THIS AGREEMENT, UNDER ANY
 * CAUSE OF ACTION OR THEORY OF LIABILITY, AND IRRESPECTIVE OF WHETHER INTEL
 * HAS ADVANCE NOTICE OF THE POSSIBILITY OF SUCH DAMAGES.  THESE LIMITATIONS
 * SHALL APPLY NOTWITHSTANDING THE FAILURE OF THE ESSENTIAL PURPOSE OF ANY
 * LIMITED REMEDY.
 *
 * 4.3. Licensee shall not export, either directly or indirectly, any of this
 * software or system incorporating such software without first obtaining any
 * required license or other approval from the U. S. Department of Commerce or
 * any other agency or department of the United States Government.  In the
 * event Licensee exports any such software from the United States or
 * re-exports any such software from a foreign destination, Licensee shall
 * ensure that the distribution and export/re-export of the software is in
 * compliance with all laws, regulations, orders, or other restrictions of the
 * U.S. Export Administration Regulations. Licensee agrees that neither it nor
 * any of its subsidiaries will export/re-export any technical data, process,
 * software, or service, directly or indirectly, to any country for which the
 * United States government or any agency thereof requires an export license,
 * other governmental approval, or letter of assurance, without first obtaining
 * such license, approval or letter.
 *
 *****************************************************************************/

#ifndef __ACTBL_H__
#define __ACTBL_H__

/*
 * Values for description table header signatures. Useful because they make
 * it more difficult to inadvertently type in the wrong signature.
 */
#define DSDT_SIG                "DSDT"      /* Differentiated System Description Table */
#define FADT_SIG                "FACP"      /* Fixed ACPI Description Table */
#define FACS_SIG                "FACS"      /* Firmware ACPI Control Structure */
#define PSDT_SIG                "PSDT"      /* Persistent System Description Table */
#define RSDP_SIG                "RSD PTR "  /* Root System Description Pointer */
#define RSDT_SIG                "RSDT"      /* Root System Description Table */
#define XSDT_SIG                "XSDT"      /* Extended  System Description Table */
#define SSDT_SIG                "SSDT"      /* Secondary System Description Table */
#define RSDP_NAME               "RSDP"


/*
 * All tables and structures must be byte-packed to match the ACPI
 * specification, since the tables are provided by the system BIOS
 */
#pragma pack(1)


/*
 * These are the ACPI tables that are directly consumed by the subsystem.
 *
 * The RSDP and FACS do not use the common ACPI table header. All other ACPI
 * tables use the header.
 *
 * Note about bitfields: The UINT8 type is used for bitfields in ACPI tables.
 * This is the only type that is even remotely portable. Anything else is not
 * portable, so do not use any other bitfield types.
 */

/*******************************************************************************
 *
 * ACPI Table Header. This common header is used by all tables except the
 * RSDP and FACS. The define is used for direct inclusion of header into
 * other ACPI tables
 *
 ******************************************************************************/

#define ACPI_TABLE_HEADER_DEF \
char                    Signature[4];           /* ASCII table signature */ \
UINT32                  Length;                 /* Length of table in bytes, including this header */ \
UINT8                   Revision;               /* ACPI Specification minor version # */ \
UINT8                   Checksum;               /* To make sum of entire table == 0 */ \
char                    OemId[6];               /* ASCII OEM identification */ \
char                    OemTableId[8];          /* ASCII OEM table identification */ \
UINT32                  OemRevision;            /* OEM revision number */ \
char                    AslCompilerId[4];       /* ASCII ASL compiler vendor ID */ \
UINT32                  AslCompilerRevision;    /* ASL compiler version */

typedef struct acpi_table_header {
	ACPI_TABLE_HEADER_DEF
} ACPI_TABLE_HEADER;


/*
 * GAS - Generic Address Structure (ACPI 2.0+)
 */
typedef struct acpi_generic_address {
	UINT8                   AddressSpaceId;     /* Address space where struct or register exists */
	UINT8                   RegisterBitWidth;   /* Size in bits of given register */
	UINT8                   RegisterBitOffset;  /* Bit offset within the register */
	UINT8                   AccessWidth;        /* Minimum Access size (ACPI 3.0) */
	UINT64                  Address;            /* 64-bit address of struct or register */
} ACPI_GENERIC_ADDRESS;


/*******************************************************************************
 *
 * RSDP - Root System Description Pointer (Signature is "RSD PTR ")
 *
 ******************************************************************************/

typedef struct rsdp_descriptor {
	char                    Signature[8];       /* ACPI signature, contains "RSD PTR " */
	UINT8                   Checksum;           /* ACPI 1.0 checksum */
	char                    OemId[6];           /* OEM identification */
	UINT8                   Revision;           /* Must be (0) for ACPI 1.0 or (2) for ACPI 2.0+ */
	UINT32                  RsdtPhysicalAddress;/* 32-bit physical address of the RSDT */
	UINT32                  Length;             /* Table length in bytes, including header (ACPI 2.0+) */
	UINT64                  XsdtPhysicalAddress;/* 64-bit physical address of the XSDT (ACPI 2.0+) */
	UINT8                   ExtendedChecksum;   /* Checksum of entire table (ACPI 2.0+) */
	UINT8                   Reserved[3];        /* Reserved, must be zero */
} RSDP_DESCRIPTOR;

#define ACPI_RSDP_REV0_SIZE     20                  /* Size of original ACPI 1.0 RSDP */


/*******************************************************************************
 *
 * RSDT/XSDT - Root System Description Tables
 *
 ******************************************************************************/

typedef struct rsdt_descriptor {
	ACPI_TABLE_HEADER_DEF
	UINT32                  TableOffsetEntry[1];/* Array of pointers to ACPI tables */
} RSDT_DESCRIPTOR;

typedef struct xsdt_descriptor {
	ACPI_TABLE_HEADER_DEF
	UINT64                  TableOffsetEntry[1];/* Array of pointers to ACPI tables */
} XSDT_DESCRIPTOR;


/*******************************************************************************
 *
 * FACS - Firmware ACPI Control Structure (FACS)
 *
 ******************************************************************************/

typedef struct facs_descriptor {
	char                    Signature[4];       /* ASCII table signature */
	UINT32                  Length;             /* Length of structure, in bytes */
	UINT32                  HardwareSignature;  /* Hardware configuration signature */
	UINT32                  FirmwareWakingVector;/* 32-bit physical address of the Firmware Waking Vector */
	UINT32                  GlobalLock;         /* Global Lock for shared hardware resources */

	/* Flags (32 bits) */

	UINT8                   S4Bios_f        : 1;/* 00:    S4BIOS support is present */
	UINT8                                   : 7;/* 01-07: Reserved, must be zero */
	UINT8                   Reserved1[3];       /* 08-31: Reserved, must be zero */

	UINT64                  XFirmwareWakingVector;/* 64-bit version of the Firmware Waking Vector (ACPI 2.0+) */
	UINT8                   Version;            /* Version of this table (ACPI 2.0+) */
	UINT8                   Reserved[31];       /* Reserved, must be zero */
} FACS_DESCRIPTOR;

#define ACPI_GLOCK_PENDING      0x01                /* 00: Pending global lock ownership */
#define ACPI_GLOCK_OWNED        0x02                /* 01: Global lock is owned */


/*
 * Common FACS - This is a version-independent FACS structure used for internal use only
 */
typedef struct acpi_common_facs {
	UINT32                  *GlobalLock;
	UINT64                  *FirmwareWakingVector;
	UINT8                   VectorWidth;
} ACPI_COMMON_FACS;


/*******************************************************************************
 *
 * FADT - Fixed ACPI Description Table (Signature "FACP")
 *
 ******************************************************************************/

/* Fields common to all versions of the FADT */

#define ACPI_FADT_COMMON \
ACPI_TABLE_HEADER_DEF \
UINT32                  V1_FirmwareCtrl;    /* 32-bit physical address of FACS */ \
UINT32                  V1_Dsdt;            /* 32-bit physical address of DSDT */ \
UINT8                   Reserved1;          /* System Interrupt Model isn't used in ACPI 2.0*/ \
UINT8                   Prefer_PM_Profile;  /* Conveys preferred power management profile to OSPM. */ \
UINT16                  SciInt;             /* System vector of SCI interrupt */ \
UINT32                  SmiCmd;             /* Port address of SMI command port */ \
UINT8                   AcpiEnable;         /* Value to write to smi_cmd to enable ACPI */ \
UINT8                   AcpiDisable;        /* Value to write to smi_cmd to disable ACPI */ \
UINT8                   S4BiosReq;          /* Value to write to SMI CMD to enter S4BIOS state */ \
UINT8                   PstateCnt;          /* Processor performance state control*/ \
UINT32                  V1_Pm1aEvtBlk;      /* Port address of Power Mgt 1a Event Reg Blk */ \
UINT32                  V1_Pm1bEvtBlk;      /* Port address of Power Mgt 1b Event Reg Blk */ \
UINT32                  V1_Pm1aCntBlk;      /* Port address of Power Mgt 1a Control Reg Blk */ \
UINT32                  V1_Pm1bCntBlk;      /* Port address of Power Mgt 1b Control Reg Blk */ \
UINT32                  V1_Pm2CntBlk;       /* Port address of Power Mgt 2 Control Reg Blk */ \
UINT32                  V1_PmTmrBlk;        /* Port address of Power Mgt Timer Ctrl Reg Blk */ \
UINT32                  V1_Gpe0Blk;         /* Port addr of General Purpose AcpiEvent 0 Reg Blk */ \
UINT32                  V1_Gpe1Blk;         /* Port addr of General Purpose AcpiEvent 1 Reg Blk */ \
UINT8                   Pm1EvtLen;          /* Byte Length of ports at pm1X_evt_blk */ \
UINT8                   Pm1CntLen;          /* Byte Length of ports at pm1X_cnt_blk */ \
UINT8                   Pm2CntLen;          /* Byte Length of ports at pm2_cnt_blk */ \
UINT8                   PmTmLen;            /* Byte Length of ports at pm_tm_blk */ \
UINT8                   Gpe0BlkLen;         /* Byte Length of ports at gpe0_blk */ \
UINT8                   Gpe1BlkLen;         /* Byte Length of ports at gpe1_blk */ \
UINT8                   Gpe1Base;           /* Offset in gpe model where gpe1 events start */ \
UINT8                   CstCnt;             /* Support for the _CST object and C States change notification.*/ \
UINT16                  Plvl2Lat;           /* Worst case HW latency to enter/exit C2 state */ \
UINT16                  Plvl3Lat;           /* Worst case HW latency to enter/exit C3 state */ \
UINT16                  FlushSize;          /* Processor's memory cache line width, in bytes */ \
UINT16                  FlushStride;        /* Number of flush strides that need to be read */ \
UINT8                   DutyOffset;         /* Processor's duty cycle index in processor's P_CNT reg*/ \
UINT8                   DutyWidth;          /* Processor's duty cycle value bit width in P_CNT register.*/ \
UINT8                   DayAlrm;            /* Index to day-of-month alarm in RTC CMOS RAM */ \
UINT8                   MonAlrm;            /* Index to month-of-year alarm in RTC CMOS RAM */ \
UINT8                   Century;            /* Index to century in RTC CMOS RAM */ \
UINT16                  IapcBootArch;       /* IA-PC Boot Architecture Flags. See Table 5-10 for description*/ \
UINT8                   Reserved2;          /* Reserved, must be zero */


/*
 * ACPI 2.0+ FADT
 */
typedef struct fadt_descriptor {
	ACPI_FADT_COMMON

	/* Flags (32 bits) */

	UINT8                   WbInvd      : 1;/* 00:    The wbinvd instruction works properly */
	UINT8                   WbInvdFlush : 1;/* 01:    The wbinvd flushes but does not invalidate */
	UINT8                   ProcC1      : 1;/* 02:    All processors support C1 state */
	UINT8                   Plvl2Up     : 1;/* 03:    C2 state works on MP system */
	UINT8                   PwrButton   : 1;/* 04:    Power button is handled as a generic feature */
	UINT8                   SleepButton : 1;/* 05:    Sleep button is handled as a generic feature, or not present */
	UINT8                   FixedRTC    : 1;/* 06:    RTC wakeup stat not in fixed register space */
	UINT8                   Rtcs4       : 1;/* 07:    RTC wakeup stat not possible from S4 */
	UINT8                   TmrValExt   : 1;/* 08:    tmr_val is 32 bits 0=24-bits */
	UINT8                   DockCap     : 1;/* 09:    Docking supported */
	UINT8                   ResetRegSup : 1;/* 10:    System reset via the FADT RESET_REG supported */
	UINT8                   SealedCase  : 1;/* 11:    No internal expansion capabilities and case is sealed */
	UINT8                   Headless    : 1;/* 12:    No local video capabilities or local input devices */
	UINT8                   CpuSwSleep  : 1;/* 13:    Must execute native instruction after writing SLP_TYPx register */

	UINT8                   PciExpWak                           : 1;/* 14:    System supports PCIEXP_WAKE (STS/EN) bits (ACPI 3.0) */
	UINT8                   UsePlatformClock                    : 1;/* 15:    OSPM should use platform-provided timer (ACPI 3.0) */
	UINT8                   S4RtcStsValid                       : 1;/* 16:    Contents of RTC_STS valid after S4 wake (ACPI 3.0) */
	UINT8                   RemotePowerOnCapable                : 1;/* 17:    System is compatible with remote power on (ACPI 3.0) */
	UINT8                   ForceApicClusterModel               : 1;/* 18:    All local APICs must use cluster model (ACPI 3.0) */
	UINT8                   ForceApicPhysicalDestinationMode    : 1;/* 19:    All local xAPICs must use physical dest mode (ACPI 3.0) */
	UINT8                                                       : 4;/* 20-23: Reserved, must be zero */
	UINT8                   Reserved3;                           /* 24-31: Reserved, must be zero */

	ACPI_GENERIC_ADDRESS    ResetRegister;  /* Reset register address in GAS format */
	UINT8                   ResetValue;     /* Value to write to the ResetRegister port to reset the system */
	UINT8                   Reserved4[3];   /* These three bytes must be zero */
	UINT64                  XFirmwareCtrl;  /* 64-bit physical address of FACS */
	UINT64                  XDsdt;          /* 64-bit physical address of DSDT */
	ACPI_GENERIC_ADDRESS    XPm1aEvtBlk;    /* Extended Power Mgt 1a AcpiEvent Reg Blk address */
	ACPI_GENERIC_ADDRESS    XPm1bEvtBlk;    /* Extended Power Mgt 1b AcpiEvent Reg Blk address */
	ACPI_GENERIC_ADDRESS    XPm1aCntBlk;    /* Extended Power Mgt 1a Control Reg Blk address */
	ACPI_GENERIC_ADDRESS    XPm1bCntBlk;    /* Extended Power Mgt 1b Control Reg Blk address */
	ACPI_GENERIC_ADDRESS    XPm2CntBlk;     /* Extended Power Mgt 2 Control Reg Blk address */
	ACPI_GENERIC_ADDRESS    XPmTmrBlk;      /* Extended Power Mgt Timer Ctrl Reg Blk address */
	ACPI_GENERIC_ADDRESS    XGpe0Blk;       /* Extended General Purpose AcpiEvent 0 Reg Blk address */
	ACPI_GENERIC_ADDRESS    XGpe1Blk;       /* Extended General Purpose AcpiEvent 1 Reg Blk address */
} FADT_DESCRIPTOR;


/*
 * "Down-revved" ACPI 2.0 FADT descriptor
 * Defined here to allow compiler to generate the length of the struct
 */
typedef struct fadt_descriptor_rev2_minus {
	ACPI_FADT_COMMON
	UINT32                  Flags;
	ACPI_GENERIC_ADDRESS    ResetRegister;  /* Reset register address in GAS format */
	UINT8                   ResetValue;     /* Value to write to the ResetRegister port to reset the system. */
	UINT8                   Reserved7[3];   /* Reserved, must be zero */
} FADT_DESCRIPTOR_REV2_MINUS;


/*
 * ACPI 1.0 FADT
 * Defined here to allow compiler to generate the length of the struct
 */
typedef struct fadt_descriptor_rev1 {
	ACPI_FADT_COMMON
	UINT32                  Flags;
} FADT_DESCRIPTOR_REV1;


/* FADT: Prefered Power Management Profiles */

#define PM_UNSPECIFIED                  0
#define PM_DESKTOP                      1
#define PM_MOBILE                       2
#define PM_WORKSTATION                  3
#define PM_ENTERPRISE_SERVER            4
#define PM_SOHO_SERVER                  5
#define PM_APPLIANCE_PC                 6

/* FADT: Boot Arch Flags */

#define BAF_LEGACY_DEVICES              0x0001
#define BAF_8042_KEYBOARD_CONTROLLER    0x0002

#define FADT2_REVISION_ID               3
#define FADT2_MINUS_REVISION_ID         2


/* Reset to default packing */

#pragma pack()

/*
 * This macro is temporary until the table bitfield flag definitions
 * are removed and replaced by a Flags field.
 */
#define ACPI_FLAG_OFFSET(d, f, o)         (UINT8) (ACPI_OFFSET (d,f) +\
	                                         sizeof(((d *)0)->f) + o)
/*
 * Get the remaining ACPI tables
 */
#include "Acpi_v1.h"

/*
 * ACPI Table information.  We save the table address, length,
 * and type of memory allocation (mapped or allocated) for each
 * table for 1) when we exit, and 2) if a new table is installed
 */
#define ACPI_MEM_NOT_ALLOCATED  0
#define ACPI_MEM_ALLOCATED      1
#define ACPI_MEM_MAPPED         2

/* Definitions for the Flags bitfield member of ACPI_TABLE_SUPPORT */

#define ACPI_TABLE_SINGLE       0x00
#define ACPI_TABLE_MULTIPLE     0x01
#define ACPI_TABLE_EXECUTABLE   0x02

#define ACPI_TABLE_ROOT         0x00
#define ACPI_TABLE_PRIMARY      0x10
#define ACPI_TABLE_SECONDARY    0x20
#define ACPI_TABLE_ALL          0x30
#define ACPI_TABLE_TYPE_MASK    0x30

/* Data about each known table type */

typedef struct acpi_table_support {
	char                    *Name;
	char                    *Signature;
	void                    **GlobalPtr;
	UINT8                   SigLength;
	UINT8                   Flags;
} ACPI_TABLE_SUPPORT;


/* Macros used to generate offsets to specific table fields */

#define ACPI_FACS_OFFSET(f)             (UINT8) ACPI_OFFSET (FACS_DESCRIPTOR,f)
#define ACPI_FADT_OFFSET(f)             (UINT8) ACPI_OFFSET (FADT_DESCRIPTOR, f)
#define ACPI_GAS_OFFSET(f)              (UINT8) ACPI_OFFSET (ACPI_GENERIC_ADDRESS,f)
#define ACPI_HDR_OFFSET(f)              (UINT8) ACPI_OFFSET (ACPI_TABLE_HEADER,f)
#define ACPI_RSDP_OFFSET(f)             (UINT8) ACPI_OFFSET (RSDP_DESCRIPTOR,f)

#define ACPI_FADT_FLAG_OFFSET(f, o)      ACPI_FLAG_OFFSET (FADT_DESCRIPTOR,f,o)
#define ACPI_FACS_FLAG_OFFSET(f, o)      ACPI_FLAG_OFFSET (FACS_DESCRIPTOR,f,o)

#endif /* __ACTBL_H__ */
