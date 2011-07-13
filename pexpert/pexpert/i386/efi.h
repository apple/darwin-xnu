/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#ifndef _PEXPERT_I386_EFI_H
#define _PEXPERT_I386_EFI_H

#include <stdint.h>

typedef uint8_t   EFI_UINT8;
typedef uint16_t  EFI_UINT16;
typedef uint32_t  EFI_UINT32;
typedef uint64_t  EFI_UINT64;

typedef uint32_t  EFI_UINTN; /* natural size for firmware, not kernel */

typedef int8_t    EFI_INT8;
typedef int16_t   EFI_INT16;
typedef int32_t   EFI_INT32;
typedef int64_t   EFI_INT64;

typedef int8_t    EFI_CHAR8;
typedef int16_t   EFI_CHAR16;
typedef int32_t   EFI_CHAR32;
typedef int64_t   EFI_CHAR64;

typedef uint32_t  EFI_STATUS;
typedef uint8_t   EFI_BOOLEAN;
typedef void      VOID;

typedef uint32_t  EFI_PTR32;
typedef uint32_t  EFI_HANDLE32;

typedef uint64_t  EFI_PTR64;
typedef uint64_t  EFI_HANDLE64;
/*

Portions Copyright 2004, Intel Corporation
All rights reserved. This program and the accompanying materials
are licensed and made available under the terms and conditions of the BSD License
which accompanies this distribution.  The full text of the license may be found at
    http://opensource.org/licenses/bsd-license.php

THE PROGRAM IS DISTRIBUTED UNDER THE BSD LICENSE ON AN "AS IS" BASIS,
WITHOUT WARRANTIES OR REPRESENTATIONS OF ANY KIND, EITHER EXPRESS OR IMPLIED.

*/


//
// Modifiers for EFI Runtime and Boot Services
//
#define EFI_RUNTIMESERVICE
#define EFIAPI
#define IN
#define OUT
#define OPTIONAL

#define EFI_MAX_BIT       0x80000000

//
// Set the upper bit to indicate EFI Error.
//
#define EFIERR(a)                 (EFI_MAX_BIT | (a))

#define EFIWARN(a)                (a)
#define EFI_ERROR(a)              (((INTN) (a)) < 0)

#define EFI_SUCCESS               0
#define EFI_LOAD_ERROR            EFIERR (1)
#define EFI_INVALID_PARAMETER     EFIERR (2)
#define EFI_UNSUPPORTED           EFIERR (3)
#define EFI_BAD_BUFFER_SIZE       EFIERR (4)
#define EFI_BUFFER_TOO_SMALL      EFIERR (5)
#define EFI_NOT_READY             EFIERR (6)
#define EFI_DEVICE_ERROR          EFIERR (7)
#define EFI_WRITE_PROTECTED       EFIERR (8)
#define EFI_OUT_OF_RESOURCES      EFIERR (9)
#define EFI_VOLUME_CORRUPTED      EFIERR (10)
#define EFI_VOLUME_FULL           EFIERR (11)
#define EFI_NO_MEDIA              EFIERR (12)
#define EFI_MEDIA_CHANGED         EFIERR (13)
#define EFI_NOT_FOUND             EFIERR (14)
#define EFI_ACCESS_DENIED         EFIERR (15)
#define EFI_NO_RESPONSE           EFIERR (16)
#define EFI_NO_MAPPING            EFIERR (17)
#define EFI_TIMEOUT               EFIERR (18)
#define EFI_NOT_STARTED           EFIERR (19)
#define EFI_ALREADY_STARTED       EFIERR (20)
#define EFI_ABORTED               EFIERR (21)
#define EFI_ICMP_ERROR            EFIERR (22)
#define EFI_TFTP_ERROR            EFIERR (23)
#define EFI_PROTOCOL_ERROR        EFIERR (24)
#define EFI_INCOMPATIBLE_VERSION  EFIERR (25)
#define EFI_SECURITY_VIOLATION    EFIERR (26)
#define EFI_CRC_ERROR             EFIERR (27)

#define EFI_WARN_UNKNOWN_GLYPH    EFIWARN (1)
#define EFI_WARN_DELETE_FAILURE   EFIWARN (2)
#define EFI_WARN_WRITE_FAILURE    EFIWARN (3)
#define EFI_WARN_BUFFER_TOO_SMALL EFIWARN (4)

//
// EFI Specification Revision information
//
#define EFI_SPECIFICATION_MAJOR_REVISION  1
#define EFI_SPECIFICATION_MINOR_REVISION  10

typedef struct {
  EFI_UINT32  Data1;
  EFI_UINT16  Data2;
  EFI_UINT16  Data3;
  EFI_UINT8   Data4[8];
} EFI_GUID;

#define APPLE_VENDOR_GUID \
    {0xAC39C713, 0x7E50, 0x423D, {0x88, 0x9D, 0x27,0x8F, 0xCC, 0x34, 0x22, 0xB6} }

#define EFI_GLOBAL_VARIABLE_GUID \
    {0x8BE4DF61, 0x93CA, 0x11d2, {0xAA, 0x0D, 0x00, 0xE0, 0x98, 0x03, 0x2B, 0x8C} }

typedef union {
  EFI_GUID  Guid;
  EFI_UINT8 Raw[16];
} EFI_GUID_UNION;

//
// EFI Time Abstraction:
//  Year:       2000 - 20XX
//  Month:      1 - 12
//  Day:        1 - 31
//  Hour:       0 - 23
//  Minute:     0 - 59
//  Second:     0 - 59
//  Nanosecond: 0 - 999,999,999
//  TimeZone:   -1440 to 1440 or 2047
//
typedef struct {
  EFI_UINT16  Year;
  EFI_UINT8   Month;
  EFI_UINT8   Day;
  EFI_UINT8   Hour;
  EFI_UINT8   Minute;
  EFI_UINT8   Second;
  EFI_UINT8   Pad1;
  EFI_UINT32  Nanosecond;
  EFI_INT16   TimeZone;
  EFI_UINT8   Daylight;
  EFI_UINT8   Pad2;
} EFI_TIME;

//
// Bit definitions for EFI_TIME.Daylight
//
#define EFI_TIME_ADJUST_DAYLIGHT  0x01
#define EFI_TIME_IN_DAYLIGHT      0x02

//
// Value definition for EFI_TIME.TimeZone
//
#define EFI_UNSPECIFIED_TIMEZONE  0x07FF

typedef enum {
  EfiReservedMemoryType,
  EfiLoaderCode,
  EfiLoaderData,
  EfiBootServicesCode,
  EfiBootServicesData,
  EfiRuntimeServicesCode,
  EfiRuntimeServicesData,
  EfiConventionalMemory,
  EfiUnusableMemory,
  EfiACPIReclaimMemory,
  EfiACPIMemoryNVS,
  EfiMemoryMappedIO,
  EfiMemoryMappedIOPortSpace,
  EfiPalCode,
  EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef struct {
  EFI_UINT64  Signature;
  EFI_UINT32  Revision;
  EFI_UINT32  HeaderSize;
  EFI_UINT32  CRC32;
  EFI_UINT32  Reserved;
} __attribute__((aligned(8))) EFI_TABLE_HEADER;

//
// possible caching types for the memory range
//
#define EFI_MEMORY_UC   0x0000000000000001ULL
#define EFI_MEMORY_WC   0x0000000000000002ULL
#define EFI_MEMORY_WT   0x0000000000000004ULL
#define EFI_MEMORY_WB   0x0000000000000008ULL
#define EFI_MEMORY_UCE  0x0000000000000010ULL

//
// physical memory protection on range
//
#define EFI_MEMORY_WP 0x0000000000001000ULL
#define EFI_MEMORY_RP 0x0000000000002000ULL
#define EFI_MEMORY_XP 0x0000000000004000ULL

//
// range requires a runtime mapping
//
#define EFI_MEMORY_RUNTIME  0x8000000000000000ULL
#define EFI_MEMORY_KERN_RESERVED (1ULL << 59)
typedef EFI_UINT64  EFI_PHYSICAL_ADDRESS;
typedef EFI_UINT64  EFI_VIRTUAL_ADDRESS;

#define EFI_MEMORY_DESCRIPTOR_VERSION 1
typedef struct {
  EFI_UINT32            Type;
  EFI_UINT32            Pad;
  EFI_PHYSICAL_ADDRESS  PhysicalStart;
  EFI_VIRTUAL_ADDRESS   VirtualStart;
  EFI_UINT64            NumberOfPages;
  EFI_UINT64            Attribute;
} __attribute__((aligned(8))) EFI_MEMORY_DESCRIPTOR;


typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_SET_VIRTUAL_ADDRESS_MAP) (
  IN EFI_UINTN                    MemoryMapSize,
  IN EFI_UINTN                    DescriptorSize,
  IN EFI_UINT32                   DescriptorVersion,
  IN EFI_MEMORY_DESCRIPTOR        * VirtualMap
  );

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_CONVERT_POINTER) (
  IN EFI_UINTN                DebugDisposition,
  IN OUT VOID                 **Address
  );

//
// Variable attributes
//
#define EFI_VARIABLE_NON_VOLATILE       0x00000001
#define EFI_VARIABLE_BOOTSERVICE_ACCESS 0x00000002
#define EFI_VARIABLE_RUNTIME_ACCESS     0x00000004
#define EFI_VARIABLE_READ_ONLY          0x00000008

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_GET_VARIABLE) (
  IN EFI_CHAR16               * VariableName,
  IN EFI_GUID                 * VendorGuid,
  OUT EFI_UINT32              * Attributes OPTIONAL,
  IN OUT EFI_UINTN            * DataSize,
  OUT VOID                    * Data
  );

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_GET_NEXT_VARIABLE_NAME) (
  IN OUT EFI_UINTN            * VariableNameSize,
  IN OUT EFI_CHAR16           * VariableName,
  IN OUT EFI_GUID             * VendorGuid
  );

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_SET_VARIABLE) (
  IN EFI_CHAR16               * VariableName,
  IN EFI_GUID                 * VendorGuid,
  IN EFI_UINT32               Attributes,
  IN EFI_UINTN                DataSize,
  IN VOID                     * Data
  );

//
// EFI Time
//
typedef struct {
  EFI_UINT32  Resolution;
  EFI_UINT32  Accuracy;
  EFI_BOOLEAN SetsToZero;
} __attribute__((aligned(4))) EFI_TIME_CAPABILITIES;

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_GET_TIME) (
  OUT EFI_TIME                * Time,
  OUT EFI_TIME_CAPABILITIES   * Capabilities OPTIONAL
  );

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_SET_TIME) (
  IN EFI_TIME                 * Time
  );

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_GET_WAKEUP_TIME) (
  OUT EFI_BOOLEAN             * Enabled,
  OUT EFI_BOOLEAN             * Pending,
  OUT EFI_TIME                * Time
  );

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_SET_WAKEUP_TIME) (
  IN EFI_BOOLEAN              Enable,
  IN EFI_TIME                 * Time OPTIONAL
  );

typedef enum {
  EfiResetCold,
  EfiResetWarm,
  EfiResetShutdown,

#ifdef TIANO_EXTENSION_FLAG
  EfiResetUpdate
#endif

} EFI_RESET_TYPE;

typedef
EFI_RUNTIMESERVICE
VOID
(EFIAPI *EFI_RESET_SYSTEM) (
  IN EFI_RESET_TYPE               ResetType,
  IN EFI_STATUS                   ResetStatus,
  IN EFI_UINTN                    DataSize,
  IN EFI_CHAR16                   * ResetData OPTIONAL
  );

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_GET_NEXT_HIGH_MONO_COUNT) (
  OUT EFI_UINT32                  * HighCount
  );

//
// Definition of Status Code extended data header
//
//  HeaderSize    The size of the architecture. This is specified to enable
//                the future expansion
//
//  Size          The size of the data in bytes. This does not include the size
//                of the header structure.
//
//  Type          A GUID defining the type of the data
//
//
#ifdef TIANO_EXTENSION_FLAG

typedef
EFI_RUNTIMESERVICE
EFI_STATUS
(EFIAPI *EFI_REPORT_STATUS_CODE) (
  IN EFI_STATUS_CODE_TYPE       Type,
  IN EFI_STATUS_CODE_VALUE      Value,
  IN EFI_UINT32                 Instance,
  IN EFI_GUID                   * CallerId OPTIONAL,
  IN EFI_STATUS_CODE_DATA       * Data OPTIONAL
  );

#endif
//
// EFI Runtime Services Table
//
#define EFI_RUNTIME_SERVICES_SIGNATURE  0x56524553544e5552ULL
#define EFI_RUNTIME_SERVICES_REVISION   ((EFI_SPECIFICATION_MAJOR_REVISION << 16) | (EFI_SPECIFICATION_MINOR_REVISION))

typedef struct {
  EFI_TABLE_HEADER              Hdr;

  //
  // Time services
  //
  EFI_PTR32                     GetTime;
  EFI_PTR32                     SetTime;
  EFI_PTR32                     GetWakeupTime;
  EFI_PTR32                     SetWakeupTime;

  //
  // Virtual memory services
  //
  EFI_PTR32                     SetVirtualAddressMap;
  EFI_PTR32                     ConvertPointer;

  //
  // Variable services
  //
  EFI_PTR32                     GetVariable;
  EFI_PTR32                     GetNextVariableName;
  EFI_PTR32                     SetVariable;

  //
  // Misc
  //
  EFI_PTR32                     GetNextHighMonotonicCount;
  EFI_PTR32                     ResetSystem;

#ifdef TIANO_EXTENSION_FLAG
  //
  // ////////////////////////////////////////////////////
  // Extended EFI Services
    //////////////////////////////////////////////////////
  //
  EFI_PTR32                     ReportStatusCode;
#endif

} __attribute__((aligned(8))) EFI_RUNTIME_SERVICES_32;

typedef struct {
  EFI_TABLE_HEADER              Hdr;

  //
  // Time services
  //
  EFI_PTR64                     GetTime;
  EFI_PTR64                     SetTime;
  EFI_PTR64                     GetWakeupTime;
  EFI_PTR64                     SetWakeupTime;

  //
  // Virtual memory services
  //
  EFI_PTR64                     SetVirtualAddressMap;
  EFI_PTR64                     ConvertPointer;

  //
  // Variable services
  //
  EFI_PTR64                     GetVariable;
  EFI_PTR64                     GetNextVariableName;
  EFI_PTR64                     SetVariable;

  //
  // Misc
  //
  EFI_PTR64                     GetNextHighMonotonicCount;
  EFI_PTR64                     ResetSystem;

#ifdef TIANO_EXTENSION_FLAG
  //
  // ////////////////////////////////////////////////////
  // Extended EFI Services
    //////////////////////////////////////////////////////
  //
  EFI_PTR64                     ReportStatusCode;
#endif

} __attribute__((aligned(8))) EFI_RUNTIME_SERVICES_64;

//
// EFI Configuration Table
//
typedef struct {
  EFI_GUID  VendorGuid;
  EFI_PTR32 VendorTable;
} EFI_CONFIGURATION_TABLE_32;

typedef struct {
  EFI_GUID  VendorGuid;
  EFI_PTR64 VendorTable;
} __attribute__((aligned(8))) EFI_CONFIGURATION_TABLE_64;

//
// EFI System Table
//
#define EFI_SYSTEM_TABLE_SIGNATURE      0x5453595320494249ULL
#define EFI_SYSTEM_TABLE_REVISION       ((EFI_SPECIFICATION_MAJOR_REVISION << 16) | (EFI_SPECIFICATION_MINOR_REVISION))
#define EFI_2_00_SYSTEM_TABLE_REVISION  ((2 << 16) | 00)
#define EFI_1_02_SYSTEM_TABLE_REVISION  ((1 << 16) | 02)
#define EFI_1_10_SYSTEM_TABLE_REVISION  ((1 << 16) | 10)

typedef struct EFI_SYSTEM_TABLE_32 {
  EFI_TABLE_HEADER              Hdr;

  EFI_PTR32                     FirmwareVendor;
  EFI_UINT32                    FirmwareRevision;

  EFI_HANDLE32                  ConsoleInHandle;
  EFI_PTR32                     ConIn;

  EFI_HANDLE32                  ConsoleOutHandle;
  EFI_PTR32                     ConOut;

  EFI_HANDLE32                  StandardErrorHandle;
  EFI_PTR32                     StdErr;

  EFI_PTR32                     RuntimeServices;
  EFI_PTR32                     BootServices;

  EFI_UINT32                    NumberOfTableEntries;
  EFI_PTR32                     ConfigurationTable;

} __attribute__((aligned(8))) EFI_SYSTEM_TABLE_32;

typedef struct EFI_SYSTEM_TABLE_64 {
  EFI_TABLE_HEADER              Hdr;

  EFI_PTR64                     FirmwareVendor;
  EFI_UINT32                    FirmwareRevision;

  EFI_UINT32                    __pad;

  EFI_HANDLE64                  ConsoleInHandle;
  EFI_PTR64                     ConIn;

  EFI_HANDLE64                  ConsoleOutHandle;
  EFI_PTR64                     ConOut;

  EFI_HANDLE64                  StandardErrorHandle;
  EFI_PTR64                     StdErr;

  EFI_PTR64                     RuntimeServices;
  EFI_PTR64                     BootServices;

  EFI_UINT64                    NumberOfTableEntries;
  EFI_PTR64                     ConfigurationTable;

} __attribute__((aligned(8))) EFI_SYSTEM_TABLE_64;

#endif /* _PEXPERT_I386_EFI_H */
