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

#ifndef	_IOCDTYPES_H
#define	_IOCDTYPES_H

#include <IOKit/IOTypes.h>

/*
 * Minutes, Seconds, Frames (M:S:F)
 *
 * All M:S:F values passed across I/O Kit APIs are guaranteed to be
 * binary-encoded numbers (no BCD-encoded numbers are ever passed).
 */

typedef struct
{
    UInt8 minute;
    UInt8 second;
    UInt8 frame;
} CDMSF;

/*
 * Media Catalogue Numbers (MCN), International Standard Recording Codes (ISRC)
 *
 * All MCN and ISRC values passed across I/O Kit APIs are guaranteed
 * to have a zero-terminating byte, for convenient use as C strings.
 */

#define kCDMCNMaxLength  13
#define kCDISRCMaxLength 12

typedef char CDMCN [kCDMCNMaxLength  + 1];
typedef char CDISRC[kCDISRCMaxLength + 1];

/*
 * Audio Status
 *
 * All CDAudioStatus fields passed across I/O Kit APIs are guaranteed to
 * be binary-encoded numbers (no BCD-encoded numbers are ever passed).
 */

#define kCDAudioStatusUnsupported 0x00
#define kCDAudioStatusActive      0x11
#define kCDAudioStatusPaused      0x12
#define kCDAudioStatusSuccess     0x13
#define kCDAudioStatusFailure     0x14
#define kCDAudioStatusNone        0x15

typedef struct
{
    UInt8 status;
    struct
    {
        CDMSF time;
        struct {
            UInt8 index;
            UInt8 number;
            CDMSF time;
        } track;
    } position;
} CDAudioStatus;

/*
 * Table Of Contents
 *
 * All CDTOC fields passed across I/O Kit APIs are guaranteed to be
 * binary-encoded numbers (not BCD) and converted to host-endianess.
 */

typedef struct
{
    UInt8 session;
#if defined(__LITTLE_ENDIAN__)
    UInt8 control:4, adr:4;
#else /* !defined(__LITTLE_ENDIAN__) */
    UInt8 adr:4, control:4;
#endif /* !defined(__LITTLE_ENDIAN__) */
    UInt8 tno;
    UInt8 point;
    CDMSF address;
    UInt8 zero;
    CDMSF p;
} CDTOCDescriptor;

typedef struct
{
    UInt16          length;
    UInt8           sessionFirst;
    UInt8           sessionLast;
    CDTOCDescriptor descriptors[0];
} CDTOC;

/*
 * M:S:F To LBA Convenience Function
 */

static UInt32 __inline CDConvertMSFToLBA(CDMSF msf)
{
    return (((msf.minute * 60UL) + msf.second) * 75UL) + msf.frame - 150;
}

/*
 * LBA To M:S:F Convenience Function
 */

static CDMSF __inline CDConvertLBAToMSF(UInt32 lba)
{
    CDMSF msf;

    lba += 150;
    msf.minute = (lba / (75 * 60));
    msf.second = (lba % (75 * 60)) / 75;
    msf.frame  = (lba % (75     ));
    
    return msf;
}

/*
 * Track Number To M:S:F Convenience Function
 *
 * The CDTOC structure is assumed to be complete, that is, none of
 * the descriptors are missing or clipped due to an insufficiently
 * sized buffer holding the CDTOC contents.
 */

static CDMSF __inline CDConvertTrackNumberToMSF(UInt8 track, CDTOC * toc)
{
    UInt32 count = (toc->length - sizeof(UInt16)) / sizeof(CDTOCDescriptor);
    UInt32 i;
    CDMSF  msf   = { 0xFF, 0xFF, 0xFF };

    for (i = 0; i < count; i++)
    {
        if (toc->descriptors[i].point == track && toc->descriptors[i].adr == 1)
        {
            msf = toc->descriptors[i].p;
            break;
        }
    }

    return msf;
}

/*
 * Sector Areas, Sector Types
 *
 * Bytes Per Type      CDDA       Mode1      Mode2   Mode2Form1 Mode2Form2
 *       Per Area  +----------+----------+----------+----------+----------+
 * Sync            | 0        | 12       | 12       | 12       | 12       |
 * Header          | 0        | 4        | 4        | 4        | 4        |
 * SubHeader       | 0        | 0        | 0        | 8        | 8        |
 * User            | 2352     | 2048     | 2336     | 2048     | 2328     |
 * Auxiliary       | 0        | 288      | 0        | 280      | 0        |
 * ErrorFlags      | 294      | 294      | 294      | 294      | 294      |
 * SubChannel      | 96       | 96       | 96       | 96       | 96       |
 *                 +----------+----------+----------+----------+----------+
 */

typedef enum
{
    kCDSectorAreaSync       = 0x80,
    kCDSectorAreaHeader     = 0x20,
    kCDSectorAreaSubHeader  = 0x40,
    kCDSectorAreaUser       = 0x10,
    kCDSectorAreaAuxiliary  = 0x08,
    kCDSectorAreaErrorFlags = 0x02,
    kCDSectorAreaSubChannel = 0x01
} CDSectorArea;

typedef enum
{
    kCDSectorTypeUnknown    = 0x00,
    kCDSectorTypeCDDA       = 0x01,
    kCDSectorTypeMode1      = 0x02,
    kCDSectorTypeMode2      = 0x03,
    kCDSectorTypeMode2Form1 = 0x04,
    kCDSectorTypeMode2Form2 = 0x05,
    kCDSectorTypeCount      = 0x06
} CDSectorType;

typedef enum
{
    kCDSectorSizeCDDA       = 2352,
    kCDSectorSizeMode1      = 2048,
    kCDSectorSizeMode2      = 2336,
    kCDSectorSizeMode2Form1 = 2048,
    kCDSectorSizeMode2Form2 = 2328,
    kCDSectorSizeWhole      = 2352
} CDSectorSize;

/*
 * Media Types
 */

typedef enum
{
    kCDMediaTypeUnknown     = 0x0100,
    kCDMediaTypeROM         = 0x0102, /* CD-ROM */
    kCDMediaTypeR           = 0x0104, /* CD-R   */
    kCDMediaTypeRW          = 0x0105, /* CD-RW  */

    kCDMediaTypeMin         = 0x0100,
    kCDMediaTypeMax         = 0x01FF
} CDMediaType;

#endif /* _IOCDTYPES_H */
