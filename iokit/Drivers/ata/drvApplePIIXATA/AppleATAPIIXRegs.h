/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright (c) 2000 Apple Computer, Inc.  All rights reserved. 
 *
 * Intel PIIX/PIIX3/PIIX4 PCI IDE controller.
 * PIIX = PCI-ISA-IDE-Xelerator. (also USB on newer controllers)
 *
 * Notes:
 * 
 * PIIX  introduced in the "Triton" chipset.
 * PIIX3 supports different timings for Master/Slave devices on both channels.
 * PIIX4 adds support for Ultra DMA/33.
 *
 * Be sure to download and read the PIIX errata from Intel's web site at
 * developer.intel.com.
 *
 * HISTORY:
 *
 */

#ifndef _APPLEATAPIIXREGS_H
#define _APPLEATAPIIXREGS_H

/*
 * PCI ID for supported PIIX variants.
 */
#define PCI_ID_PIIX     0x12308086
#define PCI_ID_PIIX3    0x70108086
#define PCI_ID_PIIX4    0x71118086
#define PCI_ID_ICH      0x24118086
#define PCI_ID_ICH0     0x24218086
#define PCI_ID_ICH2_M   0x244a8086
#define PCI_ID_ICH2     0x244b8086
#define PCI_ID_NONE     0xffffffff

/*
 * Decoded port addresses. Seems to be hardcoded and it does not
 * show up in the PCI configuration space memory ranges.
 */
#define PIIX_P_CMD_ADDR     0x1f0
#define PIIX_P_CTL_ADDR     0x3f4
#define PIIX_S_CMD_ADDR     0x170
#define PIIX_S_CTL_ADDR     0x374
#define PIIX_CMD_SIZE       8
#define PIIX_CTL_SIZE       4

/*
 * IRQ assignment.
 */
#define PIIX_P_IRQ          14
#define PIIX_S_IRQ          15

/*
 * PIIX has two IDE channels.
 */
#define PIIX_CHANNEL_PRIMARY    0
#define PIIX_CHANNEL_SECONDARY  1

/*
 * PIIX PCI config space registers.
 * Register size (bits) in parenthesis.
 */
#define PIIX_PCI_CFID           0x00

#define PIIX_PCI_PCICMD         0x04    // (16) PCI command register
#define PIIX_PCI_PCICMD_IOSE    0x01    // I/O space enable
#define PIIX_PCI_PCICMD_BME     0x04    // bus-master enable

#define PIIX_PCI_PCISTS         0x06    // (16) PCI device status register
#define PIIX_PCI_RID            0x08    // (8)  Revision ID register
#define PIIX_PCI_CLASSC         0x09    // (24) Class code register
#define PIIX_PCI_MLT            0x0d    // (8)  Master latency timer register
#define PIIX_PCI_HEDT           0x0e    // (8)  Header type register

#define PIIX_PCI_BMIBA          0x20    // (32) Bus-Master base address
#define PIIX_PCI_BMIBA_RTE      0x01    // resource type indicator (I/O)
#define PIIX_PCI_BMIBA_MASK     0xfff0  // base address mask

#define PIIX_PCI_IDETIM         0x40    // (16) IDE timing registers (pri)
#define PIIX_PCI_IDETIM_S       0x42    // (16) IDE timing registers (sec)
#define PIIX_PCI_SIDETIM        0x44    // (8)  Slave IDE timing register
#define PIIX_PCI_UDMACTL        0x48    // (8)  Ultra DMA/33 control register
#define PIIX_PCI_UDMATIM        0x4a    // (16) Ultra DMA/33 timing register

#define PIIX_PCI_IDECONFIG      0x54    // (32) IDE I/O Config register

/*
 * PIIX PCI configuration space register definition.
 *
 * PIIX_IDETIM - IDE timing register.
 *
 * Address:
 * 0x40:0x41 - Primary channel
 * 0x42:0x43 - Secondary channel
 */
#define PIIX_PCI_IDETIM_IDE           0x8000   // IDE decode enable
#define PIIX_PCI_IDETIM_SITRE         0x4000   // slave timing register enable

#define PIIX_PCI_IDETIM_ISP_MASK      0x3000
#define PIIX_PCI_IDETIM_ISP_SHIFT     12
#define PIIX_PCI_IDETIM_ISP_5         0x0000   // IORDY sample point
#define PIIX_PCI_IDETIM_ISP_4         0x1000   // (PCI clocks)
#define PIIX_PCI_IDETIM_ISP_3         0x2000
#define PIIX_PCI_IDETIM_ISP_2         0x3000

#define PIIX_PCI_IDETIM_RTC_MASK      0x0300
#define PIIX_PCI_IDETIM_RTC_SHIFT     8
#define PIIX_PCI_IDETIM_RTC_4         0x0000   // receovery time (PCI clocks)
#define PIIX_PCI_IDETIM_RTC_3         0x0100
#define PIIX_PCI_IDETIM_RTC_2         0x0200
#define PIIX_PCI_IDETIM_RTC_1         0x0300

#define PIIX_PCI_IDETIM_DTE1          0x0080   // DMA timing enable only
#define PIIX_PCI_IDETIM_PPE1          0x0040   // prefetch and posting enabled
#define PIIX_PCI_IDETIM_IE1           0x0020   // IORDY sample point enable
#define PIIX_PCI_IDETIM_TIME1         0x0010   // fast timing enable
#define PIIX_PCI_IDETIM_DTE0          0x0008   // same as above for drive 0
#define PIIX_PCI_IDETIM_PPE0          0x0004
#define PIIX_PCI_IDETIM_IE0           0x0002
#define PIIX_PCI_IDETIM_TIME0         0x0001

/*
 * PIIX PCI configuration space register definition.
 *
 * PIIX_SIDETIM - Slave IDE timing register.
 *
 * Address: 0x44
 */
#define PIIX_PCI_SIDETIM_SISP1_MASK   0xc0
#define PIIX_PCI_SIDETIM_SISP1_SHIFT  6
#define PIIX_PCI_SIDETIM_SRTC1_MASK   0x30
#define PIIX_PCI_SIDETIM_SRTC1_SHIFT  4
#define PIIX_PCI_SIDETIM_PISP1_MASK   0x0c
#define PIIX_PCI_SIDETIM_PISP1_SHIFT  2
#define PIIX_PCI_SIDETIM_PRTC1_MASK   0x03
#define PIIX_PCI_SIDETIM_PRTC1_SHIFT  0

/*
 * PIIX PCI configuration space register definition.
 *
 * PIIX_UDMACTL - Ultra DMA/33 control register
 *
 * Address: 0x48
 */
#define PIIX_PCI_UDMACTL_SSDE1        0x08    // Enable UDMA/33 Sec/Drive1
#define PIIX_PCI_UDMACTL_SSDE0        0x04    // Enable UDMA/33 Sec/Drive0
#define PIIX_PCI_UDMACTL_PSDE1        0x02    // Enable UDMA/33 Pri/Drive1
#define PIIX_PCI_UDMACTL_PSDE0        0x01    // Enable UDMA/33 Pri/Drive0

/*
 * PIIX PCI configuration space register definition.
 *
 * PIIX_UDMATIM - Ultra DMA/33 timing register
 *
 * Address: 0x4a-0x4b
 */
#define PIIX_PCI_UDMATIM_PCT0_MASK    0x0003
#define PIIX_PCI_UDMATIM_PCT0_SHIFT   0
#define PIIX_PCI_UDMATIM_PCT1_MASK    0x0030
#define PIIX_PCI_UDMATIM_PCT1_SHIFT   4
#define PIIX_PCI_UDMATIM_SCT0_MASK    0x0300
#define PIIX_PCI_UDMATIM_SCT0_SHIFT   8
#define PIIX_PCI_UDMATIM_SCT1_MASK    0x3000
#define PIIX_PCI_UDMATIM_SCT1_SHIFT   12


/*
 * PIIX IO space register offsets. Base address is set in PIIX_PCI_BMIBA.
 * Register size (bits) in parenthesis.
 *
 * Note:
 * For the primary channel, the base address is stored in PIIX_PCI_BMIBA.
 * For the secondary channel, an offset (PIIX_IO_BM_OFFSET) is added to
 * the value stored in PIIX_PCI_BMIBA.
 */
#define PIIX_IO_BMICX            0x00    // (8) Bus master command register
#define PIIX_IO_BMISX            0x02    // (8) Bus master status register
#define PIIX_IO_BMIDTPX          0x04    // (32) Descriptor table register

#define PIIX_IO_BM_OFFSET        0x08    // offset to sec channel registers
#define PIIX_IO_BM_SIZE          0x08    // BM registers size for each channel
#define PIIX_IO_BM_MASK          0xfff0  // BMIBA mask to get I/O base address

/*
 * PIIX IO space register definition.
 *
 * BMICX - Bus master IDE command register
 */
#define PIIX_IO_BMICX_SSBM       0x01    // 1=Start, 0=Stop
#define PIIX_IO_BMICX_RWCON      0x08    // 0=Read, 1=Write

/*
 * PIIX IO space register definition.
 *
 * PIIX_BMISX - Bus master IDE status register
 */
#define PIIX_IO_BMISX_DMA1CAP    0x40    // drive 1 is capable of DMA transfers
#define PIIX_IO_BMISX_DMA0CAP    0x20    // drive 0 is capable of DMA transfers
#define PIIX_IO_BMISX_IDEINTS    0x04    // IDE device asserted its interrupt
#define PIIX_IO_BMISX_ERROR      0x02    // DMA error (cleared by writing a 1)
#define PIIX_IO_BMISX_BMIDEA     0x01    // bus master active bit

#define PIIX_IO_BMISX_STATUS    (PIIX_IO_BMISX_IDEINTS | \
                                 PIIX_IO_BMISX_ERROR   | \
                                 PIIX_IO_BMISX_BMIDEA)

/*
 * PIIX Bus Master alignment/boundary requirements.
 *
 * Intel nomemclature:
 * WORD  - 16-bit
 * DWord - 32-bit
 */
#define PIIX_DT_ALIGN    4           // descriptor table must be DWord aligned.
#define PIIX_DT_BOUND    (4 * 1024)  // cannot cross 4K boundary. (or 64K ?)

#define PIIX_BUF_ALIGN   2           // memory buffer must be word aligned.
#define PIIX_BUF_BOUND   (64 * 1024) // cannot cross 64K boundary.
#define PIIX_BUF_LIMIT   (64 * 1024) // limited to 64K in size

/*
 * PIIX Bus Master Physical Region Descriptor (PRD).
 */
typedef struct {
    UInt32  base;      // base address
    UInt16  count;     // byte count
    UInt16  flags;     // flag bits
} prdEntry_t;

#define PRD_FLAG_EOT          0x8000

#define PRD_COUNT(x)          (((x) == PIIX_BUF_LIMIT) ? 0 : (x))
#define PRD_TABLE_SIZE        PAGE_SIZE
#define PRD_ENTRIES           (PRD_TABLE_SIZE / sizeof(prdEntry_t))

/*
 * PIIX Register setting macro.
 */
#define SET_REG_FIELD(reg, field, val)     \
{                                          \
    reg &= ~(field ## _MASK);              \
    reg |= (((val) << field ## _SHIFT) &   \
                    field ## _MASK);       \
}

/*
 * Convert the "isp" and "rtc" fields in PIIX_IDETIM register from
 * PCI clocks to their respective values, and vice-versa.
 */
#define PIIX_CLK_TO_ISP(x)    (5 - (x))
#define PIIX_ISP_TO_CLK(x)    PIIX_CLK_TO_ISP(x)
#define PIIX_CLK_TO_RTC(x)    (4 - (x))
#define PIIX_RTC_TO_CLK(x)    PIIX_CLK_TO_RTC(x)

#endif /* !_APPLEATAPIIXREGS_H */
