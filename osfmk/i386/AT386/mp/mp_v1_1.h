/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * @OSF_COPYRIGHT@
 */

#ifndef	_MP_MP_V1_1_H_
#define	_MP_MP_V1_1_H_

#include <mach/mach_types.h>
#include <i386/apic.h>
#include <kern/lock.h>

struct MP_Config_EntryP {
	unsigned char	Entry_Type;
	unsigned char	Local_Apic_Id;
	unsigned char	Local_Apic_Version;
	unsigned char	CPU_Flags;
	unsigned int	CPU_Signature;
	unsigned int	Feature_Flags;
	unsigned int	Reserved[2];
};

/* Entry types */

#define MP_CPU_ENTRY		0	/* Processor entry */
#define MP_BUS_ENTRY		1	/* bus entry */
#define MP_IO_APIC_ENTRY	2	/* I/O APIC entry */
#define MP_IO_INT_ENTRY		3	/* I/O Interrupt assignment */
#define MP_LOC_INT_ENTRY	4	/* Local Interrupt assignment */

struct MP_Config_EntryB {
	unsigned char	Entry_Type;
	unsigned char	Bus_Id;
	char		Ident[6];
};

struct MP_Config_EntryA {
	unsigned char	Entry_Type;
	unsigned char	IO_Apic_Id;
	unsigned char	IO_Apic_Version;
	unsigned char	IO_Apic_Flags;
	vm_offset_t	IO_Apic_Address;
};

struct MP_Config_EntryI {
	unsigned char	Entry_Type;
	unsigned char	Int_Type;
	unsigned short	Int_Flag;
	unsigned char	Source_Bus;
	unsigned char	Source_IRQ;
	unsigned char	Dest_IO_Apic;
	unsigned char	Dest_INTIN;
};
struct MP_Config_EntryL {
	unsigned char	Entry_Type;
	unsigned char	Int_Type;
	unsigned short	Int_Flag;
	unsigned char	Source_Bus;
	unsigned char	Source_IRQ;
	unsigned char	Dest_Local_Apic;
	unsigned char	Dest_INTIN;
};

struct MP_FPS_struct {
	unsigned int	Signature;
	vm_offset_t	Config_Ptr;
	unsigned char	Length;
	unsigned char	Spec_Rev;
	unsigned char	CheckSum;
	unsigned char	Feature[5];
};

struct MP_Config_Table {
	unsigned int	Signature;
	unsigned short	Length;
	unsigned char	Spec_Rev;
	unsigned char	CheckSum;
	char		OEM[8];
	char		PROD[12];
	vm_offset_t	OEM_Ptr;
	unsigned short	OEM_Size;
	unsigned short	Entries;
	vm_offset_t	Local_Apic;
	unsigned int	Reserved;
};

#define	IMCR_ADDRESS		0x22
#define IMCR_DATA		0x23
#define	IMCR_SELECT		0x70
#define IMCR_APIC_ENABLE	0x01

#if 0
extern	boolean_t 	mp_v1_1_take_irq(int 	pic,
					 int 	unit,
					 int 	spl, 
					 i386_intr_t	intr);

extern	boolean_t	mp_v1_1_reset_irq(int 		pic,
					  int 		*unit, 
					  int 		*spl, 
					  i386_intr_t 	*intr);

#endif

void mp_v1_1_init(void);
boolean_t mp_v1_1_io_lock(int, struct processor **);
void mp_v1_1_io_unlock(struct processor *);

/* Intel default Configurations */

#define	MP_PROPRIETARY_CONF	0
#define	MP_ISA_CONF		1
#define	MP_EISA_1_CONF		2
#define	MP_EISA_2_CONF		3
#define	MP_MCA_CONF		4
#define	MP_ISA_PCI_CONF		5
#define	MP_EISA_PCI_CONF	6
#define	MP_MCA_PCI_CONF		7

#if	NCPUS > 1
#define at386_io_lock_state() 	panic("at386_io_lock_state called")
#define at386_io_lock(x) 	panic("at386_io_lock called");
#define at386_io_unlock() 	panic("at386_io_unlock")
#endif	/* NCPUS > 1 */

#endif	/* _MP_MP_V1_1_H_ */
