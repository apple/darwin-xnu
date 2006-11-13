/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
#include <mach/std_types.h>
#include <ppc/proc_reg.h>
#include <ppc/boot.h>
#include <ppc/mem.h>

// The sophisticated BAT manager

unsigned int mappedSegments = 0;
unsigned int availableBATs = 0xE;		// BAT0 used, 1-3 available

vm_offset_t
PEResidentAddress( vm_offset_t address, vm_size_t length )
{
    if( mappedSegments & (1 << (15 & (address >> 28))))
	return( address);
    else
	return( 0);
}

vm_offset_t
PEMapSegment( vm_offset_t address, vm_size_t length )
{
    vm_offset_t		retAddress;
    bat_t		bat;
    int			batNum;

    retAddress = PEResidentAddress( address, length );
    if( retAddress)
	return( retAddress);

    if( length < (256 * 1024))
	return( 0);
    if( availableBATs == 0)
	return( 0);

    for( batNum = 0;
	 (0 == (availableBATs & (1 << batNum)));
	 batNum++);

    bat.upper.word	     = address & 0xf0000000;
    bat.lower.word	     = bat.upper.word;

    bat.upper.bits.bl    = 0x7ff;	/* size = 256M */
    bat.upper.bits.vs    = 1;
    bat.upper.bits.vp    = 0;		/* user disabled */

    bat.lower.bits.wimg  = PTE_WIMG_IO;
    bat.lower.bits.pp    = 2;		/* read/write access */
    
    // Update the shadow bats.
    shadow_BAT.DBATs[batNum].upper = bat.upper.word;
    shadow_BAT.DBATs[batNum].lower = bat.lower.word;
    
    sync();isync();
    switch( batNum) {			// !%$@!! mtdbat needs literal
	case 0:
	    mtdbatu( 0, BAT_INVALID); 	/* invalidate old mapping */
	    mtdbatl( 0, bat.lower.word);
	    mtdbatu( 0, bat.upper.word);
	    break;
	case 1:
	    mtdbatu( 1, BAT_INVALID);
	    mtdbatl( 1, bat.lower.word);
	    mtdbatu( 1, bat.upper.word);
	    break;
	case 2:
	    mtdbatu( 2, BAT_INVALID);
	    mtdbatl( 2, bat.lower.word);
	    mtdbatu( 2, bat.upper.word);
	    break;
	case 3:
	    mtdbatu( 3, BAT_INVALID);
	    mtdbatl( 3, bat.lower.word);
	    mtdbatu( 3, bat.upper.word);
	    break;
    }
    sync();isync();

    availableBATs &= ~(1 << batNum);
    mappedSegments |= (1 << (15 & (address >> 28)));

    return( address);
}

void initialize_bats(boot_args *args)
{
	int i;

	/* Give ourselves the virtual map that we would like */
	bat_t		      bat;

	/* Make sure that the BATs map what we expect. Note
	 * that we assume BAT0 maps kernel text & data.
	 *
	 * Except, oops, none of the BATs have ever been set.
	 * Developer worked only by fluke.
	 */

	bat.upper.word	     = 0;
	bat.upper.bits.bepi  = 0x0;	/* start at logical addr 0M */
	/*
	 * We should be smarter here about picking an
	 * amount to map
	 */
	bat.upper.bits.bl    = 0x7ff;	/* size = 256M */
	bat.upper.bits.vs    = 1;
	bat.upper.bits.vp    = 0;

	bat.lower.word       = 0;
	bat.lower.bits.brpn  = 0x0;	/* start at physical addr 0 */
	bat.lower.bits.wimg  = PTE_WIMG_DEFAULT;
	bat.lower.bits.pp    = 2;	/* read/write access */

	/* Mustn't cause any data traffic here,
	 * we're modifying our data BAT register!
	 */

	sync();
	mtdbatu(0, BAT_INVALID);	/* invalidate old mapping */
	isync();
	mtdbatl(0, bat.lower.word);
	isync();
	mtdbatu(0, bat.upper.word);	/* update with new mapping */
	isync();
	mtibatl(0, bat.lower.word);
	isync();
	mtibatu(0, bat.upper.word);	/* update with new mapping */
	isync();

	sync();isync();
	mtdbatu(1,BAT_INVALID); mtdbatl(1,BAT_INVALID);
	mtibatu(1,BAT_INVALID); mtibatl(1,BAT_INVALID);
	mtdbatu(2,BAT_INVALID); mtdbatl(2,BAT_INVALID);
	mtibatu(2,BAT_INVALID); mtibatl(2,BAT_INVALID);
	mtdbatu(3,BAT_INVALID); mtdbatl(3,BAT_INVALID);
	mtibatu(3,BAT_INVALID); mtibatl(3,BAT_INVALID);
	sync();isync();

	PEMapSegment( 0xf0000000, 0x10000000);
	if( args->Video.v_baseAddr)
	  PEMapSegment( args->Video.v_baseAddr, 0x10000000);

	/* Set up segment registers as VM through space 0 */
	isync();
	for (i=0; i<=15; i++) {
	  mtsrin(KERNEL_SEG_REG0_VALUE | i, i * 0x10000000);
	}
	isync();
}

/*
 * Adjust the size of the region mapped by a BAT
 * to to be just large enough to include the specified
 * offset, and return the offset of the new end of the region.
 * Note that both 'offsets' are really *lengths*, i.e. the
 * offset of the end of the mapped region from the beginning.
 * Either the instruction or data BATs (or both) can be specified.
 * If the new length is greater than the size mappable by a BAT,
 * then that value is just returned and no changes are made.
 */
vm_offset_t
adjust_bat_limit(
    vm_offset_t		new_minimum,
    int			batn,
    boolean_t		ibat,
    boolean_t		dbat
)
{
    vm_offset_t		new_limit;

    if (new_minimum <= 256*1024*1024) {
	unsigned int	bl = 0;

	new_limit = 128*1024;
	while (new_limit < new_minimum) {
	    new_limit *= 2;
	    bl = (bl << 1) | 1;
	}

	{
	    batu_t	batu;

	    if (dbat) switch (batn) {

	    case 0:
		mfdbatu(batu, 0 );
		batu.bits.bl = bl;

		sync(); isync();
		mtdbatu( 0, batu);
		sync(); isync();

		break;

	    case 1:
		mfdbatu(batu, 1 );
		batu.bits.bl = bl;

		sync(); isync();
		mtdbatu( 1, batu);
		sync(); isync();

		break;

	    case 2:
		mfdbatu(batu, 2 );
		batu.bits.bl = bl;

		sync(); isync();
		mtdbatu( 2, batu);
		sync(); isync();

		break;

	    case 3:
		mfdbatu(batu, 3 );
		batu.bits.bl = bl;

		sync(); isync();
		mtdbatu( 3, batu);
		sync(); isync();

		break;
	    }

	    if (ibat) switch (batn) {

	    case 0:
		mfibatu(batu, 0 );
		batu.bits.bl = bl;

		sync(); isync();
		mtibatu( 0, batu);
		sync(); isync();

		break;

	    case 1:
		mfibatu(batu, 1 );
		batu.bits.bl = bl;

		sync(); isync();
		mtibatu( 1, batu);
		sync(); isync();

		break;

	    case 2:
		mfibatu(batu, 2 );
		batu.bits.bl = bl;

		sync(); isync();
		mtibatu( 2, batu);
		sync(); isync();

		break;

	    case 3:
		mfibatu(batu, 3 );
		batu.bits.bl = bl;

		sync(); isync();
		mtibatu( 3, batu);
		sync(); isync();

		break;
	    }
	}
    }
    else
	new_limit = new_minimum;

    return (new_limit);
}
