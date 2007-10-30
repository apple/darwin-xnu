/*
 * Copyright (c) 2002-2003 Apple Computer, Inc. All rights reserved.
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

#include <vc.h>
#include <console/video_console.h>
#include <kdp/kdp_udp.h>
#include <kern/debug.h>
#include <mach/mach_time.h>
#include <sys/errno.h>
#include <string.h>


extern struct vc_info vinfo;
extern boolean_t panicDialogDesired;

#include "panic_image.c"

void panic_ui_initialize(const unsigned char * system_clut);
int panic_dialog_set_image( const unsigned char * ptr, unsigned int size );
void panic_dialog_get_image( unsigned char ** ptr, unsigned int * size );
void draw_panic_dialog( void );
void panic_dialog_test( void );

static int panic_dialog_verify( const struct panicimage * data, unsigned int size );
static int pixels_needed_to_blit_digit( int digit );
static void blit_digit( int digit );
static char * strnstr(const char * s, const char * find, size_t slen);
static void dim_screen(void);
static void panic_blit_rect(unsigned int x, unsigned int y, unsigned int width, unsigned int height,
							int transparent, unsigned char * dataPtr );

static int panic_info_x;
static int panic_info_y;

static const unsigned char * active_clut = NULL;			/* This is a copy of the active clut */

static boolean_t panicDialogDrawn = FALSE;

static const struct panicimage * panic_dialog = NULL;		/* the active panic dialog */
static const unsigned char * panic_dialog_data = NULL;		/* where the image data starts */
static const unsigned char * panic_dialog_clut = NULL;		/* where the clut used for the image starts */

static unsigned char * curr_image_ptr = NULL;				/* If NULL, the default panic dialog is active */
static unsigned int curr_image_size = 0;

#define FONT_WIDTH	8
#define FONT_HEIGHT	16
static unsigned short rendered_font[FONT_HEIGHT][FONT_WIDTH];

static char versionbuf[20];		/* ####.###~###\0 */

#define isdigit(d) ((d) >= '0' && (d) <= '9')

#define CLUT_ENTRIES	256
#define CLUT_SIZE		(CLUT_ENTRIES * 3)


/*
 * This routine sets up the default panic dialog
 */

extern unsigned char iso_font[];
extern const char version[];
extern unsigned int panic_caller;

void
panic_ui_initialize(const unsigned char * system_clut)
{
	char vstr[20];


	panic_dialog_set_image( NULL, 0 );

	active_clut = system_clut;

	strcpy(vstr, "custom");

	/* Convert xnu-####.###.obj~### into ####.###~### */

	if (version) {
		char * versionpos = strnstr(version, "xnu-", 20);

		if (versionpos) {
			int len, i;

			vstr[0] = '\0';

			for (i=0,len=4;len<20;len++) {
				if (isdigit(versionpos[len]) || versionpos[len] == '.') {	/* extract ####.###. */
					vstr[i++] = versionpos[len];
					continue;
				}
				break;
			}

			if ( versionpos[len-1] == '.' )     		/* remove trailing period if present */
				i--;

			for (;len<20;len++) {						/* skip to next digit if present */
				if ( !isdigit(versionpos[len]) )
					continue;
				break;
			}

			if ( versionpos[len-1] == '~' ) {				/* extract ~### if present */
				vstr[i++] = versionpos[len-1];
				for (;len<20;len++) {						/* extract ### */
					if ( isdigit(versionpos[len]) ) {
						vstr[i++] = versionpos[len];
						continue;
					}
					break;
				}
			}

			vstr[i] = '\0';
		}
	}

	strcpy(versionbuf, vstr);
}



void
panic_dialog_test( void )
{
	boolean_t o_panicDialogDrawn = panicDialogDrawn;
	boolean_t o_panicDialogDesired = panicDialogDesired;
	unsigned int o_logPanicDataToScreen = logPanicDataToScreen;
	unsigned int o_panic_caller = panic_caller;
	unsigned int o_panicDebugging = panicDebugging;


	panicDebugging = TRUE;
	panic_caller = (unsigned int) __builtin_return_address(0);
	logPanicDataToScreen = FALSE;
	panicDialogDesired = TRUE;
	panicDialogDrawn = FALSE;

	draw_panic_dialog();

	panicDebugging = o_panicDebugging;
	panic_caller = o_panic_caller;
	logPanicDataToScreen = o_logPanicDataToScreen;
	panicDialogDesired = o_panicDialogDesired;
	panicDialogDrawn = o_panicDialogDrawn;
}


void 
draw_panic_dialog( void )
{
	if (!panicDialogDrawn && panicDialogDesired) {
		if ( !logPanicDataToScreen ) {
			int pd_x, pd_y;
			int count, nibble, indx;
			struct ether_addr kdp_mac_addr;
			unsigned int panic_dialog_count, ip_addr;
			char panic_num_chars[13+8+1], mac_addr_chars[17+1], ip_addr_chars[15+1];
			struct {
					int	pixels;
					char * chars;
			} panic_dialog_info[3];


			/* dim the screen 50% before putting up panic dialog */
		  	dim_screen();

			/* set up to draw background box */
			/* by locating where the upper left corner is placed */

			pd_x = (vinfo.v_width/2) - panic_dialog->pd_width/2;
			pd_y = (vinfo.v_height/2) - panic_dialog->pd_height/2;
		
			/*  draw panic dialog at pd_x/pd_y */
			panic_blit_rect( pd_x, pd_y, panic_dialog->pd_width, panic_dialog->pd_height, 
										 0, (unsigned char*) panic_dialog_data);
		
			panic_dialog_count = 0;		/* number of info items to display at the bottom of dialog */

			if (panicDebugging) {
				int x1, x2;

				/*
				 * PANIC CALLER
				 *
				 *  don't display the panic caller if it is 0
				 *
				 */

				if ( panic_caller != 0 ) {
					/* Calculate the pixels need to generate the panic number */ 
					panic_dialog_info[panic_dialog_count].pixels = 0;

					for ( indx=1, count=0; count < 13; count++ ) {
						if ( versionbuf[count] == '\0' )
							break;

						panic_num_chars[indx++] = versionbuf[count];
						panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( versionbuf[count] );
					}

					panic_num_chars[indx++] = ':';
					panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( ':' );

					for ( count=8; count != 0; count-- ) {
						nibble = (panic_caller >> ((count-1)<<2)) &0xF;
						panic_num_chars[indx++] = nibble;
						panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( nibble );
					}
				
					panic_num_chars[0] = indx;
					panic_dialog_info[panic_dialog_count].chars = panic_num_chars;
					panic_dialog_count++;
				}
		
				/*
				 * MAC ADDRESS
				 *
				 * if the mac address is not available, then use ff:ff:ff:ff:ff:ff
				 *
				 */

				kdp_mac_addr  = kdp_get_mac_addr();
		
				/* If no mac_addr has been set, then force to -1 */
				if( ! (kdp_mac_addr.ether_addr_octet[0] || kdp_mac_addr.ether_addr_octet[1] || kdp_mac_addr.ether_addr_octet[2]
					|| kdp_mac_addr.ether_addr_octet[3] || kdp_mac_addr.ether_addr_octet[4] || kdp_mac_addr.ether_addr_octet[5])) {
					for (count = 0; count < 6; count++ )
						kdp_mac_addr.ether_addr_octet[count] = -1;
				}

				panic_dialog_info[panic_dialog_count].pixels = 0;

				for (indx=1, count=0; count < 6; count++ ) {
					nibble =  (kdp_mac_addr.ether_addr_octet[count] & 0xf0) >> 4;
					mac_addr_chars[indx++] = nibble;
					panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( nibble );
				
					nibble =  kdp_mac_addr.ether_addr_octet[count] & 0xf;
					mac_addr_chars[indx++] = nibble;
					panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( nibble );

					if( count < 5 ) {
						mac_addr_chars[indx++] = ':';
						panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( ':' );
					}
				}

				mac_addr_chars[0] = indx;
				panic_dialog_info[panic_dialog_count].chars = mac_addr_chars;
				panic_dialog_count++;

				/*
				 * IP ADDRESS
				 *
				 * do not display the ip addresses if the machine isn't attachable.
				 * there's no sense in possibly confusing people.
				 */

				if ( (ip_addr = (unsigned int) ntohl(kdp_get_ip_address())) != 0 ) {
					int d1, d2, d3;

					panic_dialog_info[panic_dialog_count].pixels = 0;

					for ( indx=1, count=0; count < 4; count++ ) {
						nibble = (ip_addr & 0xff000000 ) >> 24;
				
						d3 = (nibble % 10) ; nibble = nibble / 10;
						d2 = (nibble % 10) ; nibble = nibble / 10;
						d1 = (nibble % 10) ;
					
						if( d1 != 0 ) {
							ip_addr_chars[indx++] = d1; 
							panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( d1 );
						}

						ip_addr_chars[indx++] = d2; 
						panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( d2 );

						ip_addr_chars[indx++] = d3; 
						panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( d3 );

						if ( count < 3 ) {
							ip_addr_chars[indx++] = '.'; 
							panic_dialog_info[panic_dialog_count].pixels += pixels_needed_to_blit_digit( '.' );
						}
					
						d1= d2 = d3 = 0;
						ip_addr = ip_addr << 8;
					}

					ip_addr_chars[0] = indx;
					panic_dialog_info[panic_dialog_count].chars = ip_addr_chars;
					panic_dialog_count++;
				}


				/* vertical alignment for information to be displayed */
				panic_info_y = (vinfo.v_height/2) + panic_dialog->pd_height/2 - (panic_dialog->pd_info_height);

				/* blit out all the information we gathered */

				switch ( panic_dialog_count ) {
					case 1 :	/* one item is centered */
							panic_info_x = (vinfo.v_width/2) - (panic_dialog_info[0].pixels/2);
							for (indx=1; indx < panic_dialog_info[0].chars[0]; indx++)
								blit_digit(panic_dialog_info[0].chars[indx]);

							break;

					case 2 : /* left centered and right centered */
							x1 = ((panic_dialog->pd_width/2) - panic_dialog_info[0].pixels)/2;
							panic_info_x = ((vinfo.v_width/2) - (panic_dialog->pd_width/2)) + x1;

							for (indx=1; indx < panic_dialog_info[0].chars[0]; indx++)
								blit_digit(panic_dialog_info[0].chars[indx]);

							x2 = ((panic_dialog->pd_width/2) - panic_dialog_info[1].pixels)/2;
							panic_info_x = (vinfo.v_width/2) + x2;

							for (indx=1; indx < panic_dialog_info[1].chars[0]; indx++)
								blit_digit(panic_dialog_info[1].chars[indx]);

							break;

					case 3 : /* left centered, middle and right centered */
							x1 = ((panic_dialog->pd_width/2) - panic_dialog_info[0].pixels - (panic_dialog_info[1].pixels/2))/2;
							panic_info_x = ((vinfo.v_width/2) - (panic_dialog->pd_width/2)) + x1;

							for (indx=1; indx < panic_dialog_info[0].chars[0]; indx++)
								blit_digit(panic_dialog_info[0].chars[indx]);

							panic_info_x = (vinfo.v_width/2) - (panic_dialog_info[1].pixels/2);

							for (indx=1; indx < panic_dialog_info[1].chars[0]; indx++)
								blit_digit(panic_dialog_info[1].chars[indx]);

							x2 = ((panic_dialog->pd_width/2) - panic_dialog_info[2].pixels - (panic_dialog_info[1].pixels/2))/2;
							panic_info_x = (vinfo.v_width/2) + x2 + (panic_dialog_info[1].pixels/2);

							for (indx=1; indx < panic_dialog_info[2].chars[0]; indx++)
								blit_digit(panic_dialog_info[2].chars[indx]);

							break;

					default :  /* nothing */
							break;

				} /* switch */
			} /* if panic_deugging */
		} /* if ! logPanicDataToScreen */
	} /* if ! panicDialogDrawn && ! panicDialogDesired */

	panicDialogDrawn = TRUE;
	panicDialogDesired = FALSE;
}


/*
 * This routine installs a new panic dialog
 * If ptr is NULL, then the default "built-in" panic dialog will be installed.
 * note: It is the caller that must take care of deallocating memory used for the previous panic dialog
 */

int
panic_dialog_set_image( const unsigned char * ptr, unsigned int size )
{
	int error;
	unsigned int newsize;
	const struct panicimage * newimage;

	/* if ptr is NULL, restore panic image to built-in default */
	if ( ptr == NULL ) {
		newimage = &panic_dialog_default;
		newsize = sizeof(struct panicimage) + newimage->pd_dataSize;
	}
	else {
		newimage = (struct panicimage *) ptr;
		newsize = size;
	}

	if ( (error = panic_dialog_verify( newimage, newsize )) )
		return (error);

	panic_dialog = newimage;
	panic_dialog_data = &panic_dialog->data[0];
	panic_dialog_clut = &panic_dialog->data[panic_dialog->pd_dataSize-CLUT_SIZE];

	curr_image_ptr = (unsigned char *) ptr;
	curr_image_size = size;

	return (0);
}


/*
 * This routines returns the current address of the panic dialog
 * If the default panic dialog is active, then *ptr will be NULL
 */

void
panic_dialog_get_image( unsigned char ** ptr, unsigned int * size )
{
	*ptr =  curr_image_ptr;
	*size = curr_image_size;
}


/*
 * This routine verifies the panic dialog image is valid.
 */

static int
panic_dialog_verify( const struct panicimage * newimage, unsigned int size )
{
	unsigned int sum, i;

	if ( size < (sizeof(struct panicimage) + newimage->pd_dataSize) )
		return EINVAL;

	if ( newimage->pd_tag != 'RNMp' )
		return EINVAL;

	size = newimage->pd_dataSize-CLUT_SIZE;
	for (sum=0,i=0; i<size; i++) {
		sum += newimage->data[i];
		sum <<= sum&1;
	}

	if ( sum != newimage->pd_sum )
		return EINVAL;

	return 0;
}


/*
 * Service Routines for managing the panic dialog 
 */


static const struct rendered_num * find_rendered_digit( int digit );
static void panic_blit_rect_8(	unsigned int x, unsigned int y, unsigned int width, unsigned int height,
								int transparent, unsigned char * dataPtr );
static void panic_blit_rect_16(	unsigned int x, unsigned int y, unsigned int width, unsigned int height,
								int transparent, unsigned char * dataPtr );
static void panic_blit_rect_32(	unsigned int x, unsigned int y, unsigned int width, unsigned int height,
								int transparent, unsigned char * dataPtr );
static int decode_rle( unsigned char * dataPtr, unsigned int * quantity, unsigned int * depth, unsigned char ** value );


/* Utilities to convert 8 bit/gray */
static unsigned int make24bitcolor( unsigned int index, const unsigned char * clut );
static unsigned char findIndexMatch( unsigned char index );
static unsigned char color24togray8( unsigned int color24 );
static unsigned char findbestgray( unsigned int color24 );
static int isActiveClutOK( void );

static int
pixels_needed_to_blit_digit( int digit )
{
	return FONT_WIDTH;
}


static const struct rendered_num *
find_rendered_digit( int digit )
{
	//extern unsigned char iso_font[];
	const struct rendered_num *digitPtr;

	if ( digit < 16 ) {
		if ( digit < 10 )
			digit += 0x30;
		else
			digit += 0x37;
	}

	digitPtr = (const struct rendered_num *) &iso_font[digit * 16];
	return digitPtr;
}


static void 
blit_digit( int digit )
{
	unsigned char * raw_data = (unsigned char *) find_rendered_digit( digit );
	unsigned width = FONT_WIDTH, height = FONT_HEIGHT;
	int row;

	for (row=0; row<FONT_HEIGHT; row++) {
		int j;
		unsigned char bits;

		bits = raw_data[row];
		for( j=FONT_WIDTH-1; j>=0; j--) {

			if ( bits & 0x80 )
				rendered_font[row][j] = 0x0100 | panic_dialog->pd_info_color[0];
			else
				rendered_font[row][j] = 0x0100 | panic_dialog->pd_info_color[1];
			bits <<= 1;
		}
	}
	
	panic_blit_rect( panic_info_x, panic_info_y , width, height, 255, (unsigned char *) rendered_font);
	panic_info_x += width;
}


static void 
panic_blit_rect(	unsigned int x, unsigned int y,
					unsigned int width, unsigned int height,
					int transparent, unsigned char * dataPtr )
{
	if(!vinfo.v_depth)
		return;
		
    switch( vinfo.v_depth) {
	case 8:
	    panic_blit_rect_8( x, y, width, height, transparent, dataPtr);
	    break;
	case 16:
	    panic_blit_rect_16( x, y, width, height, transparent, dataPtr);
	    break;
	case 32:
	    panic_blit_rect_32( x, y, width, height, transparent, dataPtr);
	    break;
    }
}

/*
 *  panic_blit_rect_8 decodes the RLE encoded image data on the fly, looks up the
 *	color by indexing into the clut, or attempts to find the best index.
 */

static void 
panic_blit_rect_8(	unsigned int x, unsigned int y,
					unsigned int width, unsigned int height,
					int transparent, unsigned char * dataPtr )
{
	volatile unsigned char * dst;
	unsigned int line, col, i;
	static int clutOK = -1;
	unsigned int data, quantity, depth;
	unsigned char * value;
	

	if ( clutOK == -1 )
		clutOK = isActiveClutOK();

	dst = (volatile unsigned char *) (vinfo.v_baseaddr +
									 (y * vinfo.v_rowbytes) +
									 x);
	
	quantity = 0;
	i = 0;
	
	for( line = 0; line < height; line++) {
		for( col = 0; col < width; col++) {

			if (quantity == 0) {
				dataPtr += decode_rle(dataPtr, &quantity, &depth, &value);
				i = 0;
			}
			
			if ( clutOK )
				data = value[i++];
			else
				data = findIndexMatch( value[i++] );

			*(dst + col) = data;

			if ( i == depth ) {
				i = 0;
				quantity--;
			}
		}
		
		dst = (volatile unsigned char *) (((int)dst) + vinfo.v_rowbytes);
	}
}

/*
 *  panic_blit_rect_16 decodes the RLE encoded image data on the fly, looks up the
 *	color by indexing into the clut, uses the top 5 bits to fill in each of the three 
 *	pixel values (RGB) and writes each pixel to the screen.
 */

 static void 
 panic_blit_rect_16(	unsigned int x, unsigned int y,
			 			unsigned int width, unsigned int height,
			 			int transparent, unsigned char * dataPtr )
 {

	volatile unsigned short * dst;
	unsigned int line, col, i;
	unsigned int  quantity, index, data, depth;
	unsigned char * value;

	dst = (volatile unsigned short *) (vinfo.v_baseaddr +
									  (y * vinfo.v_rowbytes) +
									  (x * 2));

	quantity = 0;
	i = 0;

	for( line = 0; line < height; line++) {
		for( col = 0; col < width; col++) {

			if (quantity == 0) {
				dataPtr += decode_rle(dataPtr, &quantity, &depth, &value);
				i = 0;
			}

			index = value[i++] * 3;
			
			data = ( (unsigned short) (0xf8 & (panic_dialog_clut[index + 0])) << 7)
				 | ( (unsigned short) (0xf8 & (panic_dialog_clut[index + 1])) << 2)
			 	 | ( (unsigned short) (0xf8 & (panic_dialog_clut[index + 2])) >> 3);

			*(dst + col) = data;

			if ( i == depth ) {
				i = 0;
				quantity--;
			}
		}

		dst = (volatile unsigned short *) (((int)dst) + vinfo.v_rowbytes);
	}
 }

/*
 *	 panic_blit_rect_32 decodes the RLE encoded image data on the fly, and fills
 *	 in each of the three pixel values from the clut (RGB) for each pixel and 
 *	 writes it to the screen.
 */	

 static void 
 panic_blit_rect_32(	unsigned int x, unsigned int y,
			 			unsigned int width, unsigned int height,
			 			int transparent, unsigned char * dataPtr )
 {
	volatile unsigned int * dst;
	unsigned int line, col, i;
	unsigned int quantity, index, data, depth;
	unsigned char * value;


	dst = (volatile unsigned int *) (vinfo.v_baseaddr +
									(y * vinfo.v_rowbytes) +
									(x * 4));
	
	quantity = 0;
	i = 0;
	
	for( line = 0; line < height; line++) {
		for( col = 0; col < width; col++) {

			if (quantity == 0) {
				dataPtr += decode_rle(dataPtr, &quantity, &depth, &value);
				i = 0;
			}

			index = value[i++] * 3;
			
			data = ( (unsigned int) panic_dialog_clut[index + 0] << 16)
				 | ( (unsigned int) panic_dialog_clut[index + 1] << 8)
				 | ( (unsigned int) panic_dialog_clut[index + 2]);
			
			*(dst + col) = data;

			if ( i == depth ) {
				i = 0;
				quantity--;
			}
		}
		
		dst = (volatile unsigned int *) (((int)dst) + vinfo.v_rowbytes);
	}
}

/* 	
    decode_rle decodes a single quantity/value run of a "modified-RLE" encoded
    image. The encoding works as follows:

	The run is described in the first byte.  If the MSB is zero, then the next seven bits
	are the quantity of bytes that follow that make up the run of value bytes.  (see case 0)

	If the MSB is set, bits 0-3 are the quantity's least significant 4 bits.  If bit 5 is set,
	then the quantity is further described in the next byte, where an additional 7 bits (4-10)
	worth of quantity will be found.  If the MSB of this byte is set, then an additional
	7 bits (11-17) worth of quantity will be found in the next byte. This repeats until the MSB of
	a quantity byte is zero, thus ending the run of quantity bytes.

	Bits 5/6 of the first byte, describe the number of bytes in the value run following the quantity run.
	These bits describe value runs of 1 to 4 bytes.  And the quantity describe the number of value runs.
	(see cases 1-4)
	
	encodings are: (q = quantity, v = value, c = quantity continues)
		
  case 0: [ 0       q6-q0 ] [ v7-v0 ] ... [ v7-v0 ]
  case 1: [ 1 0 0 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ]
  case 2: [ 1 0 1 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ] [ v7-v0 ]
  case 3: [ 1 1 0 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ] [ v7-v0 ] [ v7-v0 ]
  case 4: [ 1 1 1 c q3-q0 ] [ c q10-q4 ] [ c q17-q11 ] [ q24-q18 ] [ v7-v0 ] [ v7-v0 ] [ v7-v0 ] [ v7-v0 ]
*/

static int
decode_rle( unsigned char * dataPtr, unsigned int * quantity, unsigned int * depth, unsigned char ** value )
{
	unsigned int mask;
	int i, runlen, runsize;

	i = 0;
	mask = dataPtr[i] & 0xF0;

	if ( mask & 0x80 ) {
		runsize = ((mask & 0x60) >> 5) + 1;
		runlen = dataPtr[i++] & 0x0F;

		if ( mask & 0x10 ) {
			int shift = 4;

			do {
				mask = dataPtr[i] & 0x80;
				runlen |= ((dataPtr[i++] & 0x7F) << shift);
				shift+=7;
			} while (mask);
		}
	} else {
		runlen = 1;
		runsize = dataPtr[i++];
	}

	*depth = runsize;
	*quantity = runlen;
	*value = &dataPtr[i];

	return i+runsize;
}


static void 
dim_screen(void)
{
	unsigned long *p, *endp, *row;
	int      col, rowline, rowlongs;
	register unsigned long mask;

	if(!vinfo.v_depth)
		return;

	if ( vinfo.v_depth == 32 )
		mask = 0x007F7F7F;
	else if ( vinfo.v_depth == 16 )
		mask = 0x3DEF3DEF;
	else
		return;

	rowline = vinfo.v_rowscanbytes / 4;
	rowlongs = vinfo.v_rowbytes / 4;

	p = (unsigned long*) vinfo.v_baseaddr;
	endp = p + (rowlongs * vinfo.v_height);

	for (row = p ; row < endp ; row += rowlongs) {
		for (p = &row[0], col = 0; col < rowline; col++) {
			*p++ = (*p >> 1) & mask;
		}
	}
}


/* From user mode Libc - this ought to be in a library */
static char *
strnstr(const char * s, const char * find, size_t slen)
{
  char c, sc;
  size_t len;

  if ((c = *find++) != '\0') {
    len = strlen(find);
    do {
      do {
    if ((sc = *s++) == '\0' || slen-- < 1)
      return (NULL);
      } while (sc != c);
      if (len > slen)
    return (NULL);
    } while (strncmp(s, find, len) != 0);
    s--; 
  }       
  return ((char *)s);
} 

/*
 * these routines are for converting a color into grayscale
 * in 8-bit mode, if the active clut is different than the
 * clut used to create the panic dialog, then we must convert to gray
 */

static unsigned int
make24bitcolor( unsigned int index, const unsigned char * clut )
{
	unsigned int color24 = 0;
	int i = index * 3;

	color24 |= clut[i+0] << 16;
	color24 |= clut[i+1] << 8;
	color24 |= clut[i+2];

	return color24;
}


static unsigned char
findbestgray( unsigned int color24 )
{
	unsigned int c24, rel, bestindex=-1, bestgray = -1;
	unsigned char gray8, c8;
	int i;
#define abs(v)  ((v) > 0)?(v):-(v)

	gray8 = color24togray8( color24 ); 		/* convert the original color into grayscale */

	for (i=0; i<CLUT_ENTRIES; i++) {
		c24  = make24bitcolor( i, active_clut );
		if ( (((c24>>16)&0xff) != ((c24>>8)&0xff)) || ((c24>>8)&0xff) != (c24 & 0xff) )
			continue;				/* only match against grays */

		c8 = c24 & 0xFF;			/* isolate the gray */

		/* find the gray with the smallest difference */
		rel = abs( gray8 - c8 );
		if ( rel < bestgray ) {
			bestgray = rel;
			bestindex = i;
		}
	}

	/* Did we fail to find any grays ? */
	if ( bestindex == -1 ) {
		/* someday we should look for the best color match */
		/* but for now just return the gray as the index */
		/* at least there might be something readble on the display */

		bestindex = gray8;
	}

	return bestindex;
#undef abs
}


static unsigned char
color24togray8( unsigned int color24 )
{       
    float R, G, B;
    float Gray;
    unsigned char gray8;
    
    R = (color24 & 0xFF0000) >> 16 ;
    G = (color24 & 0xFF00) >> 8 ;
    B = (color24 & 0xFF);
    
    Gray = (R*.30) + (G*.59) + (B*.11);
    gray8 = (unsigned char) ( Gray + .5);
    return gray8;
}       


static unsigned char
findIndexMatch( unsigned char index )
{
	static unsigned int last_in_index = -1;
	static unsigned char last_index;
	unsigned int sc;

	if ( index == last_in_index )
		return last_index;

	last_in_index = index;
	sc = make24bitcolor( index, panic_dialog_clut );
	last_index = findbestgray( sc );		/* find the nearest matching gray in the active clut */

	return last_index;
}

static int
isActiveClutOK( void )
{
	int i;
	int r = 1; /* assume OK */

	for (i=0; i<CLUT_ENTRIES; i++) {
		if ( panic_dialog_clut[i] == active_clut[i] ) continue;
		r = 0;
		break;
	}

	return r;
}
