/*
 * Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
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

#include <vc.h>

#include <console/video_console.h>
#include <kdp/kdp_udp.h>
#include <kern/debug.h>

#include "panic_image.c"
#include "rendered_numbers.c"

extern struct vc_info vinfo;
extern boolean_t panicDialogDesired;

/* panic image clut */
static const unsigned char *clut = NULL;
extern void panic_ui_initialize(const unsigned char * system_clut);

/* We use this standard MacOS clut as a fallback */
static const unsigned char appleClut8[ 256 * 3 ] = { 
// 00
	0xFF,0xFF,0xFF, 0xFF,0xFF,0xCC,	0xFF,0xFF,0x99,	0xFF,0xFF,0x66,
	0xFF,0xFF,0x33, 0xFF,0xFF,0x00,	0xFF,0xCC,0xFF,	0xFF,0xCC,0xCC,
	0xFF,0xCC,0x99, 0xFF,0xCC,0x66,	0xFF,0xCC,0x33,	0xFF,0xCC,0x00,
	0xFF,0x99,0xFF, 0xFF,0x99,0xCC,	0xFF,0x99,0x99,	0xFF,0x99,0x66,
// 10
	0xFF,0x99,0x33, 0xFF,0x99,0x00,	0xFF,0x66,0xFF,	0xFF,0x66,0xCC,
	0xFF,0x66,0x99, 0xFF,0x66,0x66,	0xFF,0x66,0x33,	0xFF,0x66,0x00,
	0xFF,0x33,0xFF, 0xFF,0x33,0xCC,	0xFF,0x33,0x99,	0xFF,0x33,0x66,
	0xFF,0x33,0x33, 0xFF,0x33,0x00,	0xFF,0x00,0xFF,	0xFF,0x00,0xCC,
// 20
	0xFF,0x00,0x99, 0xFF,0x00,0x66,	0xFF,0x00,0x33,	0xFF,0x00,0x00,
	0xCC,0xFF,0xFF, 0xCC,0xFF,0xCC,	0xCC,0xFF,0x99,	0xCC,0xFF,0x66,
	0xCC,0xFF,0x33, 0xCC,0xFF,0x00,	0xCC,0xCC,0xFF,	0xCC,0xCC,0xCC,
	0xCC,0xCC,0x99, 0xCC,0xCC,0x66,	0xCC,0xCC,0x33,	0xCC,0xCC,0x00,
// 30
	0xCC,0x99,0xFF, 0xCC,0x99,0xCC,	0xCC,0x99,0x99,	0xCC,0x99,0x66,
	0xCC,0x99,0x33, 0xCC,0x99,0x00,	0xCC,0x66,0xFF,	0xCC,0x66,0xCC,
	0xCC,0x66,0x99, 0xCC,0x66,0x66,	0xCC,0x66,0x33,	0xCC,0x66,0x00,
	0xCC,0x33,0xFF, 0xCC,0x33,0xCC,	0xCC,0x33,0x99,	0xCC,0x33,0x66,
// 40
	0xCC,0x33,0x33, 0xCC,0x33,0x00,	0xCC,0x00,0xFF,	0xCC,0x00,0xCC,
	0xCC,0x00,0x99, 0xCC,0x00,0x66,	0xCC,0x00,0x33,	0xCC,0x00,0x00,
	0x99,0xFF,0xFF, 0x99,0xFF,0xCC,	0x99,0xFF,0x99,	0x99,0xFF,0x66,
	0x99,0xFF,0x33, 0x99,0xFF,0x00,	0x99,0xCC,0xFF,	0x99,0xCC,0xCC,
// 50
	0x99,0xCC,0x99, 0x99,0xCC,0x66,	0x99,0xCC,0x33,	0x99,0xCC,0x00,
	0x99,0x99,0xFF, 0x99,0x99,0xCC,	0x99,0x99,0x99,	0x99,0x99,0x66,
	0x99,0x99,0x33, 0x99,0x99,0x00,	0x99,0x66,0xFF,	0x99,0x66,0xCC,
	0x99,0x66,0x99, 0x99,0x66,0x66,	0x99,0x66,0x33,	0x99,0x66,0x00,
// 60
	0x99,0x33,0xFF, 0x99,0x33,0xCC,	0x99,0x33,0x99,	0x99,0x33,0x66,
	0x99,0x33,0x33, 0x99,0x33,0x00,	0x99,0x00,0xFF,	0x99,0x00,0xCC,
	0x99,0x00,0x99, 0x99,0x00,0x66,	0x99,0x00,0x33,	0x99,0x00,0x00,
	0x66,0xFF,0xFF, 0x66,0xFF,0xCC,	0x66,0xFF,0x99,	0x66,0xFF,0x66,
// 70
	0x66,0xFF,0x33, 0x66,0xFF,0x00,	0x66,0xCC,0xFF,	0x66,0xCC,0xCC,
	0x66,0xCC,0x99, 0x66,0xCC,0x66,	0x66,0xCC,0x33,	0x66,0xCC,0x00,
	0x66,0x99,0xFF, 0x66,0x99,0xCC,	0x66,0x99,0x99,	0x66,0x99,0x66,
	0x66,0x99,0x33, 0x66,0x99,0x00,	0x66,0x66,0xFF,	0x66,0x66,0xCC,
// 80
	0x66,0x66,0x99, 0x66,0x66,0x66,	0x66,0x66,0x33,	0x66,0x66,0x00,
	0x66,0x33,0xFF, 0x66,0x33,0xCC,	0x66,0x33,0x99,	0x66,0x33,0x66,
	0x66,0x33,0x33, 0x66,0x33,0x00,	0x66,0x00,0xFF,	0x66,0x00,0xCC,
	0x66,0x00,0x99, 0x66,0x00,0x66,	0x66,0x00,0x33,	0x66,0x00,0x00,
// 90
	0x33,0xFF,0xFF, 0x33,0xFF,0xCC,	0x33,0xFF,0x99,	0x33,0xFF,0x66,
	0x33,0xFF,0x33, 0x33,0xFF,0x00,	0x33,0xCC,0xFF,	0x33,0xCC,0xCC,
	0x33,0xCC,0x99, 0x33,0xCC,0x66,	0x33,0xCC,0x33,	0x33,0xCC,0x00,
	0x33,0x99,0xFF, 0x33,0x99,0xCC,	0x33,0x99,0x99,	0x33,0x99,0x66,
// a0
	0x33,0x99,0x33, 0x33,0x99,0x00,	0x33,0x66,0xFF,	0x33,0x66,0xCC,
	0x33,0x66,0x99, 0x33,0x66,0x66,	0x33,0x66,0x33,	0x33,0x66,0x00,
	0x33,0x33,0xFF, 0x33,0x33,0xCC,	0x33,0x33,0x99,	0x33,0x33,0x66,
	0x33,0x33,0x33, 0x33,0x33,0x00,	0x33,0x00,0xFF,	0x33,0x00,0xCC,
// b0
	0x33,0x00,0x99, 0x33,0x00,0x66,	0x33,0x00,0x33,	0x33,0x00,0x00,
	0x00,0xFF,0xFF, 0x00,0xFF,0xCC,	0x00,0xFF,0x99,	0x00,0xFF,0x66,
	0x00,0xFF,0x33, 0x00,0xFF,0x00,	0x00,0xCC,0xFF,	0x00,0xCC,0xCC,
	0x00,0xCC,0x99, 0x00,0xCC,0x66,	0x00,0xCC,0x33,	0x00,0xCC,0x00,
// c0
	0x00,0x99,0xFF, 0x00,0x99,0xCC,	0x00,0x99,0x99,	0x00,0x99,0x66,
	0x00,0x99,0x33, 0x00,0x99,0x00,	0x00,0x66,0xFF,	0x00,0x66,0xCC,
	0x00,0x66,0x99, 0x00,0x66,0x66,	0x00,0x66,0x33,	0x00,0x66,0x00,
	0x00,0x33,0xFF, 0x00,0x33,0xCC,	0x00,0x33,0x99,	0x00,0x33,0x66,
// d0
	0x00,0x33,0x33, 0x00,0x33,0x00,	0x00,0x00,0xFF,	0x00,0x00,0xCC,
	0x00,0x00,0x99, 0x00,0x00,0x66,	0x00,0x00,0x33,	0xEE,0x00,0x00,
	0xDD,0x00,0x00, 0xBB,0x00,0x00,	0xAA,0x00,0x00,	0x88,0x00,0x00,
	0x77,0x00,0x00, 0x55,0x00,0x00,	0x44,0x00,0x00,	0x22,0x00,0x00,
// e0
	0x11,0x00,0x00, 0x00,0xEE,0x00,	0x00,0xDD,0x00,	0x00,0xBB,0x00,
	0x00,0xAA,0x00, 0x00,0x88,0x00,	0x00,0x77,0x00,	0x00,0x55,0x00,
	0x00,0x44,0x00, 0x00,0x22,0x00,	0x00,0x11,0x00,	0x00,0x00,0xEE,
	0x00,0x00,0xDD, 0x00,0x00,0xBB,	0x00,0x00,0xAA,	0x00,0x00,0x88,
// f0
	0x00,0x00,0x77, 0x00,0x00,0x55,	0x00,0x00,0x44,	0x00,0x00,0x22,
	0x00,0x00,0x11, 0xEE,0xEE,0xEE,	0xDD,0xDD,0xDD,	0xBB,0xBB,0xBB,
	0xAA,0xAA,0xAA, 0x88,0x88,0x88,	0x77,0x77,0x77,	0x55,0x55,0x55,
	0x44,0x44,0x44, 0x22,0x22,0x22,	0x11,0x11,0x11,	0x00,0x00,0x00
};


/* panic dialog and info saving */
static int mac_addr_digit_x;
static int mac_addr_digit_y;
static void blit_digit( int digit );
static boolean_t panicDialogDrawn = FALSE;

static void 
panic_blit_rect(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );
			
static void 
panic_blit_rect_8(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );
			
static void 
panic_blit_rect_16(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );
			
static void 
panic_blit_rect_32(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr );

static void 
dim_screen(void);

static void 
dim_screen_16(void);

static void 
dim_screen_32(void);

static int 
decode_rle( unsigned char * dataPtr, unsigned int * quantity, unsigned int * value );

void 
panic_ui_initialize(const unsigned char * system_clut)
{
	clut = system_clut;
}

void 
draw_panic_dialog( void )
{
	int pd_x,pd_y, iconx, icony, tx_line, tx_col;
	int line_width = 1;
	int f1, f2, d1, d2, d3, rem;
	char *pair = "ff";
	int count = 0;
	char digit;
	int nibble;
	char colon = ':';
	char dot = '.';
	struct ether_addr kdp_mac_addr  = kdp_get_mac_addr();
	unsigned int ip_addr = (unsigned int) ntohl(kdp_get_ip_address());

	if (!panicDialogDrawn && panicDialogDesired)
	{
		if ( !logPanicDataToScreen )
		{

			/* dim the screen 50% before putting up panic dialog */
		  	dim_screen();

			/* set up to draw background box */
			pd_x = (vinfo.v_width/2) - panic_dialog.pd_width/2;
			pd_y = (vinfo.v_height/2) - panic_dialog.pd_height/2;
		
			/*  draw image	*/
			panic_blit_rect( pd_x, pd_y, panic_dialog.pd_width, panic_dialog.pd_height, 0, (unsigned char*) panic_dialog.image_pixel_data);
		
			/* do not display the mac and ip addresses if the machine isn't attachable. */
			/* there's no sense in possibly confusing people. */
			if (panicDebugging)
			{
		
				/* offset for mac address text */
				mac_addr_digit_x = (vinfo.v_width/2) - 130; /* use 62 if no ip */
				mac_addr_digit_y = (vinfo.v_height/2) + panic_dialog.pd_height/2 - 20;
		
				if(kdp_mac_addr.ether_addr_octet[0] || kdp_mac_addr.ether_addr_octet[1]|| kdp_mac_addr.ether_addr_octet[2]
					|| kdp_mac_addr.ether_addr_octet[3] || kdp_mac_addr.ether_addr_octet[4] || kdp_mac_addr.ether_addr_octet[5])
				{
					/* blit the digits for mac address */
					for (count = 0; count < 6; count++ )
					{
						nibble =  (kdp_mac_addr.ether_addr_octet[count] & 0xf0) >> 4;
						digit = nibble < 10 ? nibble + '0':nibble - 10 + 'a';
						blit_digit(digit);
				
						nibble =  kdp_mac_addr.ether_addr_octet[count] & 0xf;
						digit = nibble < 10 ? nibble + '0':nibble - 10 + 'a';
						blit_digit(digit);
						if( count < 5 )
							blit_digit( colon );
					}
				}
				else	/* blit the ff's */
				{
					for( count = 0; count < 6; count++ )
					{
						digit = pair[0];
						blit_digit(digit);
						digit = pair[1];
						blit_digit(digit);
						if( count < 5 )
							blit_digit( colon );
					}
				}
				/* now print the ip address */
				mac_addr_digit_x = (vinfo.v_width/2) + 10;
				if(ip_addr != 0)
				{
					/* blit the digits for ip address */
					for (count = 0; count < 4; count++ )
					{
						nibble = (ip_addr & 0xff000000 ) >> 24;
				
						d3 = (nibble % 0xa) + '0';
						nibble = nibble/0xa;
						d2 = (nibble % 0xa) + '0';
						nibble = nibble /0xa;
						d1 = (nibble % 0xa) + '0';
					
						if( d1 != '0' ) blit_digit(d1);
						blit_digit(d2);
						blit_digit(d3);
						if( count < 3 )
							blit_digit(dot);
					
						d1= d2 = d3 = 0;
						ip_addr = ip_addr << 8;
					}
				}
			}
		}
	}
	panicDialogDrawn = TRUE;
	panicDialogDesired = FALSE;

}

static void 
blit_digit( int digit )
{
	switch( digit )
	{
		case '0':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_0.num_w, num_0.num_h, 255, (unsigned char*) num_0.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_0.num_w - 1;
			break;
		}
		case '1':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_1.num_w, num_1.num_h, 255, (unsigned char*) num_1.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_1.num_w ;
			break;
		}
		case '2':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_2.num_w, num_2.num_h, 255, (unsigned char*) num_2.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_2.num_w ;
			break;
		}
		case '3':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_3.num_w, num_3.num_h, 255, (unsigned char*) num_3.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_3.num_w ;
			break;
		}
		case '4':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_4.num_w, num_4.num_h, 255, (unsigned char*) num_4.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_4.num_w ;
			break;
		}
		case '5':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_5.num_w, num_5.num_h, 255, (unsigned char*) num_5.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_5.num_w ;
			break;
		}
		case '6':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_6.num_w, num_6.num_h, 255, (unsigned char*) num_6.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_6.num_w ;
			break;
		}
		case '7':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_7.num_w, num_7.num_h, 255, (unsigned char*) num_7.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_7.num_w ;
			break;
		}
		case '8':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_8.num_w, num_8.num_h, 255, (unsigned char*) num_8.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_8.num_w ;
			break;
		}
		case '9':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_9.num_w, num_9.num_h, 255, (unsigned char*) num_9.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_9.num_w ;
			break;
		}
		case 'a':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_a.num_w, num_a.num_h, 255, (unsigned char*) num_a.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_a.num_w ;
			break;
		}
		case 'b':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_b.num_w, num_b.num_h, 255, (unsigned char*) num_b.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_b.num_w ;
			break;
		}
		case 'c':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_c.num_w, num_c.num_h, 255, (unsigned char*) num_c.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_c.num_w ;
			break;
		}
		case 'd':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_d.num_w, num_d.num_h, 255, (unsigned char*) num_d.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_d.num_w ;
			break;
		}
		case 'e':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_e.num_w, num_e.num_h, 255, (unsigned char*) num_e.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_e.num_w ;
			break;
		}
		case 'f':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_f.num_w, num_f.num_h, 255, (unsigned char*) num_f.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_f.num_w ;
			break;
		}
		case ':':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y, num_colon.num_w, num_colon.num_h, 255, (unsigned char*) num_colon.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_colon.num_w;
			break;
		}
		case '.':  {
			panic_blit_rect( mac_addr_digit_x, mac_addr_digit_y + (num_colon.num_h/2), num_colon.num_w, num_colon.num_h/2, 255, (unsigned char*) num_colon.num_pixel_data);
			mac_addr_digit_x = mac_addr_digit_x + num_colon.num_w;
			break;
		}
		default:
			break;
	
	}
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

/* 	panic_blit_rect_8 uses the built in clut for drawing.

*/
static void 
panic_blit_rect_8(	unsigned int x, unsigned int y,
			unsigned int width, unsigned int height,
			int transparent, unsigned char * dataPtr )
{
	volatile unsigned char * dst;
	int line, col;
	unsigned int data, quantity, value;
	
	dst = (volatile unsigned char *) (vinfo.v_baseaddr +
					  (y * vinfo.v_rowbytes) +
					  x);
	
	quantity = 0;
	
	for( line = 0; line < height; line++) {
		for( col = 0; col < width; col++) {
			if (quantity == 0) {
				dataPtr += decode_rle(dataPtr, &quantity, &value);
			}
			
			data = value;
			*(dst + col) = data;
			quantity--;
		}
		
		dst = (volatile unsigned char *) (((int)dst) + vinfo.v_rowbytes);
	}
}

/* 	panic_blit_rect_16 draws using a clut.
	
        panic_blit_rect_16 decodes the RLE encoded image data on the fly, looks up the
	color by indexing into the clut, uses the top 5 bits to fill in each of the three 
	pixel values (RGB) and writes each pixel to the screen.
*/
 static void 
 panic_blit_rect_16(	unsigned int x, unsigned int y,
			 unsigned int width, unsigned int height,
			 int transparent, unsigned char * dataPtr )
 {
	 volatile unsigned short * dst;
	 int line, col;
	 unsigned int  quantity, index, value, data;

	 /* If our clut has disappeared, use the standard MacOS 8-bit clut */
	 if(!clut) {
		 clut = appleClut8; 
	 }

	 dst = (volatile unsigned short *) (vinfo.v_baseaddr +
					    (y * vinfo.v_rowbytes) +
					    (x * 2));

	 quantity = 0;

	 for( line = 0; line < height; line++) {
		 for( col = 0; col < width; col++) {

			 if (quantity == 0) {
				 dataPtr += decode_rle(dataPtr, &quantity, &value);
				 index = value * 3;
			 }

			 data = ( (unsigned short) (0xf8 & (clut[index + 0])) << 7)
				 | ( (unsigned short) (0xf8 & (clut[index + 1])) << 2)
				 | ( (unsigned short) (0xf8 & (clut[index + 2])) >> 3);

			 *(dst + col) = data;
			 quantity--;
		 }

		 dst = (volatile unsigned short *) (((int)dst) + vinfo.v_rowbytes);
	 }

 }

 /*
	 panic_blit_rect_32 decodes the RLE encoded image data on the fly, and fills
	 in each of the three pixel values from the clut (RGB) for each pixel and 
	 writes it to the screen.
 */	
 static void 
 panic_blit_rect_32(	unsigned int x, unsigned int y,
			 unsigned int width, unsigned int height,
			 int transparent, unsigned char * dataPtr )
 {
	 volatile unsigned int * dst;
	 int line, col;
	 unsigned int value, quantity, index, data;


	/* If our clut has disappeared, use the standard MacOS 8-bit clut */
	if(!clut) {
		clut = appleClut8; 
	}

	dst = (volatile unsigned int *) (vinfo.v_baseaddr +
					 (y * vinfo.v_rowbytes) +
					 (x * 4));
	
	quantity = 0;
	
	for( line = 0; line < height; line++) {
		for( col = 0; col < width; col++) {
			if (quantity == 0) {
				dataPtr += decode_rle(dataPtr, &quantity, &value);
				index = value * 3;
			}
			
			data = ( (unsigned int) clut[index + 0] << 16)
				| ( (unsigned int) clut[index + 1] << 8)
				| ( (unsigned int) clut[index + 2]);
			
			*(dst + col) = data;
			quantity--;
		}
		
		dst = (volatile unsigned int *) (((int)dst) + vinfo.v_rowbytes);
	}
}

/* 	
        decode_rle decodes a single quantity/value pair of a "modified-RLE" encoded
        image. The encoding works as follows:
        
        The quantity and value will be described by either two or three bytes. If the
        most significant bit of the first byte is a 0, then the next seven bits are
        the quantity (run-length) and the following 8 bits are the value (index into
        a clut, in this case). If the msb of the first byte is a 1, then the next 15 bits
        are the quantity and the following 8 are the value. Visually, the two possible
        encodings are: (q = quantity, v = value)
        
          Byte 1			   Byte 2		        Byte 3
  case 1: [ 0 q6 q5 q4 q3 q2 q1 q0 ]       [ v7 v6 v5 v4 v3 v2 v1 v0 ]  [ ]
  case 2: [ 1 q14 q13 q12 a11 q10 q9 q8 ]  [ q7 q6 q5 q4 q3 q2 q1 q0 ]  [ v7 v6 v5 v4 v3 v2 v1 v0 ]
*/
static int
decode_rle( unsigned char * dataPtr, unsigned int * quantity, unsigned int * value )
{
	unsigned char byte1 = *dataPtr++;
	unsigned char byte2 = *dataPtr++;
	int num_slots = 0;
	
	/* if the most-significant bit is 0, then the first byte is quanity, the second is value */
	if ((byte1 >> 7) ==  0) {
		*quantity = (unsigned int) byte1;
		*value = (unsigned int) byte2;
		num_slots = 2;
	} else {
		/* clear the leading 1 */
		byte1 ^= 0x80;
		
		/* the first two bytes are the quantity, the third is value */
		*quantity = (unsigned int) byte1 << 8 | byte2;
		*value = *dataPtr++;
		num_slots = 3;
	}
	
	return num_slots;
}

static void 
dim_screen(void)
{
	if(!vinfo.v_depth)
		return;

    switch( vinfo.v_depth) {
	case 16:
	    dim_screen_16();
	    break;
	case 32:
	    dim_screen_32();
	    break;
    }
}

static void 
dim_screen_16(void)
{
	unsigned long *p, *endp, *row;
	int      col;
	int      rowline, rowlongs;
        unsigned long value, tmp;

	rowline = vinfo.v_rowscanbytes / 4;
	rowlongs = vinfo.v_rowbytes / 4;

	p = (unsigned long*) vinfo.v_baseaddr;
	endp = (unsigned long*) vinfo.v_baseaddr;

        endp += rowlongs * vinfo.v_height;

	for (row = p ; row < endp ; row += rowlongs) {
		for (col = 0; col < rowline; col++) {
                        value = *(row+col);
                        tmp =  ((value & 0x7C007C00) >> 1) & 0x3C003C00;
                        tmp |= ((value & 0x03E003E0) >> 1) & 0x01E001E0;
                        tmp |= ((value & 0x001F001F) >> 1) & 0x000F000F;
                        *(row+col) = tmp;		//half (dimmed)?
                }

	}

}

static void 
dim_screen_32(void)
{
	unsigned long *p, *endp, *row;
	int      col;
	int      rowline, rowlongs;
        unsigned long value, tmp;

	rowline = vinfo.v_rowscanbytes / 4;
	rowlongs = vinfo.v_rowbytes / 4;

	p = (unsigned long*) vinfo.v_baseaddr;
	endp = (unsigned long*) vinfo.v_baseaddr;

        endp += rowlongs * vinfo.v_height;

	for (row = p ; row < endp ; row += rowlongs) {
		for (col = 0; col < rowline; col++) {
                        value = *(row+col);
                        tmp =  ((value & 0x00FF0000) >> 1) & 0x007F0000;
                        tmp |= ((value & 0x0000FF00) >> 1) & 0x00007F00;
                        tmp |= (value & 0x000000FF) >> 1;
                        *(row+col) = tmp;		//half (dimmed)?
                }

	}

}
