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
 * Copyright 1996 1995 by Open Software Foundation, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 * 
 */
/*
 * Copyright 1996 1995 by Apple Computer, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * APPLE COMPUTER DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL APPLE COMPUTER BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 */
/*
 * MKLINUX-1.0DR2
 */

/*
 * 18 June 1998 sdouglas
 * Start IOKit version.
 */

struct cuda_packet {
    int     	    a_hcount;
    unsigned char   a_header[8];
    int     	    a_bcount;	    /* on entry size, on exit, actual */
    unsigned char * a_buffer;	    /* ool data */
};

typedef struct cuda_packet cuda_packet_t;

#ifdef __cplusplus
class IOSyncer;

struct cuda_request {
    cuda_packet_t        	a_cmd;      /* Command packet */
    cuda_packet_t        	a_reply;    /* Reply packet */
    volatile struct cuda_request* a_next;
    IOSyncer *			sync;
    bool			needWake;
};

typedef struct cuda_request cuda_request_t;

#else

struct cuda_request {
    cuda_packet_t        	a_cmd;      /* Command packet */
    cuda_packet_t        	a_reply;    /* Reply packet */
    volatile struct cuda_request* a_next;
    void *			sync;
};

typedef struct cuda_request cuda_request_t;

#endif


/*
 * ADB Packet Types
 */

#define ADB_PACKET_ADB      0
#define ADB_PACKET_PSEUDO   1
#define ADB_PACKET_ERROR    2
#define ADB_PACKET_TIMER    3
#define ADB_PACKET_POWER    4
#define ADB_PACKET_MACIIC   5

/*
 * ADB Device Commands 
 */

#define ADB_ADBCMD_RESET_BUS    0x00
#define ADB_ADBCMD_FLUSH_ADB    0x01
#define ADB_ADBCMD_WRITE_ADB    0x08
#define ADB_ADBCMD_READ_ADB 	0x0c

/*
 * ADB Pseudo Commands
 */

#define ADB_PSEUDOCMD_WARM_START       		0x00
#define ADB_PSEUDOCMD_START_STOP_AUTO_POLL  	0x01
#define ADB_PSEUDOCMD_GET_6805_ADDRESS      	0x02
#define ADB_PSEUDOCMD_GET_REAL_TIME     	0x03
#define ADB_PSEUDOCMD_GET_PRAM          	0x07
#define ADB_PSEUDOCMD_SET_6805_ADDRESS      	0x08
#define ADB_PSEUDOCMD_SET_REAL_TIME     	0x09
#define ADB_PSEUDOCMD_POWER_DOWN        	0x0a
#define ADB_PSEUDOCMD_SET_POWER_UPTIME     	0x0b
#define ADB_PSEUDOCMD_SET_PRAM          	0x0c
#define ADB_PSEUDOCMD_MONO_STABLE_RESET     	0x0d
#define ADB_PSEUDOCMD_SEND_DFAC         	0x0e
#define ADB_PSEUDOCMD_BATTERY_SWAP_SENSE    	0x10
#define ADB_PSEUDOCMD_RESTART_SYSTEM        	0x11
#define ADB_PSEUDOCMD_SET_IPL_LEVEL     	0x12
#define ADB_PSEUDOCMD_FILE_SERVER_FLAG      	0x13
#define ADB_PSEUDOCMD_SET_AUTO_RATE     	0x14
#define ADB_PSEUDOCMD_GET_AUTO_RATE     	0x16
#define ADB_PSEUDOCMD_SET_DEVICE_LIST       	0x19
#define ADB_PSEUDOCMD_GET_DEVICE_LIST       	0x1a
#define ADB_PSEUDOCMD_SET_ONE_SECOND_MODE   	0x1b
#define ADB_PSEUDOCMD_SET_POWER_MESSAGES    	0x21
#define ADB_PSEUDOCMD_GET_SET_IIC       	0x22
#define ADB_PSEUDOCMD_ENABLE_DISABLE_WAKEUP 	0x23
#define ADB_PSEUDOCMD_TIMER_TICKLE      	0x24
#define ADB_PSEUDOCMD_COMBINED_FORMAT_IIC   	0X25

/*
 * Following values to be used with ADB_PSEUDOCMD_SET_POWER_MESSAGES
 */
enum {
    kADB_powermsg_disable = 0,
    kADB_powermsg_enable,
    kADB_powermsg_suspend,
    kADB_powermsg_continue,
    kADB_powermsg_debugger,
    kADB_powermsg_timed_ADB,
    kADB_powermsg_timed_power,
    kADB_powermsg_invalid
};

//These constants are used to parse Cuda power message response
//  packets, to see which selector transitioned
enum {
    kADB_powermsg_flag_rotary = 0x20,
    kADB_powermsg_flag_chassis = 0x02,
    kADB_powermsg_flag_keyboardpwr = 0x04,
    kADB_powermsg_cmd_chassis_off = 0x00,
    kADB_powermsg_cmd_keyboardoff = 0x04,
    kADB_powermsg_cmd_keyboardtimed = 0x00,
    kADB_powermsg_cmd_rotary_lock = 0x01,
    kADB_powermsg_cmd_rotary_unlock = 0x02
};


/*
 * Macros to help build commands up
 */

#define ADB_BUILD_CMD1(c, p1) {(c)->a_cmd.a_header[0] = p1; (c)->a_cmd.a_hcount = 1; }
#define ADB_BUILD_CMD2(c, p1, p2) {(c)->a_cmd.a_header[0] = p1; (c)->a_cmd.a_header[1] = p2; (c)->a_cmd.a_hcount = 2; }
#define ADB_BUILD_CMD3(c, p1, p2, p3) {(c)->a_cmd.a_header[0] = p1; (c)->a_cmd.a_header[1] = p2; (c)->a_cmd.a_header[2] = p3; (c)->a_cmd.a_hcount = 3; }

#define ADB_BUILD_CMD4(c, p1, p2, p3, p4) {(c)->a_cmd.a_header[0] = p1; (c)->a_cmd.a_header[1] = p2; \
                     (c)->a_cmd.a_header[2] = p3; (c)->a_cmd.a_header[3] = p4; (c)->a_cmd.a_hcount = 4; }
#if 0
#define ADB_BUILD_CMD2_BUFFER(c, p1, p2, len, buf) {(c)->a_cmd.a_header[0] = p1; (c)->a_cmd.a_header[1] = p2; (c)->a_cmd.a_hcount = 2;\
        (c)->a_cmd.a_bcount = len;\
        memcpy(&(c)->a_cmd.a_buffer, buf, len); }

#endif

#define adb_init_request(a) { bzero((char *) a, sizeof(*a)); }



