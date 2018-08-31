/*
 * Copyright (c) 2011-2018 Apple Inc. All rights reserved.
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

#ifndef PE_CONSISTENT_DEBUG_H
#define PE_CONSISTENT_DEBUG_H

#include <stdint.h>

#define DEBUG_RECORD_ID_LONG(a, b,c ,d, e, f, g, h) \
	( ((uint64_t)(	(((h) << 24) & 0xFF000000) | \
			(((g) << 16) & 0x00FF0000) | \
			(((f) <<  8) & 0x0000FF00) | \
			((e)         & 0x000000FF) ) << 32) | \
	  (uint64_t)(	(((d) << 24) & 0xFF000000) | \
			(((c) << 16) & 0x00FF0000) | \
			(((b) <<  8) & 0x0000FF00) | \
			((a)         & 0x000000FF) ) )
#define DEBUG_RECORD_ID_SHORT(a,b,c,d) DEBUG_RECORD_ID_LONG(a,b,c,d,0,0,0,0)

/* 
 *      Shared Memory Console Descriptors:
 *      Record ID: One per SHMConsole
 */

typedef enum {
	DBG_PROCESSOR_AP = 1,
	DBG_COPROCESSOR_ANS,
	DBG_COPROCESSOR_SEP,
	DBG_COPROCESSOR_SIO,
	DBG_COPROCESSOR_ISP,
	DBG_COPROCESSOR_OSCAR,
	DBG_NUM_PROCESSORS
} dbg_processor_t;

#define DbgIdConsoleHeaderForIOP(which_dbg_processor, which_num) (DEBUG_RECORD_ID_LONG('C','O','N',0,0,0,which_dbg_processor,which_num))

#define kDbgIdConsoleHeaderAP		DbgIdConsoleHeaderForIOP(DBG_PROCESSOR_AP, 0)
#define kDbgIdConsoleHeaderANS		DbgIdConsoleHeaderForIOP(DBG_COPROCESSOR_ANS, 0)
#define kDbgIdConsoleHeaderSIO		DbgIdConsoleHeaderForIOP(DBG_COPROCESSOR_SIO, 0)
#define kDbgIdConsoleHeaderSEP		DbgIdConsoleHeaderForIOP(DBG_COPROCESSOR_SEP, 0)
#define kDbgIdConsoleHeaderISP		DbgIdConsoleHeaderForIOP(DBG_COPROCESSOR_ISP, 0)
#define kDbgIdConsoleHeaderOscar	DbgIdConsoleHeaderForIOP(DBG_COPROCESSOR_OSCAR, 0)

#define kDbgIdAstrisConnection		DEBUG_RECORD_ID_LONG('A','S','T','R','C','N','X','N')
#define kDbgIdAstrisConnectionVers	DEBUG_RECORD_ID_LONG('A','S','T','R','C','V','E','R')

#define kDbgIdUnusedEntry	0x0ULL
#define kDbgIdReservedEntry	DEBUG_RECORD_ID_LONG('R','E','S','E','R','V','E', 'D')
#define kDbgIdFreeReqEntry	DEBUG_RECORD_ID_LONG('F','R','E','E','-','R','E','Q')
#define kDbgIdFreeAckEntry	DEBUG_RECORD_ID_LONG('F','R','E','E','-','A','C','K')

#define DEBUG_REGISTRY_MAX_RECORDS	512

typedef struct {
	uint64_t record_id;             // = kDbgIdTopLevelHeader
	uint32_t num_records;           // = DEBUG_REGISTRY_MAX_RECORDS
	uint32_t record_size_bytes;     // = sizeof(dbg_record_header_t)
} dbg_top_level_header_t;

typedef struct {
	uint64_t record_id; // 32-bit unique ID identifying the record
	uint64_t length;    // Length of the payload
	uint64_t physaddr;  // System physical address of entry
} dbg_record_header_t;

typedef struct {
	uint64_t timestamp;
	uint32_t cp_state;          // One of the cp_state_t enumerations
	uint32_t cp_state_arg;      // IOP-defined supplemental value
} dbg_cpr_state_entry_t;

#define CPR_MAX_STATE_ENTRIES 16 // Arbitrary value

// This second-level struct should be what the Debug Registry record (e.g. kDbgIdCPRHeaderANS) points to.
typedef struct {
	uint32_t rdptr;
	uint32_t wrptr;
	uint32_t num_cp_state_entries;
	uint32_t checksum;
	dbg_cpr_state_entry_t cp_state_entries[CPR_MAX_STATE_ENTRIES];
} dbg_cpr_t;

typedef struct {
	dbg_top_level_header_t	top_level_header;
	dbg_record_header_t	records[DEBUG_REGISTRY_MAX_RECORDS];

	// Stuff the AP's Progress Report buffer at the end of this
	// structure. It's currently the only processor that doesn't
	// have some easier form of persistent memory that survives the
	// iBoot->iOS handoff (e.g. ANS has its private heap)
	dbg_cpr_t		ap_cpr_region;
} dbg_registry_t;

/*
 * Inherit the consistent debug structure from bootloader
 */
int PE_consistent_debug_inherit(void);

/*
 * Register a region in the consistent debug structure
 */
int PE_consistent_debug_register(uint64_t record_id, uint64_t physaddr, uint64_t length);

/*
 * Returns whether consistent debug is enabled on the current device.
 */
int PE_consistent_debug_enabled(void);

#endif  // PE_CONSISTENT_DEBUG_H

