/*
 * Copyright (c) 2015-2020 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
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

#ifndef log_encode_types_h
#define log_encode_types_h

/*
 * These are IPIs between xnu and libtrace, used to have common encoding
 * and implementation for kernel logging and user logging. They are subject
 * to change at any point.
 */

#include <os/base.h>
#include <os/log.h>
#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#include "log_mem.h"

#pragma mark - buffer support structures, enums

OS_ENUM(os_log_fmt_hdr_flags, uint8_t,
    OSLF_HDR_FLAG_HAS_PRIVATE    = 0x01,
    OSLF_HDR_FLAG_HAS_NON_SCALAR = 0x02,
    );

OS_ENUM(os_log_fmt_cmd_type, uint8_t,
    OSLF_CMD_TYPE_SCALAR      = 0, // %u, %lld, %x, %p, %g, ...
    OSLF_CMD_TYPE_COUNT       = 1, // %.16P, %.*s
    OSLF_CMD_TYPE_STRING      = 2, // %s
    OSLF_CMD_TYPE_POINTER     = 3, // %P
    OSLF_CMD_TYPE_OBJECT      = 4, // %@
    OSLF_CMD_TYPE_WIDE_STRING = 5, // %S
    OSLF_CMD_TYPE_ERRNO       = 6, // %m
    OSLF_CMD_TYPE_MASK        = 7, // %{mask.foo}...
    );

OS_ENUM(os_log_fmt_cmd_flags, uint8_t,
    OSLF_CMD_FLAG_PRIVATE    = 0x1,
    OSLF_CMD_FLAG_PUBLIC     = 0x2,
    OSLF_CMD_FLAG_SENSITIVE  = 0x4 | OSLF_CMD_FLAG_PRIVATE,
    );

enum os_log_int_types_t {
	OST_CHAR      = -2,
	OST_SHORT     = -1,
	OST_INT       =  0,
	OST_LONG      =  1,
	OST_LONGLONG  =  2,
	OST_SIZE      =  3,
	OST_INTMAX    =  4,
	OST_PTRDIFF   =  5,
};

union os_log_fmt_types_u {
	uint16_t    u16;
	uint32_t    u32;
	uint64_t    u64;
	char        ch;
	short       s;
	int         i;
	void        *p;
	char        *pch;
	size_t      z;
	intmax_t    im;
	ptrdiff_t   pd;
	long        l;
	long long   ll;
};

typedef struct os_log_format_value_s {
	union os_log_fmt_types_u type;
	os_log_fmt_cmd_type_t ctype;
	uint16_t size;
} *os_log_format_value_t;

typedef struct os_log_fmt_hdr_s {
	os_log_fmt_hdr_flags_t hdr_flags;
	uint8_t hdr_cmd_cnt;
	uint8_t hdr_data[];
} *os_log_fmt_hdr_t;

typedef struct os_log_fmt_cmd_s {
	os_log_fmt_cmd_flags_t cmd_flags : 4;
	os_log_fmt_cmd_type_t cmd_type : 4;
	uint8_t cmd_size;
	uint8_t cmd_data[];
} *os_log_fmt_cmd_t;

typedef struct os_log_fmt_range_s {
	uint16_t offset;
	uint16_t length : 15;
	uint16_t truncated : 1;
} *os_log_fmt_range_t;

#define OS_LOG_MAX_PUB_ARGS (32)

typedef struct os_log_context_s {
	logmem_t                    *ctx_logmem;
	uint8_t                     *ctx_buffer;
	size_t                      ctx_buffer_sz;
	os_log_fmt_hdr_t            ctx_hdr;
	char                        *ctx_pubdata[OS_LOG_MAX_PUB_ARGS];
	uint16_t                    ctx_content_off; // offset into buffer->hdr_data
	uint16_t                    ctx_content_sz; // size not including the header
	uint16_t                    ctx_pubdata_sz;
	uint16_t                    ctx_pubdata_cnt;
	firehose_tracepoint_flags_t ctx_ft_flags;
	uint8_t                     ctx_truncated : 1;
	uint8_t                     ctx_allocated : 1;
} *os_log_context_t;

#endif /* log_encode_types_h */
