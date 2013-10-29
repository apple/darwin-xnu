/*
 * Copyright (c) 2011 Apple Inc. All rights reserved.
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

#ifndef	_NET_IF_UTUN_CRYPTO_H_
#define	_NET_IF_UTUN_CRYPTO_H_

// constants used in configuring the crypto context
typedef enum utun_crypto_ver {
	UTUN_CRYPTO_VER_1 = 1,
	UTUN_CRYPTO_VER_MAX,
} utun_crypto_ver_t;

#define UTUN_CRYPTO_KEYS_IPSEC_VER_1                  UTUN_CRYPTO_VER_1
#define UTUN_CRYPTO_IPSEC_VER_1                       UTUN_CRYPTO_VER_1
#define UTUN_CRYPTO_DTLS_VER_1                        UTUN_CRYPTO_VER_1

#define UTUN_CRYPTO_ARGS_VER_MAX                      UTUN_CRYPTO_VER_MAX
#define UTUN_CRYPTO_KEYS_ARGS_VER_MAX                 UTUN_CRYPTO_VER_MAX
#define UTUN_CRYPTO_FRAMER_ARGS_VER_MAX               UTUN_CRYPTO_VER_MAX

typedef enum utun_crypto_dir {
	UTUN_CRYPTO_DIR_IN = 1,
	UTUN_CRYPTO_DIR_OUT,
	UTUN_CRYPTO_DIR_MAX,
} utun_crypto_dir_t;

#define UTUN_CRYPTO_CTX_NUM_DIRS 2

#define BITSTOBYTES(n)                                (n >> 3)
#define BYTESTOBITS(n)                                (n << 3)

#define MAX_KEY_AUTH_LEN_BITS                         512 // corresponds to SHA512
#define MAX_KEY_AUTH_LEN_BYTES                        (BITSTOBYTES(MAX_KEY_AUTH_LEN_BITS))
#define MAX_KEY_ENC_LEN_BITS                          256 // corresponds to AES256
#define MAX_KEY_ENC_LEN_BYTES                         (BITSTOBYTES(MAX_KEY_ENC_LEN_BITS))

typedef enum utun_crypto_type {
	UTUN_CRYPTO_TYPE_IPSEC = 1,
	UTUN_CRYPTO_TYPE_DTLS,
	UTUN_CRYPTO_TYPE_MAX,
} utun_crypto_type_t;

typedef enum if_utun_crypto_ipsec_mode {
	IF_UTUN_CRYPTO_IPSEC_MODE_NONE = 0,
	IF_UTUN_CRYPTO_IPSEC_MODE_TRANSPORT,
	IF_UTUN_CRYPTO_IPSEC_MODE_TUNNEL,
	IF_UTUN_CRYPTO_IPSEC_MODE_MAX,
} if_utun_crypto_ipsec_mode_t;

typedef enum if_utun_crypto_ipsec_proto {
	IF_UTUN_CRYPTO_IPSEC_PROTO_NONE = 0,
	IF_UTUN_CRYPTO_IPSEC_PROTO_ESP,
	IF_UTUN_CRYPTO_IPSEC_PROTO_AH,
	IF_UTUN_CRYPTO_IPSEC_PROTO_MAX,
} if_utun_crypto_ipsec_proto_t;

typedef enum if_utun_crypto_ipsec_auth {
	IF_UTUN_CRYPTO_IPSEC_AUTH_NONE = 0,
	IF_UTUN_CRYPTO_IPSEC_AUTH_MD5,
	IF_UTUN_CRYPTO_IPSEC_AUTH_SHA1,
	IF_UTUN_CRYPTO_IPSEC_AUTH_SHA256,
	IF_UTUN_CRYPTO_IPSEC_AUTH_SHA384,
	IF_UTUN_CRYPTO_IPSEC_AUTH_SHA512,
	IF_UTUN_CRYPTO_IPSEC_AUTH_MAX,
} if_utun_crypto_ipsec_auth_t;

typedef enum if_utun_crypto_ipsec_enc {
	IF_UTUN_CRYPTO_IPSEC_ENC_NONE = 0,
	IF_UTUN_CRYPTO_IPSEC_ENC_DES,
	IF_UTUN_CRYPTO_IPSEC_ENC_3DES,
	IF_UTUN_CRYPTO_IPSEC_ENC_AES128,
	IF_UTUN_CRYPTO_IPSEC_ENC_AES256,
	IF_UTUN_CRYPTO_IPSEC_ENC_MAX,
} if_utun_crypto_ipsec_enc_t;

typedef enum if_utun_crypto_ipsec_keepalive {
	IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_NONE = 0,
	IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_NATT,
	IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_ESP,
	IF_UTUN_CRYPTO_IPSEC_KEEPALIVE_MAX,
} if_utun_crypto_ipsec_keepalive_t;

typedef enum if_utun_crypto_ipsec_natd {
	IF_UTUN_CRYPTO_IPSEC_NATD_NONE = 0,
	IF_UTUN_CRYPTO_IPSEC_NATD_MINE,
	IF_UTUN_CRYPTO_IPSEC_NATD_PEER,
	IF_UTUN_CRYPTO_IPSEC_NATD_BOTH,
	IF_UTUN_CRYPTO_IPSEC_NATD_MAX,
} if_utun_crypto_ipsec_natd_t;

// structures used for storing the App's keying index arguments
typedef struct utun_crypto_keys_idx_ipsec_args_v1 {
	struct sockaddr_storage                       src_addr; // v4 or v6 socket address (ignore port numbers)
	struct sockaddr_storage                       dst_addr; // v4 or v6 socket address (ignore port numbers)
	if_utun_crypto_ipsec_proto_t                  proto;
	if_utun_crypto_ipsec_mode_t                   mode;
	u_int32_t                                     reqid; // policy's reqid, default to 0 for now since we are avoiding policies.
	u_int32_t                                     spi;		  // 0 when requesting the index, otherwise it contains the resulting index
	u_int32_t                                     spirange_min; // default to 0
	u_int32_t                                     spirange_max; // default to 0xffffffff
} __attribute__((packed)) utun_crypto_keys_idx_ipsec_args_v1_t;

typedef struct utun_crypto_keys_idx_dtls_args_v1 {
	// stub for DTLS keying index arguments
	u_int32_t                                     unused; // place holder
} __attribute__((packed)) utun_crypto_keys_idx_dtls_args_v1_t;

// App's parent structure for sending/storing keying index arguments
typedef struct utun_crypto_keys_idx_args {
	utun_crypto_ver_t                             ver;
	utun_crypto_type_t                            type;
	utun_crypto_dir_t                             dir;
	u_int32_t                                     args_ulen;
	u_int32_t                                     varargs_buflen;
	union {
		// don't change the order, number, or size of elements above this line (in this struct). otherwise UTUN_CRYPTO_CTX_IDX_ARGS_HDR_SIZE breaks backwards compatibility
		utun_crypto_keys_idx_ipsec_args_v1_t  ipsec_v1;
		utun_crypto_keys_idx_dtls_args_v1_t   dtls_v1;
		// future (additional) versions of the arguments may be placed here
	} u;
	u_int8_t                                      varargs_buf[0];
} __attribute__((aligned(4), packed)) utun_crypto_keys_idx_args_t;

// structures used for storing the App's keying material arguments
typedef struct utun_crypto_keys_ipsec_args_v1 {
	struct sockaddr_storage                       src_addr; // v4 or v6 socket address (ignore port numbers)
	struct sockaddr_storage                       dst_addr; // v4 or v6 socket address (ignore port numbers)
	if_utun_crypto_ipsec_proto_t                  proto;
	if_utun_crypto_ipsec_mode_t                   mode;
	if_utun_crypto_ipsec_auth_t                   alg_auth;
	if_utun_crypto_ipsec_enc_t                    alg_enc;
	if_utun_crypto_ipsec_keepalive_t              keepalive;
	if_utun_crypto_ipsec_natd_t                   natd;
	u_int8_t                                      replay;   // window size default to 4
	u_int8_t                                      punt_rx_keepalive;
	u_int16_t                                     interval_tx_keepalive;
	u_int16_t                                     key_auth_len; // 128 or 160 or 192 or 256 or 384 or 512
	u_int16_t                                     key_enc_len;  // 64 or 128 or 192 or 256
	u_int16_t                                     natt_port; // if non-zero flags will be set to include SADB_X_EXT_NATT
	u_int16_t                                     unused;
	u_int32_t                                     seq;	  // default to 0
	u_int32_t                                     spi;
	u_int32_t                                     pid;      // vpnagent's process id
	u_int32_t                                     reqid; // policy's reqid, default to 0 for now since we are avoiding policies.
	u_int64_t                                     lifetime_hard; // value in seconds
	u_int64_t                                     lifetime_soft; // value in seconds
	// key_auth and key_enc will actually be stored in utun_crypto_KEYS_args_t.varargs_buf
} __attribute__((packed)) utun_crypto_keys_ipsec_args_v1_t;

typedef struct utun_crypto_keys_dtls_args_v1 {
	// stub for DTLS keying material arguments
	u_int32_t                                     unused; // place holder
} __attribute__((packed)) utun_crypto_keys_dtls_args_v1_t;

// App's parent structure for sending/storing keying material arguments
typedef struct utun_crypto_keys_args {
	utun_crypto_ver_t                             ver;
	utun_crypto_type_t                            type;
	utun_crypto_dir_t                             dir;
	u_int32_t                                     args_ulen;
	u_int32_t                                     varargs_buflen;
	union {
		// don't change the order, number, or size of elements above this line (in this struct). otherwise UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE breaks backwards compatibility
		utun_crypto_keys_ipsec_args_v1_t      ipsec_v1;
		utun_crypto_keys_dtls_args_v1_t       dtls_v1;
		// future (additional) versions of the arguments may be placed here
	} u;
	u_int8_t                                      varargs_buf[0];
} __attribute__((aligned(4), packed)) utun_crypto_keys_args_t;

// structures used for storing the App's crypto arguments
typedef struct utun_crypto_ipsec_args_v1 {
	// stub for IPSec crypto context arguments
	u_int32_t                                     unused; // place holder
} __attribute__((packed)) utun_crypto_ipsec_args_v1_t;

typedef struct utun_crypto_dtls_args_v1 {
	// stub for DTLS crypto context arguments
	int                                           kpi_handle;
} __attribute__((packed)) utun_crypto_dtls_args_v1_t;

// App's parent structure for starting/stopping crypto
typedef struct utun_crypto_args {
	utun_crypto_ver_t                             ver;
	utun_crypto_type_t                            type;
	u_int32_t                                     stop_data_traffic;
	u_int32_t                                     args_ulen;
	u_int32_t                                     varargs_buflen;
	union {
		// don't change the order, number, or size of elements above this line (in this struct). otherwise UTUN_CRYPTO_ARGS_HDR_SIZE breaks backwards compatibility
		utun_crypto_ipsec_args_v1_t           ipsec_v1;
		utun_crypto_dtls_args_v1_t            dtls_v1;
		// future (additional) versions of the arguments may be placed here
	} u;
	u_int8_t                                      varargs_buf[0]; // must be at the end of this struct
} __attribute__((aligned(4), packed)) utun_crypto_args_t;

typedef enum {
  UTUN_CRYPTO_INNER_TYPE_IPv4 = 1,
  UTUN_CRYPTO_INNER_TYPE_IPv6,
  UTUN_CRYPTO_INNER_TYPE_MAX,
} utun_crypto_framer_inner_type_t;

typedef struct utun_crypto_framer_ipsec_args_v1 {
	// stub for IPSec framer arguments
	u_int32_t                                     unused; // place holder
} __attribute__((packed)) utun_crypto_framer_ipsec_args_v1_t;

typedef struct utun_crypto_framer_dtls_in_args_v1 {
	int                                           in_pattern_len;
	int                                           in_pattern_mask_len;
	int                                           in_data_offset;
	// in_pattern, in_pattern_mask will actually be stored in utun_crypto_framer_args_t.varargs_buf
} __attribute__((packed)) utun_crypto_framer_dtls_in_args_v1_t;

typedef struct utun_crypto_framer_dtls_out_args_v1 {
	int                                           out_pattern_len;
	u_int32_t                                     len_field_mask; // 0 means unconfigured
	int                                           len_field_offset;
	int                                           len_field_extra;
	u_int32_t                                     sequence_field;
	u_int32_t                                     sequence_field_mask; // 0 means unconfigured
	int                                           sequence_field_offset;
	// out_pattern will actually be stored in utun_crypto_framer_args_t.varargs_buf
} __attribute__((packed)) utun_crypto_framer_dtls_out_args_v1_t;

typedef struct utun_crypto_framer_dtls_args_v1 {
	// the following depend on utun_crypto_framer_args_t.dir
	union {
		// don't change the order, number, or size of elements above this line (in this struct). otherwise UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE breaks backwards compatibility
		utun_crypto_framer_dtls_in_args_v1_t  in;
		utun_crypto_framer_dtls_out_args_v1_t out;
		// future (additional) versions of the arguments may be placed here
	} u;
} __attribute__((packed)) utun_crypto_framer_dtls_args_v1_t;

// App's parent structure for sending/storing framer arguments
typedef struct utun_crypto_framer_args {
	utun_crypto_ver_t                             ver;
	utun_crypto_type_t                            type;
	utun_crypto_dir_t                             dir;
	utun_crypto_framer_inner_type_t               inner_type;
	u_int32_t                                     args_ulen;
	u_int32_t                                     varargs_buflen;
	union {
		// don't change the order, number, or size of elements above this line (in this struct). otherwise UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE breaks backwards compatibility
		utun_crypto_framer_ipsec_args_v1_t    ipsec_v1;
		utun_crypto_framer_dtls_args_v1_t     dtls_v1;
		// future (additional) versions of the arguments may be placed here
	} u;
	u_int8_t                                      varargs_buf[0];
} __attribute__((aligned(4), packed)) utun_crypto_framer_args_t;

#define utun_crypto_framer_args_dtls_in(framer)   framer->u.dtls_v1.u.in
#define utun_crypto_framer_args_dtls_out(framer)  framer->u.dtls_v1.u.out

#ifdef KERNEL_PRIVATE

#include <sys/kern_control.h>
#include <net/kpi_protocol.h>
#include <net/kpi_interface.h>
#include <net/pfkeyv2.h>
#include <netkey/key.h>
#include <netkey/keydb.h>
#include <net/bpf.h>

struct utun_pcb;

// structures used for storing kernel's keying material runtime state
typedef struct utun_crypto_keys_ipsec_state {
	// kernel's ipsec keying material state
	u_int32_t                                     spi;
	struct secashead                             *sah;
	struct secasvar                              *sav;
	u_int8_t                                      proto;
	u_int8_t                                      ifamily;
	u_int8_t                                      mode;
	u_int8_t                                      unused;
} __attribute__((packed)) utun_crypto_keys_ipsec_state_t;

typedef struct utun_crypto_keys_dtls_state {
	// stub for kernel's DTLS keying material state
	u_int32_t                                     unused; // place holder
} __attribute__((packed)) utun_crypto_keys_dtls_state_t;

// kernel's parent structure for keying material state
typedef struct utun_crypto_keys_state {
	union {
		utun_crypto_keys_ipsec_state_t        ipsec;
		utun_crypto_keys_dtls_state_t         dtls;
	} u;
} __attribute__((aligned(4), packed)) utun_crypto_keys_state_t;

// kernel's parent structure for keying material
typedef struct utun_crypto_keys {
	int                                           valid; // is valid?
	utun_crypto_type_t                            type;
	u_int16_t                                     unused;
	utun_crypto_keys_state_t                      state; // runtime state
	LIST_ENTRY(utun_crypto_keys)                  chain;
} __attribute__((aligned(4), packed)) utun_crypto_keys_t;

// structures used for storing kernel's framer runtime state
typedef struct utun_crypto_framer_ipsec_state {
	// stub for kernel's IPSec framer state
	u_int32_t                                     unused; // place holder
} __attribute__((packed)) utun_crypto_framer_ipsec_state_t;

typedef struct utun_crypto_framer_dtls_in_state {
	u_int8_t                                     *in_pattern;
	int                                           in_pattern_len;
	u_int8_t                                     *in_pattern_mask;
	u_int8_t                                     *in_pattern_masked;
	int                                           in_data_offset;
	struct bpf_program                            in_pattern_filter;
} __attribute__((packed)) utun_crypto_framer_dtls_in_state_t;

typedef struct utun_crypto_framer_dtls_out_state {
	u_int8_t                                     *out_pattern;
	int                                           out_pattern_len;
	u_int32_t                                     len_field_mask; // 0 means unconfigured
	int                                           len_field_offset;
	int                                           len_field_extra;
	u_int32_t                                     sequence_field;
	u_int32_t                                     sequence_field_initval;
	u_int32_t                                     sequence_field_mask; // 0 means unconfigured
	int                                           sequence_field_offset;
} __attribute__((packed)) utun_crypto_framer_dtls_out_state_t;

typedef struct utun_crypto_framer_dtls_state {
	union {
		// don't change the order, number, or size of elements above this line (in this struct). otherwise UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE breaks backwards compatibility
		utun_crypto_framer_dtls_in_state_t  in;
		utun_crypto_framer_dtls_out_state_t out;
		// future (additional) versions of the arguments may be placed here
	} u;
} __attribute__((packed)) utun_crypto_framer_dtls_state_t;

// kernel's parent structure for framer state
typedef struct utun_crypto_framer_state {
	union {
		utun_crypto_framer_ipsec_state_t ipsec;
		utun_crypto_framer_dtls_state_t  dtls;
	} u;
} __attribute__((aligned(4), packed)) utun_crypto_framer_state_t;

// kernel's parent structure for the framer
typedef struct utun_crypto_framer {
	int                                           valid; // is valid?
	utun_crypto_type_t                            type;
	utun_crypto_dir_t                             dir;
	utun_crypto_framer_inner_type_t               inner_type;
	protocol_family_t                             inner_protocol_family;
	utun_crypto_framer_state_t                    state; // runtime state
	LIST_ENTRY(utun_crypto_framer)                framer_chain;
} __attribute__((aligned(4), packed)) utun_crypto_framer_t;

#define UTUN_CRYPTO_INNER_TYPE_TO_IDX(type)           (type - 1)
#define UTUN_CRYPTO_IDX_TO_INNER_TYPE(idx)            (idx + 1)
#define UTUN_CRYPTO_INNER_TYPE_IDX_MAX                UTUN_CRYPTO_INNER_TYPE_TO_IDX(UTUN_CRYPTO_INNER_TYPE_MAX)

#define UTUN_CRYPTO_DIR_TO_IDX(dir)                   (dir - 1)
#define UTUN_CRYPTO_IDX_TO_DIR(idx)                   (idx + 1)
#define UTUN_CRYPTO_DIR_IDX_MAX                       UTUN_CRYPTO_DIR_TO_IDX(UTUN_CRYPTO_DIR_MAX)

#define utun_crypto_framer_state_dtls_in(framer)      framer->state.u.dtls.u.in
#define utun_crypto_framer_state_dtls_out(framer)     framer->state.u.dtls.u.out

// kernel's parent structure for all crypto stuff
typedef struct utun_crypto_ctx {
	int                                           valid;
	utun_crypto_type_t                            type;
	u_int16_t                                     unused;
	LIST_HEAD(chain, utun_crypto_keys)            keys_listhead;
	LIST_HEAD(framer_chain, utun_crypto_framer)   framer_listheads[UTUN_CRYPTO_INNER_TYPE_IDX_MAX];
	int                                           num_framers;
	int                                           kpi_handle;
	caddr_t                                       kpi_ref;
	int                                           kpi_refcnt;
} __attribute__((aligned(4), packed)) utun_crypto_ctx_t;

#define UTUN_CRYPTO_KEYS_IDX_ARGS_HDR_SIZE            ((size_t)(&((utun_crypto_keys_idx_args_t *)0)->u))
#define UTUN_CRYPTO_KEYS_IDX_ARGS_VARARGS_BUF(args)   ((u_int8_t *)args + UTUN_CRYPTO_KEYS_IDX_ARGS_HDR_SIZE + args->args_ulen)
#define UTUN_CRYPTO_KEYS_IDX_ARGS_TOTAL_SIZE(args)    ((size_t)(UTUN_CRYPTO_KEYS_IDX_ARGS_HDR_SIZE + args->args_ulen + args->varargs_buflen))

#define UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE                ((size_t)(&((utun_crypto_keys_args_t *)0)->u))
#define UTUN_CRYPTO_KEYS_ARGS_VARARGS_BUF(args)       ((u_int8_t *)args + UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE + args->args_ulen)
#define UTUN_CRYPTO_KEYS_ARGS_TOTAL_SIZE(args)        ((size_t)(UTUN_CRYPTO_KEYS_ARGS_HDR_SIZE + args->args_ulen + args->varargs_buflen))

#define UTUN_CRYPTO_FRAMER_ARGS_HDR_SIZE                ((size_t)(&((utun_crypto_framer_args_t *)0)->u))
#define UTUN_CRYPTO_FRAMER_ARGS_VARARGS_BUF(args)       ((u_int8_t *)args + UTUN_CRYPTO_FRAMER_ARGS_HDR_SIZE + args->args_ulen)
#define UTUN_CRYPTO_FRAMER_ARGS_TOTAL_SIZE(args)        ((size_t)(UTUN_CRYPTO_FRAMER_ARGS_HDR_SIZE + args->args_ulen + args->varargs_buflen))

#define UTUN_CRYPTO_ARGS_HDR_SIZE                     ((size_t)(&((utun_crypto_args_t *)0)->u))
#define UTUN_CRYPTO_ARGS_VARARGS_BUF(args)            ((u_int8_t *)args + UTUN_CRYPTO_ARGS_HDR_SIZE + args->args_ulen)
#define UTUN_CRYPTO_ARGS_TOTAL_SIZE(args)             ((size_t)(UTUN_CRYPTO_ARGS_HDR_SIZE + args->args_ulen + args->varargs_buflen))

typedef caddr_t (*utun_crypto_kpi_connect_func)(int kpi_handle, struct utun_pcb *utun_ref);

typedef errno_t (*utun_crypto_kpi_send_func)(caddr_t ref, mbuf_t *pkt);

typedef struct utun_crypto_kpi_reg {
  /* Dispatch functions */
  utun_crypto_type_t           crypto_kpi_type;
  u_int32_t                    crypto_kpi_flags;
  utun_crypto_kpi_connect_func crypto_kpi_connect;
  utun_crypto_kpi_send_func    crypto_kpi_send;
} utun_crypto_kpi_reg_t;

typedef struct utun_crypto_kpi_reg_list {
  utun_crypto_kpi_reg_t            reg;
  struct utun_crypto_kpi_reg_list *next;
} utun_crypto_kpi_reg_list_t;

void
utun_ctl_init_crypto(void);

/*
 * Summary: registers the crypto KPI's Kext routines with UTUN... so that UTUN can make calls into it (e.g. DTLS)
 */
errno_t
utun_crypto_kpi_register(utun_crypto_kpi_reg_t *reg);

void
utun_cleanup_crypto(struct utun_pcb *pcb);

errno_t
utun_ctl_enable_crypto(__unused kern_ctl_ref  kctlref,
		       __unused u_int32_t     unit, 
		       __unused void         *unitinfo,
		       __unused int           opt, 
		       void                  *data, 
		       size_t                 len);

errno_t
utun_ctl_disable_crypto(__unused kern_ctl_ref  kctlref,
			__unused u_int32_t     unit, 
			__unused void         *unitinfo,
			__unused int           opt, 
			void                  *data, 
			size_t                 len);

errno_t
utun_ctl_config_crypto_keys(__unused kern_ctl_ref  kctlref,
			    __unused u_int32_t	   unit, 
			    __unused void         *unitinfo,
			    __unused int           opt, 
			    void                  *data, 
			    size_t                 len);

errno_t
utun_ctl_unconfig_crypto_keys(__unused kern_ctl_ref  kctlref,
			      __unused u_int32_t     unit, 
			      __unused void         *unitinfo,
			      __unused int           opt, 
			      void                  *data, 
			      size_t                 len);

errno_t
utun_ctl_config_crypto_framer(__unused kern_ctl_ref  kctlref,
			      __unused u_int32_t	   unit, 
			      __unused void         *unitinfo,
			      __unused int           opt, 
			      void                  *data, 
			      size_t                 len);

errno_t
utun_ctl_unconfig_crypto_framer(__unused kern_ctl_ref  kctlref,
				__unused u_int32_t     unit, 
				__unused void         *unitinfo,
				__unused int           opt, 
				void                  *data, 
				size_t                 len);

errno_t
utun_ctl_generate_crypto_keys_idx(__unused kern_ctl_ref  kctlref,
				  __unused u_int32_t     unit, 
				  __unused void         *unitinfo,
				  __unused int           opt, 
				  void                  *data, 
				  size_t                *len);

errno_t
utun_ctl_stop_crypto_data_traffic(__unused kern_ctl_ref  kctlref,
				  __unused u_int32_t     unit, 
				  __unused void         *unitinfo,
				  __unused int           opt, 
				  void                  *data, 
				  size_t                 len);

errno_t
utun_ctl_start_crypto_data_traffic(__unused kern_ctl_ref  kctlref,
				   __unused u_int32_t     unit, 
				   __unused void         *unitinfo,
				   __unused int           opt, 
				   void                  *data, 
				   size_t                 len);

int
utun_pkt_crypto_output(struct utun_pcb *pcb, mbuf_t *m);

#endif // KERNEL_PRIVATE

#endif // _NET_IF_UTUN_CRYPTO_H_
