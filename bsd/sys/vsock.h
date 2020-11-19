/*
 * Copyright (c) 2020 Apple Inc. All rights reserved.
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

#ifndef _VSOCK_H_
#define _VSOCK_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <sys/_types/_sa_family_t.h>
#include <sys/ucred.h>
#include <sys/socketvar.h>

#define VMADDR_CID_ANY (-1U)
#define VMADDR_CID_HYPERVISOR 0
#define VMADDR_CID_RESERVED 1
#define VMADDR_CID_HOST 2

#define VMADDR_PORT_ANY (-1U)

#define IOCTL_VM_SOCKETS_GET_LOCAL_CID _IOR('s',  209, uint32_t)

struct sockaddr_vm {
	__uint8_t      svm_len;        /* total length */
	sa_family_t    svm_family;     /* Address family: AF_VSOCK */
	__uint16_t     svm_reserved1;
	__uint32_t     svm_port;       /* Port # in host byte order */
	__uint32_t     svm_cid;        /* Address in host byte order */
} __attribute__((__packed__));

typedef u_quad_t vsock_gen_t;

struct xvsockpcb {
	u_int32_t      xv_len;            /* length of this structure */
	u_int64_t      xv_vsockpp;
	u_int32_t      xvp_local_cid;     /* local address cid */
	u_int32_t      xvp_local_port;    /* local address port */
	u_int32_t      xvp_remote_cid;    /* remote address cid */
	u_int32_t      xvp_remote_port;   /* remote address port */
	u_int32_t      xvp_rxcnt;         /* bytes received */
	u_int32_t      xvp_txcnt;         /* bytes transmitted */
	u_int32_t      xvp_peer_rxhiwat;  /* peer's receive buffer */
	u_int32_t      xvp_peer_rxcnt;    /* bytes received by peer */
	pid_t          xvp_last_pid;      /* last pid */
	vsock_gen_t    xvp_gencnt;        /* vsock generation count */
	struct xsocket xv_socket;
};

struct  xvsockpgen {
	u_int32_t      xvg_len;      /* length of this structure */
	u_int64_t      xvg_count;    /* number of PCBs at this time */
	vsock_gen_t    xvg_gen;      /* generation count at this time */
	so_gen_t       xvg_sogen;    /* current socket generation count */
};

__END_DECLS

#endif /* _VSOCK_H_ */
