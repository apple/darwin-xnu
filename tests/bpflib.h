/*
 * Copyright (c) 2000 Apple Inc. All rights reserved.
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


#ifndef _S_BPFLIB_H
#define _S_BPFLIB_H

int bpf_get_blen(int fd, int * blen);
int bpf_new(void);
int bpf_dispose(int fd);
int bpf_setif(int fd, const char * en_name);
int bpf_set_immediate(int fd, u_int value);
int bpf_filter_receive_none(int fd);
int bpf_arp_filter(int fd, int type_offset, int type, u_int packet_size);
int bpf_set_timeout(int fd, struct timeval * tv_p);
int bpf_set_header_complete(int fd, u_int header_complete);
int bpf_set_see_sent(int fd, u_int see_send);

#endif /* _S_BPFLIB_H */
