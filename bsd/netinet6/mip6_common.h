/*	$KAME: mip6_common.h,v 1.9 2000/03/25 07:23:50 sumikawa Exp $	*/

/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright (c) 1999 and 2000 Ericsson Radio Systems AB
 * All rights reserved.
 *
 * Author:     Hesham Soliman <hesham.soliman@ericsson.com.au>
 *             Martti Kuparinen <martti.kuparinen@ericsson.com>
 */


#ifndef _NETINET6_MIP6_COMMON_H_
#define _NETINET6_MIP6_COMMON_H_



/* SIOCs used for communication between kernel and user space.
 *
 * SIOCSDEBUG_MIP6          Set MIP6 debug on/off
 *                          <mip6config -d>
 * SIOCSBCFLUSH_MIP6        Remove list of BC
 *                          <mip6stat -C>
 * SIOCSDEFCONFIG_MIP6      Restore default configuration
 *                          <mip6stat -P>
 * SIOCSBRUPDATE_MIP6       Set time when CN should send Binding request
 *                          <mip6config -w>
 * SIOCSENABLEBR_MIP6       Enable sending BR to the MN
 *                          <mip6config -q>
 * SIOCSHALISTFLUSH_MIP6    Remove list of Home Agents
 *                          <mip6stat -A>
 * SIOCSHAPREF_MIP6         HA preference
 *                          <mip6config -y>
 * SIOCSFWDSLUNICAST_MIP6   Enable forwarding of SL Unicast dest addresses
 *                          <mip6config -u>
 * SIOCSFWDSLMULTICAST_MIP6 Enable forwarding of SL Multicast dest addresses
 *                          <mip6config -m>
 * SIOCSFORADDRFLUSH_MIP6   Remove default foreign address from list
 *                          <mip6stat -F>
 * SIOCSHADDRFLUSH_MIP6     Remove Home Address
 *                          <mip6stat -M>
 * SIOCSBULISTFLUSH_MIP6    Remove Binding Update list
 *                          <mip6stat -U>
 * SIOCACOADDR_MIP6         Set Default foreign IP Address
 *                          <mip6config -F>
 * SIOCAHOMEADDR_MIP6       Add home address
 *                          <mip6config -H>
 * SIOCSBULIFETIME_MIP6     Set default BU lifetime
 *                          <mip6config -b>
 * SIOCSHRLIFETIME_MIP6     Set default lifetime for home registration, not BU
 *                          <mip6config -l>
 * SIOCDCOADDR_MIP6         Remove default foreign address from list
 *                          <mip6config -E>
 * SIOCSPROMMODE_MIP6       Enable link layer promiscuous mode
 *                          <mip6config -p>
 * SIOCSBU2CN_MIP6          Enable sending BU to CN, i.e. Route opt on/off
 *                          <mip6config -r>
 * SIOCSREVTUNNEL_MIP6      Enable tunneling of packets from MN to CN via HA
 *                          <mip6config -t>
 * SIOCSAUTOCONFIG_MIP6     Allow autoconfiguration of Home address
 *                          <mip6config -a>
 * SIOCSEAGERMD_MIP6        Enable eager Movement Detection
 *                          <mip6config -e>
 */
#define SIOCSDEBUG_MIP6          _IOWR('M', 1, struct mip6_input_data)
#define SIOCSBCFLUSH_MIP6        _IOWR('M', 2, int)
#define SIOCSDEFCONFIG_MIP6      _IOWR('M', 3, int)
#define SIOCSBRUPDATE_MIP6       _IOWR('M', 4, u_int8_t)
#define SIOCSENABLEBR_MIP6       _IOWR('M', 5, u_int8_t)

#define SIOCSHALISTFLUSH_MIP6    _IOWR('M', 6, int)
#define SIOCSHAPREF_MIP6         _IOWR('M', 7, int)
#define SIOCSFWDSLUNICAST_MIP6   _IOWR('M', 8, int)
#define SIOCSFWDSLMULTICAST_MIP6 _IOWR('M', 9, int)

#define SIOCSFORADDRFLUSH_MIP6   _IOWR('M', 10, int)
#define SIOCSHADDRFLUSH_MIP6     _IOWR('M', 11, int)
#define SIOCSBULISTFLUSH_MIP6    _IOWR('M', 12, int)
#define SIOCACOADDR_MIP6         _IOWR('M', 13, struct mip6_input_data)
#define SIOCAHOMEADDR_MIP6       _IOWR('M', 14, struct mip6_input_data)
#define SIOCSBULIFETIME_MIP6     _IOWR('M', 15, struct mip6_input_data)
#define SIOCSHRLIFETIME_MIP6     _IOWR('M', 16, struct mip6_input_data)
#define SIOCDCOADDR_MIP6         _IOWR('M', 17, struct mip6_input_data)
#define SIOCSPROMMODE_MIP6       _IOWR('M', 18, struct mip6_input_data)
#define SIOCSBU2CN_MIP6          _IOWR('M', 19, struct mip6_input_data)
#define SIOCSREVTUNNEL_MIP6      _IOWR('M', 20, struct mip6_input_data)
#define SIOCSAUTOCONFIG_MIP6     _IOWR('M', 21, struct mip6_input_data)
#define SIOCSEAGERMD_MIP6        _IOWR('M', 22, struct mip6_input_data)
#define SIOCSATTACH_MIP6         _IOWR('M', 23, struct mip6_input_data)
#define SIOCSRELEASE_MIP6        _IOWR('M', 24, struct mip6_input_data)


/*
 * Information about which module that has been compiled into the kernel or
 * loaded as a module.
 */
#define MIP6_MN_MODULE    0x01
#define MIP6_HA_MODULE    0x02


/*
 * Generic message to pass configuration parameters from mip6config to
 * kernel.
 */
struct mip6_input_data {
	char             if_name[IFNAMSIZ]; /* Interface name */
	u_int8_t         prefix_len;        /* Prefix length for address */
	struct in6_addr  ip6_addr;          /* Address */
	struct in6_addr  ha_addr;           /* Corresponding Home Agent */
	u_int32_t        value;             /* Value */
};

#endif /* not _NETINET6_MIP6_COMMON_H_ */
