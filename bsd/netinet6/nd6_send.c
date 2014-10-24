/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/malloc.h>
#include <sys/proc.h>
#include <sys/sysctl.h>
#include <sys/syslog.h>

#include <libkern/crypto/sha1.h>

#include <net/if.h>

#include <netinet/in.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet6/nd6.h>

#if CONFIG_MACF
#include <sys/kauth.h>
#include <security/mac_framework.h>
#endif

SYSCTL_DECL(_net_inet6);	/* Note: Not in any common header. */

SYSCTL_NODE(_net_inet6, OID_AUTO, send, CTLFLAG_RW | CTLFLAG_LOCKED, 0,
	"IPv6 Secure Neighbor Discovery");

static int nd6_send_opmode = ND6_SEND_OPMODE_DISABLED;

SYSCTL_INT(_net_inet6_send, OID_AUTO, opstate, CTLFLAG_RD | CTLFLAG_LOCKED,
	&nd6_send_opstate, 0, "current SEND operating state");

int nd6_send_opstate = ND6_SEND_OPMODE_DISABLED;
SYSCTL_INT(_net_inet6_send, OID_AUTO, opmode, CTLFLAG_RW | CTLFLAG_LOCKED,
	&nd6_send_opmode, 0, "configured SEND operating mode");

static int sysctl_cga_parameters SYSCTL_HANDLER_ARGS;

SYSCTL_PROC(_net_inet6_send, OID_AUTO, cga_parameters,
	CTLTYPE_OPAQUE | CTLFLAG_RW | CTLFLAG_LOCKED, 0, 0,
	sysctl_cga_parameters, "S,nd6_send_nodecfg", "");

/*
 * The size of the buffer is sufficient to contain a public key, its size in
 * machine binary type for the kernel, and the CGA precalc for the global
 * scope. This interface is not a public API, so we don't anticipate that the
 * userland and the kernel will be mismatched between ILP32 and LP64.
 */
#define	SYSCTL_CGA_PARAMETERS_BUFFER_SIZE \
	2 * (sizeof (u_int16_t) + IN6_CGA_KEY_MAXSIZE) + \
	sizeof (struct in6_cga_prepare)

static int
sysctl_cga_parameters SYSCTL_HANDLER_ARGS
{
#pragma unused(oidp, arg1)
	u_int namelen;
	char *oldp, *newp;
	const char *fin;
	struct in6_cga_nodecfg cfg;
	struct iovec *iov;
	int error;
	char *buffer;
	u_int16_t u16;
#if CONFIG_MACF
	kauth_cred_t cred;
#endif

	namelen = arg2;
	if (namelen != 0) {
		log(LOG_ERR, "%s: name length err [len=%u]\n", __func__,
		    namelen);
		return (EINVAL);
	}

	if (req->newlen > SYSCTL_CGA_PARAMETERS_BUFFER_SIZE) {
		log(LOG_ERR, "%s: input buffer size error [len=%u]\n", __func__,
		    req->newlen);
		return (EINVAL);
	}

#if CONFIG_MACF
	cred = kauth_cred_proc_ref(current_proc());
	error = mac_system_check_info(cred, "net.inet6.send.cga_parameters");
	kauth_cred_unref(&cred);
	if (error != 0) {
		log(LOG_ERR, "%s: mac_system_check_info denied.\n", __func__);
		return (EPERM);
	}
#endif

	MALLOC(buffer, char *, SYSCTL_CGA_PARAMETERS_BUFFER_SIZE, M_IP6CGA,
	    M_WAITOK);
	if (buffer == NULL) {
		log(LOG_ERR, "%s: could not allocate marshaling buffer.\n",
		    __func__);
		return (ENOMEM);
	}

	in6_cga_node_lock();

	if (req->oldptr != USER_ADDR_NULL && req->oldlen > 0) {
		oldp = buffer;
		fin = &buffer[SYSCTL_CGA_PARAMETERS_BUFFER_SIZE];
		if (req->oldlen < SYSCTL_CGA_PARAMETERS_BUFFER_SIZE)
			fin = &buffer[req->oldlen];

		in6_cga_query(&cfg);
		iov = &cfg.cga_pubkey;
		if (iov->iov_len > 0) {
			VERIFY(iov->iov_len < UINT16_MAX);

			if (&oldp[sizeof (cfg.cga_prepare)] <= fin)
				bcopy(&cfg.cga_prepare, oldp,
				    sizeof (cfg.cga_prepare));
			oldp += sizeof (cfg.cga_prepare);

			if (&oldp[sizeof (u16)] < fin) {
				u16 = (u_int16_t) iov->iov_len;
				bcopy(&u16, oldp, sizeof (u16));
			}
			oldp += sizeof (u16);

			if (&oldp[iov->iov_len] < fin)
				bcopy(iov->iov_base, oldp, iov->iov_len);
			oldp += iov->iov_len;

			if (oldp > fin) {
				req->oldlen = oldp - buffer;
				log(LOG_ERR, "%s: marshalled data too large.\n",
				    __func__);
				error = ENOMEM;
				goto done;
			}
		}

		error = SYSCTL_OUT(req, buffer, oldp - buffer);
		if (error)
			goto done;
	}

	if (req->newptr == USER_ADDR_NULL)
		goto done;

	error = proc_suser(current_proc());
	if (error)
		goto done;

	if (req->newlen == 0) {
		in6_cga_stop();
		nd6_send_opstate = ND6_SEND_OPMODE_DISABLED;
		goto done;
	}

	error = SYSCTL_IN(req, buffer, req->newlen);
	if (error)
		goto done;

	newp = buffer;
	fin = &buffer[req->newlen];

	bzero(&cfg, sizeof cfg);

	if (&newp[sizeof (cfg.cga_prepare)] <= fin)
		bcopy(newp, &cfg.cga_prepare, sizeof (cfg.cga_prepare));
	newp += sizeof (cfg.cga_prepare);

	iov = &cfg.cga_privkey;
	if (&newp[sizeof (u16)] < fin) {
		bcopy(newp, &u16, sizeof (u16));
		iov->iov_len = u16;

		if (iov->iov_len > IN6_CGA_KEY_MAXSIZE) {
			error = EINVAL;
			goto done;
		}
	}
	newp += sizeof (u16);

	iov->iov_base = newp;
	newp += iov->iov_len;

	iov = &cfg.cga_pubkey;
	if (&newp[sizeof (u16)] < fin) {
		bcopy(newp, &u16, sizeof (u16));
		iov->iov_len = u16;

		if (iov->iov_len > IN6_CGA_KEY_MAXSIZE) {
			error = EINVAL;
			goto done;
		}
	}
	newp += sizeof (u16);

	iov->iov_base = newp;
	newp += iov->iov_len;

	if (newp > fin) {
		log(LOG_ERR, "%s: input too large [octets=%ld].\n", __func__,
		    newp - fin);
		error = ENOMEM;
		goto done;
	}

	error = in6_cga_start(&cfg);
	if (!error)
		nd6_send_opstate = nd6_send_opmode;
	else
		log(LOG_ERR, "%s: in6_cga_start error=%d.\n", __func__,
		    error);

done:
	in6_cga_node_unlock();
	FREE(buffer, M_IP6CGA);
	return (error);
}

/* End of file */
