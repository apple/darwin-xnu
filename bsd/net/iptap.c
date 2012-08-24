/*
 * Copyright (c) 1999-2010 Apple Inc. All rights reserved.
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
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <mach/mach_types.h>
#include <kern/locks.h>
#include <sys/kernel.h>
#include <sys/param.h>
#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <sys/cdefs.h>
#include <sys/kern_control.h>
#include <sys/uio_internal.h>
#include <sys/mbuf.h>
#include <net/if_types.h>
#include <net/if.h>
#include <net/kpi_interface.h>
#include <net/bpf.h>
#include <net/iptap.h>
#include <netinet/kpi_ipfilter.h>
#include <libkern/libkern.h>
#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>

#include <IOKit/IOLib.h>

#define	IPTAP_IF_NAME			"iptap"
#define IPTAP_PRINTF			printf
#define IP_TAP_NOT_USED			0

#define VALID_PACKET(type, label)\
			if (iptap_clients == 0)		\
				goto label;				\
										\
			if (type != IFT_ETHER &&	\
				type != IFT_CELLULAR)	\
				goto label

static void				*iptap_alloc(size_t);
static void				iptap_free(void *);
static errno_t			iptap_register_control(void);
static inline void		iptap_lock_shared(void);
static inline void		iptap_lock_exclusive(void);
static inline void		iptap_lock_done(void);
static void				iptap_alloc_lock(void);
static void				iptap_free_lock(void);

static void				iptap_enqueue_mbuf(struct ifnet *, protocol_family_t, struct mbuf *, u_int32_t, u_int32_t, u_int8_t);

/* kernctl callbacks */
static errno_t			iptap_ctl_connect(kern_ctl_ref, struct sockaddr_ctl *, void **);
static errno_t			iptap_ctl_disconnect(kern_ctl_ref, u_int32_t, void *);

#if IP_TAP_NOT_USED

static errno_t			iptap_deregister_control(void);

static errno_t			iptap_ctl_send(kern_ctl_ref, u_int32_t, void *, mbuf_t, int);
static errno_t			iptap_ctl_setopt(kern_ctl_ref, u_int32_t, void *, int, void *, size_t);
static errno_t			iptap_ctl_getopt(kern_ctl_ref, u_int32_t, void *, int, void *, size_t *);

#endif	/* IP_TAP_NOT_USED */

decl_lck_rw_data(static, iptap_mtx);
static lck_grp_t		*iptap_grp;
static kern_ctl_ref		iptap_kernctl;
static unsigned int		iptap_clients;
static OSMallocTag		iptap_malloc_tag;

struct iptap_client_t {
	LIST_ENTRY(iptap_client_t)		_cle;
	u_int32_t						_unit;
};

static LIST_HEAD(, iptap_client_t)	_s_iptap_clients;


__private_extern__ void
iptap_init(void) {
    
	iptap_alloc_lock();
	
	iptap_malloc_tag = OSMalloc_Tagalloc(IPTAP_CONTROL_NAME, OSMT_DEFAULT);
	if (iptap_malloc_tag == NULL) {
		iptap_free_lock();
		IPTAP_PRINTF("iptap_init failed: unable to allocate malloc tag.\n");
		return;
	}
	
	if (iptap_register_control() != 0) {
		iptap_free_lock();
		OSMalloc_Tagfree(iptap_malloc_tag);
		IPTAP_PRINTF("iptap_init failed: iptap_register_control failure.\n");
		return;
	}
	
	iptap_clients = 0;
}

__private_extern__ void
iptap_ipf_input(struct ifnet *ifp, protocol_family_t proto, struct mbuf *mp, char *frame_header)
{	
	VALID_PACKET(ifp->if_type, done);

	do {
		char *hdr = (char *)mbuf_data(mp);
		size_t start = (size_t)((char*)mbuf_datastart(mp));
		size_t o_len = mp->m_len;
		
		if (frame_header != NULL && (size_t)frame_header >= start && (size_t)frame_header <= (size_t)hdr) {
			if (mbuf_setdata(mp, frame_header, o_len + ((size_t)hdr - (size_t)frame_header)) == 0) {
				iptap_enqueue_mbuf(ifp, proto, mp, ((size_t)hdr - (size_t)frame_header), 0, IPTAP_INPUT_TAG);
				mbuf_setdata(mp, hdr, o_len);
			}
		} else {
			iptap_enqueue_mbuf(ifp, proto, mp, 0, 0, IPTAP_INPUT_TAG);
		}
		
	} while (0);

done:
	return;
}

__private_extern__ void
iptap_ipf_output(struct ifnet *ifp, protocol_family_t proto, struct mbuf *mp, u_int32_t pre, u_int32_t post)
{	
	VALID_PACKET(ifp->if_type, done);
	
	iptap_enqueue_mbuf(ifp, proto, mp, pre, post, IPTAP_OUTPUT_TAG);
	
done:
	return;
}

static void
iptap_enqueue_mbuf(struct ifnet *ifp, protocol_family_t proto, struct mbuf *mp, u_int32_t pre, u_int32_t post, u_int8_t io)
{
	errno_t err = 0;
	struct iptap_client_t *client = NULL;
	mbuf_t copy, itr = (mbuf_t)mp;
	iptap_hdr_t header;
	u_int32_t len = 0;
	
	memset(&header, 0x0, sizeof(header));
	header.version = IPTAP_VERSION_1;
	header.type = ifp->if_type;
	header.unit = ifp->if_unit;
	strlcpy(header.if_name, ifp->if_name, sizeof(header.if_name));
	header.hdr_length = sizeof(header);
	header.protocol_family = proto;
	header.frame_pre_length = pre;
	header.frame_pst_length = post;
	header.io = io;
	
	do {
		len += mbuf_len(itr);
		itr = mbuf_next(itr);
	} while (itr != NULL);
	
	iptap_lock_shared();
	
	LIST_FOREACH(client, &_s_iptap_clients, _cle) {
		
		mbuf_dup((mbuf_t)mp, MBUF_DONTWAIT, &copy);
		if (copy == NULL)
			continue;
		
		err = mbuf_prepend(&copy, sizeof(header), MBUF_DONTWAIT);
		if (err != 0) {
			if (copy != NULL) {
				mbuf_freem(copy);
				copy = NULL;
			}
			continue;
		}
		
		HTONS(header.unit);
		HTONL(header.hdr_length);
		HTONL(header.protocol_family);
		HTONL(header.frame_pre_length);
		HTONL(header.frame_pst_length);
		header.length = htonl(len);
		
		memcpy(mbuf_data(copy), &header, sizeof(header));
		
		err = ctl_enqueuembuf(iptap_kernctl, client->_unit, copy, CTL_DATA_EOR);
		if (err != 0) {
			mbuf_freem(copy);
			copy = NULL;
			IPTAP_PRINTF("iptap_enqueue_mbuf failed: %d\n", (err));
			continue;
		}
	}
	
	iptap_lock_done();
}

static void*
iptap_alloc(size_t size)
{
	size_t *mem = OSMalloc(size + sizeof(size_t), iptap_malloc_tag);
	
	if (mem) {
		*mem = size + sizeof(size_t);
		mem++;
		memset(mem, 0x0, size);
	}
	
	return (void*)mem;
}

static void
iptap_free(void *ptr)
{
	size_t *size = ptr;
	size--;
	OSFree(size, *size, iptap_malloc_tag);
	ptr = NULL;
}

static void
iptap_alloc_lock(void)
{
	lck_grp_attr_t *grp_attr;
	lck_attr_t *attr;
	
	grp_attr = lck_grp_attr_alloc_init();
	lck_grp_attr_setdefault(grp_attr);
	iptap_grp = lck_grp_alloc_init(IPTAP_IF_NAME, grp_attr);
	lck_grp_attr_free(grp_attr);
	
	attr = lck_attr_alloc_init();
	lck_attr_setdefault(attr);
	
	lck_rw_init(&iptap_mtx, iptap_grp, attr);
	lck_attr_free(attr);
}

static void
iptap_free_lock(void)
{
	lck_rw_destroy(&iptap_mtx, iptap_grp);
	lck_grp_free(iptap_grp);
	iptap_grp = NULL;
}

static inline void
iptap_lock_shared(void)
{
	lck_rw_lock_shared(&iptap_mtx);
}

static inline void
iptap_lock_exclusive(void)
{
	lck_rw_lock_exclusive(&iptap_mtx);
}

static inline void
iptap_lock_done(void)
{
	lck_rw_done(&iptap_mtx);
}

static errno_t
iptap_register_control(void)
{
	errno_t err = 0;
	struct kern_ctl_reg kern_ctl;
	
	bzero(&kern_ctl, sizeof(kern_ctl));
	strlcpy(kern_ctl.ctl_name, IPTAP_CONTROL_NAME, sizeof(kern_ctl.ctl_name));
	kern_ctl.ctl_name[sizeof(kern_ctl.ctl_name) - 1] = 0;
	kern_ctl.ctl_flags = CTL_FLAG_PRIVILEGED;
	kern_ctl.ctl_recvsize = IPTAP_BUFFERSZ;
	kern_ctl.ctl_connect = iptap_ctl_connect;
	kern_ctl.ctl_disconnect = iptap_ctl_disconnect;
	kern_ctl.ctl_send = NULL;
	kern_ctl.ctl_setopt = NULL;
	kern_ctl.ctl_getopt = NULL;
	
	err = ctl_register(&kern_ctl, &iptap_kernctl);
	
	return (err);
}

static errno_t
iptap_ctl_connect(kern_ctl_ref kctlref, struct sockaddr_ctl *sac, void **unitinfo)
{
#pragma unused(kctlref)
#pragma unused(unitinfo)
	errno_t err = 0;
	struct iptap_client_t *client = NULL;
	
	client = (struct iptap_client_t *)iptap_alloc(sizeof(struct iptap_client_t));
	if (client != NULL) {
		iptap_lock_exclusive();
		
		iptap_clients++;
		client->_unit = sac->sc_unit;
		LIST_INSERT_HEAD(&_s_iptap_clients, client, _cle);
		
		iptap_lock_done();
	} else {
		err = ENOMEM;
	}
	
	return (err == 0) ? (0) : (err);
}

static errno_t
iptap_ctl_disconnect(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo)
{
#pragma unused(kctlref)
#pragma unused(unitinfo)
	errno_t err = 0;
	struct iptap_client_t *client = NULL;
	
	iptap_lock_exclusive();
	
	LIST_FOREACH(client, &_s_iptap_clients, _cle) {
		if (client->_unit == unit) {
			iptap_clients--;
			LIST_REMOVE(client, _cle);
			break;
		}
	}
	
	iptap_lock_done();
	
	/* get rid of all the interfaces before free'ing */
	iptap_free(client);
	
	if (client == NULL)
		panic("iptap_ctl_disconnect: received a disconnect notification without a cache entry.\n");
	
	return (err == 0) ? (0) : (err);
}

#if IP_TAP_NOT_USED

__private_extern__ void
iptap_destroy(void) {
	
	if (iptap_clients != 0) {
		IPTAP_PRINTF("iptap_destroy failed: there are still outstanding clients.\n");
		return;
	}
	
	if (iptap_deregister_control() != 0) {
		IPTAP_PRINTF("iptap_destroy failed: iptap_deregister_control failed.\n");
	}
	
	OSMalloc_Tagfree(iptap_malloc_tag);
	
	iptap_free_lock();
}

static errno_t
iptap_deregister_control(void)
{
	errno_t err = 0;
	
	if (iptap_kernctl != NULL) {
		err = ctl_deregister(iptap_kernctl);
	} else {
		err = EINVAL;
	}
	
	return (err); 
}

static errno_t
iptap_ctl_send(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, mbuf_t m, int flags)
{
#pragma unused(kctlref)
#pragma unused(unit)
#pragma unused(unitinfo)
#pragma unused(m)
#pragma unused(flags)
	return (KERN_SUCCESS);
}

static errno_t
iptap_ctl_setopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t len)
{	
#pragma unused(kctlref)
#pragma unused(unit)
#pragma unused(unitinfo)
#pragma unused(opt)
#pragma unused(data)
#pragma unused(len)
	return (KERN_SUCCESS);
}

static errno_t
iptap_ctl_getopt(kern_ctl_ref kctlref, u_int32_t unit, void *unitinfo, int opt, void *data, size_t *len)
{
#pragma unused(kctlref)
#pragma unused(unit)
#pragma unused(unitinfo)
#pragma unused(opt)
#pragma unused(data)
#pragma unused(len)
	return (KERN_SUCCESS);
}

#endif /* IP_TAP_NOT_USED */

