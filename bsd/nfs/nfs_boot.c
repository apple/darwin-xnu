/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
/* Copyright (c) 1995, 1997 NeXT Computer, Inc. All Rights Reserved */
/*
 * Copyright (c) 1994 Adam Glass, Gordon Ross
 * All rights reserved.
 *
 * This software was developed by the Computer Systems Engineering group
 * at Lawrence Berkeley Laboratory under DARPA contract BG 91-66 and
 * contributed to Berkeley.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *      This product includes software developed by the University of
 *      California, Lawrence Berkeley Laboratory and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *  History:
 *  14-March-97	Dieter Siegmund (dieter@next.com)
 *	- Use BOOTP instead of RARP to get the IP address at boot time
 *
 *  23-May-97  Umesh Vaishampayan  (umeshv@apple.com)
 *	- Added the ability to mount "/private" separately.
 *
 *  30-May-97	Dieter Siegmund	(dieter@next.com)
 *	- Clear out the ireq structure before using it to prevent
 *	  our sending using a bogus source IP address, we should use
 *	  an IP address of all zeroes
 *	- Right after BOOTP, get the correct netmask using AUTONETMASK
 *  18-Jul-97	Dieter Siegmund	(dieter@apple.com)
 *	- we can't restrict the netmask until we have a default route,
 *	  removed AUTONETMASK call (ifdef'd out)
 *  5-Aug-97	Dieter Siegmund (dieter@apple.com)
 *	- use the default route from the bpwhoami call, enabled autonetmask
 *	  again
 *  19-Feb-1999	Dieter Siegmund (dieter@apple.com)
 *	- use new BOOTP routine to get the subnet mask and router
 *        and stop using SIOCAUTOADDR
 *      - don't bother mounting private separately if it's not
 *        specified or not required because they are substrings of
 *        one another ie. root=host:/A and private=host:/A/private
 *      - allow the root path to be specified in the boot variable
 *	  "rp" (AKA "rootpath")
 *  19-Jul-1999 Dieter Siegmund (dieter@apple.com)
 *	- replaced big automatic arrays with MALLOC'd data
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/proc.h>
#include <sys/mount_internal.h>
#include <sys/kpi_mbuf.h>

#include <sys/malloc.h>
#include <sys/socket.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/if_ether.h>

#include <nfs/rpcv2.h>
#include <nfs/nfsproto.h>
#include <nfs/nfs.h>
#include <nfs/nfsdiskless.h>
#include <nfs/krpc.h>

#include <pexpert/pexpert.h>

#include "ether.h"

#include <libkern/libkern.h>


#if NETHER == 0

int nfs_boot_init(struct nfs_diskless *nd, proc_t procp)
{
	panic("nfs_boot_init: no ether");
}

int nfs_boot_getfh(struct nfs_diskless *nd, proc_t procp, int v3, int sotype)
{
	panic("nfs_boot_getfh: no ether");
}

#else /* NETHER */

/*
 * Support for NFS diskless booting, specifically getting information
 * about where to boot from, what pathnames, etc.
 *
 * This implememtation uses RARP and the bootparam RPC.
 * We are forced to implement RPC anyway (to get file handles)
 * so we might as well take advantage of it for bootparam too.
 *
 * The diskless boot sequence goes as follows:
 * (1) Use RARP to get our interface address
 * (2) Use RPC/bootparam/whoami to get our hostname,
 *     our IP address, and the server's IP address.
 * (3) Use RPC/bootparam/getfile to get the root path
 * (4) Use RPC/mountd to get the root file handle
 * (5) Use RPC/bootparam/getfile to get the swap path
 * (6) Use RPC/mountd to get the swap file handle
 *
 * (This happens to be the way Sun does it too.)
 */

/* bootparam RPC */
static int bp_whoami(struct sockaddr_in *bpsin,
	struct in_addr *my_ip, struct in_addr *gw_ip);
static int bp_getfile(struct sockaddr_in *bpsin, const char *key,
	struct sockaddr_in *mdsin, char *servname, char *path);

/* mountd RPC */
static int md_mount(struct sockaddr_in *mdsin, char *path, int v3, int sotype,
	u_char *fhp, u_long *fhlenp);

/* other helpers */
static int get_file_handle(struct nfs_dlmount *ndmntp);


#define IP_FORMAT	"%d.%d.%d.%d"
#define IP_CH(ip)	((u_char *)ip)
#define IP_LIST(ip)	IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]

extern boolean_t
netboot_iaddr(struct in_addr * iaddr_p);

extern boolean_t
netboot_rootpath(struct in_addr * server_ip,
		 char * name, int name_len, 
		 char * path, int path_len);

/*
 * Called with an empty nfs_diskless struct to be filled in.
 */
int
nfs_boot_init(struct nfs_diskless *nd, __unused proc_t procp)
{
	struct sockaddr_in 	bp_sin;
	boolean_t		do_bpwhoami = TRUE;
	boolean_t		do_bpgetfile = TRUE;
	int 			error = 0;
	struct in_addr 		my_ip;
	struct sockaddr_in *	sin_p;

	/* make sure mbuf constants are set up */
	if (!nfs_mbuf_mlen)
		nfs_mbuf_init();

	/* by this point, networking must already have been configured */
	if (netboot_iaddr(&my_ip) == FALSE) {
	    printf("nfs_boot: networking is not initialized\n");
	    error = ENXIO;
	    goto failed;
	}

	/* get the root path information */
	MALLOC_ZONE(nd->nd_root.ndm_path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
	if (!nd->nd_root.ndm_path) {
	    printf("nfs_boot: can't allocate root path buffer\n");
	    error = ENOMEM;
	    goto failed;
	}
	sin_p = &nd->nd_root.ndm_saddr;
	bzero((caddr_t)sin_p, sizeof(*sin_p));
	sin_p->sin_len = sizeof(*sin_p);
	sin_p->sin_family = AF_INET;
	if (netboot_rootpath(&sin_p->sin_addr, nd->nd_root.ndm_host, 
			     sizeof(nd->nd_root.ndm_host),
			     nd->nd_root.ndm_path, MAXPATHLEN) == TRUE) {
	    do_bpgetfile = FALSE;
	    do_bpwhoami = FALSE;
	}
	nd->nd_private.ndm_saddr.sin_addr.s_addr = 0;

	if (do_bpwhoami) {
		struct in_addr router;
		/*
		 * Get client name and gateway address.
		 * RPC: bootparam/whoami
		 * Use the old broadcast address for the WHOAMI
		 * call because we do not yet know our netmask.
		 * The server address returned by the WHOAMI call
		 * is used for all subsequent booptaram RPCs.
		 */
		bzero((caddr_t)&bp_sin, sizeof(bp_sin));
		bp_sin.sin_len = sizeof(bp_sin);
		bp_sin.sin_family = AF_INET;
		bp_sin.sin_addr.s_addr = INADDR_BROADCAST;
		hostnamelen = MAXHOSTNAMELEN;
		router.s_addr = 0;
		error = bp_whoami(&bp_sin, &my_ip, &router);
		if (error) {
			printf("nfs_boot: bootparam whoami, error=%d", error);
			goto failed;
		}
		printf("nfs_boot: BOOTPARAMS server " IP_FORMAT "\n", 
		       IP_LIST(&bp_sin.sin_addr));
		printf("nfs_boot: hostname %s\n", hostname);
	}
	if (do_bpgetfile) {
		error = bp_getfile(&bp_sin, "root", &nd->nd_root.ndm_saddr,
				   nd->nd_root.ndm_host, nd->nd_root.ndm_path);
		if (error) {
			printf("nfs_boot: bootparam get root: %d\n", error);
			goto failed;
		}
	}

#if !defined(NO_MOUNT_PRIVATE) 
	if (do_bpgetfile) { /* get private path */
		MALLOC_ZONE(nd->nd_private.ndm_path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
		if (!nd->nd_private.ndm_path) {
			printf("nfs_boot: can't allocate private path buffer\n");
			error = ENOMEM;
			goto failed;
		}
		error = bp_getfile(&bp_sin, "private", 
				   &nd->nd_private.ndm_saddr,
				   nd->nd_private.ndm_host,
				   nd->nd_private.ndm_path);
		if (!error) {
			char * check_path = NULL;
			
			MALLOC_ZONE(check_path, char *, MAXPATHLEN, M_NAMEI, M_WAITOK);
			if (!check_path) {
				printf("nfs_boot: can't allocate check_path buffer\n");
				error = ENOMEM;
				goto failed;
			}
			snprintf(check_path, MAXPATHLEN, "%s/private", nd->nd_root.ndm_path);
			if ((nd->nd_root.ndm_saddr.sin_addr.s_addr 
			     == nd->nd_private.ndm_saddr.sin_addr.s_addr)
			    && (strcmp(check_path, nd->nd_private.ndm_path) == 0)) {
				/* private path is prefix of root path, don't mount */
				nd->nd_private.ndm_saddr.sin_addr.s_addr = 0;
			}
			FREE_ZONE(check_path, MAXPATHLEN, M_NAMEI);
		}
		else { 
			/* private key not defined, don't mount */
			nd->nd_private.ndm_saddr.sin_addr.s_addr = 0;
		}
	}
	else {
		error = 0;
	}
#endif /* NO_MOUNT_PRIVATE */
failed:
	return (error);
}

/*
 * Called with a partially initialized nfs_diskless struct
 * with file handles to be filled in.
 */
int
nfs_boot_getfh(struct nfs_diskless *nd, __unused proc_t procp, int v3, int sotype)
{
	int error = 0;

	nd->nd_root.ndm_nfsv3 = v3;
	nd->nd_root.ndm_sotype = sotype;
	error = get_file_handle(&nd->nd_root);
	if (error) {
		printf("nfs_boot: get_file_handle(v%d) root failed, %d\n",
			v3 ? 3 : 2, error);
		goto failed;
	}

#if !defined(NO_MOUNT_PRIVATE) 
	if (nd->nd_private.ndm_saddr.sin_addr.s_addr) {
		/* get private file handle */
		nd->nd_private.ndm_nfsv3 = v3;
		nd->nd_private.ndm_sotype = sotype;
		error = get_file_handle(&nd->nd_private);
		if (error) {
			printf("nfs_boot: get_file_handle(v%d) private failed, %d\n",
				v3 ? 3 : 2, error);
			goto failed;
		}
	}
#endif /* NO_MOUNT_PRIVATE */
failed:
	return (error);
}

static int
get_file_handle(ndmntp)
	struct nfs_dlmount *ndmntp;
{
	char *sp, *dp, *endp;
	int error;

	/*
	 * Get file handle for "key" (root or swap)
	 * using RPC to mountd/mount
	 */
	error = md_mount(&ndmntp->ndm_saddr, ndmntp->ndm_path, ndmntp->ndm_nfsv3,
			ndmntp->ndm_sotype, ndmntp->ndm_fh, &ndmntp->ndm_fhlen);
	if (error)
		return (error);

	/* Construct remote path (for getmntinfo(3)) */
	dp = ndmntp->ndm_host;
	endp = dp + MNAMELEN - 1;
	dp += strlen(dp);
	*dp++ = ':';
	for (sp = ndmntp->ndm_path; *sp && dp < endp;)
		*dp++ = *sp++;
	*dp = '\0';
	return (0);

}


/*
 * Get an mbuf with the given length, and
 * initialize the pkthdr length field.
 */
static int
mbuf_get_with_len(int msg_len, mbuf_t *m)
{
	int error;
	error = mbuf_gethdr(MBUF_WAITOK, MBUF_TYPE_DATA, m);
	if (error)
		return (error);
	if (msg_len > mbuf_maxlen(*m)) {
		error = mbuf_mclget(MBUF_WAITOK, MBUF_TYPE_DATA, m);
		if (error) {
			mbuf_freem(*m);
			return (error);
		}
		if (msg_len > mbuf_maxlen(*m))
			panic("nfs_boot: msg_len > MCLBYTES");
	}
	mbuf_setlen(*m, msg_len);
	mbuf_pkthdr_setlen(*m, msg_len);
	return (0);
}


/*
 * String representation for RPC.
 */
struct rpc_string {
	u_long len;		/* length without null or padding */
	u_char data[4];	/* data (longer, of course) */
    /* data is padded to a long-word boundary */
};
/* Compute space used given string length. */
#define	RPC_STR_SIZE(slen) (4 + ((slen + 3) & ~3))

/*
 * Inet address in RPC messages
 * (Note, really four longs, NOT chars.  Blech.)
 */
struct bp_inaddr {
	u_long  atype;
	long	addr[4];
};


/*
 * RPC: bootparam/whoami
 * Given client IP address, get:
 *	client name	(hostname)
 *	domain name (domainname)
 *	gateway address
 *
 * The hostname and domainname are set here for convenience.
 *
 * Note - bpsin is initialized to the broadcast address,
 * and will be replaced with the bootparam server address
 * after this call is complete.  Have to use PMAP_PROC_CALL
 * to make sure we get responses only from a servers that
 * know about us (don't want to broadcast a getport call).
 */
static int
bp_whoami(bpsin, my_ip, gw_ip)
	struct sockaddr_in *bpsin;
	struct in_addr *my_ip;
	struct in_addr *gw_ip;
{
	/* RPC structures for PMAPPROC_CALLIT */
	struct whoami_call {
		u_long call_prog;
		u_long call_vers;
		u_long call_proc;
		u_long call_arglen;
		struct bp_inaddr call_ia;
	} *call;

	struct rpc_string *str;
	struct bp_inaddr *bia;
	mbuf_t m;
	struct sockaddr_in sin;
	int error, msg_len;
	int cn_len, dn_len;
	u_char *p;
	long *lp;

	/*
	 * Get message buffer of sufficient size.
	 */
	msg_len = sizeof(*call);
	error = mbuf_get_with_len(msg_len, &m);
	if (error)
		return error;

	/*
	 * Build request message for PMAPPROC_CALLIT.
	 */
	call = mbuf_data(m);
	call->call_prog = htonl(BOOTPARAM_PROG);
	call->call_vers = htonl(BOOTPARAM_VERS);
	call->call_proc = htonl(BOOTPARAM_WHOAMI);
	call->call_arglen = htonl(sizeof(struct bp_inaddr));

	/* client IP address */
	call->call_ia.atype = htonl(1);
	p = (u_char*)my_ip;
	lp = call->call_ia.addr;
	*lp++ = htonl(*p);	p++;
	*lp++ = htonl(*p);	p++;
	*lp++ = htonl(*p);	p++;
	*lp++ = htonl(*p);	p++;

	/* RPC: portmap/callit */
	bpsin->sin_port = htons(PMAPPORT);

	error = krpc_call(bpsin, SOCK_DGRAM, PMAPPROG, PMAPVERS, PMAPPROC_CALLIT, &m, &sin);
	if (error)
		return error;

	/*
	 * Parse result message.
	 */
	msg_len = mbuf_len(m);
	lp = mbuf_data(m);

	/* bootparam server port (also grab from address). */
	if (msg_len < (int)sizeof(*lp))
		goto bad;
	msg_len -= sizeof(*lp);
	bpsin->sin_port = htons((short)ntohl(*lp++));
	bpsin->sin_addr.s_addr = sin.sin_addr.s_addr;

	/* length of encapsulated results */
	if (msg_len < (ntohl(*lp) + (int)sizeof(*lp)))
		goto bad;
	msg_len = ntohl(*lp++);
	p = (char*)lp;

	/* client name */
	if (msg_len < (int)sizeof(*str))
		goto bad;
	str = (struct rpc_string *)p;
	cn_len = ntohl(str->len);
	if (msg_len < cn_len)
		goto bad;
	if (cn_len >= MAXHOSTNAMELEN)
		goto bad;
	bcopy(str->data, hostname, cn_len);
	hostname[cn_len] = '\0';
	hostnamelen = cn_len;
	p += RPC_STR_SIZE(cn_len);
	msg_len -= RPC_STR_SIZE(cn_len);

	/* domain name */
	if (msg_len < (int)sizeof(*str))
		goto bad;
	str = (struct rpc_string *)p;
	dn_len = ntohl(str->len);
	if (msg_len < dn_len)
		goto bad;
	if (dn_len >= MAXHOSTNAMELEN)
		goto bad;
	bcopy(str->data, domainname, dn_len);
	domainname[dn_len] = '\0';
	domainnamelen = dn_len;
	p += RPC_STR_SIZE(dn_len);
	msg_len -= RPC_STR_SIZE(dn_len);

	/* gateway address */
	if (msg_len < (int)sizeof(*bia))
		goto bad;
	bia = (struct bp_inaddr *)p;
	if (bia->atype != htonl(1))
		goto bad;
	p = (u_char*)gw_ip;
	*p++ = ntohl(bia->addr[0]);
	*p++ = ntohl(bia->addr[1]);
	*p++ = ntohl(bia->addr[2]);
	*p++ = ntohl(bia->addr[3]);
	goto out;

bad:
	printf("nfs_boot: bootparam_whoami: bad reply\n");
	error = EBADRPC;

out:
	mbuf_freem(m);
	return(error);
}


/*
 * RPC: bootparam/getfile
 * Given client name and file "key", get:
 *	server name
 *	server IP address
 *	server pathname
 */
static int
bp_getfile(bpsin, key, md_sin, serv_name, pathname)
	struct sockaddr_in *bpsin;
	const char *key;
	struct sockaddr_in *md_sin;
	char *serv_name;
	char *pathname;
{
	struct rpc_string *str;
	mbuf_t m;
	struct bp_inaddr *bia;
	struct sockaddr_in *sin;
	u_char *p, *q;
	int error, msg_len;
	int cn_len, key_len, sn_len, path_len;

	/*
	 * Get message buffer of sufficient size.
	 */
	cn_len = hostnamelen;
	key_len = strlen(key);
	msg_len = 0;
	msg_len += RPC_STR_SIZE(cn_len);
	msg_len += RPC_STR_SIZE(key_len);
	error = mbuf_get_with_len(msg_len, &m);
	if (error)
		return error;

	/*
	 * Build request message.
	 */
	p = mbuf_data(m);
	bzero(p, msg_len);
	/* client name (hostname) */
	str = (struct rpc_string *)p;
	str->len = htonl(cn_len);
	bcopy(hostname, str->data, cn_len);
	p += RPC_STR_SIZE(cn_len);
	/* key name (root or swap) */
	str = (struct rpc_string *)p;
	str->len = htonl(key_len);
	bcopy(key, str->data, key_len);

	/* RPC: bootparam/getfile */
	error = krpc_call(bpsin, SOCK_DGRAM, BOOTPARAM_PROG, BOOTPARAM_VERS,
			BOOTPARAM_GETFILE, &m, NULL);
	if (error)
		return error;

	/*
	 * Parse result message.
	 */
	p = mbuf_data(m);
	msg_len = mbuf_len(m);

	/* server name */
	if (msg_len < (int)sizeof(*str))
		goto bad;
	str = (struct rpc_string *)p;
	sn_len = ntohl(str->len);
	if (msg_len < sn_len)
		goto bad;
	if (sn_len >= MNAMELEN)
		goto bad;
	bcopy(str->data, serv_name, sn_len);
	serv_name[sn_len] = '\0';
	p += RPC_STR_SIZE(sn_len);
	msg_len -= RPC_STR_SIZE(sn_len);

	/* server IP address (mountd) */
	if (msg_len < (int)sizeof(*bia))
		goto bad;
	bia = (struct bp_inaddr *)p;
	if (bia->atype != htonl(1))
		goto bad;
	sin = md_sin;
	bzero((caddr_t)sin, sizeof(*sin));
	sin->sin_len = sizeof(*sin);
	sin->sin_family = AF_INET;
	q = (u_char*) &sin->sin_addr;
	*q++ = ntohl(bia->addr[0]);
	*q++ = ntohl(bia->addr[1]);
	*q++ = ntohl(bia->addr[2]);
	*q++ = ntohl(bia->addr[3]);
	p += sizeof(*bia);
	msg_len -= sizeof(*bia);

	/* server pathname */
	if (msg_len < (int)sizeof(*str))
		goto bad;
	str = (struct rpc_string *)p;
	path_len = ntohl(str->len);
	if (msg_len < path_len)
		goto bad;
	if (path_len >= MAXPATHLEN)
		goto bad;
	bcopy(str->data, pathname, path_len);
	pathname[path_len] = '\0';
	goto out;

bad:
	printf("nfs_boot: bootparam_getfile: bad reply\n");
	error = EBADRPC;

out:
	mbuf_freem(m);
	return(0);
}


/*
 * RPC: mountd/mount
 * Given a server pathname, get an NFS file handle.
 * Also, sets sin->sin_port to the NFS service port.
 */
static int
md_mount(mdsin, path, v3, sotype, fhp, fhlenp)
	struct sockaddr_in *mdsin;		/* mountd server address */
	char *path;
	int v3;
	int sotype;
	u_char *fhp;
	u_long *fhlenp;
{
	/* The RPC structures */
	struct rpc_string *str;
	struct rdata {
		u_long	errno;
		u_char	data[NFSX_V3FHMAX + sizeof(u_long)];
	} *rdata;
	mbuf_t m;
	int error, mlen, slen;
	int mntversion = v3 ? RPCMNT_VER3 : RPCMNT_VER1;
	int proto = (sotype == SOCK_STREAM) ? IPPROTO_TCP : IPPROTO_UDP;
	in_port_t mntport, nfsport;

	/* Get port number for MOUNTD. */
	error = krpc_portmap(mdsin, RPCPROG_MNT, mntversion, proto, &mntport);
	if (error)
		return error;

	/* Get port number for NFS use. */
	/* (If NFS/proto unavailable, don't bother with the mount call) */
	error = krpc_portmap(mdsin, NFS_PROG, v3 ? NFS_VER3 : NFS_VER2, proto, &nfsport);
	if (error)
		return error;

	/* Set port number for MOUNTD */
	mdsin->sin_port = mntport;

	slen = strlen(path);
	mlen = RPC_STR_SIZE(slen);

	error = mbuf_get_with_len(mlen, &m);
	if (error)
		return error;
	str = mbuf_data(m);
	str->len = htonl(slen);
	bcopy(path, str->data, slen);

	/* Do RPC to mountd. */
	error = krpc_call(mdsin, sotype, RPCPROG_MNT, mntversion, RPCMNT_MOUNT, &m, NULL);
	if (error)
		return error;	/* message already freed */

	/*
	 * the reply must be long enough to hold the errno plus either of:
	 * + a v2 filehandle
	 * + a v3 filehandle length + a v3 filehandle
	 */
	mlen = mbuf_len(m);
	if (mlen < (int)sizeof(u_long))
		goto bad;
	rdata = mbuf_data(m);
	error = ntohl(rdata->errno);
	if (error)
		goto out;
	if (v3) {
		u_long fhlen;
		u_char *fh;
		if (mlen < (int)sizeof(u_long)*2)
			goto bad;
		fhlen = ntohl(*(u_long*)rdata->data);
		fh = rdata->data + sizeof(u_long);
		if (mlen < (int)(sizeof(u_long)*2 + fhlen))
			goto bad;
		bcopy(fh, fhp, fhlen);
		*fhlenp = fhlen;
	} else {
		if (mlen < ((int)sizeof(u_long) + NFSX_V2FH))
			goto bad;
		bcopy(rdata->data, fhp, NFSX_V2FH);
		*fhlenp = NFSX_V2FH;
	}

	/* Set port number for NFS use. */
	mdsin->sin_port = nfsport;
	goto out;

bad:
	error = EBADRPC;

out:
	mbuf_freem(m);
	return error;
}

#endif /* NETHER */
