/*
 * Copyright (c) 2001-2013 Apple Inc. All rights reserved.
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

/*
 * History:
 * 14 December, 2001	Dieter Siegmund (dieter@apple.com)
 * - created
 */
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/conf.h>
#include <sys/ioctl.h>
#include <sys/proc_internal.h>
#include <sys/mount_internal.h>
#include <sys/mbuf.h>
#include <sys/filedesc.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/reboot.h>
#include <sys/kauth.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/dhcp_options.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>
#include <sys/netboot.h>
#include <sys/imageboot.h>
#include <pexpert/pexpert.h>

//#include <libkern/libkern.h>
extern struct filedesc 	filedesc0;

extern int 	nfs_mountroot(void); 	/* nfs_vfsops.c */
extern int (*mountroot)(void);

extern unsigned char 	rootdevice[];

static int 			S_netboot = 0;
static struct netboot_info *	S_netboot_info_p;

void *
IOBSDRegistryEntryForDeviceTree(const char * path);

void
IOBSDRegistryEntryRelease(void * entry);

const void *
IOBSDRegistryEntryGetData(void * entry, const char * property_name, 
			  int * packet_length);

#define BOOTP_RESPONSE	"bootp-response"
#define BSDP_RESPONSE	"bsdp-response"
#define DHCP_RESPONSE	"dhcp-response"

#define IP_FORMAT	"%d.%d.%d.%d"
#define IP_CH(ip)	((u_char *)ip)
#define IP_LIST(ip)	IP_CH(ip)[0],IP_CH(ip)[1],IP_CH(ip)[2],IP_CH(ip)[3]

#define kNetBootRootPathPrefixNFS	"nfs:"
#define kNetBootRootPathPrefixHTTP	"http:"

typedef enum {
    kNetBootImageTypeUnknown = 0,
    kNetBootImageTypeNFS = 1,
    kNetBootImageTypeHTTP = 2,
} NetBootImageType;

struct netboot_info {
    struct in_addr	client_ip;
    struct in_addr	server_ip;
    char *		server_name;
    int			server_name_length;
    char *		mount_point;
    int			mount_point_length;
    char *		image_path;
    int			image_path_length;
    NetBootImageType	image_type;
    char *		second_image_path;
    int			second_image_path_length;
};

/*
 * Function: parse_booter_path
 * Purpose:
 *   Parse a string of the form:
 *        "<IP>:<host>:<mount>[:<image_path>]"
 *   into the given ip address, host, mount point, and optionally, image_path.
 *
 * Note:
 *   The passed in string is modified i.e. ':' is replaced by '\0'.
 * Example: 
 *   "17.202.16.17:seaport:/release/.images/Image9/CurrentHera"
 */
static __inline__ boolean_t
parse_booter_path(char * path, struct in_addr * iaddr_p, char const * * host,
		  char * * mount_dir, char * * image_path)
{
    char *	start;
    char *	colon;

    /* IP address */
    start = path;
    colon = strchr(start, ':');
    if (colon == NULL) {
	return (FALSE);
    }
    *colon = '\0';
    if (inet_aton(start, iaddr_p) != 1) {
	return (FALSE);
    }

    /* host */
    start = colon + 1;
    colon = strchr(start, ':');
    if (colon == NULL) {
	return (FALSE);
    }
    *colon = '\0';
    *host = start;

    /* mount */
    start = colon + 1;
    colon = strchr(start, ':');
    *mount_dir = start;
    if (colon == NULL) {
	*image_path = NULL;
    }
    else {
	/* image path */
	*colon = '\0';
	start = colon + 1;
	*image_path = start;
    }
    return (TRUE);
}

/*
 * Function: find_colon
 * Purpose:
 *   Find the next unescaped instance of the colon character.
 *   If a colon is escaped (preceded by a backslash '\' character),
 *   shift the string over by one character to overwrite the backslash.
 */
static __inline__ char *
find_colon(char * str)
{
    char * start = str;
    char * colon;
    
    while ((colon = strchr(start, ':')) != NULL) {
	char * dst;
	char * src;

	if (colon == start) {
	    break;
	}
	if (colon[-1] != '\\')
	    break;
	for (dst = colon - 1, src = colon; *dst != '\0'; dst++, src++) {
	    *dst = *src;
	}
	start = colon;
    }
    return (colon);
}

/*
 * Function: parse_netboot_path
 * Purpose:
 *   Parse a string of the form:
 *        "nfs:<IP>:<mount>[:<image_path>]"
 *   into the given ip address, host, mount point, and optionally, image_path.
 * Notes:
 * - the passed in string is modified i.e. ':' is replaced by '\0'
 * - literal colons must be escaped with a backslash
 *
 * Examples:
 * nfs:17.202.42.112:/Library/NetBoot/NetBootSP0:Jaguar/Jaguar.dmg
 * nfs:17.202.42.112:/Volumes/Foo\:/Library/NetBoot/NetBootSP0:Jaguar/Jaguar.dmg
 */
static __inline__ boolean_t
parse_netboot_path(char * path, struct in_addr * iaddr_p, char const * * host,
		   char * * mount_dir, char * * image_path)
{
    static char	tmp[MAX_IPv4_STR_LEN];	/* Danger - not thread safe */
    char *	start;
    char *	colon;

    if (strncmp(path, kNetBootRootPathPrefixNFS, 
		strlen(kNetBootRootPathPrefixNFS)) != 0) {
	return (FALSE);
    }

    /* IP address */
    start = path + strlen(kNetBootRootPathPrefixNFS);
    colon = strchr(start, ':');
    if (colon == NULL) {
	return (FALSE);
    }
    *colon = '\0';
    if (inet_aton(start, iaddr_p) != 1) {
	return (FALSE);
    }

    /* mount point */
    start = colon + 1;
    colon = find_colon(start);
    *mount_dir = start;
    if (colon == NULL) {
	*image_path = NULL;
    }
    else {
	/* image path */
	*colon = '\0';
	start = colon + 1;
	(void)find_colon(start);
	*image_path = start;
    }
    *host = inet_ntop(AF_INET, iaddr_p, tmp, sizeof(tmp));
    return (TRUE);
}

static boolean_t
parse_image_path(char * path, struct in_addr * iaddr_p, char const * * host,
		 char * * mount_dir, char * * image_path)
{
    if (path[0] >= '0' && path[0] <= '9') {
	return (parse_booter_path(path, iaddr_p, host, mount_dir,
				  image_path));
    }
    return (parse_netboot_path(path, iaddr_p, host, mount_dir,
			       image_path));
}

static boolean_t
get_root_path(char * root_path)
{
    void *		entry;
    boolean_t		found = FALSE;
    const void *	pkt;
    int			pkt_len;
    
    entry = IOBSDRegistryEntryForDeviceTree("/chosen");
    if (entry == NULL) {
	return (FALSE);
    }
    pkt = IOBSDRegistryEntryGetData(entry, BSDP_RESPONSE, &pkt_len);
    if (pkt != NULL && pkt_len >= (int)sizeof(struct dhcp)) {
	printf("netboot: retrieving root path from BSDP response\n");
    }
    else {
	pkt = IOBSDRegistryEntryGetData(entry, BOOTP_RESPONSE, 
					&pkt_len);
	if (pkt != NULL && pkt_len >= (int)sizeof(struct dhcp)) {
	    printf("netboot: retrieving root path from BOOTP response\n");
	}
    }
    if (pkt != NULL) {
	int			len;
	dhcpol_t 		options;
	const char *		path;
	const struct dhcp *	reply;

	reply = (const struct dhcp *)pkt;
	(void)dhcpol_parse_packet(&options, reply, pkt_len);

	path = (const char *)dhcpol_find(&options, 
					 dhcptag_root_path_e, &len, NULL);
	if (path) {
	    memcpy(root_path, path, len);
	    root_path[len] = '\0';
	    found = TRUE;
	}
    }
    IOBSDRegistryEntryRelease(entry);
    return (found);

}

static void
save_path(char * * str_p, int * length_p, char * path)
{
    *length_p = strlen(path) + 1;
    *str_p = (char *)kalloc(*length_p);
    strlcpy(*str_p, path, *length_p);
    return;
}

static struct netboot_info *
netboot_info_init(struct in_addr iaddr)
{
    boolean_t			have_root_path = FALSE;
    struct netboot_info *	info = NULL;
    char * 			root_path = NULL;

    info = (struct netboot_info *)kalloc(sizeof(*info));
    bzero(info, sizeof(*info));
    info->client_ip = iaddr;
    info->image_type = kNetBootImageTypeUnknown;

    /* check for a booter-specified path then a NetBoot path */
    MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
    if (root_path  == NULL)
    	panic("netboot_info_init: M_NAMEI zone exhausted");
    if (PE_parse_boot_argn("rp0", root_path, MAXPATHLEN) == TRUE
	|| PE_parse_boot_argn("rp", root_path, MAXPATHLEN) == TRUE
	|| PE_parse_boot_argn("rootpath", root_path, MAXPATHLEN) == TRUE) {
	if (imageboot_format_is_valid(root_path)) {
	    printf("netboot_info_init: rp0='%s' isn't a network path,"
		   " ignoring\n", root_path);
	}
	else {
	    have_root_path = TRUE;
	}
    }
    if (have_root_path == FALSE) {
	have_root_path = get_root_path(root_path);
    }
    if (have_root_path) {
	const char * server_name = NULL;
	char * mount_point = NULL;
	char * image_path = NULL;
	struct in_addr 	server_ip;

	if (parse_image_path(root_path, &server_ip, &server_name, 
			     &mount_point, &image_path)) {
	    info->image_type = kNetBootImageTypeNFS;
	    info->server_ip = server_ip;
	    info->server_name_length = strlen(server_name) + 1;
	    info->server_name = (char *)kalloc(info->server_name_length);
	    info->mount_point_length = strlen(mount_point) + 1;
	    info->mount_point = (char *)kalloc(info->mount_point_length);
	    strlcpy(info->server_name, server_name, info->server_name_length);
	    strlcpy(info->mount_point, mount_point, info->mount_point_length);
	    
	    printf("netboot: NFS Server %s Mount %s", 
		   server_name, info->mount_point);
	    if (image_path != NULL) {
		boolean_t 	needs_slash = FALSE;
		
		info->image_path_length = strlen(image_path) + 1;
		if (image_path[0] != '/') {
		    needs_slash = TRUE;
		    info->image_path_length++;
		}
		info->image_path = (char *)kalloc(info->image_path_length);
		if (needs_slash) {
			info->image_path[0] = '/';
			strlcpy(info->image_path + 1, image_path,
					info->image_path_length - 1);
		} else {
			strlcpy(info->image_path, image_path,
					info->image_path_length);
		}
		printf(" Image %s", info->image_path);
	    }
	    printf("\n");
	}
	else if (strncmp(root_path, kNetBootRootPathPrefixHTTP, 
			 strlen(kNetBootRootPathPrefixHTTP)) == 0) {
	    info->image_type = kNetBootImageTypeHTTP;
	    save_path(&info->image_path, &info->image_path_length,
		      root_path);
	    printf("netboot: HTTP URL %s\n",  info->image_path);
	}	    
	else {
	    printf("netboot: root path uses unrecognized format\n");
	}

	/* check for image-within-image */
	if (info->image_path != NULL) {
		if (PE_parse_boot_argn(IMAGEBOOT_ROOT_ARG, root_path, MAXPATHLEN)
			|| PE_parse_boot_argn("rp1", root_path, MAXPATHLEN)) {
			/* rp1/root-dmg is the second-level image */
			save_path(&info->second_image_path, &info->second_image_path_length, 
					root_path);
		}
	}
	if (info->second_image_path != NULL) {
		printf("netboot: nested image %s\n", info->second_image_path);
	}
    }
    FREE_ZONE(root_path, MAXPATHLEN, M_NAMEI);
    return (info);
}

static void 
netboot_info_free(struct netboot_info * * info_p)
{
    struct netboot_info * info = *info_p;

    if (info) {
	if (info->mount_point) {
	    kfree(info->mount_point, info->mount_point_length);
	}
	if (info->server_name) {
	    kfree(info->server_name, info->server_name_length);
	}
	if (info->image_path) {
	    kfree(info->image_path, info->image_path_length);
	}
	if (info->second_image_path) {
	    kfree(info->second_image_path, info->second_image_path_length);
	}
	kfree(info, sizeof(*info));
    }
    *info_p = NULL;
    return;
}

boolean_t
netboot_iaddr(struct in_addr * iaddr_p)
{
    if (S_netboot_info_p == NULL)
	return (FALSE);

    *iaddr_p = S_netboot_info_p->client_ip;
    return (TRUE);
}

boolean_t
netboot_rootpath(struct in_addr * server_ip,
		 char * name, int name_len, 
		 char * path, int path_len)
{
    if (S_netboot_info_p == NULL)
	return (FALSE);

    name[0] = '\0';
    path[0] = '\0';

    if (S_netboot_info_p->mount_point_length == 0) {
	return (FALSE);
    }
    if (path_len < S_netboot_info_p->mount_point_length) {
	printf("netboot: path too small %d < %d\n",
	       path_len, S_netboot_info_p->mount_point_length);
	return (FALSE);
    }
    strlcpy(path, S_netboot_info_p->mount_point, path_len);
    strlcpy(name, S_netboot_info_p->server_name, name_len);
    *server_ip = S_netboot_info_p->server_ip;
    return (TRUE);
}


static boolean_t
get_ip_parameters(struct in_addr * iaddr_p, struct in_addr * netmask_p, 
		   struct in_addr * router_p)
{
    void *		entry;
    const void *	pkt;
    int			pkt_len;


    entry = IOBSDRegistryEntryForDeviceTree("/chosen");
    if (entry == NULL) {
	return (FALSE);
    }
    pkt = IOBSDRegistryEntryGetData(entry, DHCP_RESPONSE, &pkt_len);
    if (pkt != NULL && pkt_len >= (int)sizeof(struct dhcp)) {
	printf("netboot: retrieving IP information from DHCP response\n");
    }
    else {
	pkt = IOBSDRegistryEntryGetData(entry, BOOTP_RESPONSE, &pkt_len);
	if (pkt != NULL && pkt_len >= (int)sizeof(struct dhcp)) {
	    printf("netboot: retrieving IP information from BOOTP response\n");
	}
    }
    if (pkt != NULL) {
	const struct in_addr *	ip;
	int			len;
	dhcpol_t 		options;
	const struct dhcp *	reply;

	reply = (const struct dhcp *)pkt;
	(void)dhcpol_parse_packet(&options, reply, pkt_len);
	*iaddr_p = reply->dp_yiaddr;
	ip = (const struct in_addr *)
	    dhcpol_find(&options, 
			dhcptag_subnet_mask_e, &len, NULL);
	if (ip) {
	    *netmask_p = *ip;
	}
	ip = (const struct in_addr *)
	    dhcpol_find(&options, dhcptag_router_e, &len, NULL);
	if (ip) {
	    *router_p = *ip;
	}
    }
    IOBSDRegistryEntryRelease(entry);
    return (pkt != NULL);
}

static int
route_cmd(int cmd, struct in_addr d, struct in_addr g, 
	  struct in_addr m, uint32_t more_flags, unsigned int ifscope)
{
    struct sockaddr_in 		dst;
    int				error;
    uint32_t			flags = RTF_UP | RTF_STATIC;
    struct sockaddr_in		gw;
    struct sockaddr_in		mask;
    
    flags |= more_flags;

    /* destination */
    bzero((caddr_t)&dst, sizeof(dst));
    dst.sin_len = sizeof(dst);
    dst.sin_family = AF_INET;
    dst.sin_addr = d;

    /* gateway */
    bzero((caddr_t)&gw, sizeof(gw));
    gw.sin_len = sizeof(gw);
    gw.sin_family = AF_INET;
    gw.sin_addr = g;

    /* mask */
    bzero(&mask, sizeof(mask));
    mask.sin_len = sizeof(mask);
    mask.sin_family = AF_INET;
    mask.sin_addr = m;

    error = rtrequest_scoped(cmd, (struct sockaddr *)&dst,
        (struct sockaddr *)&gw, (struct sockaddr *)&mask, flags, NULL, ifscope);

    return (error);

}

static int
default_route_add(struct in_addr router, boolean_t proxy_arp)
{
    uint32_t			flags = 0;
    struct in_addr		zeroes = { 0 };
    
    if (proxy_arp == FALSE) {
	flags |= RTF_GATEWAY;
    }
    return (route_cmd(RTM_ADD, zeroes, router, zeroes, flags, IFSCOPE_NONE));
}

static int
host_route_delete(struct in_addr host, unsigned int ifscope)
{
    struct in_addr		zeroes = { 0 };
    
    return (route_cmd(RTM_DELETE, host, zeroes, zeroes, RTF_HOST, ifscope));
}

static struct ifnet *
find_interface(void)
{
    struct ifnet *		ifp = NULL;

    dlil_if_lock();
    if (rootdevice[0]) {
		ifp = ifunit((char *)rootdevice);
    }
    if (ifp == NULL) {
		ifnet_head_lock_shared();
		TAILQ_FOREACH(ifp, &ifnet_head, if_link)
			if ((ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT)) == 0)
				break;
		ifnet_head_done();
    }
    dlil_if_unlock();
    return (ifp);
}

static const struct sockaddr_in blank_sin = {
    sizeof(struct sockaddr_in),
    AF_INET,
    0,
    { 0 },
    { 0, 0, 0, 0, 0, 0, 0, 0 }
};

static int
inet_aifaddr(struct socket * so, const char * name,
	     const struct in_addr * addr,
	     const struct in_addr * mask,
	     const struct in_addr * broadcast)
{
    struct ifaliasreq	ifra;

    bzero(&ifra, sizeof(ifra));
    strlcpy(ifra.ifra_name, name, sizeof(ifra.ifra_name));
    if (addr) {
	*((struct sockaddr_in *)(void *)&ifra.ifra_addr) = blank_sin;
	((struct sockaddr_in *)(void *)&ifra.ifra_addr)->sin_addr = *addr;
    }
    if (mask) {
	*((struct sockaddr_in *)(void *)&ifra.ifra_mask) = blank_sin;
	((struct sockaddr_in *)(void *)&ifra.ifra_mask)->sin_addr = *mask;
    }
    if (broadcast) {
	*((struct sockaddr_in *)(void *)&ifra.ifra_broadaddr) = blank_sin;
	((struct sockaddr_in *)(void *)&ifra.ifra_broadaddr)->sin_addr = *broadcast;
    }
    return (ifioctl(so, SIOCAIFADDR, (caddr_t)&ifra, current_proc()));
}


int
netboot_mountroot(void)
{
    int 			error = 0;
    struct in_addr 		iaddr = { 0 };
    struct ifreq 		ifr;
    struct ifnet *		ifp;
    struct in_addr		netmask = { 0 };
    proc_t			procp = current_proc();
    struct in_addr		router = { 0 };
    struct socket *		so = NULL;
    unsigned int		try;

    bzero(&ifr, sizeof(ifr));

    /* find the interface */
    ifp = find_interface();
    if (ifp == NULL) {
	printf("netboot: no suitable interface\n");
	error = ENXIO;
	goto failed;
    }
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", if_name(ifp));
    printf("netboot: using network interface '%s'\n", ifr.ifr_name);

    /* bring it up */
    if ((error = socreate(AF_INET, &so, SOCK_DGRAM, 0)) != 0) {
	printf("netboot: socreate, error=%d\n", error);
	goto failed;
    }
    ifr.ifr_flags = ifp->if_flags | IFF_UP;
    error = ifioctl(so, SIOCSIFFLAGS, (caddr_t)&ifr, procp);
    if (error) {
	printf("netboot: SIFFLAGS, error=%d\n", error);
	goto failed;
    }

    /* grab information from the registry */
    if (get_ip_parameters(&iaddr, &netmask, &router) == FALSE) {
	printf("netboot: can't retrieve IP parameters\n");
	goto failed;
    }
    printf("netboot: IP address " IP_FORMAT, IP_LIST(&iaddr));
    if (netmask.s_addr) {
	printf(" netmask " IP_FORMAT, IP_LIST(&netmask));
    }
    if (router.s_addr) {
	printf(" router " IP_FORMAT, IP_LIST(&router));
    }
    printf("\n");
    error = inet_aifaddr(so, ifr.ifr_name, &iaddr, &netmask, NULL);
    if (error) {
	printf("netboot: inet_aifaddr failed, %d\n", error);
	goto failed;
    }
    if (router.s_addr == 0) {
	/* enable proxy arp if we don't have a router */
	router.s_addr = iaddr.s_addr;
    }
    printf("netboot: adding default route " IP_FORMAT "\n", 
	   IP_LIST(&router));
    error = default_route_add(router, router.s_addr == iaddr.s_addr);
    if (error) {
	printf("netboot: default_route_add failed %d\n", error);
    }

    soclose(so);

    S_netboot_info_p = netboot_info_init(iaddr);
    switch (S_netboot_info_p->image_type) {
    default:
    case kNetBootImageTypeNFS:
	for (try = 1; TRUE; try++) {
	    error = nfs_mountroot();
	    if (error == 0) {
		break;
	    }
	    printf("netboot: nfs_mountroot() attempt %u failed; "
		   "clearing ARP entry and trying again\n", try);
	    /* 
	     * error is either EHOSTDOWN or EHOSTUNREACH, which likely means
	     * that the port we're plugged into has spanning tree enabled,
	     * and either the router or the server can't answer our ARP
	     * requests.  Clear the incomplete ARP entry by removing the
	     * appropriate route, depending on the error code:
	     *     EHOSTDOWN		NFS server's route
	     *     EHOSTUNREACH		router's route
	     */
	    switch (error) {
	    default:
		/* NOT REACHED */
	    case EHOSTDOWN:
		/* remove the server's arp entry */
		error = host_route_delete(S_netboot_info_p->server_ip,
					  ifp->if_index);
		if (error) {
		    printf("netboot: host_route_delete(" IP_FORMAT
			   ") failed %d\n", 
			   IP_LIST(&S_netboot_info_p->server_ip), error);
		}
		break;
	    case EHOSTUNREACH:
		error = host_route_delete(router, ifp->if_index);
		if (error) {
		    printf("netboot: host_route_delete(" IP_FORMAT
			   ") failed %d\n", IP_LIST(&router), error);
		}
		break;
	    }
	}
	break;
    case kNetBootImageTypeHTTP:
	error = netboot_setup();
	break;
    }
    if (error == 0) {
	S_netboot = 1;
    }
    else {
	S_netboot = 0;
    }
    return (error);
failed:
    if (so != NULL) {
	soclose(so);
    }
    return (error);
}

int
netboot_setup()
{
    int 	error = 0;

    if (S_netboot_info_p == NULL
	|| S_netboot_info_p->image_path == NULL) {
	goto done;
    }
    printf("netboot_setup: calling imageboot_mount_image\n");
    error = imageboot_mount_image(S_netboot_info_p->image_path, -1);
    if (error != 0) {
	printf("netboot: failed to mount root image, %d\n", error);
    }
    else if (S_netboot_info_p->second_image_path != NULL) {
	error = imageboot_mount_image(S_netboot_info_p->second_image_path, 0);
	if (error != 0) {
	    printf("netboot: failed to mount second root image, %d\n", error);
	}
    }

 done:
    netboot_info_free(&S_netboot_info_p);
    return (error);
}

int
netboot_root(void)
{
    return (S_netboot);
}
