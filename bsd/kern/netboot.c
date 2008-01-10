/*
 * Copyright (c) 2001-2004 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
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
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/dhcp_options.h>
#include <pexpert/pexpert.h>

#include <kern/kern_types.h>
#include <kern/kalloc.h>

//#include <libkern/libkern.h>
extern struct filedesc 	filedesc0;

extern int	strncmp(const char *,const char *, size_t);
extern unsigned long strtoul(const char *, char **, int);
extern char *	strchr(const char *str, int ch);

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

extern int vndevice_root_image(const char * path, char devname[], 
			       dev_t * dev_p);
extern int di_root_image(const char *path, char devname[], dev_t *dev_p);

#define BOOTP_RESPONSE	"bootp-response"
#define BSDP_RESPONSE	"bsdp-response"
#define DHCP_RESPONSE	"dhcp-response"

extern int 
bootp(struct ifnet * ifp, struct in_addr * iaddr_p, int max_retry,
      struct in_addr * netmask_p, struct in_addr * router_p,
      struct proc * procp);


/* forward declarations */
int	inet_aton(char * cp, struct in_addr * pin);

boolean_t	netboot_iaddr(struct in_addr * iaddr_p);
boolean_t	netboot_rootpath(struct in_addr * server_ip,
				 char * name, int name_len, 
				 char * path, int path_len);
int	netboot_setup(struct proc * p);
int	netboot_mountroot(void);
int	netboot_root(void);



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
    boolean_t		use_hdix;
};

int
inet_aton(char * cp, struct in_addr * pin)
{
    u_char * b = (char *)pin;
    int	   i;
    char * p;

    for (p = cp, i = 0; i < 4; i++) {
	u_long l = strtoul(p, 0, 0);
	if (l > 255)
	    return (FALSE);
	b[i] = l;
	p = strchr(p, '.');
	if (i < 3 && p == NULL)
	    return (FALSE);
	p++;
    }
    return (TRUE);
}

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
parse_booter_path(char * path, struct in_addr * iaddr_p, char * * host,
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
parse_netboot_path(char * path, struct in_addr * iaddr_p, char * * host,
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
parse_image_path(char * path, struct in_addr * iaddr_p, char * * host,
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
	char *			path;
	struct dhcp *		reply;

	reply = (struct dhcp *)pkt;
	(void)dhcpol_parse_packet(&options, reply, pkt_len, NULL);

	path = (char *)dhcpol_find(&options, 
				   dhcptag_root_path_e, &len, NULL);
	if (path) {
	    bcopy(path, root_path, len);
	    root_path[len] = '\0';
	    found = TRUE;
	}
    }
    IOBSDRegistryEntryRelease(entry);
    return (found);

}

static struct netboot_info *
netboot_info_init(struct in_addr iaddr)
{
    struct netboot_info *	info;
    char * 			root_path = NULL;
    boolean_t			use_hdix = TRUE;
    char *			vndevice = NULL;

    MALLOC_ZONE(vndevice, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
    if (vndevice == NULL)
    	panic("netboot_info_init: M_NAMEI zone exhausted");
    if (PE_parse_boot_arg("vndevice", vndevice) == TRUE) {
	use_hdix = FALSE;
    }
    FREE_ZONE(vndevice, MAXPATHLEN, M_NAMEI);

    info = (struct netboot_info *)kalloc(sizeof(*info));
    bzero(info, sizeof(*info));
    info->client_ip = iaddr;
    info->image_type = kNetBootImageTypeUnknown;
    info->use_hdix = use_hdix;

    /* check for a booter-specified path then a NetBoot path */
    MALLOC_ZONE(root_path, caddr_t, MAXPATHLEN, M_NAMEI, M_WAITOK);
    if (root_path  == NULL)
    	panic("netboot_info_init: M_NAMEI zone exhausted");
    if (PE_parse_boot_arg("rp", root_path) == TRUE
	|| PE_parse_boot_arg("rootpath", root_path) == TRUE
	|| get_root_path(root_path) == TRUE) {
	char * server_name = NULL;
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
	    strcpy(info->server_name, server_name);
	    strcpy(info->mount_point, mount_point);
	    
	    printf("Server %s Mount %s", 
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
		    strcpy(info->image_path + 1, image_path);
		}
		else {
		    strcpy(info->image_path, image_path);
		}
		printf(" Image %s", info->image_path);
	    }
	    printf("\n");
	}
	else if (strncmp(root_path, kNetBootRootPathPrefixHTTP, 
			 strlen(kNetBootRootPathPrefixHTTP)) == 0) {
	    /* only HDIX supports HTTP */
	    info->image_type = kNetBootImageTypeHTTP;
	    info->use_hdix = TRUE;
	    info->image_path_length = strlen(root_path) + 1;
	    info->image_path = (char *)kalloc(info->image_path_length);
	    strcpy(info->image_path, root_path);
	}	    
	else {
	    printf("netboot: root path uses unrecognized format\n");
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
    strcpy(path, S_netboot_info_p->mount_point);
    strncpy(name, S_netboot_info_p->server_name, name_len);
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
	struct in_addr *	ip;
	int			len;
	dhcpol_t 		options;
	struct dhcp *		reply;

	reply = (struct dhcp *)pkt;
	(void)dhcpol_parse_packet(&options, reply, pkt_len, NULL);
	*iaddr_p = reply->dp_yiaddr;
	ip = (struct in_addr *)
	    dhcpol_find(&options, 
			dhcptag_subnet_mask_e, &len, NULL);
	if (ip) {
	    *netmask_p = *ip;
	}
	ip = (struct in_addr *)
	    dhcpol_find(&options, dhcptag_router_e, &len, NULL);
	if (ip) {
	    *router_p = *ip;
	}
    }
    IOBSDRegistryEntryRelease(entry);
    return (pkt != NULL);
}

static int
inet_aifaddr(struct socket * so, char * name, const struct in_addr * addr, 
	     const struct in_addr * mask,
	     const struct in_addr * broadcast)
{
    struct sockaddr	blank_sin;
    struct ifaliasreq	ifra;

    bzero(&blank_sin, sizeof(blank_sin));
    blank_sin.sa_len = sizeof(blank_sin);
    blank_sin.sa_family = AF_INET;

    bzero(&ifra, sizeof(ifra));
    strncpy(ifra.ifra_name, name, sizeof(ifra.ifra_name));
    if (addr) {
	ifra.ifra_addr = blank_sin;
	((struct sockaddr_in *)&ifra.ifra_addr)->sin_addr = *addr;
    }
    if (mask) {
	ifra.ifra_mask = blank_sin;
	((struct sockaddr_in *)&ifra.ifra_mask)->sin_addr = *mask;
    }
    if (broadcast) {
	ifra.ifra_broadaddr = blank_sin;
	((struct sockaddr_in *)&ifra.ifra_broadaddr)->sin_addr = *broadcast;
    }
    return (ifioctl(so, SIOCAIFADDR, (caddr_t)&ifra, current_proc()));
}

static int
route_cmd(int cmd, struct in_addr d, struct in_addr g, 
	  struct in_addr m, u_long more_flags)
{
    struct sockaddr_in 		dst;
    u_long			flags = RTF_UP | RTF_STATIC;
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

    return (rtrequest(cmd, (struct sockaddr *)&dst, (struct sockaddr *)&gw,
		      (struct sockaddr *)&mask, flags, NULL));
}

static int
default_route_add(struct in_addr router, boolean_t proxy_arp)
{
    u_long			flags = 0;
    struct in_addr		zeroes = { 0 };
    
    if (proxy_arp == FALSE) {
	flags |= RTF_GATEWAY;
    }
    return (route_cmd(RTM_ADD, zeroes, router, zeroes, flags));
}

static int
host_route_delete(struct in_addr host)
{
    struct in_addr		zeroes = { 0 };
    
    return (route_cmd(RTM_DELETE, host, zeroes, zeroes, RTF_HOST));
}

static struct ifnet *
find_interface(void)
{
    struct ifnet *		ifp = NULL;

    if (rootdevice[0]) {
		ifp = ifunit(rootdevice);
    }
    if (ifp == NULL) {
		ifnet_head_lock_shared();
		TAILQ_FOREACH(ifp, &ifnet_head, if_link)
			if ((ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT)) == 0)
				break;
		ifnet_head_done();
    }
    return (ifp);
}

int
netboot_mountroot(void)
{
    int 			error = 0;
    struct in_addr 		iaddr = { 0 };
    struct ifreq 		ifr;
    struct ifnet *		ifp;
    struct in_addr		netmask = { 0 };
    struct proc *		procp = current_proc();
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
    sprintf(ifr.ifr_name, "%s%d", ifp->if_name, ifp->if_unit);
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
	/* use BOOTP to retrieve IP address, netmask and router */
	error = bootp(ifp, &iaddr, 32, &netmask, &router, procp);
	if (error) {
	    printf("netboot: BOOTP failed %d\n", error);
	    goto failed;
	}
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
		error = host_route_delete(S_netboot_info_p->server_ip);
		if (error) {
		    printf("netboot: host_route_delete(" IP_FORMAT
			   ") failed %d\n", 
			   IP_LIST(&S_netboot_info_p->server_ip), error);
		}
		break;
	    case EHOSTUNREACH:
		error = host_route_delete(router);
		if (error) {
		    printf("netboot: host_route_delete(" IP_FORMAT
			   ") failed %d\n", IP_LIST(&router), error);
		}
		break;
	    }
	}
	break;
    case kNetBootImageTypeHTTP:
	error = netboot_setup(procp);
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
netboot_setup(struct proc * p)
{
    dev_t 	dev;
    int 	error = 0;

    if (S_netboot_info_p == NULL
	|| S_netboot_info_p->image_path == NULL) {
	goto done;
    }
    if (S_netboot_info_p->use_hdix) {
	printf("netboot_setup: calling di_root_image\n");
	error = di_root_image(S_netboot_info_p->image_path, 
			      rootdevice, &dev);
	if (error) {
	    printf("netboot_setup: di_root_image: failed %d\n", error);
	    goto done;
	}
    }
    else {
	printf("netboot_setup: calling vndevice_root_image\n");
	error = vndevice_root_image(S_netboot_info_p->image_path, 
				    rootdevice, &dev);
	if (error) {
	    printf("netboot_setup: vndevice_root_image: failed %d\n", error);
	    goto done;
	}
    }
    rootdev = dev;
    mountroot = NULL;
    printf("netboot: root device 0x%x\n", rootdev);
    error = vfs_mountroot();
    if (error == 0 && rootvnode != NULL) {
        struct vnode *tvp;
        struct vnode *newdp;
	struct vfs_context context;

	context.vc_proc = p;
	context.vc_ucred = kauth_cred_proc_ref(p);	/* XXX kauth_cred_get() ??? proxy */

	/* Get the vnode for '/'.  Set fdp->fd_fd.fd_cdir to reference it. */
	if (VFS_ROOT(mountlist.tqh_last, &newdp, &context))
		panic("netboot_setup: cannot find root vnode");
	vnode_ref(newdp);
	vnode_put(newdp);
	tvp = rootvnode;
	vnode_rele(tvp);
	filedesc0.fd_cdir = newdp;
	rootvnode = newdp;
	mount_list_lock();
	TAILQ_REMOVE(&mountlist, TAILQ_FIRST(&mountlist), mnt_list);
	mount_list_unlock();
	mountlist.tqh_first->mnt_flag |= MNT_ROOTFS;
	kauth_cred_unref(&context.vc_ucred);
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
