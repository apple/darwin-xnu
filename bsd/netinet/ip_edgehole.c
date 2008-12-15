#include <sys/param.h>
#include <sys/proc.h>
#include <sys/kpi_mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <string.h>		// For bzero
#include <libkern/libkern.h> // for printf
#include <kern/debug.h> // For panic
#include <net/if.h>
#include <net/if_types.h>
#include <net/route.h>
#include <netinet/in.h>
#include <netinet/in_pcb.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_fsm.h>
#include <netinet/tcp_seq.h>
#include <netinet/tcp_timer.h>
#include <netinet/tcp_var.h>
#include <libkern/OSMalloc.h>
#include <libkern/OSAtomic.h>
#include <kern/thread_call.h>
#include "ip_edgehole.h"

enum
{
	kEdgeHoleFlag_BlockInternet	=	0x00000001,
	kEdgeHoleFlag_BlockVV		=	0x00000002
};

struct edgehole_tag
{
	// flags tells us whether or not we should block traffic
	u_int32_t			eh_flags;
	
	// These fields are used to help us find the PCB after we block traffic for TCP
	struct inpcbinfo	*eh_inpinfo;
	struct inpcb		*eh_inp;
};

struct edgehole_delayed_notify
{
	// flags tells us whether or not we should block traffic
	struct edgehole_delayed_notify	*next;
	
	// These fields are used to help us find the PCB after we block traffic for TCP
	struct inpcbinfo	*inpinfo;
	struct inpcb		*inp;
};

static mbuf_tag_id_t	edgehole_tag = 0;
static thread_call_t	edgehole_callout = NULL;
static OSMallocTag		edgehole_mtag = 0;
static struct edgehole_delayed_notify	*edgehole_delay_list = NULL;

#ifndef	HAS_COMPARE_AND_SWAP_PTR
// 64bit kernels have an OSCompareAndSwapPtr that does the right thing
static Boolean
OSCompareAndSwapPtr(
	void *oldValue,
	void *newValue,
	volatile void *address)
{
	return OSCompareAndSwap((UInt32)oldValue, (UInt32)newValue, (volatile UInt32*)address);
}
#endif

static void
ip_edgehole_notify_delayed(
	struct inpcb		*inp,
	struct inpcbinfo	*inpinfo)
{
	if (in_pcb_checkstate(inp, WNT_ACQUIRE, 0) != WNT_STOPUSING)
	{
		// We've found an inpcb for the packet we're dropping.
		struct socket	*so = inp->inp_socket;
		if (so && so != &inpinfo->nat_dummy_socket)
		{
			socket_lock(so, 1);
			if (in_pcb_checkstate(inp, WNT_RELEASE,1) != WNT_STOPUSING)
			{
				if (inp->inp_ip_p == IPPROTO_TCP)
				{
					// Why do we still have caddr_t? Come on! Casting from
					// caddr_t to something else causes "cast increases required alignment"
					// warnings. warnings are treated as failures. This union does the
					// exact same thing without the warning.
					union
					{
						caddr_t	caddrt_sucks;
						void	*void_ptr;
					} bite_me;
					
					bite_me.caddrt_sucks = inp->inp_ppcb;
					tcp_drop((struct tcpcb*)bite_me.void_ptr, EPERM);
				}
				else
				{
					// Is this enough?
					socantsendmore(so);
				}
			}
			socket_unlock(so, 1);
		}
	}
}

// Some shortcomings of this strategy:
// 1) an inpcb could be reused for a new socket before we get a chance to notify

static void
ip_edgehole_process_delayed(
	__unused void *unused1,
	__unused void *unused2)
{
	struct edgehole_delayed_notify	*head;
	
	while (edgehole_delay_list)
	{
		// Atomically grab the list
		do
		{
			head = edgehole_delay_list;
		}
		while (!OSCompareAndSwapPtr(head, NULL, &edgehole_delay_list));
		
		if (head == NULL)
		{
			break;
		}
		
		// Prune duplicates from the list
		struct edgehole_delayed_notify	*current;
		struct edgehole_delayed_notify	**current_p;
		struct edgehole_delayed_notify	*ye_dead;
		for (current = head; current && current->next; current = current->next)
		{
			current_p = &head;
			while (*current_p)
			{
				if ((*current_p)->inp == current->inp)
				{
					ye_dead = *current_p;
					*current_p = ye_dead->next;
					OSFree(ye_dead, sizeof(*ye_dead), edgehole_mtag);
				}
				else
				{
					current_p = &(*current_p)->next;
				}
			}
		}
		
		while (head)
		{
			struct inpcbinfo *lockedinfo;
			
			lockedinfo = head->inpinfo;
			
			// Lock the list
			lck_rw_lock_shared(lockedinfo->mtx);
			
			struct inpcb *inp;
			
			// Walk the inp list.
			LIST_FOREACH(inp, lockedinfo->listhead, inp_list)
			{
				// Walk the list of notifications
				for (current = head; current != NULL; current = current->next)
				{
					// Found a match, notify
					if (current->inpinfo == lockedinfo && current->inp == inp)
					{
						ip_edgehole_notify_delayed(inp, lockedinfo);
					}
				}
			}
			
			lck_rw_done(lockedinfo->mtx);
			
			// Release all the notifications for this inpcbinfo
			current_p = &head;
			while (*current_p)
			{
				// Free any items for this inpcbinfo
				if ((*current_p)->inpinfo == lockedinfo)
				{
					ye_dead = *current_p;
					*current_p = ye_dead->next;
					OSFree(ye_dead, sizeof(*ye_dead), edgehole_mtag);
				}
				else
				{
					current_p = &(*current_p)->next;
				}
			}
		}
	}
}

static void
ip_edgehole_notify(
	struct edgehole_tag	*tag)
{
	// Since the lock on the socket may be held while a packet is being transmitted,
	// we must allocate storage to keep track of this information and schedule a
	// thread to handle the work.
	
	if (tag->eh_inp == NULL || tag->eh_inpinfo == NULL)
		return;
	
	struct edgehole_delayed_notify	*delayed = OSMalloc(sizeof(*delayed), edgehole_mtag);
	if (delayed)
	{
		delayed->inp = tag->eh_inp;
		delayed->inpinfo = tag->eh_inpinfo;
		do
		{
			delayed->next = edgehole_delay_list;
		}
		while (!OSCompareAndSwapPtr(delayed->next, delayed, &edgehole_delay_list));
		
		thread_call_enter(edgehole_callout);
	}
}

__private_extern__ void
ip_edgehole_attach(
	struct inpcb	*inp)
{
	inp->inpcb_edgehole_flags = 0;
	inp->inpcb_edgehole_mask = 0;
	
	// TBD: call MAC framework to find out of we are allowed to use EDGE
#ifdef	TEST_THE_EVIL_EDGE_HOLE
	char	pidname[64];
	proc_selfname(pidname, sizeof(pidname));
	pidname[sizeof(pidname) -1] = 0;
	if (strcmp(pidname, "MobileSafari") == 0 ||
		strcmp(pidname, "ping") == 0)
	{
		inp->inpcb_edgehole_flags = kEdgeHoleFlag_BlockInternet;
		inp->inpcb_edgehole_mask = kEdgeHoleFlag_BlockInternet;
	}
#endif
	
	if (inp->inpcb_edgehole_mask != 0)
	{
		// Allocate a callout
		if (edgehole_callout == NULL)
		{
			thread_call_t tmp_callout = thread_call_allocate(ip_edgehole_process_delayed, NULL);
			if (!tmp_callout) panic("ip_edgehole_attach: thread_call_allocate failed");
			if (!OSCompareAndSwapPtr(NULL, tmp_callout, &edgehole_callout))
				thread_call_free(tmp_callout);
		}
		
		// Allocate a malloc tag
		if (edgehole_mtag == 0)
		{
			OSMallocTag	mtag = OSMalloc_Tagalloc("com.apple.ip_edgehole", 0);
			if (!mtag) panic("ip_edgehole_attach: OSMalloc_Tagalloc failed");
			if (!OSCompareAndSwapPtr(NULL, mtag, &edgehole_mtag))
				OSMalloc_Tagfree(mtag);
		}
	}
}

__private_extern__ void
ip_edgehole_mbuf_tag(
	struct inpcb	*inp,
	mbuf_t			m)
{
	// Immediately bail if there are no flags on this inpcb
	if (inp->inpcb_edgehole_mask == 0)
	{
		return;
	}
	
	// Allocate a tag_id if we don't have one already
	if (edgehole_tag == 0)
		mbuf_tag_id_find("com.apple.edgehole", &edgehole_tag);
	
	struct edgehole_tag	*tag;
	size_t	length;
	
	// Find an existing tag
	if (mbuf_tag_find(m, edgehole_tag, 0, &length, (void**)&tag) == 0)
	{
		if (length != sizeof(*tag))
			panic("ip_edgehole_mbuf_tag - existing tag is wrong size");
		
		// add restrictions
		tag->eh_flags = (tag->eh_flags & (~inp->inpcb_edgehole_mask)) |
						(inp->inpcb_edgehole_flags & inp->inpcb_edgehole_mask);
	}
	else if ((inp->inpcb_edgehole_mask & inp->inpcb_edgehole_flags) != 0)
	{
		// Add the tag
		if (mbuf_tag_allocate(m, edgehole_tag, 0, sizeof(*tag), MBUF_WAITOK, (void**)&tag) != 0)
			panic("ip_edgehole_mbuf_tag - mbuf_tag_allocate failed"); // ouch - how important is it that we block this stuff?
		
		tag->eh_flags = (inp->inpcb_edgehole_flags & inp->inpcb_edgehole_mask);
		tag->eh_inp = inp;
		tag->eh_inpinfo = inp->inp_pcbinfo;
	}
}

int
ip_edgehole_filter(
	mbuf_t			*m,
	__unused int	isVV)
{
	struct edgehole_tag	*tag;
	size_t	length;
	
	if (mbuf_tag_find(*m, edgehole_tag, 0, &length, (void**)&tag) == 0)
	{
		if (length != sizeof(*tag))
			panic("ip_edgehole_filter - existing tag is wrong size");
		
		if ((tag->eh_flags & kEdgeHoleFlag_BlockInternet) != 0)
		{
			ip_edgehole_notify(tag);
			
			mbuf_freem(*m); *m = NULL;
			return EPERM;
		}
	}
	
	return 0;
}
