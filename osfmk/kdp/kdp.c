/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <kern/debug.h>

#include <kdp/kdp_internal.h>
#include <kdp/kdp_private.h>

#include <libsa/types.h>

#include <string.h> /* bcopy */

int kdp_vm_read( caddr_t, caddr_t, unsigned int);
int kdp_vm_write( caddr_t, caddr_t, unsigned int);

#define DO_ALIGN	1	/* align all packet data accesses */

#define KDP_TEST_HARNESS 0
#if KDP_TEST_HARNESS 
#define dprintf(x) kprintf x 
#else
#define dprintf(x)
#endif

static kdp_dispatch_t
    dispatch_table[KDP_HOSTREBOOT - KDP_CONNECT +1] =
    {
/* 0 */	kdp_connect,
/* 1 */	kdp_disconnect,
/* 2 */	kdp_hostinfo,
/* 3 */	kdp_version,
/* 4 */	kdp_maxbytes,
/* 5 */	kdp_readmem,
/* 6 */	kdp_writemem,
/* 7 */	kdp_readregs,
/* 8 */	kdp_writeregs,
/* 9 */ kdp_unknown,
/* A */ kdp_unknown,
/* B */	kdp_suspend,
/* C */	kdp_resumecpus,
/* D */	kdp_unknown,
/* E */ kdp_unknown,
/* F */ kdp_breakpoint_set,
/*10 */ kdp_breakpoint_remove,
/*11 */	kdp_regions,
/*12 */ kdp_reattach,
/*13 */ kdp_reboot
    };
    
kdp_glob_t	kdp;


#define MAX_BREAKPOINTS 100
#define KDP_MAX_BREAKPOINTS 100

#define BREAKPOINT_NOT_FOUND 101
#define BREAKPOINT_ALREADY_SET 102

#define KDP_VERSION 10

typedef struct{
  unsigned int address;
  unsigned int old_instruction;
} kdp_breakpoint_record_t;

static kdp_breakpoint_record_t breakpoint_list[MAX_BREAKPOINTS];
static unsigned int breakpoints_initialized = 0;

int reattach_wait = 0;
int noresume_on_disconnect = 0;

boolean_t
kdp_packet(
    unsigned char	*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    static unsigned	aligned_pkt[1538/sizeof(unsigned)+1]; // max ether pkt
    kdp_pkt_t		*rd = (kdp_pkt_t *)&aligned_pkt;
    int			plen = *len;
    unsigned int	req;
    boolean_t		ret;
    
#if DO_ALIGN
    bcopy((char *)pkt, (char *)rd, sizeof(aligned_pkt));
#else
    rd = (kdp_pkt_t *)pkt;
#endif
    if (plen < sizeof (rd->hdr) || rd->hdr.len != plen) {
	printf("kdp_packet bad len pkt %d hdr %d\n", plen, rd->hdr.len);

	return (FALSE);
    }
    
    if (rd->hdr.is_reply) {
	printf("kdp_packet reply recvd req %x seq %x\n",
	    rd->hdr.request, rd->hdr.seq);

	return (FALSE);  
    }
    
    req = rd->hdr.request;
    if ((req < KDP_CONNECT) || (req > KDP_HOSTREBOOT)) {
	printf("kdp_packet bad request %x len %d seq %x key %x\n",
	    rd->hdr.request, rd->hdr.len, rd->hdr.seq, rd->hdr.key);

	return (FALSE);
    }
    
    ret = ((*dispatch_table[req - KDP_CONNECT])(rd, len, reply_port));
#if DO_ALIGN
    bcopy((char *)rd, (char *) pkt, *len);
#endif
    return ret;
}

static boolean_t
kdp_unknown(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_pkt_t		*rd = (kdp_pkt_t *)pkt;

    printf("kdp_unknown request %x len %d seq %x key %x\n",
	rd->hdr.request, rd->hdr.len, rd->hdr.seq, rd->hdr.key);

    return (FALSE);
}

static boolean_t
kdp_connect(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_connect_req_t	*rq = &pkt->connect_req;
    int			plen = *len;
    kdp_connect_reply_t	*rp = &pkt->connect_reply;

    if (plen < sizeof (*rq))
	return (FALSE);

    dprintf(("kdp_connect seq %x greeting %s\n", rq->hdr.seq, rq->greeting));

    if (kdp.is_conn) {
	if (rq->hdr.seq == kdp.conn_seq)	/* duplicate request */
	    rp->error = KDPERR_NO_ERROR;
	else
	    rp->error = KDPERR_ALREADY_CONNECTED;
    }
    else { 
	kdp.reply_port = rq->req_reply_port;
	kdp.exception_port = rq->exc_note_port;
	kdp.is_conn = TRUE;
	kdp.conn_seq = rq->hdr.seq;
    
	rp->error = KDPERR_NO_ERROR;
    }

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
    
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    if (current_debugger == KDP_CUR_DB)    
    	active_debugger=1;

    return (TRUE);
}

static boolean_t
kdp_disconnect(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_disconnect_req_t	*rq = &pkt->disconnect_req;
    int				plen = *len;
    kdp_disconnect_reply_t	*rp = &pkt->disconnect_reply;

    if (plen < sizeof (*rq))
	return (FALSE);
	
    if (!kdp.is_conn)
	return (FALSE);

    dprintf(("kdp_disconnect\n"));
 
    *reply_port = kdp.reply_port;

    kdp.reply_port = kdp.exception_port = 0;
    kdp.is_halted = kdp.is_conn = FALSE;
    kdp.exception_seq = kdp.conn_seq = 0;

    if (noresume_on_disconnect == 1) {
	reattach_wait = 1;
	noresume_on_disconnect = 0;
    }

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
    
    *len = rp->hdr.len;
    
    if (current_debugger == KDP_CUR_DB)
    	active_debugger=0;

    return (TRUE);
}

static boolean_t
kdp_reattach(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
  kdp_reattach_req_t            *rq = &pkt->reattach_req;
  kdp_disconnect_reply_t	*rp = &pkt->disconnect_reply;

  kdp.is_conn = TRUE;
  kdp_disconnect(pkt, len, reply_port);
  *reply_port = rq->req_reply_port;
  reattach_wait = 1;
  return (TRUE);
}

static boolean_t
kdp_hostinfo(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_hostinfo_req_t	*rq = &pkt->hostinfo_req;
    int			plen = *len;
    kdp_hostinfo_reply_t *rp = &pkt->hostinfo_reply;

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    kdp_machine_hostinfo(&rp->hostinfo);

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_suspend(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_suspend_req_t	*rq = &pkt->suspend_req;
    int			plen = *len;
    kdp_suspend_reply_t *rp = &pkt->suspend_reply;

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    dprintf(("kdp_suspend\n"));

    kdp.is_halted = TRUE;
    
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_resumecpus(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_resumecpus_req_t	*rq = &pkt->resumecpus_req;
    int			plen = *len;
    kdp_resumecpus_reply_t 	*rp = &pkt->resumecpus_reply;

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    dprintf(("kdp_resumecpus %x\n", rq->cpu_mask));
    
    kdp.is_halted = FALSE;
    
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_writemem(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_writemem_req_t	*rq = &pkt->writemem_req;
    int			plen = *len;
    kdp_writemem_reply_t *rp = &pkt->writemem_reply;
    int 		cnt;

    if (plen < sizeof (*rq))
	return (FALSE);

    if (rq->nbytes > MAX_KDP_DATA_SIZE)
	rp->error = KDPERR_BAD_NBYTES;
    else {
	dprintf(("kdp_writemem addr %x size %d\n", rq->address, rq->nbytes));

	cnt = kdp_vm_write((caddr_t)rq->data, (caddr_t)rq->address, rq->nbytes);
	rp->error = KDPERR_NO_ERROR;
    }

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_readmem(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_readmem_req_t	*rq = &pkt->readmem_req;
    int			plen = *len;
    kdp_readmem_reply_t *rp = &pkt->readmem_reply;
    int			cnt;

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    if (rq->nbytes > MAX_KDP_DATA_SIZE)
	rp->error = KDPERR_BAD_NBYTES;
    else {
	unsigned int	n = rq->nbytes;

	dprintf(("kdp_readmem addr %x size %d\n", rq->address, rq->nbytes));

	cnt = kdp_vm_read((caddr_t)rq->address, (caddr_t)rp->data, rq->nbytes);
	rp->error = KDPERR_NO_ERROR;

	rp->hdr.len += cnt;
    }

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_maxbytes(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_maxbytes_req_t	*rq = &pkt->maxbytes_req;
    int			plen = *len;
    kdp_maxbytes_reply_t *rp = &pkt->maxbytes_reply;

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    dprintf(("kdp_maxbytes\n"));

    rp->max_bytes = MAX_KDP_DATA_SIZE;

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_version(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_version_req_t	*rq = &pkt->version_req;
    int			plen = *len;
    kdp_version_reply_t *rp = &pkt->version_reply;
    kdp_region_t	*r;	

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    dprintf(("kdp_version\n"));

    rp->version = KDP_VERSION;
#ifdef	__ppc__
    if (!(kdp_flag & KDP_BP_DIS))
      rp->feature = KDP_FEATURE_BP;
    else
      rp->feature = 0;
#else
    rp->feature = 0;
#endif

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_regions(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_regions_req_t	*rq = &pkt->regions_req;
    int			plen = *len;
    kdp_regions_reply_t *rp = &pkt->regions_reply;
    kdp_region_t	*r;	

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    dprintf(("kdp_regions\n"));

    r = rp->regions;
    rp->nregions = 0;

    (vm_offset_t)r->address = 0;
    r->nbytes = 0xffffffff;

    r->protection = VM_PROT_ALL; r++; rp->nregions++;
    
    rp->hdr.len += rp->nregions * sizeof (kdp_region_t);
    
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_writeregs(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_writeregs_req_t	*rq = &pkt->writeregs_req;
    int			plen = *len;
    int			size;
    kdp_writeregs_reply_t *rp = &pkt->writeregs_reply;

    if (plen < sizeof (*rq))
	return (FALSE);
    
    size = rq->hdr.len - sizeof(kdp_hdr_t) - sizeof(unsigned int);
    rp->error = kdp_machine_write_regs(rq->cpu, rq->flavor, rq->data, &size);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
    
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_readregs(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    kdp_readregs_req_t	*rq = &pkt->readregs_req;
    int			plen = *len;
    kdp_readregs_reply_t *rp = &pkt->readregs_reply;
    int			size;

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
    
    rp->error = kdp_machine_read_regs(rq->cpu, rq->flavor, rp->data, &size);
    rp->hdr.len += size;
    
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t 
kdp_breakpoint_set(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
  kdp_breakpoint_req_t	*rq = &pkt->breakpoint_req;
  kdp_breakpoint_reply_t *rp = &pkt->breakpoint_reply;
  int			plen = *len;
  int                   cnt, i;
  unsigned int          old_instruction = 0;
  unsigned int breakinstr = kdp_ml_get_breakinsn();

  if(breakpoints_initialized == 0)
    {
      for(i=0;(i < MAX_BREAKPOINTS); breakpoint_list[i].address=0, i++);
      breakpoints_initialized++;
    }
  if (plen < sizeof (*rq))
    return (FALSE);
  cnt = kdp_vm_read((caddr_t)rq->address, (caddr_t)(&old_instruction), sizeof(int));

  if (old_instruction==breakinstr)
    {
      printf("A trap was already set at that address, not setting new breakpoint\n");
      rp->error = BREAKPOINT_ALREADY_SET;
      
      rp->hdr.is_reply = 1;
      rp->hdr.len = sizeof (*rp);
      *reply_port = kdp.reply_port;
      *len = rp->hdr.len;

      return (TRUE);
    }

  for(i=0;(i < MAX_BREAKPOINTS) && (breakpoint_list[i].address != 0); i++);

  if (i == MAX_BREAKPOINTS)
    {
      rp->error = KDP_MAX_BREAKPOINTS; 
      
      rp->hdr.is_reply = 1;
      rp->hdr.len = sizeof (*rp);
      *reply_port = kdp.reply_port;
      *len = rp->hdr.len;

      return (TRUE);
    }
  breakpoint_list[i].address =  rq->address;
  breakpoint_list[i].old_instruction = old_instruction;

  cnt = kdp_vm_write((caddr_t)&breakinstr, (caddr_t)rq->address, sizeof(&breakinstr));

  rp->error = KDPERR_NO_ERROR;
  rp->hdr.is_reply = 1;
  rp->hdr.len = sizeof (*rp);
  *reply_port = kdp.reply_port;
  *len = rp->hdr.len;

  return (TRUE);
}

static boolean_t
kdp_breakpoint_remove(
    kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
  kdp_breakpoint_req_t	*rq = &pkt->breakpoint_req;
  kdp_breakpoint_reply_t *rp = &pkt->breakpoint_reply;
  int			plen = *len;
  int                   cnt,i;

  if (plen < sizeof (*rq))
    return (FALSE);

  for(i=0;(i < MAX_BREAKPOINTS) && (breakpoint_list[i].address != rq->address); i++);
  if (i == MAX_BREAKPOINTS)
    {
      rp->error = BREAKPOINT_NOT_FOUND; 
      rp->hdr.is_reply = 1;
      rp->hdr.len = sizeof (*rp);
      *reply_port = kdp.reply_port;
      *len = rp->hdr.len;

      return (TRUE); /* Check if it needs to be FALSE in case of error */
    }

  breakpoint_list[i].address = 0;
  cnt = kdp_vm_write((caddr_t)&(breakpoint_list[i].old_instruction), (caddr_t)rq->address, sizeof(int));
  rp->error = KDPERR_NO_ERROR;
  rp->hdr.is_reply = 1;
  rp->hdr.len = sizeof (*rp);
  *reply_port = kdp.reply_port;
  *len = rp->hdr.len;

  return (TRUE);
}

boolean_t
kdp_remove_all_breakpoints()
{
  int i;
  boolean_t breakpoint_found = FALSE;
  
  if (breakpoints_initialized)
    {
      for(i=0;i < MAX_BREAKPOINTS; i++)
	{
	  if (breakpoint_list[i].address)
	    {
	      kdp_vm_write((caddr_t)&(breakpoint_list[i].old_instruction), (caddr_t)breakpoint_list[i].address, sizeof(int));
	      breakpoint_found = TRUE;
	      breakpoint_list[i].address = 0;
	    }
	}
      if (breakpoint_found)
       printf("kdp_remove_all_breakpoints: found extant breakpoints, removing them.\n");
    }
  return breakpoint_found;
}
