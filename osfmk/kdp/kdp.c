/*
 * Copyright (c) 2000-2007 Apple Computer, Inc. All rights reserved.
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

#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <sys/appleapiopts.h>
#include <kern/debug.h>
#include <uuid/uuid.h>

#include <kdp/kdp_internal.h>
#include <kdp/kdp_private.h>
#include <kdp/kdp_core.h>
#include <kdp/kdp_dyld.h>

#include <libsa/types.h>
#include <libkern/version.h>

#include <string.h> /* bcopy */

#include <kern/processor.h>
#include <kern/thread.h>
#include <kern/clock.h>
#include <vm/vm_map.h>
#include <vm/vm_kern.h>
#include <vm/vm_pageout.h>

extern int count_busy_buffers(void);   /* must track with declaration in bsd/sys/buf_internal.h */

#define DO_ALIGN	1	/* align all packet data accesses */

#define KDP_TEST_HARNESS 0
#if KDP_TEST_HARNESS 
#define dprintf(x) kprintf x 
#else
#define dprintf(x)
#endif

static kdp_dispatch_t
    dispatch_table[KDP_INVALID_REQUEST-KDP_CONNECT] =
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
/*13 */ kdp_reboot,
/*14 */ kdp_readmem64,
/*15 */ kdp_writemem64,
/*16 */ kdp_breakpoint64_set,
/*17 */ kdp_breakpoint64_remove,
/*18 */ kdp_kernelversion,
/*19 */ kdp_readphysmem64,
/*1A */ kdp_writephysmem64,
/*1B */ kdp_readioport,
/*1C */ kdp_writeioport,
/*1D */ kdp_readmsr64,
/*1E */ kdp_writemsr64,
/*1F */ kdp_dumpinfo,
    };
    
kdp_glob_t	kdp;

#define MAX_BREAKPOINTS 100

/*
 * Version 11 of the KDP Protocol adds support for 64-bit wide memory
 * addresses (read/write and breakpoints) as well as a dedicated
 * kernelversion request. Version 12 adds read/writing of physical
 * memory with 64-bit wide memory addresses. 
 */
#define KDP_VERSION 12

typedef struct{
	mach_vm_address_t	address;
	uint32_t	bytesused;
	uint8_t		oldbytes[MAX_BREAKINSN_BYTES];
} kdp_breakpoint_record_t;

static kdp_breakpoint_record_t breakpoint_list[MAX_BREAKPOINTS];
static unsigned int breakpoints_initialized = 0;

int reattach_wait = 0;
int noresume_on_disconnect = 0;
extern unsigned int return_on_panic;

typedef struct thread_snapshot *thread_snapshot_t;
typedef struct task_snapshot *task_snapshot_t;

extern int
machine_trace_thread(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);
extern int
machine_trace_thread64(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);
extern int
proc_pid(void *p);
extern void
proc_name_kdp(task_t  task, char *buf, int size);

extern void
kdp_snapshot_postflight(void);

static int
pid_from_task(task_t task);

kdp_error_t
kdp_set_breakpoint_internal(
							   mach_vm_address_t	address
							   );

kdp_error_t
kdp_remove_breakpoint_internal(
							   mach_vm_address_t	address
							   );


int
kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size, uint32_t trace_flags, uint32_t dispatch_offset, uint32_t *pbytesTraced);

boolean_t kdp_copyin(pmap_t, uint64_t, void *, size_t);
extern void bcopy_phys(addr64_t, addr64_t, vm_size_t);

boolean_t
kdp_packet(
    unsigned char	*pkt,
    int			*len,
    unsigned short	*reply_port
)
{
    static unsigned	aligned_pkt[1538/sizeof(unsigned)+1]; // max ether pkt
    kdp_pkt_t		*rd = (kdp_pkt_t *)&aligned_pkt;
    size_t		plen = *len;
    kdp_req_t		req;
    boolean_t		ret;
    
#if DO_ALIGN
    bcopy((char *)pkt, (char *)rd, sizeof(aligned_pkt));
#else
    rd = (kdp_pkt_t *)pkt;
#endif
    if (plen < sizeof (rd->hdr) || rd->hdr.len != plen) {
	printf("kdp_packet bad len pkt %lu hdr %d\n", plen, rd->hdr.len);

	return (FALSE);
    }
    
    if (rd->hdr.is_reply) {
	printf("kdp_packet reply recvd req %x seq %x\n",
	    rd->hdr.request, rd->hdr.seq);

	return (FALSE);  
    }
    
    req = rd->hdr.request;
    if (req >= KDP_INVALID_REQUEST) {
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
    __unused int	*len,
    __unused unsigned short	*reply_port
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
    size_t		plen = *len;
    kdp_connect_reply_t	*rp = &pkt->connect_reply;
    uint16_t            rport, eport;
    uint32_t            key;
    uint8_t             seq;

    if (plen < sizeof (*rq))
	return (FALSE);

    dprintf(("kdp_connect seq %x greeting %s\n", rq->hdr.seq, rq->greeting));

    rport = rq->req_reply_port;
    eport = rq->exc_note_port;
    key   = rq->hdr.key;
    seq   = rq->hdr.seq;
    if (kdp.is_conn) {
	if ((seq == kdp.conn_seq) &&	/* duplicate request */
            (rport == kdp.reply_port) &&
            (eport == kdp.exception_port) &&
            (key == kdp.session_key))
	    rp->error = KDPERR_NO_ERROR;
	else 
	    rp->error = KDPERR_ALREADY_CONNECTED;
    }
    else { 
	    kdp.reply_port     = rport;
	    kdp.exception_port = eport;
	    kdp.is_conn        = TRUE;
	    kdp.conn_seq       = seq;
        kdp.session_key    = key;

	rp->error = KDPERR_NO_ERROR;
    }

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
    
    *reply_port = rport;
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
    size_t			plen = *len;
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
    kdp.session_key = 0;

    if ((panicstr != NULL) && (return_on_panic == 0))
	    reattach_wait = 1;

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
    size_t		plen = *len;
    kdp_hostinfo_reply_t *rp = &pkt->hostinfo_reply;

    if (plen < sizeof (*rq))
	return (FALSE);

	dprintf(("kdp_hostinfo\n"));

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    kdp_machine_hostinfo(&rp->hostinfo);

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_kernelversion(
				  kdp_pkt_t		*pkt,
				  int			*len,
				  unsigned short	*reply_port
)
{
    kdp_kernelversion_req_t	*rq = &pkt->kernelversion_req;
    size_t		plen = *len;
    kdp_kernelversion_reply_t *rp = &pkt->kernelversion_reply;
	size_t		slen;
	
    if (plen < sizeof (*rq))
		return (FALSE);
	
    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
	
    dprintf(("kdp_kernelversion\n"));
	slen = strlcpy(rp->version, kdp_kernelversion_string, MAX_KDP_DATA_SIZE);
	
	rp->hdr.len += slen + 1; /* strlcpy returns the amount copied with NUL */
	
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
    size_t		plen = *len;
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
    size_t			plen = *len;
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
    size_t		plen = *len;
    kdp_writemem_reply_t *rp = &pkt->writemem_reply;
    mach_vm_size_t 		cnt;

    if (plen < sizeof (*rq))
	return (FALSE);

    if (rq->nbytes > MAX_KDP_DATA_SIZE)
	rp->error = KDPERR_BAD_NBYTES;
    else {
	dprintf(("kdp_writemem addr %x size %d\n", rq->address, rq->nbytes));

	cnt = kdp_machine_vm_write((caddr_t)rq->data, (mach_vm_address_t)rq->address, rq->nbytes);
	rp->error = KDPERR_NO_ERROR;
    }

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_writemem64(
			 kdp_pkt_t		*pkt,
			 int			*len,
			 unsigned short	*reply_port
)
{
    kdp_writemem64_req_t	*rq = &pkt->writemem64_req;
    size_t		plen = *len;
    kdp_writemem64_reply_t *rp = &pkt->writemem64_reply;
    mach_vm_size_t 		cnt;
	
    if (plen < sizeof (*rq))
		return (FALSE);
	
    if (rq->nbytes > MAX_KDP_DATA_SIZE)
		rp->error = KDPERR_BAD_NBYTES;
    else {
		dprintf(("kdp_writemem64 addr %llx size %d\n", rq->address, rq->nbytes));
		
		cnt = kdp_machine_vm_write((caddr_t)rq->data, (mach_vm_address_t)rq->address, (mach_vm_size_t)rq->nbytes);
		rp->error = KDPERR_NO_ERROR;
    }
	
    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
	
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_writephysmem64(
			 kdp_pkt_t		*pkt,
			 int			*len,
			 unsigned short	*reply_port
)
{
    kdp_writephysmem64_req_t	*rq = &pkt->writephysmem64_req;
    size_t		plen = *len;
    kdp_writephysmem64_reply_t *rp = &pkt->writephysmem64_reply;
	
    if (plen < sizeof (*rq))
		return (FALSE);
	
    if (rq->nbytes > MAX_KDP_DATA_SIZE)
		rp->error = KDPERR_BAD_NBYTES;
    else {
		dprintf(("kdp_writephysmem64 addr %llx size %d\n", rq->address, rq->nbytes));
		kdp_machine_phys_write(rq, rq->data, rq->lcpu);
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
    size_t		plen = *len;
    kdp_readmem_reply_t *rp = &pkt->readmem_reply;
    mach_vm_size_t			cnt;
#if __i386__
    void		*pversion = &kdp_kernelversion_string;
#endif

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    if (rq->nbytes > MAX_KDP_DATA_SIZE)
	rp->error = KDPERR_BAD_NBYTES;
    else {
	unsigned int	n = rq->nbytes;

	dprintf(("kdp_readmem addr %x size %d\n", rq->address, n));
#if __i386__
	/* XXX This is a hack to facilitate the "showversion" macro
	 * on i386, which is used to obtain the kernel version without
	 * symbols - a pointer to the version string should eventually
	 * be pinned at a fixed address when an equivalent of the
	 * VECTORS segment (loaded at a fixed load address, and contains
	 * a table) is implemented on these architectures, as with PPC.
	 * N.B.: x86 now has a low global page, and the version indirection
	 * is pinned at 0x201C. We retain the 0x501C address override
	 * for compatibility. Future architectures should instead use
	 * the KDP_KERNELVERSION request.
	 */
	if (rq->address == 0x501C)
		rq->address = (uintptr_t)&pversion;
#endif
	cnt = kdp_machine_vm_read((mach_vm_address_t)rq->address, (caddr_t)rp->data, n);
	rp->error = KDPERR_NO_ERROR;

	rp->hdr.len += cnt;
    }

    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_readmem64(
			kdp_pkt_t		*pkt,
			int			*len,
			unsigned short	*reply_port
)
{
    kdp_readmem64_req_t	*rq = &pkt->readmem64_req;
    size_t		plen = *len;
    kdp_readmem64_reply_t *rp = &pkt->readmem64_reply;
    mach_vm_size_t			cnt;

    if (plen < sizeof (*rq))
		return (FALSE);
	
    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
	
    if (rq->nbytes > MAX_KDP_DATA_SIZE)
		rp->error = KDPERR_BAD_NBYTES;
    else {

		dprintf(("kdp_readmem64 addr %llx size %d\n", rq->address, rq->nbytes));

		cnt = kdp_machine_vm_read((mach_vm_address_t)rq->address, (caddr_t)rp->data, rq->nbytes);
		rp->error = KDPERR_NO_ERROR;
		
		rp->hdr.len += cnt;
    }
	
    *reply_port = kdp.reply_port;
    *len = rp->hdr.len;
    
    return (TRUE);
}

static boolean_t
kdp_readphysmem64(
			kdp_pkt_t		*pkt,
			int			*len,
			unsigned short	*reply_port
)
{
    kdp_readphysmem64_req_t	*rq = &pkt->readphysmem64_req;
    size_t		plen = *len;
    kdp_readphysmem64_reply_t *rp = &pkt->readphysmem64_reply;
    int			cnt;

    if (plen < sizeof (*rq))
		return (FALSE);
	
    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);
	
    if (rq->nbytes > MAX_KDP_DATA_SIZE)
		rp->error = KDPERR_BAD_NBYTES;
    else {

		dprintf(("kdp_readphysmem64 addr %llx size %d\n", rq->address, rq->nbytes));

		cnt = (int)kdp_machine_phys_read(rq, rp->data, rq->lcpu);
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
    size_t		plen = *len;
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
    size_t		plen = *len;
    kdp_version_reply_t *rp = &pkt->version_reply;

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    dprintf(("kdp_version\n"));

    rp->version = KDP_VERSION;
    if (!(kdp_flag & KDP_BP_DIS))
      rp->feature = KDP_FEATURE_BP;
    else
      rp->feature = 0;
	
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
    size_t		plen = *len;
    kdp_regions_reply_t *rp = &pkt->regions_reply;
    kdp_region_t	*r;	

    if (plen < sizeof (*rq))
	return (FALSE);

    rp->hdr.is_reply = 1;
    rp->hdr.len = sizeof (*rp);

    dprintf(("kdp_regions\n"));

    r = rp->regions;
    rp->nregions = 0;

    r->address = 0;
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
    size_t		plen = *len;
    int			size;
    kdp_writeregs_reply_t *rp = &pkt->writeregs_reply;

    if (plen < sizeof (*rq))
	return (FALSE);
    
    size = rq->hdr.len - (unsigned)sizeof(kdp_hdr_t) - (unsigned)sizeof(unsigned int);
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
    size_t		plen = *len;
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


boolean_t 
kdp_breakpoint_set(
				   kdp_pkt_t		*pkt,
				   int			*len,
				   unsigned short	*reply_port
)
{
	kdp_breakpoint_req_t	*rq = &pkt->breakpoint_req;
	kdp_breakpoint_reply_t *rp = &pkt->breakpoint_reply;
	size_t		plen = *len;
	kdp_error_t	kerr;
	
	if (plen < sizeof (*rq))
		return (FALSE);
	
	dprintf(("kdp_breakpoint_set %x\n", rq->address));

	kerr = kdp_set_breakpoint_internal((mach_vm_address_t)rq->address);
	
	rp->error = kerr; 
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
	
	return (TRUE);
}

boolean_t 
kdp_breakpoint64_set(
					 kdp_pkt_t		*pkt,
					 int			*len,
					 unsigned short	*reply_port
)
{
	kdp_breakpoint64_req_t	*rq = &pkt->breakpoint64_req;
	kdp_breakpoint64_reply_t *rp = &pkt->breakpoint64_reply;
	size_t		plen = *len;
	kdp_error_t	kerr;
	
	if (plen < sizeof (*rq))
		return (FALSE);
	
	dprintf(("kdp_breakpoint64_set %llx\n", rq->address));

	kerr = kdp_set_breakpoint_internal((mach_vm_address_t)rq->address);
	
	rp->error = kerr; 
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
	
	return (TRUE);
}

boolean_t 
kdp_breakpoint_remove(
					  kdp_pkt_t		*pkt,
					  int			*len,
					  unsigned short	*reply_port
)
{
	kdp_breakpoint_req_t	*rq = &pkt->breakpoint_req;
	kdp_breakpoint_reply_t *rp = &pkt->breakpoint_reply;
	size_t		plen = *len;
	kdp_error_t	kerr;
	if (plen < sizeof (*rq))
		return (FALSE);
	
	dprintf(("kdp_breakpoint_remove %x\n", rq->address));

	kerr = kdp_remove_breakpoint_internal((mach_vm_address_t)rq->address);
	
	rp->error = kerr; 
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
	
	return (TRUE);
}

boolean_t 
kdp_breakpoint64_remove(
						kdp_pkt_t		*pkt,
						int			*len,
						unsigned short	*reply_port
)
{
	kdp_breakpoint64_req_t	*rq = &pkt->breakpoint64_req;
	kdp_breakpoint64_reply_t *rp = &pkt->breakpoint64_reply;
	size_t		plen = *len;
	kdp_error_t	kerr;
	
	if (plen < sizeof (*rq))
		return (FALSE);
	
	dprintf(("kdp_breakpoint64_remove %llx\n", rq->address));

	kerr = kdp_remove_breakpoint_internal((mach_vm_address_t)rq->address);
	
	rp->error = kerr; 
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
	
	return (TRUE);
}


kdp_error_t
kdp_set_breakpoint_internal(
							mach_vm_address_t	address
							)
{
	
	uint8_t		breakinstr[MAX_BREAKINSN_BYTES], oldinstr[MAX_BREAKINSN_BYTES];
	uint32_t	breakinstrsize = sizeof(breakinstr);
	mach_vm_size_t	cnt;
	int			i;
	
	kdp_machine_get_breakinsn(breakinstr, &breakinstrsize);
	
	if(breakpoints_initialized == 0)
    {
		for(i=0;(i < MAX_BREAKPOINTS); breakpoint_list[i].address=0, i++);
		breakpoints_initialized++;
    }
	
	cnt = kdp_machine_vm_read(address, (caddr_t)&oldinstr, (mach_vm_size_t)breakinstrsize);
	
	if (0 == memcmp(oldinstr, breakinstr, breakinstrsize)) {
		printf("A trap was already set at that address, not setting new breakpoint\n");
		
		return KDPERR_BREAKPOINT_ALREADY_SET;
	}
	
	for(i=0;(i < MAX_BREAKPOINTS) && (breakpoint_list[i].address != 0); i++);
	
	if (i == MAX_BREAKPOINTS) {
		return KDPERR_MAX_BREAKPOINTS;
	}
	
	breakpoint_list[i].address =  address;
	memcpy(breakpoint_list[i].oldbytes, oldinstr, breakinstrsize);
	breakpoint_list[i].bytesused =  breakinstrsize;
	
	cnt = kdp_machine_vm_write((caddr_t)&breakinstr, address, breakinstrsize);
	
	return KDPERR_NO_ERROR;
}

kdp_error_t
kdp_remove_breakpoint_internal(
							   mach_vm_address_t	address
							   )
{
	mach_vm_size_t	cnt;
	int		i;
	
	for(i=0;(i < MAX_BREAKPOINTS) && (breakpoint_list[i].address != address); i++);
	
	if (i == MAX_BREAKPOINTS)
    {
		return KDPERR_BREAKPOINT_NOT_FOUND; 
	}
	
	breakpoint_list[i].address = 0;
	cnt = kdp_machine_vm_write((caddr_t)&breakpoint_list[i].oldbytes, address, breakpoint_list[i].bytesused);
	
	return KDPERR_NO_ERROR;
}

boolean_t
kdp_remove_all_breakpoints(void)
{
	int i;
	boolean_t breakpoint_found = FALSE;
	
	if (breakpoints_initialized)
    {
		for(i=0;i < MAX_BREAKPOINTS; i++)
		{
			if (breakpoint_list[i].address)
			{
				kdp_machine_vm_write((caddr_t)&(breakpoint_list[i].oldbytes), (mach_vm_address_t)breakpoint_list[i].address, (mach_vm_size_t)breakpoint_list[i].bytesused);
				breakpoint_found = TRUE;
				breakpoint_list[i].address = 0;
			}
		}
		
		if (breakpoint_found)
			printf("kdp_remove_all_breakpoints: found extant breakpoints, removing them.\n");
    }
	return breakpoint_found;
}

boolean_t
kdp_reboot(
		   __unused kdp_pkt_t *pkt,
		   __unused int	*len,
		   __unused unsigned short *reply_port
)
{
	dprintf(("kdp_reboot\n"));

	kdp_machine_reboot();
	
	return (TRUE); // no, not really, we won't return
}

#define MAX_FRAMES 1000

static int pid_from_task(task_t task)
{
	int pid = -1;

	if (task->bsd_info)
		pid = proc_pid(task->bsd_info);

	return pid;
}

boolean_t
kdp_copyin(pmap_t p, uint64_t uaddr, void *dest, size_t size) {
	size_t rem = size;
	char *kvaddr = dest;

	while (rem) {
		ppnum_t upn = pmap_find_phys(p, uaddr);
		uint64_t phys_src = ptoa_64(upn) | (uaddr & PAGE_MASK);
		uint64_t phys_dest = kvtophys((vm_offset_t)kvaddr);
		uint64_t src_rem = PAGE_SIZE - (phys_src & PAGE_MASK);
		uint64_t dst_rem = PAGE_SIZE - (phys_dest & PAGE_MASK);
		size_t cur_size = (uint32_t) MIN(src_rem, dst_rem);
		cur_size = MIN(cur_size, rem);

		if (upn && pmap_valid_page(upn) && phys_dest) {
			bcopy_phys(phys_src, phys_dest, cur_size);
		}
		else
			break;
		uaddr += cur_size;
		kvaddr += cur_size;
		rem -= cur_size;	
	}
	return (rem == 0);
}


static void
kdp_mem_and_io_snapshot(struct mem_and_io_snapshot *memio_snap)
{
  unsigned int pages_reclaimed;
  unsigned int pages_wanted;
  kern_return_t kErr;

  memio_snap->snapshot_magic = STACKSHOT_MEM_AND_IO_SNAPSHOT_MAGIC;
  memio_snap->free_pages = vm_page_free_count;
  memio_snap->active_pages = vm_page_active_count;
  memio_snap->inactive_pages = vm_page_inactive_count;
  memio_snap->purgeable_pages = vm_page_purgeable_count;
  memio_snap->wired_pages = vm_page_wire_count;
  memio_snap->speculative_pages = vm_page_speculative_count;
  memio_snap->throttled_pages = vm_page_throttled_count;
  memio_snap->busy_buffer_count = count_busy_buffers();
  kErr = mach_vm_pressure_monitor(FALSE, VM_PRESSURE_TIME_WINDOW, &pages_reclaimed, &pages_wanted);
  if ( ! kErr ) {
	memio_snap->pages_wanted = (uint32_t)pages_wanted;
	memio_snap->pages_reclaimed = (uint32_t)pages_reclaimed;
	memio_snap->pages_wanted_reclaimed_valid = 1;
  } else {
	memio_snap->pages_wanted = 0;
	memio_snap->pages_reclaimed = 0;
	memio_snap->pages_wanted_reclaimed_valid = 0;
  }
}



/* 
 * Method for grabbing timer values safely, in the sense that no infinite loop will occur 
 * Certain flavors of the timer_grab function, which would seem to be the thing to use,   
 * can loop infinitely if called while the timer is in the process of being updated.      
 * Unfortunately, it is (rarely) possible to get inconsistent top and bottom halves of    
 * the timer using this method. This seems insoluble, since stackshot runs in a context   
 * where the timer might be half-updated, and has no way of yielding control just long    
 * enough to finish the update.                                                           
 */

static uint64_t safe_grab_timer_value(struct timer *t)
{
#if   defined(__LP64__)
  return t->all_bits;
#else
  uint64_t time = t->high_bits;    /* endian independent grab */
  time = (time << 32) | t->low_bits;
  return time;
#endif
}

int
kdp_stackshot(int pid, void *tracebuf, uint32_t tracebuf_size, uint32_t trace_flags, uint32_t dispatch_offset, uint32_t *pbytesTraced)
{
	char *tracepos = (char *) tracebuf;
	char *tracebound = tracepos + tracebuf_size;
	uint32_t tracebytes = 0;
	int error = 0;

	task_t task = TASK_NULL;
	thread_t thread = THREAD_NULL;
	thread_snapshot_t tsnap = NULL;
	unsigned framesize = 2 * sizeof(vm_offset_t);
	struct task ctask;
	struct thread cthread;
	struct _vm_map cmap;
	struct pmap cpmap;

	queue_head_t *task_list = &tasks;
	boolean_t is_active_list = TRUE;
	
	boolean_t dispatch_p = ((trace_flags & STACKSHOT_GET_DQ) != 0);
	boolean_t save_loadinfo_p = ((trace_flags & STACKSHOT_SAVE_LOADINFO) != 0);

	if(trace_flags & STACKSHOT_GET_GLOBAL_MEM_STATS) {
	  if(tracepos + sizeof(struct mem_and_io_snapshot) > tracebound) {
	    error = -1;
	    goto error_exit;
	  }
	  kdp_mem_and_io_snapshot((struct mem_and_io_snapshot *)tracepos);
	  tracepos += sizeof(struct mem_and_io_snapshot);
	}

walk_list:
	queue_iterate(task_list, task, task_t, tasks) {
		if ((task == NULL) || (ml_nofault_copy((vm_offset_t) task, (vm_offset_t) &ctask, sizeof(struct task)) != sizeof(struct task)))
			goto error_exit;

		int task_pid = pid_from_task(task);
		boolean_t task64 = task_has_64BitAddr(task);

		if (!task->active) {
			/* 
			 * Not interested in terminated tasks without threads, and
			 * at the moment, stackshot can't handle a task  without a name.
			 */
			if (queue_empty(&task->threads) || task_pid == -1) {
				continue;
			}
		}

		/* Trace everything, unless a process was specified */
		if ((pid == -1) || (pid == task_pid)) {
			task_snapshot_t task_snap;
			uint32_t uuid_info_count = 0;
			mach_vm_address_t uuid_info_addr = 0;
			boolean_t have_map = (task->map != NULL) && 
			  (ml_nofault_copy((vm_offset_t)(task->map), (vm_offset_t)&cmap, sizeof(struct _vm_map)) == sizeof(struct _vm_map));
			boolean_t have_pmap = have_map && (cmap.pmap != NULL) &&
			  (ml_nofault_copy((vm_offset_t)(cmap.pmap), (vm_offset_t)&cpmap, sizeof(struct pmap)) == sizeof(struct pmap));

			if (have_pmap && task->active && save_loadinfo_p && task_pid > 0) {
				// Read the dyld_all_image_infos struct from the task memory to get UUID array count and location
				if (task64) {
					struct user64_dyld_all_image_infos task_image_infos;
					if (kdp_copyin(task->map->pmap, task->all_image_info_addr, &task_image_infos, sizeof(struct user64_dyld_all_image_infos))) {
						uuid_info_count = (uint32_t)task_image_infos.uuidArrayCount;
						uuid_info_addr = task_image_infos.uuidArray;
					}
				} else {
					struct user32_dyld_all_image_infos task_image_infos;
					if (kdp_copyin(task->map->pmap, task->all_image_info_addr, &task_image_infos, sizeof(struct user32_dyld_all_image_infos))) {
						uuid_info_count = task_image_infos.uuidArrayCount;
						uuid_info_addr = task_image_infos.uuidArray;
					}
				}

				// If we get a NULL uuid_info_addr (which can happen when we catch dyld in the middle of updating
				// this data structure), we zero the uuid_info_count so that we won't even try to save load info
				// for this task.
				if (!uuid_info_addr) {
					uuid_info_count = 0;
				}
			}

			if (tracepos + sizeof(struct task_snapshot) > tracebound) {
				error = -1;
				goto error_exit;
			}

			task_snap = (task_snapshot_t) tracepos;
			task_snap->snapshot_magic = STACKSHOT_TASK_SNAPSHOT_MAGIC;
			task_snap->pid = task_pid;
			task_snap->nloadinfos = uuid_info_count;
			/* Add the BSD process identifiers */
			if (task_pid != -1)
				proc_name_kdp(task, task_snap->p_comm, sizeof(task_snap->p_comm));
			else
				task_snap->p_comm[0] = '\0';
			task_snap->ss_flags = 0;
			if (task64)
				task_snap->ss_flags |= kUser64_p;
			if (!task->active) 
				task_snap->ss_flags |= kTerminatedSnapshot;
			if(task->pidsuspended) task_snap->ss_flags |= kPidSuspended;
			if(task->frozen) task_snap->ss_flags |= kFrozen;

			task_snap->suspend_count = task->suspend_count;
			task_snap->task_size = have_pmap ? pmap_resident_count(task->map->pmap) : 0;
			task_snap->faults = task->faults;
			task_snap->pageins = task->pageins;
			task_snap->cow_faults = task->cow_faults;
			
			task_snap->user_time_in_terminated_threads = task->total_user_time;
			task_snap->system_time_in_terminated_threads = task->total_system_time;
			tracepos += sizeof(struct task_snapshot);

			if (task_pid > 0 && uuid_info_count > 0) {
				uint32_t uuid_info_size = (uint32_t)(task64 ? sizeof(struct user64_dyld_uuid_info) : sizeof(struct user32_dyld_uuid_info));
				uint32_t uuid_info_array_size = uuid_info_count * uuid_info_size;

				if (tracepos + uuid_info_array_size > tracebound) {
					error = -1;
					goto error_exit;
				}

				// Copy in the UUID info array
				// It may be nonresident, in which case just fix up nloadinfos to 0 in the task_snap
				if (have_pmap && !kdp_copyin(task->map->pmap, uuid_info_addr, tracepos, uuid_info_array_size))
					task_snap->nloadinfos = 0;
				else
					tracepos += uuid_info_array_size;
			}

			queue_iterate(&task->threads, thread, thread_t, task_threads){
				uint64_t tval;

				if ((thread == NULL) || (ml_nofault_copy((vm_offset_t) thread, (vm_offset_t) &cthread, sizeof(struct thread)) != sizeof(struct thread)))
					goto error_exit;

				if (((tracepos + 4 * sizeof(struct thread_snapshot)) > tracebound)) {
					error = -1;
					goto error_exit;
				}
				/* Populate the thread snapshot header */
				tsnap = (thread_snapshot_t) tracepos;
				tsnap->thread_id = thread_tid(thread);
				tsnap->state = thread->state;
				tsnap->sched_pri = thread->sched_pri;
				tsnap->sched_flags = thread->sched_flags;
				tsnap->wait_event = VM_KERNEL_UNSLIDE(thread->wait_event);
				tsnap->continuation = VM_KERNEL_UNSLIDE(thread->continuation);
				tval = safe_grab_timer_value(&thread->user_timer);
				tsnap->user_time = tval;
				tval = safe_grab_timer_value(&thread->system_timer);
				if (thread->precise_user_kernel_time) {
					tsnap->system_time = tval;
				} else {
					tsnap->user_time += tval;
					tsnap->system_time = 0;
				}
				tsnap->snapshot_magic = STACKSHOT_THREAD_SNAPSHOT_MAGIC;
				tracepos += sizeof(struct thread_snapshot);
				tsnap->ss_flags = 0;

				if (dispatch_p && (task != kernel_task) && (task->active) && have_pmap) {
					uint64_t dqkeyaddr = thread_dispatchqaddr(thread);
					if (dqkeyaddr != 0) {
						uint64_t dqaddr = 0;
						if (kdp_copyin(task->map->pmap, dqkeyaddr, &dqaddr, (task64 ? 8 : 4)) && (dqaddr != 0)) {
							uint64_t dqserialnumaddr = dqaddr + dispatch_offset;
							uint64_t dqserialnum = 0;
							if (kdp_copyin(task->map->pmap, dqserialnumaddr, &dqserialnum, (task64 ? 8 : 4))) {
								tsnap->ss_flags |= kHasDispatchSerial;
								*(uint64_t *)tracepos = dqserialnum;
								tracepos += 8;
							}
						}
					}
				}
/* Call through to the machine specific trace routines
 * Frames are added past the snapshot header.
 */
				tracebytes = 0;
				if (thread->kernel_stack != 0) {
#if defined(__LP64__)					
					tracebytes = machine_trace_thread64(thread, tracepos, tracebound, MAX_FRAMES, FALSE);
					tsnap->ss_flags |= kKernel64_p;
					framesize = 16;
#else
					tracebytes = machine_trace_thread(thread, tracepos, tracebound, MAX_FRAMES, FALSE);
					framesize = 8;
#endif
				}
				tsnap->nkern_frames = tracebytes/framesize;
				tracepos += tracebytes;
				tracebytes = 0;
				/* Trace user stack, if any */
				if (task->active && thread->task->map != kernel_map) {
					/* 64-bit task? */
					if (task_has_64BitAddr(thread->task)) {
						tracebytes = machine_trace_thread64(thread, tracepos, tracebound, MAX_FRAMES, TRUE);
						tsnap->ss_flags |= kUser64_p;
						framesize = 16;
					}
					else {
						tracebytes = machine_trace_thread(thread, tracepos, tracebound, MAX_FRAMES, TRUE);
						framesize = 8;
					}
				}
				tsnap->nuser_frames = tracebytes/framesize;
				tracepos += tracebytes;
				tracebytes = 0;
			}
		}
	}

	if (is_active_list) { 
		is_active_list = FALSE;
		task_list = &terminated_tasks;
		goto walk_list;
	}

error_exit:
	/* Release stack snapshot wait indicator */
	kdp_snapshot_postflight();

	*pbytesTraced = (uint32_t)(tracepos - (char *) tracebuf);

	return error;
}

static boolean_t
kdp_readioport(kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
	       )
{
	kdp_readioport_req_t   *rq = &pkt->readioport_req;
	kdp_readioport_reply_t *rp = &pkt->readioport_reply;
	size_t plen = *len;

	if (plen < sizeof (*rq))
		return (FALSE);
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	
	if (rq->nbytes > MAX_KDP_DATA_SIZE)
		rp->error = KDPERR_BAD_NBYTES;
	else {
#if KDP_TEST_HARNESS
                uint16_t addr = rq->address;
#endif
		uint16_t size = rq->nbytes;
		dprintf(("kdp_readioport addr %x size %d\n", addr, size));

		rp->error = kdp_machine_ioport_read(rq, rp->data, rq->lcpu);
		if (rp->error == KDPERR_NO_ERROR)
			rp->hdr.len += size;
	}
	
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
    
	return (TRUE);
}

static boolean_t
kdp_writeioport(
	kdp_pkt_t	*pkt,
	int		*len,
	unsigned short	*reply_port
                )
{
	kdp_writeioport_req_t   *rq = &pkt->writeioport_req;
	kdp_writeioport_reply_t *rp = &pkt->writeioport_reply;
	size_t	plen = *len;
	
	if (plen < sizeof (*rq))
		return (FALSE);
	
	if (rq->nbytes > MAX_KDP_DATA_SIZE)
		rp->error = KDPERR_BAD_NBYTES;
	else {
		dprintf(("kdp_writeioport addr %x size %d\n", rq->address, 
			rq->nbytes));
		
		rp->error = kdp_machine_ioport_write(rq, rq->data, rq->lcpu);
	}
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
    
	return (TRUE);
}

static boolean_t
kdp_readmsr64(kdp_pkt_t		*pkt,
    int			*len,
    unsigned short	*reply_port
              )
{
	kdp_readmsr64_req_t   *rq = &pkt->readmsr64_req;
	kdp_readmsr64_reply_t *rp = &pkt->readmsr64_reply;
	size_t plen = *len;

	if (plen < sizeof (*rq))
		return (FALSE);
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	
	dprintf(("kdp_readmsr64 lcpu %x addr %x\n", rq->lcpu, rq->address));
	rp->error = kdp_machine_msr64_read(rq, rp->data, rq->lcpu);
	if (rp->error == KDPERR_NO_ERROR)
		rp->hdr.len += sizeof(uint64_t);
	
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
    
	return (TRUE);
}

static boolean_t
kdp_writemsr64(
	kdp_pkt_t	*pkt,
	int		*len,
	unsigned short	*reply_port
	       )
{
	kdp_writemsr64_req_t   *rq = &pkt->writemsr64_req;
	kdp_writemsr64_reply_t *rp = &pkt->writemsr64_reply;
	size_t	plen = *len;
	
	if (plen < sizeof (*rq))
		return (FALSE);
	
	dprintf(("kdp_writemsr64 lcpu %x addr %x\n", rq->lcpu, rq->address)); 
	rp->error = kdp_machine_msr64_write(rq, rq->data, rq->lcpu);
	
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	
	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
    
	return (TRUE);
}

static boolean_t
kdp_dumpinfo(
	kdp_pkt_t	*pkt,
	int		*len,
	unsigned short	*reply_port
	       )
{
	kdp_dumpinfo_req_t   *rq = &pkt->dumpinfo_req;
	kdp_dumpinfo_reply_t *rp = &pkt->dumpinfo_reply;
	size_t	plen = *len;
	
	if (plen < sizeof (*rq))
		return (FALSE);
	
	dprintf(("kdp_dumpinfo file=%s destip=%s routerip=%s\n", rq->name, rq->destip, rq->routerip));
	rp->hdr.is_reply = 1;
	rp->hdr.len = sizeof (*rp);
	
        if ((rq->type & KDP_DUMPINFO_MASK) != KDP_DUMPINFO_GETINFO) {
            kdp_set_dump_info(rq->type, rq->name, rq->destip, rq->routerip, 
                                rq->port);
        }

        /* gather some stats for reply */
        kdp_get_dump_info(&rp->type, rp->name, rp->destip, rp->routerip, 
                          &rp->port);

	*reply_port = kdp.reply_port;
	*len = rp->hdr.len;
    
	return (TRUE);
}
