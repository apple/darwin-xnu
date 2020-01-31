/*
 * Copyright (c) 2000-2012 Apple Inc. All rights reserved.
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

#include <sys/kdebug.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/proc_internal.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/systm.h>
#include <vm/vm_kern.h>
#include <machine/machine_routines.h>

vm_offset_t pc_buftomem = 0;
unsigned int *  pc_buffer   = 0;   /* buffer that holds each pc */
unsigned int *  pc_bufptr   = 0;
unsigned int *  pc_buflast  = 0;
unsigned int npcbufs         = 8192;      /* number of pc entries in buffer */
unsigned int pc_bufsize      = 0;
unsigned int pcsample_flags  = 0;
unsigned int pcsample_enable = 0;

pid_t pc_sample_pid = 0;
boolean_t pc_trace_frameworks = FALSE;

char pcsample_comm[MAXCOMLEN + 1];

/* Set the default framework boundaries */
unsigned int pcsample_beg    = 0;
unsigned int pcsample_end    = 0;

static pid_t global_state_pid = -1;       /* Used to control exclusive use of pc_buffer */

extern unsigned int pc_trace_buf[];
extern int pc_trace_cnt;

void add_pcbuffer(void);
int branch_tracing_enabled(void);
int disable_branch_tracing(void);
int enable_branch_tracing(void);
int pcsamples_bootstrap(void);
void pcsamples_clear(void);
int pcsamples_control(int *name, u_int namelen, user_addr_t where, size_t *sizep);
int pcsamples_read(user_addr_t buffer, size_t *number);
int pcsamples_reinit(void);

int
enable_branch_tracing(void)
{
	struct proc *p;
	if (-1 != pc_sample_pid) {
		p = proc_find(pc_sample_pid);
		if (p) {
			p->p_btrace = 1;
			proc_rele(p);
		}
	} else {
		pc_trace_frameworks = TRUE;
	}

	return 1;
}

int
disable_branch_tracing(void)
{
	struct proc *p;
	switch (pc_sample_pid) {
	case -1:
		pc_trace_frameworks = FALSE;
		break;
	case 0:
		break;
	default:
		p = proc_find(pc_sample_pid);
		if (p) {
			p->p_btrace = 0;
			proc_rele(p);
		}
		break;
	}
	clr_be_bit();
	return 1;
}

/*
 * this only works for the current proc as it
 * is called from context_switch in the scheduler
 */
int
branch_tracing_enabled(void)
{
	struct proc *p = current_proc();
	if (TRUE == pc_trace_frameworks) {
		return TRUE;
	}
	if (p) {
		return p->p_btrace;
	}
	return 0;
}


void
add_pcbuffer(void)
{
	int      i;
	unsigned int  pc;

	if (!pcsample_enable) {
		return;
	}

	for (i = 0; i < pc_trace_cnt; i++) {
		pc = pc_trace_buf[i];

		if ((pcsample_beg <= pc) && (pc < pcsample_end)) {
			if (pc_bufptr > pc_buffer) {
				if ((*(pc_bufptr - 1)) == pc) {
					continue; /* Ignore, probably spinning */
				}
			}

			/* Then the sample is in our range */
			*pc_bufptr = pc;
			pc_bufptr++;
		}
	}

	/* We never wrap the buffer */
	if ((pc_bufptr + pc_trace_cnt) >= pc_buflast) {
		pcsample_enable = 0;
		(void)disable_branch_tracing();
		wakeup(&pcsample_enable);
	}
	return;
}

int
pcsamples_bootstrap(void)
{
	if (!disable_branch_tracing()) {
		return ENOTSUP;
	}

	pc_bufsize = npcbufs * sizeof(*pc_buffer);
	if (kmem_alloc(kernel_map, &pc_buftomem,
	    (vm_size_t)pc_bufsize) == KERN_SUCCESS) {
		pc_buffer = (unsigned int *) pc_buftomem;
	} else {
		pc_buffer = NULL;
	}

	if (pc_buffer) {
		pc_bufptr = pc_buffer;
		pc_buflast = &pc_bufptr[npcbufs];
		pcsample_enable = 0;
		return 0;
	} else {
		pc_bufsize = 0;
		return EINVAL;
	}
}

int
pcsamples_reinit(void)
{
	int ret = 0;

	pcsample_enable = 0;

	if (pc_bufsize && pc_buffer) {
		kmem_free(kernel_map, (vm_offset_t)pc_buffer, pc_bufsize);
	}

	ret = pcsamples_bootstrap();
	return ret;
}

void
pcsamples_clear(void)
{
	/* Clean up the sample buffer, set defaults */
	global_state_pid = -1;
	pcsample_enable = 0;
	if (pc_bufsize && pc_buffer) {
		kmem_free(kernel_map, (vm_offset_t)pc_buffer, pc_bufsize);
	}
	pc_buffer   = NULL;
	pc_bufptr   = NULL;
	pc_buflast  = NULL;
	pc_bufsize  = 0;
	pcsample_beg = 0;
	pcsample_end = 0;
	bzero((void *)pcsample_comm, sizeof(pcsample_comm));
	(void)disable_branch_tracing();
	pc_sample_pid = 0;
	pc_trace_frameworks = FALSE;
}

int
pcsamples_control(int *name, __unused u_int namelen, user_addr_t where, size_t *sizep)
{
	int ret = 0;
	size_t size = *sizep;
	int value = name[1];
	pcinfo_t pc_bufinfo = {};
	pid_t *pidcheck;

	pid_t curpid;
	struct proc *p, *curproc;

	if (name[0] != PCSAMPLE_GETNUMBUF) {
		curproc = current_proc();
		if (curproc) {
			curpid = curproc->p_pid;
		} else {
			return ESRCH;
		}

		if (global_state_pid == -1) {
			global_state_pid = curpid;
		} else if (global_state_pid != curpid) {
			if ((p = proc_find(global_state_pid)) == NULL) {
				/* The global pid no longer exists */
				global_state_pid = curpid;
			} else {
				proc_rele(p);
				/* The global pid exists, deny this request */
				return EBUSY;
			}
		}
	}


	switch (name[0]) {
	case PCSAMPLE_DISABLE: /* used to disable */
		pcsample_enable = 0;
		break;
	case PCSAMPLE_SETNUMBUF:
		/* The buffer size is bounded by a min and max number of samples */
		if (value < pc_trace_cnt) {
			ret = EINVAL;
			break;
		}
		if (value <= MAX_PCSAMPLES) {
			/*	npcbufs = value & ~(PC_TRACE_CNT-1); */
			npcbufs = value;
		} else {
			npcbufs = MAX_PCSAMPLES;
		}
		break;
	case PCSAMPLE_GETNUMBUF:
		if (size < sizeof(pc_bufinfo)) {
			ret = EINVAL;
			break;
		}
		pc_bufinfo.npcbufs = npcbufs;
		pc_bufinfo.bufsize = pc_bufsize;
		pc_bufinfo.enable = pcsample_enable;
		pc_bufinfo.pcsample_beg = pcsample_beg;
		pc_bufinfo.pcsample_end = pcsample_end;
		if (copyout(&pc_bufinfo, where, sizeof(pc_bufinfo))) {
			ret = EINVAL;
		}
		break;
	case PCSAMPLE_SETUP:
		ret = pcsamples_reinit();
		break;
	case PCSAMPLE_REMOVE:
		pcsamples_clear();
		break;
	case PCSAMPLE_READBUF:
		/* A nonzero value says enable and wait on the buffer */
		/* A zero value says read up the buffer immediately */
		if (value == 0) {
			/* Do not wait on the buffer */
			pcsample_enable = 0;
			(void)disable_branch_tracing();
			ret = pcsamples_read(where, sizep);
			break;
		} else if ((pc_bufsize <= 0) || (!pc_buffer)) {
			/* enable only if buffer is initialized */
			ret = EINVAL;
			break;
		}

		/* Turn on branch tracing */
		if (!enable_branch_tracing()) {
			ret = ENOTSUP;
			break;
		}

		/* Enable sampling */
		pcsample_enable = 1;

		ret = tsleep(&pcsample_enable, PRIBIO | PCATCH, "pcsample", 0);
		pcsample_enable = 0;
		(void)disable_branch_tracing();

		if (ret) {
			/*	Eventually fix this...  if (ret != EINTR) */
			if (ret) {
				/* On errors, except EINTR, we want to cleanup buffer ptrs */
				/* pc_bufptr = pc_buffer; */
				*sizep = 0;
			}
		} else {
			/* The only way to get here is if the buffer is full */
			ret = pcsamples_read(where, sizep);
		}

		break;
	case PCSAMPLE_SETREG:
		if (size < sizeof(pc_bufinfo)) {
			ret = EINVAL;
			break;
		}
		if (copyin(where, &pc_bufinfo, sizeof(pc_bufinfo))) {
			ret = EINVAL;
			break;
		}

		pcsample_beg = pc_bufinfo.pcsample_beg;
		pcsample_end = pc_bufinfo.pcsample_end;
		break;
	case PCSAMPLE_COMM:
		if (!(sizeof(pcsample_comm) > size)) {
			ret = EINVAL;
			break;
		}
		bzero((void *)pcsample_comm, sizeof(pcsample_comm));
		if (copyin(where, pcsample_comm, size)) {
			ret = EINVAL;
			break;
		}

		/* Check for command name or pid */
		if (pcsample_comm[0] != '\0') {
			ret = ENOTSUP;
			break;
		} else {
			if (size != (2 * sizeof(pid_t))) {
				ret = EINVAL;
				break;
			} else {
				pidcheck = (pid_t *)pcsample_comm;
				pc_sample_pid = pidcheck[1];
			}
		}
		break;
	default:
		ret = ENOTSUP;
		break;
	}
	return ret;
}


/*
 *  This buffer must be read up in one call.
 *  If the buffer isn't big enough to hold
 *  all the samples, it will copy up enough
 *  to fill the buffer and throw the rest away.
 *  This buffer never wraps.
 */
int
pcsamples_read(user_addr_t buffer, size_t *number)
{
	size_t count = 0;
	size_t copycount;

	count = (*number) / sizeof(*pc_buffer);

	if (count && pc_bufsize && pc_buffer) {
		copycount = pc_bufptr - pc_buffer;

		if (copycount <= 0) {
			*number = 0;
			return 0;
		}

		if (copycount > count) {
			copycount = count;
		}

		/* We actually have data to send up */
		if (copyout(pc_buffer, buffer, copycount * sizeof(*pc_buffer))) {
			*number = 0;
			return EINVAL;
		}
		*number = copycount;
		pc_bufptr = pc_buffer;
		return 0;
	} else {
		*number = 0;
		return 0;
	}
}
