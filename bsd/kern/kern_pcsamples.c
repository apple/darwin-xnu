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

#include <sys/kdebug.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <vm/vm_kern.h>

unsigned int pc_buftomem = 0;
u_long     * pc_buffer   = 0;   /* buffer that holds each pc */
u_long     * pc_bufptr   = 0;
u_long     * pc_buflast  = 0;
unsigned int npcbufs         = 8192;      /* number of pc entries in buffer */
unsigned int pc_bufsize      = 0;
unsigned int pcsample_flags  = 0;
unsigned int pcsample_enable = 0;

char pcsample_comm[MAXCOMLEN + 1];

/* Set the default framework boundaries */
u_long pcsample_beg    = 0;
u_long pcsample_end    = 0;

static pid_t global_state_pid = -1;       /* Used to control exclusive use of pc_buffer */

extern int pc_trace_buf[];
extern int pc_trace_cnt;

void
add_pcbuffer()
{
	int      i;
	u_long  pc;
	struct proc *curproc;
	extern unsigned int kdebug_flags;

	if (!pcsample_enable)
	  return;

	if (pcsample_comm[0] != '\0')
	{
	  /* If command string does not match, then return */
	    curproc = current_proc();
	    if (curproc && 
		(strncmp(curproc->p_comm, pcsample_comm, sizeof(pcsample_comm))))
	      return;
	}

	for (i=0; i < pc_trace_cnt; i++)
	  {
	    pc = pc_trace_buf[i];
	    
	    if ((pcsample_beg <= pc) && (pc < pcsample_end))
	      {
		if (pc_bufptr > pc_buffer)
		  {
		    if ( (*(pc_bufptr-1)) == pc )
		      continue;   /* Ignore, probably spinning */
		  }

		/* Then the sample is in our range */
		*pc_bufptr = (u_long)pc;
		pc_bufptr++;
	      }
	  }

	/* We never wrap the buffer */
	if ((pc_bufptr + pc_trace_cnt) >= pc_buflast)
	  {
	    pcsample_enable = 0;
	    (void)clr_be_bit();
	    wakeup(&pcsample_enable);
	  }
	return;
}

pcsamples_bootstrap()
{
       if (!clr_be_bit())
            return(ENOTSUP);

	pc_bufsize = npcbufs * sizeof(* pc_buffer);
	if (kmem_alloc(kernel_map, &pc_buftomem,
		       (vm_size_t)pc_bufsize) == KERN_SUCCESS) 
	  pc_buffer = (u_long *) pc_buftomem;
	else 
	  pc_buffer= (u_long *) 0;

	if (pc_buffer) {
		pc_bufptr = pc_buffer;
		pc_buflast = &pc_bufptr[npcbufs];
		pcsample_enable = 0;
		return(0);
	} else {
		pc_bufsize=0;
		return(EINVAL);
	}
	
}

pcsamples_reinit()
{
int x;
int ret=0;

        pcsample_enable = 0;

	if (pc_bufsize && pc_buffer)
		kmem_free(kernel_map,pc_buffer,pc_bufsize);

	ret= pcsamples_bootstrap();
	return(ret);
}

pcsamples_clear()
{
        /* Clean up the sample buffer, set defaults */ 
        global_state_pid = -1;
	pcsample_enable = 0;
	if(pc_bufsize && pc_buffer)
	  kmem_free(kernel_map,pc_buffer,pc_bufsize);
	pc_buffer   = (u_long *)0;
	pc_bufptr   = (u_long *)0;
	pc_buflast  = (u_long *)0;
	pc_bufsize  = 0;
	pcsample_beg= 0;
	pcsample_end= 0;
	bzero((void *)pcsample_comm, sizeof(pcsample_comm));
	(void)clr_be_bit();
}

pcsamples_control(name, namelen, where, sizep)
int *name;
u_int namelen;
char *where;
size_t *sizep;
{
int ret=0;
int size=*sizep;
unsigned int value = name[1];
pcinfo_t pc_bufinfo;

pid_t curpid;
struct proc *p, *curproc;

        if (name[0] != PCSAMPLE_GETNUMBUF)
	  { 
	    if(curproc = current_proc())
	      curpid = curproc->p_pid;
	    else
	      return (ESRCH);

	    if (global_state_pid == -1)
	      global_state_pid = curpid;
	    else if (global_state_pid != curpid)
	      {
		if((p = pfind(global_state_pid)) == NULL)
		  {
		    /* The global pid no longer exists */
		    global_state_pid = curpid;
		  }
		else
		  {
		    /* The global pid exists, deny this request */
		    return(EBUSY);
		  }
	      }
	  }


	switch(name[0]) {
	        case PCSAMPLE_DISABLE:    /* used to disable */
		  pcsample_enable=0;
		  break;
		case PCSAMPLE_SETNUMBUF:
		        /* The buffer size is bounded by a min and max number of samples */
		        if (value < pc_trace_cnt) {
			     ret=EINVAL;
			     break;
			}
			if (value <= MAX_PCSAMPLES)
			  /*	npcbufs = value & ~(PC_TRACE_CNT-1); */
			  npcbufs = value;
			else
			  npcbufs = MAX_PCSAMPLES;
			break;
		case PCSAMPLE_GETNUMBUF:
		        if(size < sizeof(pcinfo_t)) {
		            ret=EINVAL;
			    break;
			}
			pc_bufinfo.npcbufs = npcbufs;
			pc_bufinfo.bufsize = pc_bufsize;
			pc_bufinfo.enable = pcsample_enable;
			pc_bufinfo.pcsample_beg = pcsample_beg;
			pc_bufinfo.pcsample_end = pcsample_end;
			if(copyout (&pc_bufinfo, where, sizeof(pc_bufinfo)))
			  {
			    ret=EINVAL;
			  }
			break;
		case PCSAMPLE_SETUP:
			ret=pcsamples_reinit();
			break;
		case PCSAMPLE_REMOVE:
			pcsamples_clear();
			break;
	        case PCSAMPLE_READBUF:
		        /* A nonzero value says enable and wait on the buffer */
		        /* A zero value says read up the buffer immediately */
		        if (value == 0)
			  {
			    /* Do not wait on the buffer */
			    pcsample_enable = 0;
			    (void)clr_be_bit();
			    ret = pcsamples_read(where, sizep);
			    break;
			  }
		        else if ((pc_bufsize <= 0) || (!pc_buffer))
			{
			  /* enable only if buffer is initialized */
			  ret=EINVAL;
			  break;
			}

			/* Turn on branch tracing */
			if (!set_be_bit())
			  {
			    ret = ENOTSUP;;
			    break;
			  }

			/* Enable sampling */
		        pcsample_enable = 1;

			ret = tsleep(&pcsample_enable, PRIBIO | PCATCH, "pcsample", 0);
			pcsample_enable = 0;
			(void)clr_be_bit();

			if (ret)
			  {
			    /*	Eventually fix this...  if (ret != EINTR) */
			    if (ret)
			      {
				/* On errors, except EINTR, we want to cleanup buffer ptrs */
				/* pc_bufptr = pc_buffer; */
				*sizep = 0;
			      }
			  }
			else
			  {
			    /* The only way to get here is if the buffer is full */
			    ret = pcsamples_read(where, sizep);
			  }

			break;
	        case PCSAMPLE_SETREG:
		        if (size < sizeof(pcinfo_t))
			  {
			    ret = EINVAL;
			    break;
			  }
			if (copyin(where, &pc_bufinfo, sizeof(pcinfo_t)))
			  {
			    ret = EINVAL;
			    break;
			  }

			pcsample_beg = pc_bufinfo.pcsample_beg;
			pcsample_end = pc_bufinfo.pcsample_end;
			break;
	        case PCSAMPLE_COMM:
		        if (!(sizeof(pcsample_comm) > size))
		        {
		            ret = EINVAL;
		            break;
		        }
		        bzero((void *)pcsample_comm, sizeof(pcsample_comm));
		        if (copyin(where, pcsample_comm, size))
		        {
		            ret = EINVAL;
		        }
		        break;
		default:
		        ret= EOPNOTSUPP;
			break;
	}
	return(ret);
}


/* 
   This buffer must be read up in one call.
   If the buffer isn't big enough to hold
   all the samples, it will copy up enough
   to fill the buffer and throw the rest away.
   This buffer never wraps.
*/
pcsamples_read(u_long *buffer, size_t *number)
{
int count=0;
int ret=0;
int copycount;

	count = (*number)/sizeof(u_long);

	if (count && pc_bufsize && pc_buffer)
	  {
	      copycount = pc_bufptr - pc_buffer;
	      
	      if (copycount <= 0)
		{
		  *number = 0;
		  return(0);
		}

	      if (copycount > count)
		copycount = count;

	      /* We actually have data to send up */
	      if(copyout(pc_buffer, buffer, copycount * sizeof(u_long)))
		{
		  *number = 0;
		  return(EINVAL);
		}
	      *number = copycount;
	      pc_bufptr = pc_buffer;
	      return(0);
	  }
	else
	  {
	    *number = 0;
	    return(0);
	  }
}




