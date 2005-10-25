/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

/*
 *	Author: Bill Angell, Apple
 *	Date:	6/97
 *
 * exceptions and certain C functions write into a trace table which
 * can be examined via the machine 'lt' command under kdb
 */


#include <string.h>			/* For strcpy() */
#include <mach/boolean.h>
#include <machine/db_machdep.h>

#include <ddb/db_access.h>
#include <ddb/db_lex.h>
#include <ddb/db_output.h>
#include <ddb/db_command.h>
#include <ddb/db_sym.h>
#include <ddb/db_task_thread.h>
#include <ddb/db_command.h>		/* For db_option() */
#include <ddb/db_examine.h>
#include <ddb/db_expr.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <mach/vm_param.h>
#include <mach/kmod.h>
#include <ppc/Firmware.h>
#include <ppc/low_trace.h>
#include <ppc/db_low_trace.h>
#include <ppc/mappings.h>
#include <ppc/pmap.h>
#include <ppc/mem.h>
#include <ppc/savearea.h>
#include <ppc/vmachmon.h>

void db_dumppca(unsigned int ptegindex); 	
void db_dumpmapping(struct mapping *mp); 					/* Dump out a mapping */
extern kmod_info_t *kmod;									/* Find the kmods */

db_addr_t	db_low_trace_prev = 0;

/*
 *		Print out the low level trace table:
 *
 *		Displays the entry and 15 before it in newest to oldest order
 *		
 *		lt [entaddr]
 
 *		If entaddr is omitted, it starts with the most current
 *		If entaddr = 0, it starts with the most current and does the whole table
 */
void db_low_trace(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int		c, i;
	unsigned int tempx, cnt;
	unsigned int xTraceCurr, xTraceStart, xTraceEnd, cxltr;
	db_addr_t	next_addr;
	LowTraceRecord xltr;
	unsigned char cmark;
	addr64_t xxltr;
	
	cnt = 16;													/* Default to 16 entries */
	
	xTraceCurr = trcWork.traceCurr;								/* Transfer current pointer */
	xTraceStart = trcWork.traceStart;							/* Transfer start of table */
	xTraceEnd = trcWork.traceEnd;								/* Transfer end of table */
	
	if(addr == -1) cnt = 0x7FFFFFFF;							/* Max the count */

	if(!addr || (addr == -1)) {
		addr=xTraceCurr-sizeof(LowTraceRecord);					/* Start at the newest */
		if((unsigned int)addr<xTraceStart) addr=xTraceEnd-sizeof(LowTraceRecord);	/* Wrap low back to high */
	}
	
	if((unsigned int)addr<xTraceStart||(unsigned int)addr>=xTraceEnd) {	/* In the table? */
		db_printf("address not in low memory trace table\n");	/* Tell the fool */
		return;													/* Leave... */
	}

	if((unsigned int)addr&0x0000007F) {							/* Proper alignment? */
		db_printf("address not aligned on trace entry boundary (0x80)\n");	/* Tell 'em */
		return;													/* Leave... */
	}
	
	xxltr = addr;												/* Set the start */
	cxltr = ((xTraceCurr == xTraceStart ? xTraceEnd : xTraceCurr) - sizeof(LowTraceRecord));	/* Get address of newest entry */

	db_low_trace_prev = addr;									/* Starting point */

	for(i=0; i < cnt; i++) {									/* Dump the 16 (or all) entries */
	
		ReadReal((addr64_t)xxltr, (unsigned int *)&xltr);					/* Get the first half */
		ReadReal((addr64_t)xxltr + 32, &(((unsigned int *)&xltr)[8]));		/* Get the second half */
		ReadReal((addr64_t)xxltr + 64, &(((unsigned int *)&xltr)[16]));		/* Get the second half */
		ReadReal((addr64_t)xxltr + 96, &(((unsigned int *)&xltr)[24]));		/* Get the second half */
		
		db_printf("\n%s%08llX  %1X  %08X %08X - %04X", (xxltr != cxltr ? " " : "*"), 
			xxltr,
			(xltr.LTR_cpu & 0xFF), xltr.LTR_timeHi, xltr.LTR_timeLo, 
			(xltr.LTR_excpt & 0x8000 ? 0xFFFF : xltr.LTR_excpt * 64));	/* Print the first line */

		if(xltr.LTR_cpu & 0xFF00) db_printf(", sflgs = %02X\n", ((xltr.LTR_cpu >> 8) & 0xFF));
		else db_printf("\n");
			
		db_printf("              DAR/DSR/CR: %016llX %08X %08X\n", xltr.LTR_dar, xltr.LTR_dsisr, xltr.LTR_cr);
		
		db_printf("                SRR0/SRR1 %016llX %016llX\n",  xltr.LTR_srr0, xltr.LTR_srr1);
		db_printf("                LR/CTR    %016llX %016llX\n",  xltr.LTR_lr, xltr.LTR_ctr);

		db_printf("                R0/R1/R2  %016llX %016llX %016llX\n", xltr.LTR_r0, xltr.LTR_r1, xltr.LTR_r2);
		db_printf("                R3/R4/R5  %016llX %016llX %016llX\n", xltr.LTR_r3, xltr.LTR_r4, xltr.LTR_r5);
		db_printf("              R6/sv/rsv   %016llX %016llX %08X\n", xltr.LTR_r6, xltr.LTR_save, xltr.LTR_rsvd0);
	
		if((cnt != 16) && (xxltr == xTraceCurr)) break;			/* If whole table dump, exit when we hit start again... */

		xxltr-=sizeof(LowTraceRecord);							/* Back it on up */
		if(xxltr<xTraceStart)
			xxltr=(xTraceEnd-sizeof(LowTraceRecord));			/* Wrap low back to high */
	
	}
	db_next = (db_expr_t)(xxltr);
	return;
}


/*
 *		Print out 256 bytes
 *
 *		
 *		dl [entaddr]
 */
void db_display_long(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int				i;

	for(i=0; i<8; i++) {									/* Print 256 bytes */
		db_printf("%016llX   %08X %08X %08X %08X  %08X %08X %08X %08X\n", addr,	/* Print a line */
			((unsigned long *)addr)[0], ((unsigned long *)addr)[1], ((unsigned long *)addr)[2], ((unsigned long *)addr)[3], 
			((unsigned long *)addr)[4], ((unsigned long *)addr)[5], ((unsigned long *)addr)[6], ((unsigned long *)addr)[7]);
		addr=(db_expr_t)(addr+0x00000020);					/* Point to next address */
	}
	db_next = addr;


}

unsigned char xtran[256] = {
/*  x0   x1   x2   x3   x4   x5   x6   x7   x8   x9   xA   xB   xC   xD   xE   xF   	   */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* 0x */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* 1x */
	' ', '!', '"', '#', '$', '%', '&',0x27, '(', ')', '*', '+', ',', '-', '.', '/',  /* 2x */
	'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', ':', ';', '<', '=', '>', '?',  /* 3x */
	'@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O',  /* 4x */
	'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z', '[',0x5C, ']', '^', '_',  /* 5x */
	'`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o',  /* 6x */
	'p', 'q', 'r', 's', 't', 'u', 'v', 'w', 'x', 'y', 'z', '{', '|', '}', '~', '.',  /* 7x */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* 8x */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* 9x */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* Ax */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* Bx */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* Cx */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* Dx */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* Ex */
	'.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.', '.',  /* Fx */
};

/*
 *		Print out 256 bytes in characters
 *
 *		
 *		dc [entaddr]
 */
void db_display_char(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int				i, j, k;
	unsigned char xlt[256], *xaddr;
	
	xaddr = (unsigned char *)addr;
	

	for(i = 0; i < 8; i++) {								/* Print 256 bytes */
		j = 0;
		for(k = 0; k < 32; k++) {
			xlt[j] = xtran[*xaddr];
			xaddr++;
			j++;
			if((k & 3) == 3) {
				xlt[j] = ' ';
				j++;
			}
		}
		xlt[j] = 0;
		
		db_printf("%016llX   %s\n", (addr64_t)(xaddr - 32), xlt);	/* Print a line */
	}

	db_next = (db_expr_t)xaddr;


}

/*
 *		Print out 256 bytes of real storage
 *
 *		Displays the entry and 15 before it in newest to oldest order
 *		
 *		dr [entaddr]
 */
void db_display_real(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int				i;
	unsigned int xbuf[8];

	for(i=0; i<8; i++) {									/* Print 256 bytes */
		ReadReal(addr, &xbuf[0]);							/* Get the real storage data */
		db_printf("%016llX   %08X %08X %08X %08X  %08X %08X %08X %08X\n", addr,	/* Print a line */
			xbuf[0], xbuf[1], xbuf[2], xbuf[3], 
			xbuf[4], xbuf[5], xbuf[6], xbuf[7]);
		addr = addr + 0x00000020;							/* Point to next address */
	}
	db_next = addr;
}

unsigned int	dvspace = 0;

/*
 *		Print out virtual to real translation information
 *
 *		
 *		dm vaddr [space] (defaults to last entered) 
 */
void db_display_mappings(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	db_expr_t	xspace;
	pmap_t			pmap;
	addr64_t		lnextva;

	mapping_t	*mp;
	
	if (db_expression(&xspace)) {							/* Get the address space requested */
		if(xspace >= maxAdrSp) {
			db_printf("requested address space (%llX) larger than max (%X)\n", xspace, maxAdrSp - 1);
			return;
		}
		dvspace = xspace;									/* Get the space or set default */
	}
	
	db_printf("mapping information for %016llX in space %8X:\n", addr, dvspace);

	pmap = pmapTrans[dvspace].pmapVAddr;					/* Find the pmap address */
	if(!pmap) {												/* The pmap is not in use */
		db_printf("The space %X is not assigned to a pmap\n", dvspace);	/* Say we are wrong */
		return;
	}

	mp = hw_find_map(pmap, (addr64_t)addr, &lnextva);		/* Try to find the mapping for this address */
	if((unsigned int)mp == mapRtBadLk) {					/* Did we lock up ok? */
		db_printf("Timeout locking physical entry for virtual address %016ll8X\n", addr);	
		return;
	}
	
	if(!mp) {												/* Did we find one? */
		db_printf("Not mapped\n");	
		return;												/* Didn't find any, return FALSE... */
	}
	
	mapping_drop_busy(mp);									/* The mapping shouldn't be changing */

	db_dumpmapping(mp);										/* Dump it all out */

	return;													/* Tell them we did it */


}

/*
 *		Print out hash table data
 *
 *		
 *		dh vaddr [space] (defaults to last entered) 
 */
void db_display_hash(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	db_expr_t		xspace;
	unsigned int	seg, vsid, ptegindex, htsize;
	pmap_t			pmap;
	addr64_t		lnextva, llva, vpn, esid;
	uint64_t		hash;
	int 			s4bit;

	llva = (addr64_t)((unsigned int)addr);					/* Make sure we are 64-bit now */
	
	s4bit = !((PerProcTable[0].ppe_vaddr->pf.Available & pf64Bit) == 0);	/* Are we a big guy? */
	if (db_expression(&xspace)) {							/* Get the address space requested */
		if(xspace >= maxAdrSp) {
			db_printf("requested address space (%llX) larger than max (%X)\n", xspace, maxAdrSp - 1);
			return;
		}
		dvspace = xspace;									/* Get the space or set default */
	}
	
	pmap = pmapTrans[dvspace].pmapVAddr;					/* Find the pmap address */
	if(!pmap) {												/* The pmap is not in use */
		db_printf("The space %X is not assigned to a pmap\n", dvspace);	/* Say we are wrong */
		return;
	}

	hash = (uint64_t)pmap->space | ((uint64_t)pmap->space << maxAdrSpb) | ((uint64_t)pmap->space << (2 * maxAdrSpb));	/* Get hash value */
	hash = hash & 0x0000001FFFFFFFFF;						/* Make sure we stay within supported ranges */
	
	esid = ((llva >> 14) & -maxAdrSp) ^ hash;				/* Get ESID */
	llva = ((llva >> 12) & 0xFFFF) ^ esid;					/* Get index into hash table */

	if(s4bit) htsize = hash_table_size >> 7;				/* Get number of entries in hash table for 64-bit */
	else htsize = hash_table_size >> 6;						/* get number of entries in hash table for 32-bit */
	
	ptegindex = llva & (htsize - 1);						/* Get the index to the pteg and pca */
	db_dumppca(ptegindex);									/* dump the info */
	
	return;													/* Tell them we did it */


}

/*
 *		Displays all of the in-use pmaps in the system.
 *
  *		dp
 */
void db_display_pmap(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	pmap_t			pmap;
	int i;
	unsigned int v0, v1, st0, st1;
	
	pmap = (pmap_t)addr;
	if(!have_addr) pmap = kernel_pmap;						/* Start at the beginning */
	
	db_printf("PMAP     (real)            Next     Prev     Space    Flags    Ref      spaceNum Resident Wired\n"); 
//	           xxxxxxxx rrrrrrrrrrrrrrrr  xxxxxxxx pppppppp ssssssss cccccccc vvvvvvvv nnnnnnnn rrrrrrrr wwwwwwwww
	while(1) {												/* Do them all */
		db_printf("%08X %016llX  %08X %08X %08X %08X %08X %08X %08X %08X\n",
			pmap, (addr64_t)pmap ^ pmap->pmapvr,
			pmap->pmap_link.next,  pmap->pmap_link.prev,
			pmap->space, pmap->pmapFlags, pmap->ref_count, pmap->spaceNum,
			pmap->stats.resident_count,
			pmap->stats.wired_count);

		db_printf("lists = %d, rand = %08X, visits = %016llX, searches = %08X\n",
			pmap->pmapCurLists, pmap->pmapRandNum,
			pmap->pmapSearchVisits, pmap->pmapSearchCnt); 

		db_printf("cctl = %08X, SCSubTag = %016llX\n",
			pmap->pmapCCtl, pmap->pmapSCSubTag); 
		
		for(i = 0; i < 16; i +=2) {
			v0 = (pmap->pmapCCtl >> (31 - i) & 1);			/* Get high order bit */
			v1 = (pmap->pmapCCtl >> (30 - i) & 1);			/* Get high order bit */
			st0 = (pmap->pmapSCSubTag >> (60 - (4 * i))) & 0xF;	/* Get the sub-tag */
			st1 = (pmap->pmapSCSubTag >> (56 - (4 * i))) & 0xF;	/* Get the sub-tag */
			
			db_printf("         %01X %01X %016llX/%016llX  %01X %01X %016llX/%016llX\n", 
				v0, st0, pmap->pmapSegCache[i].sgcESID, pmap->pmapSegCache[i].sgcVSID,
				v1, st1, pmap->pmapSegCache[i+1].sgcESID, pmap->pmapSegCache[i+1].sgcVSID);
		}

		db_printf("\n");
		if(have_addr) break;								/* Do only one if address supplied */
		pmap = (pmap_t)pmap->pmap_link.next;				/* Skip to the next */
		if(pmap == kernel_pmap) break;						/* We've wrapped, we're done */
	}
	return;
}


/*
 *		Checks the pmap skip lists
 *
 *		
 *		cp pmap
 */
void db_check_pmaps(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int				i;
	unsigned int ret;
	uint64_t dumpa[32];
	pmap_t pmap;
	
	pmap = (pmap_t)addr;
	if(!have_addr) pmap = kernel_pmap;						/* If no map supplied, start with kernel */
	
	while(1) {												/* Do them all */
		ret = mapSkipListVerifyC(pmap, &dumpa);							/* Check out the map */
		if(!ret) db_printf("Skiplists verified ok, pmap = %08X\n", pmap);
		else { 
			db_printf("Verification failure at %08X, pmap = %08X\n", ret, pmap);
			for(i = 0; i < 32; i += 4) {
				db_printf("R%02d  %016llX  %016llX  %016llX  %016llX\n", i,
					dumpa[i], dumpa[i + 1], dumpa[i + 2], dumpa[i + 3]);
			}
		}
		if(have_addr) break;								/* Do only one if address supplied */
		pmap = (pmap_t)pmap->pmap_link.next;				/* Skip to the next */
		if(pmap == kernel_pmap) break;						/* We've wrapped, we're done */
	}
	
	return;

}


/*
 *		Displays iokit junk
 *
  *		di
 */

void db_piokjunk(void);

void db_display_iokit(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	db_piokjunk();

	return;
}

/*
 *		Prints out a mapping control block
 *
 */
 
void db_dumpmapping(struct mapping *mp) { 					/* Dump out a mapping */

	pmap_t pmap;
	int i;

	db_printf("Dump of mapping block: %08X,  pmap: %08X (%016llX)\n", mp, pmapTrans[mp->mpSpace].pmapVAddr, 
		pmapTrans[mp->mpSpace].pmapPAddr);			/* Header */
	db_printf("              mpFlags: %08X\n", mp->mpFlags);                 
	db_printf("              mpSpace: %04X\n", mp->mpSpace);                 
	db_printf("              mpBSize: %04X\n", mp->u.mpBSize);                 
	db_printf("                mpPte: %08X\n", mp->mpPte);                 
	db_printf("              mpPAddr: %08X\n", mp->mpPAddr);                 
	db_printf("              mpVAddr: %016llX\n", mp->mpVAddr);                 
	db_printf("              mpAlias: %016llX\n", mp->mpAlias);                 
	db_printf("             mpList00: %016llX\n", mp->mpList0);                 
	
	for(i = 1; i < (mp->mpFlags & mpLists); i++) {			/* Dump out secondary physical skip lists */
		db_printf("             mpList%02d: %016llX\n", i, mp->mpList[i - 1]);     
	}
	            
	return;
}

/*
 *		Prints out a PTEG and PCA
 *
 */
 
void db_dumppca(unsigned int ptegindex) { 	

	addr64_t pteg, pca, llva;	
	unsigned int xpteg[32], xpca[8], space, hash, pva, seg, api, va;
	int i, s4bit;
	unsigned long long llslot, llseg, llhash;

	s4bit = !((PerProcTable[0].ppe_vaddr->pf.Available & pf64Bit) == 0);	/* Are we a big guy? */

	pteg = hash_table_base + (ptegindex << 6);				/* Point to the PTEG */
	if(s4bit) pteg = hash_table_base + (ptegindex << 7);	/* Point to the PTEG */
	pca  = hash_table_base - ((ptegindex + 1) * 4);			/* Point to the PCA */
	db_printf("PTEG = %016llX, PCA = %016llX (index = %08X)\n", pteg, pca, ptegindex);
	
	ReadReal(pteg, &xpteg[0]);								/* Get first half of the pteg */
	ReadReal(pteg + 0x20, &xpteg[8]);						/* Get second half of the pteg */
	ReadReal(pca, &xpca[0]);								/* Get pca */

	db_printf("PCA: free = %02X, steal = %02X, auto = %02X, misc = %02X\n", 
		((xpca[0] >> 24) & 255), ((xpca[0] >> 16) & 255), ((xpca[0] >> 8) & 255), xpca[0] & 255);
		
	if(!s4bit) {											/* Little guy? */

		for(i = 0; i < 16; i += 2) {						/* Step through pteg */
			db_printf("%08X %08X - ", xpteg[i], xpteg[i + 1]);	/* Dump the pteg slot */
			
			if(xpteg[i] & 0x80000000) db_printf("  valid - ");	/* Is it valid? */
			else db_printf("invalid - ");					/* Nope, invalid */
		
			space = (xpteg[i] >> 7) & (maxAdrSp - 1);		/* Extract the space */
			hash = space | (space << maxAdrSpb) | (space << (2 * maxAdrSpb));	/* Get the hash */
			pva =  ptegindex ^ hash;						/* Get part of the vaddr */
			seg = (xpteg[i] >> 7) ^ hash;					/* Get the segment number */
			api = (xpteg[i] & 0x3F);						/* Get the API */
			va = ((seg << (28 - maxAdrSpb)) & 0xF0000000) | (api << 22) | ((pva << 12) & 0x003FF000);	/* Get the vaddr */
			db_printf("va = %08X\n", va);
		}
	}
	else {
		ReadReal(pteg + 0x40, &xpteg[16]);					/* Get third half of the pteg */
		ReadReal(pteg + 0x60, &xpteg[24]);					/* Get fourth half of the pteg */

		for(i = 0; i < 32; i += 4) {						/* Step through pteg */
			db_printf("%08X%08X %08X%08X - ", xpteg[i], xpteg[i + 1], xpteg[i + 2], xpteg[i + 3]);	/* Dump the pteg slot */
			
			if(xpteg[i + 1] & 1) db_printf("  valid - ");	/* Is it valid? */
			else db_printf("invalid - ");					/* Nope, invalid */

			llslot = ((long long)xpteg[i] << 32) | (long long)xpteg[i + 1];	/* Make a long long version of this */ 
			space = (llslot >> 12) & (maxAdrSp - 1);		/* Extract the space */
			llhash = (unsigned long long)space | ((unsigned long long)space << maxAdrSpb) | ((unsigned long long)space << (2 * maxAdrSpb));	/* Get the hash */
			llhash = llhash & 0x0000001FFFFFFFFFULL;		/* Make sure we stay within supported ranges */
			pva =  (unsigned long long)ptegindex ^ llhash;	/* Get part of the vaddr */
			llseg = (llslot >> 12) ^ llhash;				/* Get the segment number */
			api = (llslot >> 7) & 0x1F;						/* Get the API */
			llva = ((llseg << (28 - maxAdrSpb)) & 0xFFFFFFFFF0000000ULL) | (api << 23) | ((pva << 12) & 0x007FF000);	/* Get the vaddr */
			db_printf("va = %016llX\n", llva);
		}
	}

	return;
}


/*
 *		Print out 256 bytes of virtual storage
 *
 *		
 *		dv [entaddr] [space]
 *		address must be on 32-byte boundary.  It will be rounded down if not
 */
void db_display_virtual(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int			i, size, lines, rlines;
	unsigned int 	xbuf[8];
	db_expr_t	xspace;
	pmap_t		pmap;

	mapping_t	*mp, *mpv;
	addr64_t	pa;
	ppnum_t		pnum;

	if (db_expression(&xspace)) {							/* Parse the space ID */
		if(xspace >= (1 << maxAdrSpb)) {					/* Check if they gave us a sane space number */
			db_printf("Invalid space ID: %llX - max is %X\n", xspace, (1 << maxAdrSpb) - 1);
			return;
		}
		dvspace = xspace;									/* Get the space or set default */
	}
	
	pmap = (pmap_t)pmapTrans[dvspace].pmapVAddr;			/* Find the pmap address */
	if((unsigned int)pmap == 0) {							/* Is there actually a pmap here? */
		db_printf("Address space not found: %X\n", dvspace);	/* Complain */
		return;
	}
	
	addr &= -32;
	
	size = 4096 - (addr & 0x00000FFF);						/* Bytes left on page */
	lines = size / 32;										/* Number of lines in first or only part */
	if(lines > 8) lines = 8;
	rlines = 8 - lines;
	if(rlines < 0) lines = 0;
	
	db_printf("Dumping %016llX (pmap = %08X, space = %X); ", addr, pmap, dvspace);

	pnum = pmap_find_phys(pmap, (addr64_t)addr);			/* Phynd the Physical */
	if(!pnum) {												/* Did we find one? */
		db_printf("Not mapped\n");	
		return;												/* Didn't find any, return FALSE... */
	}

	pa = (addr64_t)(pnum << 12) | (addr64_t)(addr & 0xFFF);	/* Get the physical address */
	db_printf("phys = %016llX\n", pa);

	for(i=0; i<lines; i++) {								/* Print n bytes */
		ReadReal(pa, &xbuf[0]);								/* Get the real storage data */
		db_printf("%016llX   %08X %08X %08X %08X  %08X %08X %08X %08X\n", addr,	/* Print a line */
			xbuf[0], xbuf[1], xbuf[2], xbuf[3], 
			xbuf[4], xbuf[5], xbuf[6], xbuf[7]);
		addr = (db_expr_t)(addr + 0x00000020);				/* Point to next address */
		pa = pa + 0x00000020;								/* Point to next address */
	}
	db_next = addr;
	
	if(!rlines) return;
	
	db_printf("Dumping %016llX (pmap = %08X, space = %X); ", addr, pmap, dvspace);

	pnum = pmap_find_phys(pmap, (addr64_t)((unsigned int)addr));	/* Phynd the Physical */
	if(!pnum) {												/* Did we find one? */
		db_printf("Not mapped\n");	
		return;												/* Didn't find any, return FALSE... */
	}

	pa = (addr64_t)(pnum << 12) | (addr64_t)((unsigned int)addr & 0xFFF);	/* Get the physical address */
	db_printf("phys = %016llX\n", pa);

	for(i=0; i<rlines; i++) {								/* Print n bytes */
		ReadReal(pa, &xbuf[0]);								/* Get the real storage data */
		db_printf("%016llX   %08X %08X %08X %08X  %08X %08X %08X %08X\n", addr,	/* Print a line */
			xbuf[0], xbuf[1], xbuf[2], xbuf[3], 
			xbuf[4], xbuf[5], xbuf[6], xbuf[7]);
		addr = (db_expr_t)(addr + 0x00000020);				/* Point to next address */
		pa = pa + 0x00000020;								/* Point to next address */
	}
	db_next = addr;


}


/*
 *		Print out savearea stuff
 *
 *		
 *		ds 
 */

#define chainmax 32

void db_display_save(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int				i, j, totsaves, tottasks, taskact, chainsize, vmid, didvmhead;
	processor_set_t	pset = &default_pset;
	task_t			task;
	thread_act_t	act;
	savearea		*save;
	vmmCntrlTable	*CTable;
	
	tottasks = 0;
	totsaves = 0;
	
	for(task = (task_t)pset->tasks.next; task != (task_t)&pset->tasks.next; task = (task_t)task->pset_tasks.next) {	/* Go through the tasks */
		taskact = 0;								/* Reset activation count */
		db_printf("\nTask %4d @%08X:\n", tottasks, task);	/* Show where we're at */
		for(act = (thread_act_t)task->threads.next; act != (thread_act_t)&task->threads; act = (thread_act_t)act->task_threads.next) {	/* Go through activations */
			db_printf("   Act %4d @%08X - p: %08X  current context: %08X\n",
					  taskact, act, act->machine.pcb, act->machine.curctx);					
					
			save = (savearea *)act->machine.pcb; 		/* Set the start of the normal chain */
			chainsize = 0;
			
			db_printf("      General context - fp: %08X  fl: %08X  fc: %d  vp: %08X  vl: %08X  vp: %d\n",
				act->machine.facctx.FPUsave, act->machine.facctx.FPUlevel, act->machine.facctx.FPUcpu, 		
				act->machine.facctx.VMXsave, act->machine.facctx.VMXlevel, act->machine.facctx.VMXcpu);
			
			while(save) {							/* Do them all */
				totsaves++;							/* Count savearea */
				db_printf("         Norm %08X: %016llX %016llX - tot = %d\n", save, save->save_srr0, save->save_srr1, totsaves);
				save = (savearea *)save->save_hdr.save_prev;	/* Next one */
				if(chainsize++ > chainmax) {		/* See if we might be in a loop */
					db_printf("         Chain terminated by count (%d) before %08X\n", chainmax, save);
					break;
				}
			}
			
			save = (savearea *)act->machine.facctx.FPUsave; 	/* Set the start of the floating point chain */
			chainsize = 0;
			while(save) {							/* Do them all */
				totsaves++;							/* Count savearea */
				db_printf("         FPU  %08X: %08X - tot = %d\n", save, save->save_hdr.save_level, totsaves);
				save = (savearea *)save->save_hdr.save_prev;	/* Next one */
				if(chainsize++ > chainmax) {		/* See if we might be in a loop */
					db_printf("         Chain terminated by count (%d) before %08X\n", chainmax, save);
					break;
				}
			}
			
			save = (savearea *)act->machine.facctx.VMXsave; 	/* Set the start of the floating point chain */
			chainsize = 0;
			while(save) {							/* Do them all */
				totsaves++;							/* Count savearea */
				db_printf("         Vec  %08X: %08X - tot = %d\n", save, save->save_hdr.save_level, totsaves);
				save = (savearea *)save->save_hdr.save_prev;	/* Next one */
				if(chainsize++ > chainmax) {		/* See if we might be in a loop */
					db_printf("         Chain terminated by count (%d) before %08X\n", chainmax, save);
					break;
				}
			}
			
			if(CTable = act->machine.vmmControl) {		/* Are there virtual machines? */
				
				for(vmid = 0; vmid < kVmmMaxContexts; vmid++) {
					
					if(!(CTable->vmmc[vmid].vmmFlags & vmmInUse)) continue;	/* Skip if vm is not in use */
					
					if(!CTable->vmmc[vmid].vmmFacCtx.FPUsave && !CTable->vmmc[vmid].vmmFacCtx.VMXsave) continue;	/* If neither types, skip this vm */
					
					db_printf("      VMachine ID %3d - fp: %08X  fl: %08X  fc: %d  vp: %08X  vl: %08X  vp: %d\n", vmid,	/* Title it */
						CTable->vmmc[vmid].vmmFacCtx.FPUsave, CTable->vmmc[vmid].vmmFacCtx.FPUlevel, CTable->vmmc[vmid].vmmFacCtx.FPUcpu, 		
						CTable->vmmc[vmid].vmmFacCtx.VMXsave, CTable->vmmc[vmid].vmmFacCtx.VMXlevel, CTable->vmmc[vmid].vmmFacCtx.VMXcpu
					);
					
					save = (savearea *)CTable->vmmc[vmid].vmmFacCtx.FPUsave; 	/* Set the start of the floating point chain */
					chainsize = 0;
					while(save) {						/* Do them all */
						totsaves++;						/* Count savearea */
						db_printf("         FPU  %08X: %08X - tot = %d\n", save, save->save_hdr.save_level, totsaves);
						save = (savearea *)save->save_hdr.save_prev;	/* Next one */
						if(chainsize++ > chainmax) {	/* See if we might be in a loop */
							db_printf("         Chain terminated by count (%d) before %08X\n", chainmax, save);
							break;
						}
					}
					
					save = (savearea *)CTable->vmmc[vmid].vmmFacCtx.VMXsave; 	/* Set the start of the floating point chain */
					chainsize = 0;
					while(save) {						/* Do them all */
						totsaves++;						/* Count savearea */
						db_printf("         Vec  %08X: %08X - tot = %d\n", save, save->save_hdr.save_level, totsaves);
						save = (savearea *)save->save_hdr.save_prev;	/* Next one */
						if(chainsize++ > chainmax) {	/* See if we might be in a loop */
							db_printf("         Chain terminated by count (%d) before %08X\n", chainmax, save);
							break;
						}
					}
				}
			}
			taskact++;
		}
		tottasks++;
	}
	
	db_printf("Total saveareas accounted for: %d\n", totsaves);
	return;
}

/*
 *		Print out extra registers
 *
 *		
 *		dx 
 */

extern unsigned int dbfloats[33][2];
extern unsigned int dbvecs[33][4];
extern unsigned int dbspecrs[336];

void db_display_xregs(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int				i, j, pents;

	stSpecrs(dbspecrs);										/* Save special registers */
	if(PerProcTable[0].ppe_vaddr->pf.Available & pf64Bit) {
		db_printf("PIR:    %08X\n", dbspecrs[0]);
		db_printf("PVR:    %08X\n", dbspecrs[1]);
		db_printf("SDR1:   %08X.%08X\n", dbspecrs[26], dbspecrs[27]);
		db_printf("HID0:   %08X.%08X\n", dbspecrs[28], dbspecrs[29]);
		db_printf("HID1:   %08X.%08X\n", dbspecrs[30], dbspecrs[31]);
		db_printf("HID4:   %08X.%08X\n", dbspecrs[32], dbspecrs[33]);
		db_printf("HID5:   %08X.%08X\n", dbspecrs[34], dbspecrs[35]);
		db_printf("SPRG0:  %08X.%08X %08X.%08X\n", dbspecrs[18], dbspecrs[19], dbspecrs[20], dbspecrs[21]);
		db_printf("SPRG2:  %08X.%08X %08X.%08X\n", dbspecrs[22], dbspecrs[23], dbspecrs[24], dbspecrs[25]);
		db_printf("\n");
		for(i = 0; i < (64 * 4); i += 4) {
			db_printf("SLB %02d: %08X.%08X %08X.%08X\n", i / 4, dbspecrs[80 + i], dbspecrs[81 + i], dbspecrs[82 + i], dbspecrs[83 + i]);
		}
	}
	else {	
		db_printf("PIR:    %08X\n", dbspecrs[0]);
		db_printf("PVR:    %08X\n", dbspecrs[1]);
		db_printf("SDR1:   %08X\n", dbspecrs[22]);
		db_printf("HID0:   %08X\n", dbspecrs[39]);
		db_printf("HID1:   %08X\n", dbspecrs[40]);
		db_printf("L2CR:   %08X\n", dbspecrs[41]);
		db_printf("MSSCR0: %08X\n", dbspecrs[42]);
		db_printf("MSSCR1: %08X\n", dbspecrs[43]);
		db_printf("THRM1:  %08X\n", dbspecrs[44]);
		db_printf("THRM2:  %08X\n", dbspecrs[45]);
		db_printf("THRM3:  %08X\n", dbspecrs[46]);
		db_printf("ICTC:   %08X\n", dbspecrs[47]);
		db_printf("L2CR2:  %08X\n", dbspecrs[48]);
		db_printf("DABR:   %08X\n", dbspecrs[49]);
	
		db_printf("DBAT: %08X %08X %08X %08X\n", dbspecrs[2], dbspecrs[3], dbspecrs[4], dbspecrs[5]);
		db_printf("      %08X %08X %08X %08X\n", dbspecrs[6], dbspecrs[7], dbspecrs[8], dbspecrs[9]);
		db_printf("IBAT: %08X %08X %08X %08X\n", dbspecrs[10], dbspecrs[11], dbspecrs[12], dbspecrs[13]);
		db_printf("      %08X %08X %08X %08X\n", dbspecrs[14], dbspecrs[15], dbspecrs[16], dbspecrs[17]);
		db_printf("SPRG: %08X %08X %08X %08X\n", dbspecrs[18], dbspecrs[19], dbspecrs[20], dbspecrs[21]);
		db_printf("\n");
		for(i = 0; i < 16; i += 8) {						/* Print 8 at a time */
			db_printf("SR%02d: %08X %08X %08X %08X %08X %08X %08X %08X\n", i,
				dbspecrs[23+i], dbspecrs[24+i], dbspecrs[25+i], dbspecrs[26+i], 
				dbspecrs[27+i], dbspecrs[28+i], dbspecrs[29+i], dbspecrs[30+i]); 
		}
	}
	
	db_printf("\n");

	stFloat(dbfloats);										/* Save floating point registers */
	for(i = 0; i < 32; i += 4) {							/* Print 4 at a time */
		db_printf("F%02d: %08X %08X  %08X %08X  %08X %08X  %08X %08X\n", i,
			dbfloats[i][0], dbfloats[i][1], dbfloats[i+1][0], dbfloats[i+1][1], 
			dbfloats[i+2][0], dbfloats[i+2][1], dbfloats[i+3][0], dbfloats[i+3][1]); 
	}
	db_printf("FCR: %08X %08X\n", dbfloats[32][0], dbfloats[32][1]);	/* Print FSCR */
	
	if(!stVectors(dbvecs)) return;							/* Return if not Altivec capable */
	
	db_printf("\n");
	
	for(i = 0; i < 32; i += 2) {							/* Print 2 at a time */
		db_printf("V%02d: %08X %08X %08X %08X  %08X %08X %08X %08X\n", i,
			dbvecs[i][0], dbvecs[i][1], dbvecs[i][2], dbvecs[i][3], 
			dbvecs[i+1][0], dbvecs[i+1][1], dbvecs[i+1][2], dbvecs[i+1][3]); 
	}
	db_printf("VCR: %08X %08X %08X %08X\n", dbvecs[32][0], dbvecs[32][1], dbvecs[32][2], dbvecs[32][3]);	/* Print VSCR */

	return;													/* Tell them we did it */


}

/*
 *		Check check mappings and hash table for consistency
 *
  *		cm
 */
void db_check_mappings(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	addr64_t  pteg, pca, llva, lnextva;	
	unsigned int xpteg[32], xpca[8], space, hash, pva, seg, api, va, free, free2, xauto, PTEGcnt, wimgkk, wimgxx, slotoff;
	int i, j, fnderr, slot, slot2, k, s4bit;
	pmap_t pmap;
	mapping_t *mp;
	ppnum_t ppn, pa, aoff;
	unsigned long long llslot, llseg, llhash;
	
	s4bit = 0;												/* Assume dinky? */
	if(PerProcTable[0].ppe_vaddr->pf.Available & pf64Bit) s4bit = 1;	/* Are we a big guy? */
	
	PTEGcnt = hash_table_size / 64;							/* Get the number of PTEGS */
	if(s4bit) PTEGcnt = PTEGcnt / 2;						/* PTEGs are twice as big */	

	pteg = hash_table_base;									/* Start of hash table */
	pca = hash_table_base - 4;								/* Start of PCA */
	
	for(i = 0; i < PTEGcnt; i++) {							/* Step through them all */

		fnderr = 0;
	
		ReadReal(pteg, &xpteg[0]);							/* Get first half of the pteg */
		ReadReal(pteg + 0x20, &xpteg[8]);					/* Get second half of the pteg */
		if(s4bit) {											/* See if we need the other half */
			ReadReal(pteg + 0x40, &xpteg[16]);				/* Get third half of the pteg */
			ReadReal(pteg + 0x60, &xpteg[24]);				/* Get fourth half of the pteg */
		}
		ReadReal(pca, &xpca[0]);							/* Get pca */
	
		if(xpca[0] & 0x00000001) {							/* Is PCA locked? */
			db_printf("Unexpected locked PCA\n");			/* Yeah, this may be bad */
			fnderr = 1;										/* Remember to print the pca/pteg pair later */
		}

		free = 0x80000000;
		
		for(j = 0; j < 7; j++) {							/* Search for duplicates */
			slot = j * 2;									/* Point to the slot */
			if(s4bit) slot = slot * 2;						/* Adjust for bigger slots */
			if(!(xpca[0] & free)) {							/* Check more if slot is allocated */
				for(k = j + 1; k < 8; k++) {				/* Search remaining slots */
					slot2 = k * 2;							/* Point to the slot */
					if(s4bit) slot2 = slot2 * 2;			/* Adjust for bigger slots */
					if((xpteg[slot] == xpteg[slot2]) 
					   && (!s4bit || (xpteg[slot + 1] == xpteg[slot2 + 1]))) {		/* Do we have duplicates? */
						db_printf("Duplicate tags in pteg, slot %d and slot %d\n", j, k);
						fnderr = 1;
					}
				}
			}
			free = free >> 1;								/* Move slot over */
		}
		
		free = 0x80000000;
		xauto = 0x00008000;

		for(j = 0; j < 8; j++) {							/* Step through the slots */
		
			slot = j * 2;									/* Point to the slot */
			if(s4bit) slot = slot * 2;						/* Hagfish? */
			if(xpca[0] & free) {							/* Check if marked free */
				if((!s4bit && (xpteg[slot] & 0x80000000))	/* Is a supposedly free slot valid? */
				   || (s4bit && (xpteg[slot + 1] & 1))) {	
					db_printf("Free slot still valid - %d\n", j);	
					fnderr = 1;
				}	
			}
			else {											/* We have an in use slot here */
								
				if(!(!s4bit && (xpteg[slot] & 0x80000000))	/* Is a supposedly in use slot valid? */
				   && !(s4bit && (xpteg[slot + 1] & 1))) {	
					db_printf("Inuse slot not valid - %d\n", j);	
					fnderr = 1;
				}	
				else {										/* Slot is valid, check mapping */
					if(!s4bit) {							/* Not Hagfish? */
						space = (xpteg[slot] >> 7) & (maxAdrSp - 1);	/* Extract the space */
						hash = space | (space << maxAdrSpb) | (space << (2 * maxAdrSpb));	/* Get the hash */
						pva =  i ^ hash;					/* Get part of the vaddr */
						seg = (xpteg[slot] >> 7) ^ hash;	/* Get the segment number */
						api = (xpteg[slot] & 0x3F);			/* Get the API */
						va = ((seg << (28 - maxAdrSpb)) & 0xF0000000) | (api << 22) | ((pva << 12) & 0x003FF000);	/* Get the vaddr */
						llva = (addr64_t)va;				/* Make this a long long */
						wimgxx = xpteg[slot + 1] & 0x7F;	/* Get the wimg and pp */
						ppn = xpteg[slot + 1] >> 12;		/* Get physical page number */
						slotoff = (i * 64) + (j * 8) | 1;	/* Get offset to slot and valid bit */
					}
					else {									/* Yes, Hagfish */
						llslot = ((long long)xpteg[slot] << 32) | (long long)xpteg[slot + 1];	/* Make a long long version of this */ 
						space = (llslot >> 12) & (maxAdrSp - 1);	/* Extract the space */
						llhash = (unsigned long long)space | ((unsigned long long)space << maxAdrSpb) | ((unsigned long long)space << (2 * maxAdrSpb));	/* Get the hash */
						llhash = llhash & 0x0000001FFFFFFFFFULL;	/* Make sure we stay within supported ranges */
						pva =  i ^ llhash;					/* Get part of the vaddr */
						llseg = ((llslot >> 12) ^ llhash);	/* Get the segment number */
						api = (llslot >> 7) & 0x1F;			/* Get the API */
						llva = ((llseg << (28 - maxAdrSpb)) & 0xFFFFFFFFF0000000ULL) | (api << 23) | ((pva << 12) & 0x007FF000);	/* Get the vaddr */
						wimgxx = xpteg[slot + 3] & 0x7F;	/* Get the wimg and pp */
						ppn =  (xpteg[slot + 2] << 20) | (xpteg[slot + 3] >> 12);	/* Get physical page number */
						slotoff = (i * 128) + (j * 16) | 1;		/* Get offset to slot and valid bit */
					}
					
					pmap = pmapTrans[space].pmapVAddr;	/* Find the pmap address */
					if(!pmap) {								/* The pmap is not in use */
						db_printf("The space %08X is not assigned to a pmap, slot = %d\n", space, slot);	/* Say we are wrong */
						fnderr = 1;
						goto dcmout;
					}

					if (pmap->pmapFlags & pmapVMgsaa) {
						unsigned int ret;
						mapping_t mpcopy;
						ret = hw_find_map_gv(pmap, llva, &mpcopy);
					} else {
						mp = hw_find_map(pmap, llva, &lnextva);		/* Try to find the mapping for this address */
	//					db_printf("%08X - %017llX\n", mp, llva);
						if((unsigned int)mp == mapRtBadLk) {	/* Did we lock up ok? */
							db_printf("Timeout locking mapping for for virtual address %016ll8X, slot = %d\n", llva, j);	
							return;
						}
						
						if(!mp) {								/* Did we find one? */
							db_printf("Not mapped, slot = %d, va = %08X\n", j, (unsigned int)llva);	
							fnderr = 1;
							goto dcmout;
						}
						
						if((mp->mpFlags & 0xFF000000) > 0x01000000) {	/* Is busy count too high? */
							db_printf("Busy count too high, slot = %d\n", j);
							fnderr = 1;
						}
						
						if((mp->mpFlags & mpType) == mpBlock) {		/* Is this a block map? */
							if(!(xpca[0] & xauto)) {				/* Is it marked as such? */
								db_printf("mapping marked as block, PCA is not, slot = %d\n", j);
								fnderr = 1;
							}
						}
						else {									/* Is a block */
							if(xpca[0] & xauto) {				/* Is it marked as such? */
								db_printf("mapping not marked as block, PCA is, slot = %d\n", j);
								fnderr = 1;
							}
							if(mp->mpPte != slotoff) {			/* See if mapping PTEG offset is us */
								db_printf("mapping does not point to PTE, slot = %d\n", j);
								fnderr = 1;
							}
						}
					
						wimgkk = (unsigned int)mp->mpVAddr;		/* Get last half of vaddr where keys, etc are */
						wimgkk = (wimgkk ^ wimgxx) & 0x7F;		/* XOR to find differences from PTE */
						if(wimgkk) {							/* See if key in PTE is what we want */
							db_printf("key or WIMG does not match, slot = %d\n", j);
							fnderr = 1;
						}
						
						aoff = (ppnum_t)((llva >> 12) - (mp->mpVAddr >> 12));	/* Get the offset from vaddr */
						pa = aoff + mp->mpPAddr;				/* Get the physical page number we expect */
						if(pa != ppn) {							/* Is physical address expected? */
							db_printf("Physical address does not match, slot = %d\n", j);
							fnderr = 1;
						}
		
						mapping_drop_busy(mp);					/* We're done with the mapping */
					}
				}
				
			}
dcmout:
			free = free >> 1;
			xauto = xauto >> 1;
		}


		if(fnderr)db_dumppca(i);							/* Print if error */

		pteg = pteg + 64;									/* Go to the next one */
		if(s4bit) pteg = pteg + 64;							/* Hagfish? */
		pca = pca - 4;										/* Go to the next one */


	}

	return;
}

/*
 *		Displays all of the kmods in the system.
 *
  *		dp
 */
void db_display_kmod(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	kmod_info_t	*kmd;
	unsigned int strt, end;
	
	kmd = kmod;							/* Start at the start */
	
	db_printf("info      addr      start    - end       name ver\n");

	while(kmd) {						/* Dump 'em all */
		strt = (unsigned int)kmd->address + kmd->hdr_size;	/* Get start of kmod text */
		end = (unsigned int)kmd->address + kmd->size;			/* Get end of kmod */
		db_printf("%08X  %08X  %08X - %08X: %s, %s\n", kmd, kmd->address, strt, end, 
			kmd->name, kmd->version);
		kmd = kmd->next;				/* Step to it */
	}

	return;
}

/*
 *		Displays stuff
 *
  *		gs
 */
unsigned char xxgpo[36] = {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

void db_gsnoop(db_expr_t addr, int have_addr, db_expr_t count, char * modif) {

	int i, j;
	unsigned char *gp, gpn[36];
#define ngpr 34
	
	gp = (unsigned char *)0x8000005C;
	
	for(i = 0; i < ngpr; i++) gpn[i] = gp[i];	/* Copy 'em */
	
	for(i = 0; i < ngpr; i++) {
		db_printf("%02X ", gpn[i]);
	}
	db_printf("\n");
	
	for(i = 0; i < ngpr; i++) {
		if(gpn[i] != xxgpo[i]) db_printf("^^ ");
		else  db_printf("   ");
	}
	db_printf("\n");
	
	for(i = 0; i < ngpr; i++) xxgpo[i] = gpn[i];	/* Save 'em */

	return;
}


void Dumbo(void);
void Dumbo(void){
}
