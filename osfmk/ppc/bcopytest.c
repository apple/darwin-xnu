#include <debug.h>
#include <mach_kgdb.h>
#include <mach_vm_debug.h>
#include <db_machine_commands.h>

#include <kern/thread.h>
#include <mach/vm_attributes.h>
#include <mach/vm_param.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <vm/vm_page.h>
#include <kern/spl.h>

#include <kern/misc_protos.h>
#include <ppc/exception.h>
#include <ppc/misc_protos.h>
#include <ppc/proc_reg.h>

#include <vm/pmap.h>
#include <ppc/pmap.h>
#include <ppc/mem.h>

#include <ppc/new_screen.h>
#include <ppc/Firmware.h>
#include <ppc/mappings.h>
#include <ddb/db_output.h>

#include <console/video_console.h>		/* (TEST/DEBUG) */

#define patper 253


int main(void);
void clrarea(unsigned int *source, unsigned int *sink);
int tstcopy(void *src, void *snk, unsigned int lgn);
void clrarea2(unsigned int *source, unsigned int *sink);
int tstcopy2(void *src, void *snk, unsigned int lgn);
int tstcopy3(void *src, void *snk, unsigned int lgn);
int tstcopy4(void *src, void *snk, unsigned int lgn);
int tstcopy5(void *src, void *snk, unsigned int lgn);
int dumbcopy(void *src, void *snk, unsigned int lgn);


unsigned int gtick(void);


void bcopytest(void);
void bcopytest(void) {

	void *srcptr, *snkptr, *asrc, *asnk;
	int bsrc, bsnk, size, i, ret, n; 
	volatile int dbg = 0;
	unsigned int *sink, *source;
	
	kern_return_t retr;
	
	db_printf("bcopy test\n");	
	
	retr = kmem_alloc_kobject(kernel_map, (vm_offset_t *)&sink, (1024*1024)+4096);	/* Get sink area */
	if(retr != KERN_SUCCESS) {	/* Did we find any memory at all? */
		panic("bcopytest: Whoops...  no memory for sink\n");
	}
	
	retr = kmem_alloc_kobject(kernel_map, (vm_offset_t *)&source, (1024*1024)+4096);	/* Get source area */
	if(retr != KERN_SUCCESS) {	/* Did we find any memory at all? */
		panic("bcopytest: Whoops...  no memory for source\n");
	}

	db_printf("Source at %08X; Sink at %08X\n", source, sink);
	
	srcptr = (void *)&source[0];
	snkptr = (void *)&sink[0];
	
#if 1
	db_printf("Testing non-overlap case; source bndry = 0 to 7F; sink bndry = 0 - 7F; lgn = 1 to 256\n");
	for(bsrc = 0; bsrc < 128; bsrc++) {			/* Step the source by 1 */
		for(bsnk = 0; bsnk < 128; bsnk++) {		/* Step the sink by 1 */
			for(size = 1; size <= 256; size++) {	/* Step the size by 1 */
			
				clrarea(source, sink);						/* Reset source and clear sink */
				if(size == 255) {
					dbg = 99;
				}
				if(tstcopy((void *)((unsigned int)srcptr + bsrc), (void *)((unsigned int)snkptr + bsnk), size)) {	
					db_printf("Test failed; source = %02X; sink = %02X; length = %d\n", bsrc, bsnk, size);
					db_printf("failed\n");
				}
			}
		}
	}
	db_printf("Non-overlap test complete\n");
#endif


#if 1	
	db_printf("Testing overlap\n");
	for(bsrc = 1; bsrc < 128; bsrc++) {			/* Step the source by 1 */
		for(bsnk = 0; bsnk < 128; bsnk++) {		/* Step the sink by 1 */
			for(size = 1; size <= 256; size++) {	/* Step the size by 1 */
			
				clrarea2(source, sink);						/* Reset source and clear sink */
				if(bsrc < bsnk) {
					dbg = 88;
				}
				else {
					dbg = 99;
				}
				if(tstcopy2((void *)((unsigned int)srcptr + bsrc), (void *)((unsigned int)srcptr + bsnk), size)) {	
					db_printf("Test failed; source = %02X; sink = %02X; length = %d\n", bsrc, bsnk, size);
					db_printf("failed\n");
				}
			}
		}
	}
	db_printf("Overlap test complete\n");
#endif

#if 1
	db_printf("Starting exhaustive tests\n");
	for(i = 0; i < 262144 * 4; i++) {		/* Set all 1MB of source and dest to known pattern */
		((unsigned char *)srcptr)[i] = i % patper;	/* Make a non-power-of-two length pattern */
		((unsigned char *)snkptr)[i] = i % patper;	/* Make a non-power-of-two length pattern */
	}

	db_printf("No overlap; source < sink, length = 0 to 1023\nSource =");

#if 1
	for(bsrc = 0; bsrc < 128; bsrc++) {				/* Step source by 1 */
		db_printf(" %3d", bsrc);					/* Show where we're at */
		for(bsnk = 0; bsnk < 128; bsnk++) {			/* Step sink by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsrc); 			/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk + 2048);	/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, sink = %3d size = %d\n", bsrc, bsnk, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				
	db_printf("\n");
	db_printf("No overlap; source > sink, length = 0 to 1023\nSource =");

#if 1
	for(bsrc = 0; bsrc < 128; bsrc++) {				/* Step source by 1 */
		db_printf(" %3d", bsrc);					/* Show where we're at */
		for(bsnk = 0; bsnk < 128; bsnk++) {			/* Step sink by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsrc + 2048);	/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk);			/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, sink = %3d size = %d\n", bsrc, bsnk, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				
	db_printf("\n");
	db_printf("Overlap; source = sink + N (N = 0 to 127), length = 0 to 1023\nN =");

#if 1
	for(n = 0; n < 128; n++) {						/* Step n by 1 */
		db_printf(" %3d", n);					/* Show where we're at */
		for(bsnk = 0; bsnk < 128; bsnk++) {			/* Step sink by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsnk + n);	/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk);		/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, sink = %3d size = %d\n", bsrc, bsnk, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				
	db_printf("\n");
	db_printf("Overlap; source + N = sink (N = 0 to 127), length = 0 to 1023\nSource =");

#if 1
	for(bsrc = 0; bsrc < 128; bsrc++) {				/* Step source by 1 */
		db_printf(" %3d", bsrc);					/* Show where we're at */
		for(n = 0; n < 128; n++) {					/* Step N by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsnk);	/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk + n);	/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, n = %3d size = %d\n", bsrc, n, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				
				
	db_printf("\n");
	db_printf("Overlap; source = sink + N + 128 (N = 0 to 127), length = 0 to 1023\nN =");

#if 1
	for(n = 0; n < 128; n++) {						/* Step n by 1 */
		db_printf(" %3d", n);					/* Show where we're at */
		for(bsnk = 0; bsnk < 128; bsnk++) {			/* Step sink by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsnk + n + 128);	/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk);		/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, sink = %3d size = %d\n", bsrc, bsnk, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				
	db_printf("\n");
	db_printf("Overlap; source + N + 128 = sink (N = 0 to 127), length = 0 to 1023\nSource =");

#if 1
	for(bsrc = 0; bsrc < 128; bsrc++) {				/* Step source by 1 */
		db_printf(" %3d", bsrc);					/* Show where we're at */
		for(n = 0; n < 128; n++) {					/* Step N by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsnk);	/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk + n + 128);	/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, n = %3d size = %d\n", bsrc, n, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				
	db_printf("\n");
	db_printf("Overlap; source = sink + N + 256 (N = 0 to 127), length = 0 to 1023\nSource =");

#if 1
	for(n = 0; n < 128; n++) {						/* Step n by 1 */
		db_printf(" %3d", n);					/* Show where we're at */
		for(bsnk = 0; bsnk < 128; bsnk++) {			/* Step sink by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsnk + n + 256);	/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk);		/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, sink = %3d size = %d\n", bsrc, bsnk, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				
	db_printf("\n");
	db_printf("Overlap; source + N + 256 = sink (N = 0 to 127), length = 0 to 1023\nSource =");
#if 1
	for(bsrc = 0; bsrc < 128; bsrc++) {				/* Step source by 1 */
		db_printf(" %3d", bsrc);					/* Show where we're at */
		for(n = 0; n < 128; n++) {					/* Step N by 1 */
			for(size = 0; size < 1025; size++) {	/* Step size from 0 to 1023 */				
				asrc = (void *)((unsigned int)srcptr + bsnk);	/* Start byte address */
				asnk = (void *)((unsigned int)srcptr + bsnk + n + 256);	/* End byte address */
				ret = tstcopy5(asrc, asnk, size);	/* Copy and validate */
				if(ret) {	
					db_printf("\nTest failed - source = %3d, n = %3d size = %d\n", bsrc, n, size);
					db_printf("failed\n");
				}
			}
		}
	}
#endif
				





#endif
	
#if 0
	iterations = 1000;
	tottime = 0;
	totbytes = 0;
	
	db_printf("Random test starting; iterations = %d\n", iterations);
	for(i = 0; i < 262144 * 4; i++) {		/* Clear all 2MB of source (and dest for this test) */
		((unsigned char *)srcptr)[i] = i & 255;
	}
	
	for(i = 0; i < iterations; i++) {			/* Test until we are done */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		bsrc = makerand & 0x0007FFFF;			/* Generate source */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		bsnk = makerand & 0x0007FFFF;			/* Generate sink */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		size = makerand & 0x0007FFFF;			/* Generate length */
#if 1
		db_printf("rt %7d: src = %08X; sink = %08X; length = %7d\n", i, ((unsigned int)srcptr + bsrc),
			((unsigned int)srcptr + bsnk), size);
#endif

		asrc = (void *)((unsigned int)srcptr + bsrc); 
		asnk = (void *)((unsigned int)srcptr + bsnk); 
		timein = gtick();
		ret = tstcopy3(asrc, asnk, size);
		timeout = gtick();
		if(ret) {	
			db_printf("Test failed; source = %02X; sink = %02X; length = %d\n", bsrc, bsnk, size);
			db_printf("failed\n");
	
		}
		ticks = timeout - timein;				/* Get time in ticks for copy */
		tottime += ticks;
		totbytes += size;
		
		rate = (double) totbytes / (double)tottime;	/* Get bytes per tick */ 
//		rate = rate * (double)11250000.0;				/* Bytes per second */
//		rate = rate * (double)16500000.0;				/* Bytes per second */
		rate = rate * (double)tbfreq;					/* Bytes per second */
		rate = rate / (double)1000000.0;				/* Get number of MBs */
		
		db_printf("Total bytes = %lld; total time = %lld; rate = %f10\n", totbytes, tottime, rate);
		
	}
#endif


	
#if 0
	iterations = 100;
	tottime = 0;
	totbytes = 0;
	
	db_printf("Random test starting; iterations = %d\n", iterations);
	for(i = 0; i < 262144 * 4; i++) {		/* Clear all 2MB of source (and dest for this test) */
		((unsigned char *)srcptr)[i] = i & 255;
	}
	
	for(i = 0; i < iterations; i++) {			/* Test until we are done */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		bsrc = makerand & 0x0007FFFF;			/* Generate source */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		bsnk = makerand & 0x0007FFFF;			/* Generate sink */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		size = makerand & 0x0007FFFF;			/* Generate length */
#if 1
		db_printf("rt %7d: src = %08X; sink = %08X; length = %7d\n", i, ((unsigned int)srcptr + bsrc),
			((unsigned int)srcptr + bsnk), size);
#endif

		asrc = (void *)((unsigned int)srcptr + bsrc); 
		asnk = (void *)((unsigned int)srcptr + bsnk); 
		timein = gtick();
		ret = tstcopy4(asrc, asnk, size);
		timeout = gtick();
		if(ret) {	
			db_printf("Test failed; source = %02X; sink = %02X; length = %d\n", bsrc, bsnk, size);
			db_printf("failed\n");
	
		}
		ticks = timeout - timein;				/* Get time in ticks for copy */
		tottime += ticks;
		totbytes += size;
		
		rate = (double) totbytes / (double)tottime;	/* Get bytes per tick */ 
//		rate = rate * (double)11250000.0;				/* Bytes per second */
//		rate = rate * (double)16500000.0;				/* Bytes per second */
		rate = rate * (double)tbfreq;					/* Bytes per second */
		rate = rate / (double)1000000.0;				/* Get number of MBs */
		
		db_printf("Total bytes = %lld; total time = %lld; rate = %f10\n", totbytes, tottime, rate);
		
	}
#endif
	
#if 0
	iterations = 100;
	tottime = 0;
	totbytes = 0;
	
	db_printf("Random test starting; iterations = %d\n", iterations);
	for(i = 0; i < 262144 * 4; i++) {		/* Clear all 2MB of source (and dest for this test) */
		((unsigned char *)srcptr)[i] = i & 255;
	}
	
	for(i = 0; i < iterations; i++) {			/* Test until we are done */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		bsrc = makerand & 0x0007FFFF;			/* Generate source */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		bsnk = makerand & 0x0007FFFF;			/* Generate sink */
		makerand = rand() << 16 | (rand() & 0x0000FFFF);
		size = makerand & 0x0007FFFF;			/* Generate length */
#if 1
		db_printf("rt %7d: src = %08X; sink = %08X; length = %7d\n", i, ((unsigned int)srcptr + bsrc),
			((unsigned int)srcptr + bsnk), size);
#endif

		asrc = (void *)((unsigned int)srcptr + bsrc); 
		asnk = (void *)((unsigned int)srcptr + bsnk); 
		timein = gtick();
		ret = dumbcopy(asrc, asnk, size);
		timeout = gtick();
		if(ret) {	
			db_printf("Test failed; source = %02X; sink = %02X; length = %d\n", bsrc, bsnk, size);
			db_printf("failed\n");
	
		}
		ticks = timeout - timein;				/* Get time in ticks for copy */
		tottime += ticks;
		totbytes += size;
		
		rate = (double) totbytes / (double)tottime;	/* Get bytes per tick */ 
		rate = rate * (double)tbfreq;				/* Bytes per second */
		rate = rate / (double)1000000.0;			/* Get number of MBs */
		
		db_printf("Total bytes = %lld; total time = %lld; rate = %f10\n", totbytes, tottime, rate);
		
	}
#endif
	
	kmem_free(kernel_map, (vm_offset_t) sink, (1024*1024)+4096);	/* Release this mapping block */
	kmem_free(kernel_map, (vm_offset_t) source, (1024*1024)+4096);	/* Release this mapping block */
	
	if(dbg == 22) db_printf("Gabbagoogoo\n");
	return;
}

void clrarea(unsigned int *source, unsigned int *sink) {

	unsigned int i;
	
	for(i=0; i < 1024; i++) {		/* Init source & sink */
		source[i]	= 0x55555555;	/* Known pattern */
		sink[i] 	= 0xAAAAAAAA;	/* Known pattern */
	}
	return;
}

void
clrarea2(unsigned int *source, __unused unsigned int *sink)
{
	unsigned int i;
	unsigned char *ss;
	
	ss = (unsigned char *)&source[0];
	
	for(i=0; i < 1024 * 4; i++) {	/* Init source/sink */
		ss[i] = i & 0xFF;			/* Known pattern */
	}
	return;
}

int tstcopy(void *src, void *snk, unsigned int lgn) {

	unsigned int i, crap;
	
	bcopy(src, snk, lgn);
	
	for(i = 0; i < lgn; i++) {
		if(((unsigned char *)snk)[i] != 0x55) {
			crap = (unsigned int)&((unsigned char *)snk)[i];
			db_printf("bad copy at sink[%d] (%08X) it is %02X\n", i,crap, ((unsigned char *)snk)[i]);
			return 1;
		}
	}
	if(((unsigned char *)snk)[lgn] != 0xAA) {	/* Is it right? */
		crap = (unsigned int)&((unsigned char *)snk)[i];
		db_printf("Copied too far at sink[%d] (%08X) it is %02X\n", i, crap, ((unsigned char *)snk)[lgn]);
		return 1;
	}
	return 0;

}

int tstcopy2(void *src, void *snk, unsigned int lgn) {

	unsigned int i, crap;
	unsigned char ic, ec;
	
	ic = ((unsigned char *)src)[0];
	ec = ((unsigned char *)snk)[lgn];
	
	bcopy(src, snk, lgn);
	
	for(i = 0; i < lgn; i++) {
		if(((unsigned char *)snk)[i] != ic) {
			crap = (unsigned int)&((unsigned char *)snk)[i];
			db_printf("bad copy at sink[%d] (%08X) it is %02X\n", i,crap, ((unsigned char *)snk)[i]);
			return 1;
		}
		ic = (ic + 1) & 0xFF;
	}
	
	if(((unsigned char *)snk)[lgn] != ec) {	/* Is it right? */
		crap = (unsigned int)&((unsigned char *)snk)[i];
		db_printf("Copied too far at sink[%d] (%08X) it is %02X\n", i, crap, ((unsigned char *)snk)[lgn]);
		return 1;
	}
	return 0;

}

int tstcopy3(void *src, void *snk, unsigned int lgn) {

	unsigned int i, crap;
	unsigned char ic, ec, oic;
	
	oic = ((unsigned char *)snk)[0];
	ic = ((unsigned char *)src)[0];
	ec = ((unsigned char *)snk)[lgn];
	
	bcopy(src, snk, lgn);
	
	for(i = 0; i < lgn; i++) {
		if(((unsigned char *)snk)[i] != ic) {
			crap = (unsigned int)&((unsigned char *)snk)[i];
			db_printf("bad copy at sink[%d] (%08X) it is %02X\n", i ,crap, ((unsigned char *)snk)[i]);
			return 1;
		}
		ic = (ic + 1) & 0xFF;
	}
	
	if(((unsigned char *)snk)[lgn] != ec) {	/* Is it right? */
		crap = (unsigned int)&((unsigned char *)snk)[i];
		db_printf("Copied too far at sink[%d] (%08X) it is %02X\n", i, crap, ((unsigned char *)snk)[lgn]);
		return 1;
	}

	for(i=0; i < lgn; i++) {	/* Restore pattern */
		((unsigned char *)snk)[i] = oic;		
		oic = (oic + 1) & 0xFF;
	}

	return 0;

}

int tstcopy4(void *src, void *snk, unsigned int lgn) {
	
	bcopy(src, snk, lgn);
	return 0;

}

int tstcopy5(void *src, void *snk, unsigned int lgn) {

	unsigned int i = 0, crap;
	unsigned char ic, ec, oic, pc;
	
	oic = ((unsigned char *)snk)[0];				/* Original first sink character */
	ic = ((unsigned char *)src)[0];					/* Original first source character */
	ec = ((unsigned char *)snk)[lgn];				/* Original character just after last sink character */
	pc = ((unsigned char *)snk)[-1];				/* Original character just before sink */
	
	bcopy(src, snk, lgn);
	
	if(((unsigned char *)snk)[lgn] != ec) {			/* Did we copy too far forward? */
		crap = (unsigned int)&((unsigned char *)snk)[i];
		db_printf("Copied too far at sink[%d] (%08X) it is %02X\n", i, crap, ((unsigned char *)snk)[lgn]);
		return 1;
	}

	if(((unsigned char *)snk)[-1] != pc) {			/* Did we copy too far backward? */
		crap = (unsigned int)&((unsigned char *)snk)[i];
		db_printf("Copied too far at sink[%d] (%08X) it is %02X\n", i, crap, ((unsigned char *)snk)[lgn]);
		return 1;
	}

	for(i = 0; i < lgn; i++) {						/* Check sink byte sequence */
		if(((unsigned char *)snk)[i] != ic) {
			crap = (unsigned int)&((unsigned char *)snk)[i];
			db_printf("bad copy at sink[%d] (%08X) it is %02X\n", i ,crap, ((unsigned char *)snk)[i]);
			return 1;
		}
		ic = (ic + 1) % patper;
	}

	for(i=0; i < lgn; i++) {	/* Restore pattern */
		((unsigned char *)snk)[i] = oic;		
		oic = (oic + 1) % patper;
	}

	return 0;

}

int dumbcopy(void *src, void *snk, unsigned int lgn) {
	unsigned int i;
	char *p = (char *)snk;
	char *q = (char *)src;
	
	for(i = 0; i < lgn; i++) {
		*p++ = *q++;
	}
	return 0;

}













