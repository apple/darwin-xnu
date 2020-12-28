#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <time.h>

#define SUPERPAGE_SIZE (2*1024*1024)
#define SUPERPAGE_MASK (-SUPERPAGE_SIZE)
#define SUPERPAGE_ROUND_UP(a) ((a + SUPERPAGE_SIZE-1) & SUPERPAGE_MASK)

#define RUNS0 100000
#define STEP 4 /* KB */
#define START STEP
#define MAX (1024*1024) /* KB */

#define RUNS1 RUNS0
#define RUNS2 (RUNS0/20)

clock_t
testt(boolean_t superpages, int mode, int write, int kb)
{
	static int sum;
	char *data;
	unsigned int run, p, p2, i, res;
	mach_vm_address_t addr = 0;
	int pages = kb / 4;
	mach_vm_size_t  size = SUPERPAGE_ROUND_UP(pages * PAGE_SIZE); /* allocate full superpages */
	int kr;

	kr = mach_vm_allocate(mach_task_self(), &addr, size, VM_FLAGS_ANYWHERE | (superpages? VM_FLAGS_SUPERPAGE_SIZE_2MB : VM_FLAGS_SUPERPAGE_NONE));

	if (!addr) {
		return 0;
	}

	data = (char*)(long)addr;

	/* touch every base page to make sure everything is mapped and zero-filled */
	for (p = 0; p < pages; p++) {
		sum += data[p * PAGE_SIZE];
	}

	clock_t a = clock(); /* start timing */
	switch (mode) {
	case 0:         /* one byte every 4096 */
		if (write) {
			for (run = 0; run < RUNS0; run++) {
				for (p = 0; p < pages; p++) {
					data[p * PAGE_SIZE] = run & 0xFF;
				}
			}
		} else {
			for (run = 0; run < RUNS0; run++) {
				for (p = 0; p < pages; p++) {
					sum += data[p * PAGE_SIZE];
				}
			}
		}
		break;
	case 1:         /* every byte */
		if (write) {
			for (run = 0; run < RUNS1 / PAGE_SIZE; run++) {
				for (i = 0; i < pages * PAGE_SIZE; i++) {
					data[i] = run & 0xFF;
				}
			}
		} else {
			for (run = 0; run < RUNS1 / PAGE_SIZE; run++) {
				for (i = 0; i < pages * PAGE_SIZE; i++) {
					sum += data[i];
				}
			}
		}
		break;
	case 2:         /* random */
#define PRIME 15485863
#define NODE_SIZE 128           /* bytes per node */
#define NODE_ACCESSES 16        /* accesses per node */
		p = 0;
		if (write) {
			for (run = 0; run < RUNS2 * pages; run++) {
				p += PRIME;
				p2 = p % (pages * PAGE_SIZE / NODE_SIZE);
//printf("p2 = %d\n", p2);
				for (i = 0; i < NODE_ACCESSES; i++) {
					data[p2 * NODE_SIZE + i] = run & 0xFF;
				}
			}
		} else {
			for (run = 0; run < RUNS2 * pages; run++) {
				p += PRIME;
				p2 = p % (pages * PAGE_SIZE / NODE_SIZE);
				for (i = 0; i < NODE_ACCESSES; i++) {
					sum += data[p2 * NODE_SIZE + i];
				}
			}
		}
		break;
	}
	clock_t b = clock(); /* stop timing */
	mach_vm_deallocate(mach_task_self(), addr, size);
	res = b - a;
	res /= pages;
	return res;
}

int
main(int argc, char **argv)
{
	int kb;
	uint64_t time1, time2, time3, time4;

	int mode;

	printf("; m0 r s; m0 r b; m0 w s; m0 w b; m1 r s; m1 r b; m1 w s; m1 w b; m2 r s; m2 r b; m2 w s; m2 w b\n");
	for (kb = START; kb < MAX; kb += STEP) {
		printf("%d", kb);
		for (mode = 0; mode <= 2; mode++) {
			time1 = time2 = time3 = time4 = -1;
			time1 = testt(TRUE, mode, 0, kb);       // read super
			time2 = testt(FALSE, mode, 0, kb);      // read base
			time3 = testt(TRUE, mode, 1, kb);       // write super
			time4 = testt(FALSE, mode, 1, kb);      // write base
			printf("; %lld; %lld; %lld; %lld", time1, time2, time3, time4);
			fflush(stdout);
		}
		printf("\n");
	}

	return 0;
}
