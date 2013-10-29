#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <sys/kern_memorystatus.h>

#define PAGESIZE 4096

/* Trigger forced jetsam */
#define MEMORYSTATUS_CMD_TEST_JETSAM                  1000

static void
dirty_chunk(void *chunk, int chunk_size)
{
	int i;
	char *p;

	// Dirty every word in the chunk.
	for (p = chunk; p < (char *)chunk + (chunk_size * 1024 * 1024); p += 4) {
		*p = 'Z';
	}
}

char *pname;

void usage(void) {
	printf("usage: %s [-re] [-l MB] [-w MB] [-m MB] [-o num] [-k pid] <chunk_size in MB> <interval in milliseconds>\n", pname);
	printf("\t-r: after reaching max, re-dirty it all when the user prompts to do so.\n");
	printf("\t-l: program the task's physical footprint limit to this value (in MB).\n");
	printf("\t-w: program the task's jetsam high watermark to this value (in MB).\n");
	printf("\t-m: dirty no more than this amount (in MB).\n");
	printf("\t-e: exit after reaching -m max dirty.\n");
	printf("\t-o: oscillate at the max this number of times and then continue on up.\n");
	printf("\t-k: trigger explicit jetsam kill of this pid (and then exit).\n");
}

int main(int argc, char *argv[])
{
	int ch;
	void **chunks;
	int nchunks;
	int max_chunks;
	int oscillations = -1;
	int tot_mb = 0;
	int chunk_size;
	int interval;
	int max = -1;
	int limit = -2;
	int high_watermark = -1;
	int victim = -1;
	int old_limit;
	boolean_t redirty = FALSE;
	boolean_t exit_after_max = FALSE;

	int oscillation_cnt = 0;
	
	pname = argv[0];

	printf("pid: %d\n", getpid());

	while ((ch = getopt(argc, argv, "rem:l:w:k:o:")) != -1) {
		switch (ch) {
		case 'm':
			max = atoi(optarg);
			break;
		case 'l':
			limit = atoi(optarg);
			break;
		case 'w':
			high_watermark = atoi(optarg);
			break;
		case 'o':
			oscillations = atoi(optarg);
			break;
		case 'r':
			redirty = TRUE;
			break;
		case 'e':
			exit_after_max = TRUE;
			break;
		case 'k':
			victim = atoi(optarg);
			break;
		case 'h':
		default:
			usage();
			exit(1);
		}
	}

	argc -= optind;
	argv += optind;

	if (victim != -1) {
		int r;
		/*
		 * int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, user_addr_t buffer, size_t buffersize);
		 */
        if ((r = memorystatus_control(MEMORYSTATUS_CMD_TEST_JETSAM, victim, 0, 0, 0)) != 0) {
        	perror("memorystatus_control");
        	exit(1);
        }
        printf("killed process %d\n", victim);

	}

	if (argc != 2) {
		usage();
		exit(1);
	}

	chunk_size = atoi(argv[0]);
	interval = atoi(argv[1]);

	if (limit != -2) {
		kern_return_t kr;
		if ((kr = task_set_phys_footprint_limit(mach_task_self(), limit, &old_limit)) != KERN_SUCCESS) {
			fprintf(stderr, "task_set_phys_footprint_limit() failed: %s\n", mach_error_string(kr));
			exit(1);
		}
		printf("phys footprint limit set to %d MB (was: %d MB)\n", limit, old_limit);
	}

	if (high_watermark != -1) {
		int r;
		/*
		 * int memorystatus_control(uint32_t command, int32_t pid, uint32_t flags, user_addr_t buffer, size_t buffersize);
		 */
        if ((r = memorystatus_control(MEMORYSTATUS_CMD_SET_JETSAM_HIGH_WATER_MARK, getpid(), high_watermark, 0, 0)) != 0) {
        	perror("memorystatus_control");
        	exit(1);
        }
        printf("high watermark set to %d MB\n", high_watermark);
	}

	printf("consuming memory in chunks of %d MB every %d milliseconds.\n", chunk_size, interval);

	printf("total consumed:      ");
	fflush(stdout);

	/*
	 * Estimate max number of chunks possible, using 4GB as absolute max amount of memory
	 * we could ever use.
	 */
	max_chunks = 4000 / chunk_size;
	if ((chunks = calloc(max_chunks, sizeof (*chunks))) == NULL) {
		perror("malloc");
		exit(1);
	}
	nchunks = 0;

	while (1) {
		if ((chunks[nchunks] = malloc(chunk_size * 1024 * 1024)) == NULL) {
			perror("malloc");
			exit(1);
		}
	
		tot_mb += chunk_size;

		dirty_chunk(chunks[nchunks], chunk_size);

		nchunks++;

		putchar(0x8); putchar(0x8); putchar(0x8); putchar(0x8);
		printf("%4d", tot_mb);
		fflush(stdout);

		if ((max != -1) && (tot_mb > max)) {
			printf("\nMax reached.\n");

			if (exit_after_max) {
				exit(0);
			}

			if ((oscillations == -1) || (oscillation_cnt < oscillations)) {
				if (redirty) {
					while (1) {
						int i, ch;

						printf("Press any key to re-dirty ('q' to quit)...");
						fflush(stdout);
						if ((ch = getchar()) == 'q') {
							exit(0);
						}

						for (i = 0; i < nchunks; i++) {
							dirty_chunk(chunks[i], chunk_size);
						}
					}
				}

				/*
				 * We've broken the limit of what we should be consuming; free the
				 * most recent three chunks and go round again.
				 */
				nchunks--;
				free(chunks[nchunks]);
				chunks[nchunks] = NULL;
				tot_mb -= chunk_size;

				if (nchunks > 1) {
					nchunks--;
					free(chunks[nchunks]);
					chunks[nchunks] = NULL;			 	
					tot_mb -= chunk_size;
					nchunks--;
					free(chunks[nchunks]);
					chunks[nchunks] = NULL;			 	
					tot_mb -= chunk_size;
				}

				oscillation_cnt++;
			}
		}

		usleep(interval * 1000);
	}

	return (1);
}
