
#include <stdio.h>
#include <stdlib.h>
#include "../aes.h"
#include <mach/mach_time.h>
#include <sys/sysctl.h>


aes_encrypt_ctx	encrypt_ctx;
aes_decrypt_ctx	decrypt_ctx;

size_t getFreq()
{
    int mib[2];
    size_t cpufreq, len;
    mib[0] = CTL_HW;
    mib[1] = HW_CPU_FREQ;
    len = sizeof(cpufreq);

    sysctl(mib, 2, &cpufreq, &len, NULL, 0);

    return  cpufreq;
}


uint32_t	cpu_freq;

main(int argc, char **argv)
{

	char	*plain;
	char	*cipher;
	char	*decrypt;

uint32_t	ITERATIONS;
uint32_t	NUM_BLOCKS;
uint32_t	data_size;

	char 	key[32];
	char 	iv[16];
	int		checksum=0;
	int		i, j, iterations;
	uint64_t    t0, t1, t2, sum=0, max_time=0, min_time=-1, sum1=0, max_time1=0, min_time1=-1;
    float       time, time_max, time_min, time1, time_max1, time_min1;

	cpu_freq = getFreq();

	if (cpu_freq == 0) {
		fprintf(stderr, "this appears to be an iPhone device, where cpu_freq can not be detected. set to 800MHz.\n");
		cpu_freq = 800000000;
	} else {
		fprintf(stderr, "device max CPU clock rate = %.2f MHz\n", cpu_freq/1.e6);
	}

    mach_timebase_info_data_t info;
    kern_return_t err = mach_timebase_info( &info );

	if (argc!=3) {
		fprintf(stderr, "usage : %s iterations num_16bytes_block\n", argv[0]);
		exit(1);
	}
	ITERATIONS = atoi(argv[1]);
	NUM_BLOCKS = atoi(argv[2]);
	data_size = 16*NUM_BLOCKS;

	plain = malloc(data_size);
	cipher = malloc(data_size);
	decrypt = malloc(data_size);

	if ((plain==NULL) || (cipher==NULL) || (decrypt==NULL)) {
		fprintf(stderr,"malloc error.\n");
		exit(1);
	}

	for (i=0;i<data_size;i++) plain[i] = random();
	for (i=0;i<32;i++) key[i] = random();
	for (i=0;i<16;i++) iv[i] = random();

	aes_encrypt_key128(key, &encrypt_ctx);
	aes_decrypt_key128(key, &decrypt_ctx);

	for (iterations=0;iterations<ITERATIONS;iterations++) {
		t0 = mach_absolute_time();

		// encrypt
		aes_encrypt_cbc(plain, iv, NUM_BLOCKS, cipher, &encrypt_ctx);

		t1 = mach_absolute_time();

		// decrypt
		aes_decrypt_cbc(cipher, iv, NUM_BLOCKS, decrypt, &decrypt_ctx);

		t2 = mach_absolute_time();

		for (i=0;i<(16*NUM_BLOCKS);i++) if (plain[i]!=decrypt[i]) {
				fprintf(stderr,"error : decrypt != plain. i = %d\n", i);
				exit(1);
		}
		sum += (t1-t0);
		sum1 += (t2-t1);
		t2-=t1;
		t1-=t0;
		if (t1>max_time) max_time = t1;
        if (t1<min_time) min_time = t1;
		if (t2>max_time1) max_time1 = t2;
        if (t2<min_time1) min_time1 = t2;
	}

	time = sum * 1e-9* ((double) info.numer)/((double) info.denom);
	time_max = max_time * 1e-9* ((double) info.numer)/((double) info.denom);
    time_min = min_time * 1e-9* ((double) info.numer)/((double) info.denom);

	time1 = sum1 * 1e-9* ((double) info.numer)/((double) info.denom);
	time_max1 = max_time1 * 1e-9* ((double) info.numer)/((double) info.denom);
    time_min1 = min_time1 * 1e-9* ((double) info.numer)/((double) info.denom);

	printf("%d bytes per cbc call\n", data_size);
	printf(" aes_encrypt_cbc : time elapsed = %8.2f usecs, %7.2f MBytes/sec, %8.2f cycles/byte\n", 1.e6*time/ITERATIONS,data_size*ITERATIONS/1024./1024./time, time*1.*cpu_freq/ITERATIONS/data_size);
	printf("  best iteration : time elapsed = %8.2f usecs, %7.2f MBytes/sec, %8.2f cycles/byte\n", 1.e6*time_min,data_size/1024./1024./time_min, time_min*1.*cpu_freq/data_size);
    printf(" worst iteration : time elapsed = %8.2f usecs, %7.2f MBytes/sec, %8.2f cycles/byte\n", 1.e6*time_max,data_size/1024./1024./time_max, time_max*1.*cpu_freq/data_size);

	printf("\n");

	printf(" aes_decrypt_cbc : time elapsed = %8.2f usecs, %7.2f MBytes/sec, %8.2f cycles/byte\n", 1.e6*time1/ITERATIONS,data_size*ITERATIONS/1024./1024./time1, time1*1.*cpu_freq/ITERATIONS/data_size);
	printf("  best iteration : time elapsed = %8.2f usecs, %7.2f MBytes/sec, %8.2f cycles/byte\n", 1.e6*time_min1,data_size/1024./1024./time_min1, time_min1*1.*cpu_freq/data_size);
    printf(" worst iteration : time elapsed = %8.2f usecs, %7.2f MBytes/sec, %8.2f cycles/byte\n", 1.e6*time_max1,data_size/1024./1024./time_max1, time_max1*1.*cpu_freq/data_size);

	free(plain);
	free(cipher);
	free(decrypt);
}
