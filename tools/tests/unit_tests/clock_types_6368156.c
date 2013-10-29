#include <mach/mach.h>
#include <stdio.h>

int main(void)
{
    long long good = 5 * 1000000000LL;
    long long bad = 5 * NSEC_PER_SEC;

    printf("%lld\n%lld\n", good, bad);
    if (good == bad ){
        printf("[PASS] successfully verified that (5 * 1000000000LL) == (5 * NSEC_PER_SEC). \n");
        return 0;
    }else {
	printf("[FAIL] NSEC_PER_SEC is not long long.\n");
	return -1;
	}
    /* by default return as error */

    return 1; 
}
