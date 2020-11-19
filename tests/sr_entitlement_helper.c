#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * This is a test helper that just has to run for a while.
 */
int
main(int argc, char **argv)
{
	printf("Hello, world.\n");
	sleep(15);
	printf("That's all folks.\n");
	exit(0);
}
