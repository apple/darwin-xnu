/* This is a file that compiles as a 32-bit helper to test
 * forking of 32-bit programs, now that 32-bit has been
 * deprecated on macOS despite still requiring its support in
 * the watchOS simulator.
 */

#include <stdio.h>
#include <unistd.h>

int
main(int argc __unused, char **argv)
{
	(void)argc;
	size_t retval = sizeof(void *);
	printf("%s(%d): sizeof(void *) = %lu\n", argv[0], getpid(), retval);
	return (int)retval;
}
