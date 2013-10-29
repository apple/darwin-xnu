#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int fd, r;
	char buf[32];

	if (argc != 2) {
		fprintf(stderr, "Usage: %s fd\n", argv[0]);
		return 1;
	}
	fd = atoi(argv[1]);

	printf("child read(%d)...\n", fd);
	r = read(fd, buf, sizeof buf - 1);
	if (r < 0)
		perror("read");
	else {
		buf[r] = 0;
		printf("child read(%d) = \"%s\"\n", fd, buf);
	}
	close(fd);
	printf("child done\n");
	return 0;
}
