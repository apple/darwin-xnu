#include <stdio.h>
#include <fcntl.h>
#include <util.h>
#include <unistd.h>
#include <darwintest.h>

T_DECL(dev_zero,
    "test reading from /dev/zero",
    T_META_ASROOT(false))
{
	int dev = opendev("/dev/zero", O_RDONLY, NULL, NULL);
	char buffer[100];

	for (int i = 0; i < 100; i++) {
		buffer[i] = 0xff;
	}

	int rd_sz = read(dev, buffer, sizeof(buffer));

	T_EXPECT_EQ(rd_sz, 100, "read from /dev/zero failed");

	for (int i = 0; i < 100; i++) {
		if (buffer[i]) {
			T_FAIL("Unexpected non-zero character read from /dev/zero");
		}
	}

	close(dev);
}
