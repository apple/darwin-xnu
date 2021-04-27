#include <darwintest.h>
#include <sys/socket.h>

T_DECL(socket_raw_uint8_max, "create socket with borderline proto numbers")
{
	int fd = socket(AF_INET, SOCK_RAW, 256);

	T_ASSERT_POSIX_FAILURE(fd, EINVAL, "socket(AF_INET, SOCK_RAW, 256);");

	int fd2 = socket(AF_INET, SOCK_RAW, 255);

	T_ASSERT_POSIX_SUCCESS(fd2, "socket(AF_INET, SOCK_RAW, 255);");
}
