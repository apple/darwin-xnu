#ifdef T_NAMESPACE
#undef T_NAMESPACE
#endif

#include <darwintest.h>
#include <darwintest_multiprocess.h>

#define PRIVATE 1
#include "../bsd/sys/dirent.h"

T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true));

ssize_t __getdirentries64(int fd, void *buf, size_t bufsize, off_t *basep);

T_DECL(getdirentries64_extended, "check for GETDIRENTRIES64_EOF")
{
	char buf[GETDIRENTRIES64_EXTENDED_BUFSIZE];
	getdirentries64_flags_t *flags;
	ssize_t result;
	off_t offset;
	int fd;
	bool eof = false;

	flags = (getdirentries64_flags_t *)(uintptr_t)(buf + sizeof(buf) -
	    sizeof(getdirentries64_flags_t));
	fd = open("/", O_DIRECTORY | O_RDONLY);
	T_ASSERT_POSIX_SUCCESS(fd, "open(/)");

	for (;;) {
		*flags = (getdirentries64_flags_t)~0;
		result = __getdirentries64(fd, buf, sizeof(buf), &offset);
		T_ASSERT_POSIX_SUCCESS(result, "__getdirentries64()");
		T_ASSERT_LE((size_t)result, sizeof(buf) - sizeof(getdirentries64_flags_t),
		    "The kernel should have left space for the flags");
		T_ASSERT_NE(*flags, (getdirentries64_flags_t)~0,
		    "The kernel should have returned status");
		if (eof) {
			T_ASSERT_EQ(result, 0l, "At EOF, we really should be done");
			T_ASSERT_TRUE(*flags & GETDIRENTRIES64_EOF, "And EOF should still be set");
			T_END;
		}
		T_ASSERT_NE(result, 0l, "We're not at EOF, we should have an entry");
		eof = (*flags & GETDIRENTRIES64_EOF);
	}
}
