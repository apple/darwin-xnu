/*
 * Copyright (c) 2013 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <err.h>
#include <sysexits.h>

#include <sys/stat.h>
#include <sys/fcntl.h>
#include <sys/param.h>
#include <sys/time.h>

void usage(void);

int main(int argc, char * argv[])
{
	struct stat sb;
	char *newcontent = NULL;
	size_t newcontentlength = 0;
	char *oldcontent = NULL;
	int ret;
	int dstfd;
	const char *dst = NULL;
	ssize_t readsize, writesize;
	int i;

	if (argc < 2) {
		usage();
	}

	dst = argv[1];

	for (i=2; i < argc; i++) {
		newcontentlength += strlen(argv[i]) + 1 /* space or newline */;
	}
	newcontentlength += 1; /* NUL */

	newcontent = malloc(newcontentlength);
	if (newcontent == NULL)
		err(EX_UNAVAILABLE, "malloc() failed");

	newcontent[0] = '\0';

	for (i=2; i < argc; i++) {
		strlcat(newcontent, argv[i], newcontentlength);
		if (i < argc - 1) {
			strlcat(newcontent, " ", newcontentlength);
		} else {
			strlcat(newcontent, "\n", newcontentlength);
		}
	}

	dstfd = open(dst, O_RDWR | O_CREAT | O_APPEND, DEFFILEMODE);
	if (dstfd < 0)
		err(EX_NOINPUT, "open(%s)", dst);

	ret = fstat(dstfd, &sb);
	if (ret < 0)
		err(EX_NOINPUT, "fstat(%s)", dst);

	if (!S_ISREG(sb.st_mode))
		err(EX_USAGE, "%s is not a regular file", dst);

	if (sb.st_size != newcontentlength) {
		/* obvious new content must be different than old */
		goto replace;
	}

	oldcontent = malloc(newcontentlength);
	if (oldcontent == NULL)
		err(EX_UNAVAILABLE, "malloc(%lu) failed", newcontentlength);

	readsize = read(dstfd, oldcontent, newcontentlength);
	if (readsize == -1)
		err(EX_UNAVAILABLE, "read() failed");
	else if (readsize != newcontentlength)
		errx(EX_UNAVAILABLE, "short read of file");

	if (0 == memcmp(oldcontent, newcontent, newcontentlength)) {
		/* binary comparison succeeded, just exit */
		free(oldcontent);
		ret = close(dstfd);
		if (ret < 0)
			err(EX_UNAVAILABLE, "close() failed");

		exit(0);
	}

replace:
	ret = ftruncate(dstfd, 0);
	if (ret < 0)
		err(EX_UNAVAILABLE, "ftruncate() failed");

	writesize = write(dstfd, newcontent, newcontentlength);
	if (writesize == -1)
		err(EX_UNAVAILABLE, "write() failed");
	else if (writesize != newcontentlength)
		errx(EX_UNAVAILABLE, "short write of file");

	ret = close(dstfd);
	if (ret < 0)
		err(EX_NOINPUT, "close(dst)");

	return 0;
}

void usage(void)
{
	fprintf(stderr, "Usage: %s <dst> <new> <contents> <...>\n",
			getprogname());
	exit(EX_USAGE);
}
