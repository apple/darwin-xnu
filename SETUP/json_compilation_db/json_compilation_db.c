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

/*
 * json_compilation_db is a helper tool that takes a compiler invocation, and
 * appends it in JSON format to the specified database.
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

void usage(void);
char *escape_string(const char *);

/*
 * We support appending to two databases.
 *
 * 0-byte: ""
 *
 * or
 *
 * "["
 * "{"
 * "  ..."
 * "}"
 * "]"
 */

int main(int argc, char * argv[])
{
	struct stat sb;
	int ret;
	int dstfd;
	FILE *dst = NULL;
	const char *json_output = NULL;
	const char *cwd = NULL;
	const char *input_file = NULL;
	char start[2];
	size_t read_bytes;
	int i;
	size_t input_file_len;

	if (argc < 5) {
		usage();
	}

	json_output = argv[1];
	cwd = argv[2];
	input_file = argv[3];

	argv += 4;
	argc -= 4;

	input_file_len = strlen(input_file);
	if (!(input_file_len > 2 && 0 == strcmp(".c",   input_file + input_file_len - 2)) &&
		!(input_file_len > 3 && 0 == strcmp(".cp",  input_file + input_file_len - 3)) &&
		!(input_file_len > 4 && 0 == strcmp(".cpp", input_file + input_file_len - 4))) {
		/* Not a C/C++ file, just skip it */
		return 0;
	}

	dstfd = open(json_output, O_RDWR | O_CREAT | O_EXLOCK, DEFFILEMODE);
	if (dstfd < 0)
		err(EX_NOINPUT, "open(%s)", json_output);

	ret = fstat(dstfd, &sb);
	if (ret < 0)
		err(EX_NOINPUT, "fstat(%s)", json_output);

	if (!S_ISREG(sb.st_mode))
		err(EX_USAGE, "%s is not a regular file", json_output);

	dst = fdopen(dstfd, "w+");
	if (dst == NULL)
		err(EX_UNAVAILABLE, "fdopen");

	read_bytes = fread(start, sizeof(start[0]), sizeof(start)/sizeof(start[0]), dst);
	if ((read_bytes != sizeof(start)) || (0 != memcmp(start, "[\n", sizeof(start)/sizeof(start[0])))) {
		/* no JSON start, we don't really care why */
		ret = fseeko(dst, 0, SEEK_SET);
		if (ret < 0)
			err(EX_UNAVAILABLE, "fseeko");

		ret = fputs("[", dst);
		if (ret < 0)
			err(EX_UNAVAILABLE, "fputs");
	} else {
		/* has at least two bytes at the start. Seek to 3 bytes before the end */
		ret = fseeko(dst, -3, SEEK_END);
		if (ret < 0)
			err(EX_UNAVAILABLE, "fseeko");

		ret = fputs(",", dst);
		if (ret < 0)
			err(EX_UNAVAILABLE, "fputs");
	}

	fprintf(dst, "\n");
	fprintf(dst, "{\n");
	fprintf(dst, "  \"directory\": \"%s\",\n", cwd);
	fprintf(dst, "  \"file\": \"%s\",\n", input_file);
	fprintf(dst, "  \"command\": \"");
	for (i=0; i < argc; i++) {
		bool needs_escape = strchr(argv[i], '\\') || strchr(argv[i], '"') || strchr(argv[i], ' ');
		
		if (needs_escape) {
			char *escaped_string = escape_string(argv[i]);
			fprintf(dst, "%s\\\"%s\\\"", i == 0 ? "" : " ", escaped_string);
			free(escaped_string);
		} else {
			fprintf(dst, "%s%s", i == 0 ? "" : " ", argv[i]);
		}
	}
	fprintf(dst, "\"\n");
	fprintf(dst, "}\n");
	fprintf(dst, "]\n");

	ret = fclose(dst);
	if (ret < 0)
		err(EX_UNAVAILABLE, "fclose");

	return 0;
}

void usage(void)
{
	fprintf(stderr, "Usage: %s <json_output> <cwd> <input_file> <compiler> [<invocation> ...]\n", getprogname());
	exit(EX_USAGE);
}

/*
 * A valid JSON string can't contain \ or ", so we look for these in our argv[] array (which
 * our parent shell would have done shell metacharacter evaluation on, and escape just these.
 * The entire string is put in \" escaped quotes to handle spaces that are valid JSON
 * but should be used for grouping when running the compiler for real.
 */
char *
escape_string(const char *input)
{
	size_t len = strlen(input);
	size_t i, j;
	char *output = malloc(len * 4 + 1);

	for (i=0, j=0; i < len; i++) {
		char ch = input[i];

		if (ch == '\\' || ch == '"') {
			output[j++] = '\\';
			output[j++] = '\\'; /* output \\ in JSON, which the final shell will see as \ */
			output[j++] = '\\'; /* escape \ or ", which the final shell will see and pass to the compiler */
		}
		output[j++] = ch;
	}

	output[j] = '\0';

	return output;
}
