#include <Foundation/Foundation.h>
#include <darwintest.h>
#include <darwintest_utils.h>
#include <mach-o/dyld.h>
#include <System/sys/codesign.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/sysctl.h>


T_GLOBAL_META(T_META_RUN_CONCURRENTLY(true),
    T_META_ASROOT(true));

struct procargs {
	int argc;
	size_t preflightSize;
	NSString *executablePath;
	NSArray *components;
	NSString *legacyExecutablePath;
	void *rawBuffer;
	size_t rawBufferSize;
};

static void printHexDump(void* buffer, size_t size);

typedef struct procargs *procargs_t;

#define TEST_ENVIRONMENT_VARIABLE       "TESTENVVARIABLE"
#define TEST_ENVIRONMENT_VARIABLE_VALUE "TESTENVVARIABLE_VALUE"


static size_t argmax;

static procargs_t getProcArgs(int type, pid_t pid, size_t allocSize)
{
	int sysctlArgs[3] = {CTL_KERN, type, pid};
	int argc;
	NSMutableArray *components = [NSMutableArray array];
	procargs_t args = (procargs_t) malloc(sizeof(struct procargs));
	size_t currentLen = 0;
	bool legacyPathPresent = false;
	NSString *current = nil;
	NSString *legacyExecutablePath = nil;
	NSString *executablePath = nil;
	size_t bufferSize;
	size_t preflightSize = 0;
	const char *name = type == KERN_PROCARGS ? "KERN_PROCARGS" : "KERN_PROCARGS2";
	const char *cursor;
	void *buffer;

	T_LOG("Get proc args for pid %d, allocSize %lu with %s", pid, allocSize, name);


	T_ASSERT_TRUE(type == KERN_PROCARGS || type == KERN_PROCARGS2, "type is valid");

	/* Determine how much memory to allocate. If allocSize is 0 we will use the size
	 * we get from the sysctl for our buffer. */
	T_ASSERT_POSIX_SUCCESS(sysctl(sysctlArgs, 3, NULL, &preflightSize, NULL, 0), "sysctl %s", name);
	T_LOG("procargs data should be %lu bytes", preflightSize);

	if (allocSize == 0) {
		allocSize = preflightSize;
	}

	buffer = malloc(allocSize);
	T_QUIET; T_ASSERT_NOTNULL(buffer, "malloc buffer of size %lu", allocSize);
	bufferSize = allocSize;
	
	T_ASSERT_POSIX_SUCCESS(sysctl(sysctlArgs, 3, buffer, &bufferSize, NULL, 0), "sysctl %s", name);
	T_ASSERT_LE(bufferSize, allocSize, "returned buffer size should be less than allocated size");
	T_LOG("sysctl wrote %lu bytes", bufferSize);
	if (allocSize >= bufferSize) {
		/* Allocated buffer is larger than what kernel wrote, so it should match preflightSize */
		T_ASSERT_EQ(bufferSize, preflightSize, "buffer size should be the same as preflight size");
	}

	printHexDump(buffer, bufferSize);

	if (type == KERN_PROCARGS2) {
		argc = *(int *)buffer;
		cursor = (const char *)buffer + sizeof(int);
	} else {
		/* Without KERN_PROCARGS2, we can't tell where argv ends and environ begins.
		 * Set argc to -1 to indicate this */
		argc = -1;
		cursor = buffer;
	}

	while ((uintptr_t)cursor < (uintptr_t)buffer + bufferSize) {
		/* Ensure alignment and check if the uint16_t at cursor is the magic value */
		if (!((uintptr_t)cursor & (sizeof(uint16_t) - 1)) && 
			(uintptr_t)buffer + bufferSize - (uintptr_t)cursor > sizeof(uint16_t)) {
			/* Silence -Wcast-align by casting to const void * */
			uint16_t value = *(const uint16_t *)(const void *)cursor;
			if (value == 0xBFFF) {
				/* Magic value that specifies the end of the argument/environ section */
				cursor += sizeof(uint16_t) + sizeof(uint32_t);
				legacyPathPresent = true;
				break;
			}
		}
		currentLen = strnlen(cursor, bufferSize - ((uintptr_t)cursor - (uintptr_t)buffer));
		current = [[NSString alloc] initWithBytes:cursor length:currentLen encoding:NSUTF8StringEncoding];
		T_QUIET; T_ASSERT_NOTNULL(current, "allocated string");
		cursor += currentLen + 1;

		if (executablePath == nil) {
			executablePath = current;
			[executablePath retain];
			while (*cursor == 0) {
				cursor++;
			}
		} else {
			[components addObject:current];
		}
		[current release];
	}
	if (legacyPathPresent) {
		T_ASSERT_EQ(type, KERN_PROCARGS, "Legacy executable path should only be present for KERN_PROCARGS");
		currentLen = strnlen(cursor, bufferSize - ((uintptr_t)cursor - (uintptr_t)buffer));
		current = [[NSString alloc] initWithBytes:cursor length:currentLen encoding:NSUTF8StringEncoding];
		T_QUIET; T_ASSERT_NOTNULL(current, "allocated string");
		legacyExecutablePath = current;
	}
	args->argc = argc;
	args->executablePath = executablePath;
	args->components = components;
	args->legacyExecutablePath = legacyExecutablePath;
	args->preflightSize = preflightSize;
	args->rawBuffer = buffer;
	args->rawBufferSize = bufferSize;
	return args;
}

static void printProcArgs(procargs_t procargs) {
	if (procargs->argc == -1) {
		T_LOG("No argument count");
	} else {
		T_LOG("Argc is %d", procargs->argc);
	}
	T_LOG("Executable path: %s (length %lu)", [procargs->executablePath UTF8String], [procargs->executablePath length]);
	for (size_t i = 0; i < [procargs->components count]; i++) {
		NSString *component = [procargs->components objectAtIndex:i];
		const char *str = [component UTF8String];
		size_t len = [component length];
		if (procargs->argc != -1) {
			T_LOG("%s %zu: %s (length %lu)", i >= (size_t)procargs->argc ? "Env var" : "Argument", i, str, len);
		} else {
			T_LOG("Component %zu: %s (length %lu)", i, str, len);
		}
	}
	if (procargs->legacyExecutablePath) {
		T_LOG("Contains legacy executable path: %s (length %lu)", [procargs->legacyExecutablePath UTF8String], [procargs->legacyExecutablePath length]);
	}
	printHexDump(procargs->rawBuffer, procargs->rawBufferSize);
}

static void printHexDump(void* buffer, size_t size) {
	#define ROW_LENGTH 24
	T_LOG("Buffer %p, size %zu", buffer, size);
	for (size_t row = 0; row < size; row += ROW_LENGTH) {
		NSMutableString *line = [[NSMutableString alloc] initWithCapacity:0];
		NSMutableString *text = [[NSMutableString alloc] initWithCapacity:0];
		[line appendFormat:@"    %04zx    ", row];
		for (size_t col = row; col < row + ROW_LENGTH; col++) {
			if (col < size) {
				char c = ((char *)buffer)[col];
				[line appendFormat:@"%02x ", c];
				if (isprint(c)) {
					[text appendFormat:@"%c", c];
				} else {
					[text appendString:@"."];
				}
			} else {
				[line appendString:@"   "];
			}
		}
		[line appendFormat:@"  %@", text];
		T_LOG("%s", [line UTF8String]);
		[text release];
		[line release];
	}
}

static void deallocProcArgs(procargs_t procargs)
{
	[procargs->components release];
	[procargs->executablePath release];
	[procargs->legacyExecutablePath release];
	free(procargs->rawBuffer);
	free(procargs);
}

T_HELPER_DECL(child_helper, "Child process helper")
{
	while (true) {
		wait(NULL);
	}
}

static pid_t
launch_child_process(NSArray *args, bool cs_restrict)
{
	pid_t pid;
	char path[PATH_MAX];
	uint32_t path_size = sizeof(path);
	uint32_t csopsStatus = 0;
	const char** dt_args;
	size_t dt_args_count;

	T_ASSERT_POSIX_SUCCESS(_NSGetExecutablePath(path, &path_size), "get executable path");
	
	/* We need to add 4 arguments to the beginning and NULL at the end */
	dt_args_count = [args count] + 5;
	dt_args = malloc(sizeof(char *) * dt_args_count);
	dt_args[0] = path;
	dt_args[1] = "-n";
	dt_args[2] = "child_helper";
	dt_args[3] = "--";
	for (size_t i = 0; i < [args count]; i++) {
		NSString *arg = [args objectAtIndex:i];
		dt_args[i + 4] = [arg UTF8String];
	}
	dt_args[[args count] + 4] = NULL;

	T_LOG("Launching %s", path);
	T_LOG("Arguments: ");
	for (size_t i = 0; i < dt_args_count; i++) {
		T_LOG("     %s", dt_args[i] ? dt_args[i] : "(null)");
	}
	T_ASSERT_POSIX_SUCCESS(dt_launch_tool(&pid, (char **)dt_args, false, NULL, NULL), "launched helper");
	free(dt_args);

	if (cs_restrict) {
		csopsStatus |= CS_RESTRICT;
		T_ASSERT_POSIX_SUCCESS(csops(pid, CS_OPS_SET_STATUS, &csopsStatus, sizeof(csopsStatus)), "set CS_RESTRICT");
	}
	return pid;
}

T_DECL(test_sysctl_kern_procargs_25397314, "Test kern.procargs and kern.procargs2 sysctls")
{
	procargs_t procargs;
	size_t argsize = sizeof(argmax);
	NSString *testArgument1 = @"test argument 1";
	bool containsTestArgument1 = false;
	NSString *testArgument2 = @"test argument 2";
	bool containsTestArgument2 = false;
	NSString *testEnvironmentVariable = @TEST_ENVIRONMENT_VARIABLE;
	bool containsTestEnvironmentVariable = false;
	bool containsPathEnvironmentVariable = false;
	int development = 0;
	size_t development_size = sizeof(development);
	uint32_t csopsStatus = 0;


	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.development", &development, &development_size, NULL, 0), "sysctl kern.development");
	
	T_ASSERT_POSIX_SUCCESS(sysctlbyname("kern.argmax", &argmax, &argsize, NULL, 0), "sysctl kern.argmax");
	procargs = getProcArgs(KERN_PROCARGS2, getpid(), argmax);
	T_ASSERT_NOTNULL(procargs->executablePath, "executable path should be non-null");
	T_ASSERT_GT([procargs->executablePath length], 0, "executable path should not be empty");
	printProcArgs(procargs);
	deallocProcArgs(procargs);

	procargs = getProcArgs(KERN_PROCARGS2, getpid(), 0);
	T_ASSERT_NOTNULL(procargs->executablePath, "executable path should be non-null");
	T_ASSERT_GT([procargs->executablePath length], 0, "executable path should not be empty");
	printProcArgs(procargs);
	deallocProcArgs(procargs);

	setenv(TEST_ENVIRONMENT_VARIABLE, TEST_ENVIRONMENT_VARIABLE_VALUE, true);

	pid_t child = launch_child_process(@[testArgument1, testArgument2], false);
	procargs = getProcArgs(KERN_PROCARGS2, child, argmax);
	T_ASSERT_NOTNULL(procargs->executablePath, "executable path should be non-null");
	T_ASSERT_GT([procargs->executablePath length], 0, "executable path should not be empty");
	printProcArgs(procargs);

	for (NSString *component in procargs->components) {
		if ([component isEqualToString:testArgument1]) {
			containsTestArgument1 = true;
		}
		if ([component isEqualToString:testArgument2]) {
			containsTestArgument2 = true;
		}
		if ([component containsString:testEnvironmentVariable]) {
			containsTestEnvironmentVariable = true;
		}
	}
	deallocProcArgs(procargs);
	kill(child, SIGKILL);
	T_ASSERT_TRUE(containsTestArgument1, "Found test argument 1");
	T_ASSERT_TRUE(containsTestArgument2, "Found test argument 2");
	T_ASSERT_TRUE(containsTestEnvironmentVariable, "Found test environment variable");

	if (development) {
		T_LOG("Skipping test on DEVELOPMENT || DEBUG kernel");
	} else {
		containsTestArgument1 = false;
		containsTestArgument2 = false;
		containsTestEnvironmentVariable = false;

		child = launch_child_process(@[testArgument1, testArgument2], true);
		procargs = getProcArgs(KERN_PROCARGS2, child, argmax);
		T_ASSERT_NOTNULL(procargs->executablePath, "executable path should be non-null");
		T_ASSERT_GT([procargs->executablePath length], 0, "executable path should not be empty");
		printProcArgs(procargs);
		for (NSString *component in procargs->components) {
			if ([component isEqualToString:testArgument1]) {
				containsTestArgument1 = true;
			}
			if ([component isEqualToString:testArgument2]) {
				containsTestArgument2 = true;
			}
			if ([component containsString:testEnvironmentVariable]) {
				containsTestEnvironmentVariable = true;
			}
		}
		deallocProcArgs(procargs);
		kill(child, SIGKILL);
		T_ASSERT_TRUE(containsTestArgument1, "Found test argument 1");
		T_ASSERT_TRUE(containsTestArgument2, "Found test argument 2");
		T_ASSERT_FALSE(containsTestEnvironmentVariable, "No test environment variable");


		csopsStatus |= CS_RESTRICT;
		T_ASSERT_POSIX_SUCCESS(csops(getpid(), CS_OPS_SET_STATUS, &csopsStatus, sizeof(csopsStatus)), "set CS_RESTRICT on self");
		procargs = getProcArgs(KERN_PROCARGS2, getpid(), argmax);
		T_ASSERT_NOTNULL(procargs->executablePath, "executable path should be non-null");
		T_ASSERT_GT([procargs->executablePath length], 0, "executable path should not be empty");
		printProcArgs(procargs);
		for (NSString *component in procargs->components) {
			if ([component containsString:@"PATH"]) {
				containsPathEnvironmentVariable = true;
			}
		}
		deallocProcArgs(procargs);
		T_ASSERT_TRUE(containsPathEnvironmentVariable, "Found $PATH environment variable");
	}
}
