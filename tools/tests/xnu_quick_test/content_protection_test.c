#include "tests.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/mount.h>
#include <sys/wait.h>

#include <IOKit/IOKitLib.h>
#include <Kernel/IOKit/crypto/AppleKeyStoreDefs.h>
#include <Kernel/sys/content_protection.h>

/* Note that this test (due to the need to lock/unlock the device on demand, and the
   need to manipulate the passcode) has the unfortunate effect of link xnu_quick_test
   to the IOKit Framework. */

/* TODO: Change the test to use a single cleanup label. */

#define CPT_IO_SIZE      4096
#define CPT_AKS_BUF_SIZE 256
#define CPT_MAX_PASS_LEN 64

#define GET_PROT_CLASS(fd)             fcntl((fd), F_GETPROTECTIONCLASS)
#define SET_PROT_CLASS(fd, prot_class) fcntl((fd), F_SETPROTECTIONCLASS, (prot_class))

#define PRINT_LOCK_FAIL   printf("%s, line %d: failed to lock the device.\n", cpt_fail_header, __LINE__);
#define PRINT_UNLOCK_FAIL printf("%s, line %d: failed to unlock the device.\n", cpt_fail_header, __LINE__);

extern char g_target_path[PATH_MAX];

char * cpt_fail_header = "Content protection test failed";
char * keystorectl_path = "/usr/local/bin/keystorectl";

/* Shamelessly ripped from keystorectl routines; a wrapper for invoking the AKS user client. */
int apple_key_store(uint32_t command,
                    uint64_t * inputs,
                    uint32_t input_count,
                    void * input_structs,
                    size_t input_struct_count,
                    uint64_t * outputs,
                    uint32_t * output_count)
{
	int result = -1;
	io_connect_t connection = IO_OBJECT_NULL;
	io_registry_entry_t apple_key_bag_service = IO_OBJECT_NULL;
	kern_return_t k_result = KERN_FAILURE;
	IOReturn io_result = IO_OBJECT_NULL;

	apple_key_bag_service = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(kAppleKeyStoreServiceName));

	if (apple_key_bag_service == IO_OBJECT_NULL)
	{
		printf("FAILURE: failed to match kAppleKeyStoreServiceName.\n");
		goto end;
	}

	k_result = IOServiceOpen(apple_key_bag_service, mach_task_self(), 0, &connection);

	if (k_result != KERN_SUCCESS)
	{
		printf("FAILURE: failed to open AppleKeyStore.\n");
		goto end;
	}

	k_result = IOConnectCallMethod(connection, kAppleKeyStoreUserClientOpen, NULL, 0, NULL, 0, NULL, NULL, NULL, NULL);

	if (k_result != KERN_SUCCESS)
	{
		printf("FAILURE: call to AppleKeyStore method kAppleKeyStoreUserClientOpen failed.\n");
		goto close;
	}

	io_result = IOConnectCallMethod(connection, command, inputs, input_count, input_structs, input_struct_count, outputs, output_count, NULL, NULL);

	if (io_result != kIOReturnSuccess)
	{
		printf("FAILURE: call to AppleKeyStore method %d failed.\n", command);
		goto close;
	}

	result = 0;

close:
	IOServiceClose(apple_key_bag_service);

end:
	return(result);
}

#ifndef   KEYBAG_ENTITLEMENTS
/* Just a wrapper around forking to exec keystorectl for commands requiring entitlements. */
int keystorectl(char * const command[])
{
	int child_result = -1;
	int result = -1;
	pid_t child = -1;

	child = fork();

	if (child == -1)
	{
		printf("FAILURE: failed to fork.\n");
		goto end;
	}
	else if (child == 0)
	{
		/* TODO: This keeps keystorectl from bombarding us with key state changes, but
		   there must be a better way of doing this; killing stderr is a bit nasty,
		   and if keystorectl fails, we want all the information we can get. */
		fclose(stderr);
		fclose(stdin);
		execv(keystorectl_path, command);
		printf("FAILURE: child failed to execv keystorectl, errno = %s.\n",
		  strerror(errno));
		exit(EXIT_FAILURE);
	}

	if ((waitpid(child, &child_result, 0) != child) || WEXITSTATUS(child_result))
	{
		printf("FAILURE: keystorectl failed.\n");
		result = -1;
	}
	else
	{
		result = 0;
	}

end:
	return(result);
}
#endif /* KEYBAG_ENTITLEMENTS */

/* Code based on Mobile Key Bag; specifically MKBDeviceSupportsContentProtection
   and MKBDeviceFormattedForContentProtection. */
/* We want to verify that we support content protection, and that
   we are formatted for it. */
int supports_content_prot()
{
	int local_result = -1;
	int result = -1;
	uint32_t buffer_size = 1;
	char buffer[buffer_size];
	io_registry_entry_t defaults = IO_OBJECT_NULL;
	kern_return_t k_result = KERN_FAILURE;
	struct statfs statfs_results;

	defaults = IORegistryEntryFromPath(kIOMasterPortDefault, kIODeviceTreePlane ":/defaults");

	if (defaults == IO_OBJECT_NULL)
	{
		printf("FAILURE: failed to find defaults registry entry.\n");
		goto end;
	}

	k_result = IORegistryEntryGetProperty(defaults, "content-protect", buffer, &buffer_size);

	if (k_result != KERN_SUCCESS)
	{	/* This isn't a failure; it means the entry doesn't exist, so we assume CP
		   is unsupported. */
		result = 0;
		goto end;
	}

	/* At this point, we SUPPORT content protection... but are we formatted for it? */
	/* This is ugly; we should be testing the file system we'll be testing in, not
	   just /tmp/. */
	local_result = statfs(g_target_path, &statfs_results);

	if (local_result == -1)
	{
		printf("FAILURE: failed to statfs the test directory, errno = %s.\n",
		  strerror(errno));
	}
	else if (statfs_results.f_flags & MNT_CPROTECT)
	{
		result = 1;
	}
	else
	{	/* This isn't a failure, it means the filesystem isn't formatted for CP. */
		result = 0;
	}

end:
	return(result);
}

#if 0
int device_lock_state()
{
	/* TODO: Actually implement this. */
	/* We fail if a passcode already exists, and the methods being used to lock/unlock
	   the device in this test appear to be synchronous... do we need this function? */
	int result = -1;

	return(result);
}
#endif

int lock_device()
{
	int result = -1;

#ifdef    KEYBAG_ENTITLEMENTS
	/* If we're entitled, we can lock the device ourselves. */
	uint64_t inputs[] = {device_keybag_handle};
	uint32_t input_count = (sizeof(inputs) / sizeof(*inputs));
	result = apple_key_store(kAppleKeyStoreKeyBagLock, inputs, input_count, NULL, 0, NULL, NULL);
#else
	/* If we aren't entitled, we'll need to use keystorectl to lock the device. */
	/* keystorectl seems to have a bus error (though it locks successfully) unless
	   lock is passed an argument, so we'll also pass it the empty string. */
	char * const keystorectl_args[] = {keystorectl_path, "lock", "", NULL};
	result = keystorectl(keystorectl_args);
#endif /* KEYBAG_ENTITLEMENTS */

	return(result);
}

int unlock_device(char * passcode)
{
	int result = -1;

#ifdef    KEYBAG_ENTITLEMENTS
	/* If we're entitled, we can unlock the device ourselves. */
	uint64_t inputs[] = {device_keybag_handle};
	uint32_t input_count = (sizeof(inputs) / sizeof(*inputs));
	size_t input_struct_count = 0;

	if ((passcode == NULL) || ((input_struct_count = strnlen(passcode, CPT_MAX_PASS_LEN)) == CPT_MAX_PASS_LEN))
	{
		passcode = "";
		input_struct_count = 0;
	}

	result = apple_key_store(kAppleKeyStoreKeyBagUnlock, inputs, input_count, passcode, input_struct_count, NULL, NULL);
#else
	/* If we aren't entitled, we'll need to use keystorectl to unlock the device. */
	if ((passcode == NULL) || (strnlen(passcode, CPT_MAX_PASS_LEN) == CPT_MAX_PASS_LEN))
	{
		passcode = "";
	}

	char * const keystorectl_args[] = {keystorectl_path, "unlock", passcode, NULL};
	result = keystorectl(keystorectl_args);
#endif /* KEYBAG_ENTITLEMENTS */

	return(result);
}

int set_passcode(char * new_passcode, char * old_passcode)
{
	int result = -1;

#ifdef    KEYBAG_ENTITLEMENTS
	/* If we're entitled, we can set the passcode ourselves. */
	uint64_t inputs[] = {device_keybag_handle};
	uint32_t input_count = (sizeof(inputs) / sizeof(*inputs));
	void * input_structs = NULL;
	size_t input_struct_count = 0;
	char buffer[CPT_AKS_BUF_SIZE];
	char * buffer_ptr = buffer;
	uint32_t old_passcode_len = 0;
	uint32_t new_passcode_len = 0;

	if ((old_passcode == NULL) || ((old_passcode_len = strnlen(old_passcode, CPT_MAX_PASS_LEN)) == CPT_MAX_PASS_LEN))
	{
		old_passcode = "";
		old_passcode_len = 0;
	}

	if ((new_passcode == NULL) || ((new_passcode_len = strnlen(new_passcode, CPT_MAX_PASS_LEN)) == CPT_MAX_PASS_LEN))
	{
		new_passcode = "";
		new_passcode_len = 0;
	}

	*((uint32_t *) buffer_ptr) = ((uint32_t) 2);
	buffer_ptr += sizeof(uint32_t);
	*((uint32_t *) buffer_ptr) = old_passcode_len;
	buffer_ptr += sizeof(uint32_t);
	memcpy(buffer_ptr, old_passcode, old_passcode_len);
	buffer_ptr += ((old_passcode_len + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1));
	*((uint32_t *) buffer_ptr) = new_passcode_len;
	buffer_ptr += sizeof(uint32_t);
	memcpy(buffer_ptr, new_passcode, new_passcode_len);
	buffer_ptr += ((new_passcode_len + sizeof(uint32_t) - 1) & ~(sizeof(uint32_t) - 1));
	input_structs = buffer;
	input_struct_count = (buffer_ptr - buffer);

	result = apple_key_store(kAppleKeyStoreKeyBagSetPasscode, inputs, input_count, input_structs, input_struct_count, NULL, NULL);
#else
	/* If we aren't entitled, we'll need to use keystorectl to set the passcode. */
	if ((old_passcode == NULL) || (strnlen(old_passcode, CPT_MAX_PASS_LEN) == CPT_MAX_PASS_LEN))
	{
		old_passcode = "";
	}

	if ((new_passcode == NULL) || (strnlen(new_passcode, CPT_MAX_PASS_LEN) == CPT_MAX_PASS_LEN))
	{
		new_passcode = "";
	}

	char * const keystorectl_args[] = {keystorectl_path, "change-password", old_passcode, new_passcode, NULL};
	result = keystorectl(keystorectl_args);
#endif /* KEYBAG_ENTITLEMENTS */

	return(result);
}

int clear_passcode(char * passcode)
{
	/* For the moment, this will set the passcode to the empty string (a known value);
	   this will most likely need to change, or running this test may ruin everything(tm). */
	int result = -1;

	result = set_passcode(NULL, passcode);

	return(result);
}

#if 0
/* Determines if we will try to test class C semanatics. */
int unlocked_since_boot()
{
	/* TODO: Actually implement this. */
	/* The actual semantics for CP mean that even with this primative, we would need
	   set a passcode and then reboot the device in order to test this; this function
	   will probably be rather worthless as a result. */
	int result = 1;

	return(result);
}
#endif

/* If the device has a passcode when we want to test it, things are going to go wrong.
   As such, we'll assume the device never has a passcode.
   No, not even then.
   Or we could just try "" to ""; it works. */
int has_passcode()
{
	int result = -1;

	result = set_passcode(NULL, NULL);

	return(result);
}

int content_protection_test(void * argp)
{
	#pragma unused (argp)
	int init_result = 0;
	int local_result = -1;
	int test_result = -1;
	int fd = -1;
	int dir_fd = -1;
	int subdir_fd = -1;
	int new_prot_class = -1;
	int old_prot_class = -1;
	int current_byte = 0;
	char filepath[PATH_MAX];
	char dirpath[PATH_MAX];
	char subdirpath[PATH_MAX];
	char rd_buffer[CPT_IO_SIZE];
	char wr_buffer[CPT_IO_SIZE];
	char * passcode = "IAmASecurePassword";

	/* Do some initial setup (names). */
	bzero(filepath, PATH_MAX);
	bzero(dirpath, PATH_MAX);
	bzero(subdirpath, PATH_MAX);

	/* This is just easier than checking each result individually. */
	init_result |= (strlcat(filepath, g_target_path, PATH_MAX) == PATH_MAX);
	init_result |= (strlcat(filepath, "/", PATH_MAX) == PATH_MAX);
	init_result |= (strlcpy(dirpath, filepath, PATH_MAX) == PATH_MAX);
	init_result |= (strlcat(filepath, "cpt_test_file", PATH_MAX) == PATH_MAX);
	init_result |= (strlcat(dirpath, "cpt_test_dir/", PATH_MAX) == PATH_MAX);
	init_result |= (strlcpy(subdirpath, dirpath, PATH_MAX) == PATH_MAX);
	init_result |= (strlcat(subdirpath, "cpt_test_subdir/", PATH_MAX) == PATH_MAX);

	if (init_result)
	{	/* If any of the initialization failed, we're just going to fail now. */
		printf("%s, line %d: failed to initialize test strings.\n",
		  cpt_fail_header, __LINE__);
		goto end;
	}

	local_result = supports_content_prot();

	if (local_result == -1)
	{
		printf("%s, line %d: failed to determine if content protection is supported.\n",
		  cpt_fail_header, __LINE__);
		goto end;
	}
	else if (local_result == 0)
	{	/* If we don't support content protection at the moment, pass the test. */
		printf("This device does not support or is not formatted for content protection.\n");
		test_result = 0;
		goto end;
	}

	/* If we support content protection, we'll need to be able to set the passcode. */
	local_result = has_passcode();

	if (local_result == -1)
	{
		printf("%s, line %d: the device appears to have a passcode.\n",
		  cpt_fail_header, __LINE__);
		goto end;
	}

	if (set_passcode(passcode, NULL))
	{
		printf("%s, line %d: failed to set a new passcode.\n",
		  cpt_fail_header, __LINE__);
		goto end;
	}

	fd = open(filepath, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC);

	if (fd == -1)
	{
		printf("%s, line %d: failed to create the test file, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto remove_passcode;
	}

	/* Ensure we can freely read and change protection classes when unlocked. */
	for (new_prot_class = PROTECTION_CLASS_A; new_prot_class <= PROTECTION_CLASS_F; new_prot_class++)
	{
		old_prot_class = GET_PROT_CLASS(fd);

		if (old_prot_class == -1)
		{
			printf("%s, line %d: failed to get protection class when unlocked, errno = %s.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_file;
		}

		if (SET_PROT_CLASS(fd, new_prot_class))
		{
			printf("%s, line %d: failed to change protection class from %d to %d during unlock, errno = %s.\n",
			  cpt_fail_header, __LINE__, old_prot_class, new_prot_class, strerror(errno));
			goto cleanup_file;
		}
	}

	if (SET_PROT_CLASS(fd, PROTECTION_CLASS_D))
	{
		printf("%s, line %d: failed to change protection class from F to D when unlocked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_file;
	}

	/* Try making a class A file while locked. */
	if (lock_device())
	{
		PRINT_LOCK_FAIL;
		goto cleanup_file;
	}

	if (!SET_PROT_CLASS(fd, PROTECTION_CLASS_A))
	{
		printf("%s, line %d: was able to change protection class from D to A when locked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	if (unlock_device(passcode))
	{
		PRINT_UNLOCK_FAIL;
		goto cleanup_file;
	}

	/* Attempt opening/IO to a class A file while unlocked. */
	if (SET_PROT_CLASS(fd, PROTECTION_CLASS_A))
	{
		printf("%s, line %d: failed to change protection class from D to A when unlocked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_file;
	}

	close(fd);
	fd = open(filepath, O_RDWR | O_CLOEXEC);

	if (fd == -1)
	{
		printf("%s, line %d: failed to open a class A file when unlocked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto remove_file;
	}

	/* TODO: Write specific data we can check for.
	   If we're going to do that, the write scheme should be deliberately ugly. */
	current_byte = 0;

	while (current_byte < CPT_IO_SIZE)
	{
		local_result = pwrite(fd, &wr_buffer[current_byte], CPT_IO_SIZE - current_byte, current_byte);

		if (local_result == -1)
		{
			printf("%s, line %d: failed to write to class A file when unlocked, errno = %s.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_file;
		}

		current_byte += local_result;
	}	

	current_byte = 0;

	while (current_byte < CPT_IO_SIZE)
	{
		local_result = pread(fd, &rd_buffer[current_byte], CPT_IO_SIZE - current_byte, current_byte);

		if (local_result == -1)
		{
			printf("%s, line %d: failed to read from class A file when unlocked, errno = %s.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_file;
		}

		current_byte += local_result;
	}

	/* Again, but now while locked; and try to change the file class as well. */
	if (lock_device())
	{
		PRINT_LOCK_FAIL;
		goto cleanup_file;
	}

	if (pread(fd, rd_buffer, CPT_IO_SIZE, 0) > 0)
	{
		printf("%s, line %d: was able to read from a class A file when locked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	if (pwrite(fd, wr_buffer, CPT_IO_SIZE, 0) > 0)
	{
		printf("%s, line %d: was able to write to a class A file when locked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	if (!SET_PROT_CLASS(fd, PROTECTION_CLASS_D))
	{
		printf("%s, line %d: was able to change protection class from A to D when locked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	/* Try to open and truncate the file. */
	close(fd);
	fd = open(filepath, O_RDWR | O_TRUNC | O_CLOEXEC);

	if (fd != -1)
	{
		printf("%s, line %d: was able to open and truncate a class A file when locked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	/* Try to open the file */
	fd = open(filepath, O_RDWR | O_CLOEXEC);

	if (fd != -1)
	{
		printf("%s, line %d: was able to open a class A file when locked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	/* What about class B files? */
	if (unlock_device(passcode))
	{
		PRINT_UNLOCK_FAIL;
		goto cleanup_file;
	}

	fd = open(filepath, O_RDWR | O_CLOEXEC);

	if (fd == -1)
	{
		printf("%s, line %d: was unable to open a class A file when unlocked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	if (SET_PROT_CLASS(fd, PROTECTION_CLASS_D))
	{
		printf("%s, line %d: failed to change protection class from A to D when unlocked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_file;
	}

	if (lock_device())
	{
		PRINT_LOCK_FAIL;
		goto cleanup_file;
	}

	/* Can we create a class B file while locked? */
	if (SET_PROT_CLASS(fd, PROTECTION_CLASS_B))
	{
		printf("%s, line %d: failed to change protection class from D to B when locked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_file;
	}

	/* We should also be able to read/write to the file descriptor while it is open. */
	current_byte = 0;

	while (current_byte < CPT_IO_SIZE)
	{
		local_result = pwrite(fd, &wr_buffer[current_byte], CPT_IO_SIZE - current_byte, current_byte);

		if (local_result == -1)
		{
			printf("%s, line %d: failed to write to new class B file when locked, errno = %s.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_file;
		}

		current_byte += local_result;
	}

	current_byte = 0;

	while (current_byte < CPT_IO_SIZE)
	{
		local_result = pread(fd, &rd_buffer[current_byte], CPT_IO_SIZE - current_byte, current_byte);

		if (local_result == -1)
		{
			printf("%s, line %d: failed to read from new class B file when locked, errno = %s.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_file;
		}

		current_byte += local_result;
	}

	/* We should not be able to open a class B file under lock. */
	close(fd);
	fd = open(filepath, O_RDWR | O_CLOEXEC);

	if (fd != -1)
	{
		printf("%s, line %d: was able to open a class B file when locked.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_file;
	}

	unlink(filepath);

	/* We still need to test directory semantics. */
	if (mkdir(dirpath, 0x0777) == -1)
	{
		printf("%s, line %d: failed to create a new directory when locked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto remove_passcode;
	}

	/* The newly created directory should not have a protection class. */
	dir_fd = open(dirpath, O_RDONLY | O_CLOEXEC);

	if (dir_fd == -1)
	{
		printf("%s, line %d: failed to open an unclassed directory when locked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto remove_dir;
	}

	if (GET_PROT_CLASS(dir_fd) != PROTECTION_CLASS_D)
	{
		printf("%s, line %d: newly created directory had a non-D protection class.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_dir;
	}

	if (SET_PROT_CLASS(dir_fd, PROTECTION_CLASS_A))
	{
		printf("%s, line %d: was unable to change a directory from class D to class A during lock.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_dir;
	}

	if (SET_PROT_CLASS(dir_fd, PROTECTION_CLASS_D))
	{
		printf("%s, line %d: failed to change a directory from class A to class D during lock, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_dir;
	}

	/* Do all files created in the directory properly inherit the directory's protection class? */
	if ((strlcpy(filepath, dirpath, PATH_MAX) == PATH_MAX) || (strlcat(filepath, "cpt_test_file", PATH_MAX) == PATH_MAX))
	{
		printf("%s, line %d: failed to construct the path for a file in the directory.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_dir;
	}

	if (unlock_device(passcode))
	{
		PRINT_UNLOCK_FAIL;
		goto cleanup_dir;
	}

	for (new_prot_class = PROTECTION_CLASS_A; new_prot_class <= PROTECTION_CLASS_E; new_prot_class++)
	{
		old_prot_class = GET_PROT_CLASS(dir_fd);
		
		if (old_prot_class == -1)
		{
			printf("%s, line %d: failed to get the protection class for the directory, errno = %s.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_dir;
		}

		if (SET_PROT_CLASS(dir_fd, new_prot_class))
		{
			printf("%s, line %d: failed to change the protection class for the directory from %d to %d, errno = %s.\n",
			  cpt_fail_header, __LINE__, old_prot_class, new_prot_class, strerror(errno));
			goto cleanup_dir;
		}

		fd = open(filepath, O_CREAT | O_EXCL | O_CLOEXEC);

		if (fd == -1)
		{
			printf("%s, line %d: failed to create a file in a class %d directory when unlocked, errno = %s.\n",
			  cpt_fail_header, __LINE__, new_prot_class, strerror(errno));
			goto cleanup_dir;
		}

		local_result = GET_PROT_CLASS(fd);

		if (local_result == -1)
		{
			printf("%s, line %d: failed to get the new file's protection class, errno = %s.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_file;
		}
		else if (local_result != new_prot_class)
		{
			printf("%s, line %d: new file did not inherit the directory's protection class.\n",
			  cpt_fail_header, __LINE__, strerror(errno));
			goto cleanup_file;
		}

		close(fd);
		unlink(filepath);
	}

	/* Do we disallow creation of a class F directory? */
	if (!SET_PROT_CLASS(dir_fd, PROTECTION_CLASS_F))
	{
		printf("%s, line %d: creation of a class F directory did not fail as expected.\n",
		  cpt_fail_header, __LINE__);
		goto cleanup_dir;
	}

	/* And are class A and class B semantics followed for when we create these files during lock? */
	if (SET_PROT_CLASS(dir_fd, PROTECTION_CLASS_A))
	{
		printf("%s, line %d: failed to change directory class from F to A when unlocked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_dir;
	}

	if (lock_device())
	{
		PRINT_LOCK_FAIL;
		goto cleanup_dir;
	}

	fd = open(filepath, O_CREAT | O_EXCL | O_CLOEXEC);

	if (fd != -1)
	{
		printf("%s, line %d: was able to create a new file in a class A directory when locked.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_file;
	}

	if (unlock_device(passcode))
	{
		PRINT_UNLOCK_FAIL;
		goto cleanup_dir;
	}

	if (SET_PROT_CLASS(dir_fd, PROTECTION_CLASS_B))
	{
		printf("%s, line %d: failed to change directory class from A to B when unlocked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_dir;
	}

	if (lock_device())
	{
		PRINT_LOCK_FAIL;
		goto cleanup_dir;
	}

	fd = open(filepath, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC);

	if (fd == -1)
	{
		printf("%s, line %d: failed to create new file in class B directory when locked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_dir;
	}

	local_result = GET_PROT_CLASS(fd);

	if (local_result == -1)
	{
		printf("%s, line %d: failed to get protection class for a new file when locked, errno = %s.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_file;
	}
	else if (local_result != PROTECTION_CLASS_B)
	{
		printf("%s, line %d: new file in class B directory did not inherit protection class.\n",
		  cpt_fail_header, __LINE__, strerror(errno));
		goto cleanup_file;
	}

	/* What happens when we try to create new subdirectories? */
	if (unlock_device(passcode))
	{
		PRINT_UNLOCK_FAIL;
		goto cleanup_file;
	}

	for (new_prot_class = PROTECTION_CLASS_A; new_prot_class <= PROTECTION_CLASS_E; new_prot_class++)
	{
		if (SET_PROT_CLASS(dir_fd, new_prot_class))
		{
			printf("%s, line %d: failed to change directory to class %d, errno = %s.\n",
			  cpt_fail_header, __LINE__, new_prot_class, strerror(errno));
			goto cleanup_file;
		}

		local_result = mkdir(subdirpath, 0x0777);

		if (local_result == -1)
		{
			printf("%s, line %d: failed to create subdirectory in class %d directory, errno = %s.\n",
			  cpt_fail_header, __LINE__, new_prot_class, strerror(errno));
			goto cleanup_file;
		}

		subdir_fd = open(subdirpath, O_RDONLY | O_CLOEXEC);

		if (subdir_fd == -1)
		{
			printf("%s, line %d: failed to open subdirectory in class %d directory, errno = %s.\n",
			  cpt_fail_header, __LINE__, new_prot_class, strerror(errno));
			goto remove_subdir;
		}

		local_result = GET_PROT_CLASS(subdir_fd);

		if (local_result == -1)
		{
			printf("%s, line %d: failed to get class of new subdirectory of class %d directory, errno = %s.\n",
			  cpt_fail_header, __LINE__, new_prot_class, strerror(errno));
			goto cleanup_subdir;
		}
		else if (local_result != new_prot_class)
		{
			printf("%s, line %d: new subdirectory had different class than class %d parent.\n",
			  cpt_fail_header, __LINE__, new_prot_class);
			goto cleanup_subdir;
		}

		close(subdir_fd);
		rmdir(subdirpath);
	}

	/* If we've made it this far, the test was successful. */
	test_result = 0;

cleanup_subdir:
	close(subdir_fd);

remove_subdir:
	rmdir(subdirpath);

cleanup_file:
	close(fd);

remove_file:
	unlink(filepath);

cleanup_dir:
	close(dir_fd);

remove_dir:
	rmdir(dirpath);

remove_passcode:
	/* Try to unlock the device (no ramifications if it isn't locked when we try) and remove the passcode. */
	if (unlock_device(passcode))
	{
		printf("WARNING: failed to unlock the device.\n");
	}

	if (clear_passcode(passcode))
	{
		printf("WARNING: failed to clear the passcode.\n");
	}

end:
	return(test_result);
}

