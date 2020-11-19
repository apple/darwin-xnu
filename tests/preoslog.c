#include <darwintest.h>
#include <darwintest_utils.h>
#include <sys/sysctl.h>
#include <string.h>
#include <errno.h>

/*
 * Any change to this structure must be reflected in iBoot / MacEFI / PanicDump / XNU Tests and vice versa.
 */
typedef struct  __attribute__((packed)) {
	uint32_t magic; /* g_valid_magic if valid */
	uint32_t size; /* Size of the preoslog buffer including the header */
	uint32_t offset; /* Write pointer. Indicates where in the buffer new log entry would go */
	uint8_t source; /* Indicates who filled in the buffer (e.g. iboot vs MacEFI) */
	uint8_t wrapped; /* If equal to 1, the preoslog ring buffer wrapped at least once */
	char data[]; /* log buffer */
} preoslog_header_t;

static const char* g_sysctl_kern_version = "kern.version";
static const char* g_sysctl_kern_preoslog = "kern.preoslog";
static const uint32_t g_valid_magic = 'LSOP';

/*
 * Defines substrings to look up in preoslog buffer.
 * To pass the test, one of the entries should match a substring in preoslog buffer.
 */
static const char* g_preoslog_buffer_string[] = {"serial output"};

static boolean_t
check_for_substrings(const char* string, size_t len)
{
	int i;
	boolean_t res = FALSE;

	for (i = 0; i < (sizeof(g_preoslog_buffer_string) / sizeof(char*)); i++) {
		res = res || strnstr(string, g_preoslog_buffer_string[i], len) == NULL ? FALSE : TRUE;
	}

	return res;
}

static boolean_t
is_development_kernel(void)
{
	int ret;
	int dev = 0;
	size_t dev_size = sizeof(dev);

	ret = sysctlbyname("kern.development", &dev, &dev_size, NULL, 0);
	if (ret != 0) {
		return FALSE;
	}

	return dev != 0;
}

/*
 *       Valid cases:
 *       1. Development & Debug iBoot/macEFI provides a preoslog buffer.
 *       2. Release iBoot/macEFI doesn't provide a presoslog buffer.
 *       3. Development & Debug xnu provids kern.preoslog sysctl.
 *       4. Release xnu doesn't provide kern.preoslog sysctl.
 */

T_DECL(test_preoslog, "Validate kern.preoslog sysctl has expected log content from the boot loader")
{
	int ret = 0;
	size_t size = 0;
	void *buffer = NULL;
	preoslog_header_t *header = NULL;
	char tmp = 0;
	const char *lower_buffer = NULL;
	size_t lower_buffer_size = 0;
	const char *upper_buffer = NULL;
	size_t upper_buffer_size = 0;
	boolean_t found = FALSE;

	// kern.preoslog is writable
	ret = sysctlbyname(g_sysctl_kern_preoslog, buffer, &size, &tmp, sizeof(tmp));
	T_ASSERT_POSIX_SUCCESS(ret, "kern.preoslog write check");

	ret = sysctlbyname(g_sysctl_kern_preoslog, NULL, &size, NULL, 0);
	if (!is_development_kernel()) {
		// kern.preoslog mustn't exist on release builds of xnu
		T_ASSERT_NE(ret, 0, "get size kern.preoslog ret != 0 on release builds");
		T_ASSERT_POSIX_ERROR(ret, ENOENT, " get size kern.preoslog errno==ENOENT on release builds");
		return;
	}

	/*
	 * Everything below is applicable only to development & debug xnu
	 */

	T_ASSERT_POSIX_SUCCESS(ret, "get size for kern.preoslog");
	if (size == 0) {
		// No preoslog buffer available, valid case if iboot is release
		return;
	}

	buffer = calloc(size, sizeof(char));
	T_ASSERT_NOTNULL(buffer, "allocate buffer for preoslog");

	ret = sysctlbyname(g_sysctl_kern_preoslog, buffer, &size, NULL, 0);
	T_ASSERT_POSIX_SUCCESS(ret, "get preoslog buffer");

	header = (preoslog_header_t *)buffer;
	T_ASSERT_EQ(header->magic, g_valid_magic, "check preoslog header magic - expected %#x, given %#x", g_valid_magic, header->magic);
	T_ASSERT_EQ(header->size, size, "check preoslog sizes - expected %zu, given %zu", size, header->size);
	T_ASSERT_LT(header->offset, header->size - sizeof(*header), "check write offset");

	lower_buffer = header->data;
	lower_buffer_size = header->offset + 1;
	upper_buffer = lower_buffer + lower_buffer_size;
	upper_buffer_size = header->size - lower_buffer_size - sizeof(*header);
	if (header->wrapped) {
		found = check_for_substrings(upper_buffer, upper_buffer_size);
	}

	found = found || check_for_substrings(lower_buffer, lower_buffer_size);
	T_ASSERT_TRUE(found, "Verify buffer content");

	free(buffer);
	buffer = NULL;
	header = NULL;
}
