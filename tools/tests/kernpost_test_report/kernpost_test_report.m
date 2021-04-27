#import <Foundation/Foundation.h>
#include <kcdata.h>
#import <kdd.h>
#include <mach/mach_time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/sysctl.h>
#include <sysexits.h>
#include <unistd.h>

#define FREE_BUF(_buf)   \
	do {                 \
		if (_buf) {      \
			free(_buf);  \
			_buf = NULL; \
		}                \
	} while (0);

#define ERR(_msg_format, ...) fprintf(stderr, "error: " _msg_format "\n", ##__VA_ARGS__)

#define PERR(_msg) perror("error: " _msg)

/* XNUPost KCData constants */
NSString * const kXNUPostKCDataKeyTestConfig      = @"xnupost_testconfig";
NSString * const kXNUPostKCDataKeyOSVersion       = @"osversion";
NSString * const kXNUPostKCDataKeyBootargs        = @"boot_args";
NSString * const kXNUPostKCDataKeyMachTBInfo      = @"mach_timebase_info";
NSString * const kXNUPostKCDataKeyMachTBInfoDenom = @"denom";
NSString * const kXNUPostKCDataKeyMachTBInfoNumer = @"numer";
NSString * const kXNUPostKCDataKeySubTestConfig   = @"xnupost_test_config";
NSString * const kXNUPostKCDataKeyTestName        = @"test_name";
NSString * const kXNUPostKCDataKeyBeginTime       = @"begin_time";
NSString * const kXNUPostKCDataKeyEndTime         = @"end_time";
NSString * const kXNUPostKCDataKeyRetval          = @"retval";
NSString * const kXNUPostKCDataKeyExpectedRetval  = @"expected_retval";

/* Resultbundle info constants */
NSString * const kRBInfoKeyVersion         = @"version";
NSString * const kRBInfoKeyCategory        = @"test_category";
NSString * const kRBInfoKeyTestID          = @"test_id";
NSString * const kRBInfoKeyProject         = @"Project";
NSString * const kRBInfoKeyBootargs        = @"boot-args";
NSString * const kRBInfoKeyOSVersion       = @"osVersion";
NSString * const kRBInfoKeyResultCode      = @"result_code";
NSString * const kRBInfoKeyResultStarted   = @"result_started";
NSString * const kRBInfoKeyResultFinished  = @"result_finished";
NSString * const kRBInfoKeyMachTBInfo      = @"mach_timebase_info";
NSString * const kRBInfoKeyMachTBInfoDenom = @"denom";
NSString * const kRBInfoKeyMachTBInfoNumer = @"numer";
NSString * const kRBInfoKeyBeginTimeRaw    = @"beginTimeRaw";
NSString * const kRBInfoKeyEndTimeRaw      = @"endTimeRaw";

NSNumber * const kResultBundleVersion  = @2;
NSString * const kResultBundleCategory = @"unittest";
NSString * const kResultBundleProject  = @"xnu";
NSNumber * const kResultCodePass       = @200;
NSNumber * const kResultCodeFail       = @400;

#define COMMAND_EXPORT (0)
static int g_command = COMMAND_EXPORT;
#define OUTPUT_FORMAT_RAW (0)
#define OUTPUT_FORMAT_PLIST_XML (1)
#define OUTPUT_FORMAT_RESULTBUNDLE (2)
static int g_output_format = OUTPUT_FORMAT_RAW;
static char * g_output_dir = NULL;

static void
usage(void)
{
	const char * progname = getprogname();
	fprintf(stderr,
	        "Usage:\t%s COMMAND [OPTIONS]\n\n"
	        "\t%s export -o OUTPUT_DIR_PATH [-f raw|plist|resultbundle]\n"
	        "\nSupported command:\n"
	        "\texport\n",
	        progname, progname);
}

static void
parse_export_options(int argc, char * argv[])
{
	int ch;
	bool error = false;

	while ((ch = getopt(argc, argv, "o:f:")) != -1) {
		switch (ch) {
		case 'o':
			g_output_dir = optarg;
			break;
		case 'f':
			if (strncmp(optarg, "raw", 4) == 0) {
				g_output_format = OUTPUT_FORMAT_RAW;
			} else if (strncmp(optarg, "plist", 6) == 0) {
				g_output_format = OUTPUT_FORMAT_PLIST_XML;
			} else if (strncmp(optarg, "resultbundle", 13) == 0) {
				g_output_format = OUTPUT_FORMAT_RESULTBUNDLE;
			} else {
				error = true;
			}
			break;
		default:
			error = true;
			break;
		}
	}

	if (g_output_dir == NULL) {
		error = true;
	}

	struct stat path_stat;
	if (stat(g_output_dir, &path_stat)) {
		PERR("Failed to access output dir");
		error = true;
	} else if (!S_ISDIR(path_stat.st_mode)) {
		ERR("error: Output path must be a directory");
		error = true;
	}

	if (error) {
		usage();
		exit(EX_USAGE);
	}
}

static void
parse_options(int argc, char * argv[])
{
	if (argc > 1) {
		char * cmd = argv[1];
		argc--;
		argv++;
		if (strncmp(cmd, "export", 7) == 0) {
			g_command = COMMAND_EXPORT;
			parse_export_options(argc, argv);
		} else {
			usage();
			exit(EX_USAGE);
		}
	} else {
		usage();
		exit(EX_USAGE);
	}
}

static void
retrieve_test_data(void ** raw_buf_p, size_t * raw_size_p)
{
	int rc = sysctlbyname("debug.xnupost_get_tests", NULL, raw_size_p, NULL, 0);
	if (rc == 0 && *raw_size_p > 0) {
		*raw_buf_p = malloc(*raw_size_p);
		if (*raw_buf_p) {
			rc = sysctlbyname("debug.xnupost_get_tests", *raw_buf_p, raw_size_p, NULL, 0);
			if (0 != rc) {
				PERR("Failed to get KCData through sysctl");
			}
		} else {
			PERR("Failed to allocate KCData raw buffer");
		}
	} else {
		PERR("Failed to get size through sysctl");
	}
}

static void
export_raw(void * raw_buf, size_t raw_size)
{
	if (raw_buf) {
		char output_path[MAXPATHLEN];
		snprintf(output_path, MAXPATHLEN, "%s/xnupost.kcdata", g_output_dir);
		FILE * output_fp = fopen(output_path, "w");
		if (output_fp) {
			fwrite(raw_buf, raw_size, 1, output_fp);
			fclose(output_fp);
		} else {
			PERR("Failed to open output path");
		}
	}
}

static void
export_to_plist(void * raw_buf, size_t raw_size)
{
	if (raw_buf) {
		char output_path[MAXPATHLEN];
		snprintf(output_path, MAXPATHLEN, "%s/xnupost.plist", g_output_dir);
		NSError * nsError          = nil;
		NSDictionary * parsed_dict = parseKCDataBuffer(raw_buf, raw_size, &nsError);
		if (parsed_dict) {
			NSData * plist_data = [NSPropertyListSerialization dataWithPropertyList:parsed_dict
			                                                                 format:NSPropertyListXMLFormat_v1_0
			                                                                options:0
			                                                                  error:&nsError];
			if (plist_data) {
				if (![plist_data writeToFile:[NSString stringWithUTF8String:output_path] atomically:YES]) {
					ERR("Failed to write plist to %s", output_path);
				}
			} else {
				ERR("Failed to serialize result plist: %s", nsError.localizedDescription.UTF8String);
			}
		} else {
			ERR("Failed to parse KCData to plist: %s", nsError.localizedDescription.UTF8String);
		}
	}
}

#define RESULTBUNDLE_TIME_STR_SIZE (30) // 0000-00-00T00:00:00.000+00:00'\0'
#define RESULTBUNLDE_TIME_MS_INDEX (20)
#define RESULTBUNLDE_TIME_TZ_COLON_INDEX (26)
#define RESULTBUNDLE_TIME_MS_STR_SIZE (4) // 000'\0'
#define MSEC_PER_USEC 1000ull

static void
get_estimated_time_str_resultbundle(char * output_str, uint64_t mach_abs_time_usec)
{
	uint64_t est_usec          = mach_boottime_usec() + mach_abs_time_usec;
	time_t est_sec             = (time_t)(est_usec / USEC_PER_SEC);
	uint64_t est_usec_fraction = est_usec % USEC_PER_SEC;
	struct tm tm_info;
	int i = 0;

	localtime_r(&est_sec, &tm_info);
	strftime(output_str, RESULTBUNDLE_TIME_STR_SIZE, "%Y-%m-%dT%H:%M:%S.000%z", &tm_info);

	/* Fill out milliseconds */
	char ms_str[RESULTBUNDLE_TIME_MS_STR_SIZE] = {0};
	snprintf(ms_str, RESULTBUNDLE_TIME_MS_STR_SIZE, "%03llu", est_usec_fraction / MSEC_PER_USEC);
	for (i = 0; i < 3; i++) {
		output_str[RESULTBUNLDE_TIME_MS_INDEX + i] = ms_str[i];
	}

	/* Add colon for timezone offset */
	for (i = RESULTBUNDLE_TIME_STR_SIZE - 1; i > RESULTBUNLDE_TIME_TZ_COLON_INDEX; i--) {
		output_str[i] = output_str[i - 1];
	}
	output_str[RESULTBUNLDE_TIME_TZ_COLON_INDEX] = ':';
}

static void
create_subtest_bundle_config(NSDictionary * testconfig, NSDictionary * subtest, char * bundle_dir)
{
	NSString * testName    = subtest[kXNUPostKCDataKeyTestName];
	NSNumber * tbInfoDenom = testconfig[kXNUPostKCDataKeyMachTBInfo][kXNUPostKCDataKeyMachTBInfoDenom];
	NSNumber * tbInfoNumer = testconfig[kXNUPostKCDataKeyMachTBInfo][kXNUPostKCDataKeyMachTBInfoNumer];
	struct mach_timebase_info tb_info;
	tb_info.denom            = tbInfoDenom.unsignedIntValue;
	tb_info.numer            = tbInfoNumer.unsignedIntValue;
	NSNumber * beginTimeRaw  = subtest[kXNUPostKCDataKeyBeginTime];
	NSNumber * endTimeRaw    = subtest[kXNUPostKCDataKeyEndTime];
	uint64_t begin_time_usec = (beginTimeRaw.unsignedLongLongValue * tb_info.numer) / (tb_info.denom * NSEC_PER_USEC);
	uint64_t end_time_usec   = (endTimeRaw.unsignedLongLongValue * tb_info.numer) / (tb_info.denom * NSEC_PER_USEC);
	bool test_status =
	    subtest[kXNUPostKCDataKeyRetval] && (subtest[kXNUPostKCDataKeyRetval] == subtest[kXNUPostKCDataKeyExpectedRetval]);

	char output_path[MAXPATHLEN];
	char * output_dir_end = NULL;

	snprintf(output_path, MAXPATHLEN, "%s/test_%s", bundle_dir, testName.UTF8String);
	if (mkdir(output_path, 0777)) {
		PERR("Failed to create subtest bundle dir");
	}
	output_dir_end = output_path + strlen(output_path);

	*output_dir_end = '\0';
	strlcat(output_path, "/Attachments", MAXPATHLEN);
	if (mkdir(output_path, 0777)) {
		PERR("Failed to create subtest Attachments dir");
	}

	*output_dir_end = '\0';
	strlcat(output_path, "/Diagnostics", MAXPATHLEN);
	if (mkdir(output_path, 0777)) {
		PERR("Failed to create subtest Diagnostics dir");
	}

	NSMutableDictionary * rbInfo = [NSMutableDictionary new];
	rbInfo[kRBInfoKeyVersion]    = kResultBundleVersion;
	rbInfo[kRBInfoKeyCategory]   = kResultBundleCategory;
	rbInfo[kRBInfoKeyTestID]     = testName;
	rbInfo[kRBInfoKeyProject]    = kResultBundleProject;
	rbInfo[kRBInfoKeyOSVersion]  = testconfig[kXNUPostKCDataKeyOSVersion];
	rbInfo[kRBInfoKeyBootargs]   = testconfig[kXNUPostKCDataKeyBootargs];
	rbInfo[kRBInfoKeyResultCode] = test_status ? kResultCodePass : kResultCodeFail;

	char estimated_time_str[RESULTBUNDLE_TIME_STR_SIZE];
	get_estimated_time_str_resultbundle(estimated_time_str, begin_time_usec);
	rbInfo[kRBInfoKeyResultStarted] = [NSString stringWithUTF8String:estimated_time_str];
	get_estimated_time_str_resultbundle(estimated_time_str, end_time_usec);
	rbInfo[kRBInfoKeyResultFinished] = [NSString stringWithUTF8String:estimated_time_str];

	rbInfo[kRBInfoKeyMachTBInfo] = @{kRBInfoKeyMachTBInfoDenom : tbInfoDenom, kRBInfoKeyMachTBInfoNumer : tbInfoNumer};

	rbInfo[kRBInfoKeyBeginTimeRaw] = beginTimeRaw;
	rbInfo[kRBInfoKeyEndTimeRaw]   = endTimeRaw;

	*output_dir_end = '\0';
	strlcat(output_path, "/Info.plist", MAXPATHLEN);
	NSURL * output_url   = [NSURL fileURLWithFileSystemRepresentation:output_path isDirectory:NO relativeToURL:nil];
	NSError * writeError = nil;
	if (![rbInfo writeToURL:output_url error:&writeError]) {
		ERR("Failed to write Info.plist file: %s", writeError.localizedDescription.UTF8String);
	}

	*output_dir_end = '\0';
	strlcat(output_path, test_status ? "/PASS.status" : "/FAIL.status", MAXPATHLEN);
	int fd = open(output_path, O_CREAT | O_TRUNC | O_WRONLY, 0666);
	if (fd == -1) {
		PERR("Failed to create subtest status file");
	} else {
		close(fd);
	}
}

static void
export_to_resultbundle(void * raw_buf, size_t raw_size)
{
	if (raw_buf) {
		NSError * nsError          = nil;
		NSDictionary * parsed_dict = parseKCDataBuffer(raw_buf, raw_size, &nsError);
		if (parsed_dict) {
			NSDictionary * testconfig = parsed_dict[kXNUPostKCDataKeyTestConfig];
			NSArray * subtests        = testconfig[kXNUPostKCDataKeySubTestConfig];

			char bundle_dir[MAXPATHLEN];
			snprintf(bundle_dir, MAXPATHLEN, "%s/xnupost", g_output_dir);
			if (mkdir(bundle_dir, 0777)) {
				PERR("Failed to create result bundle dir");
			}

			for (NSDictionary * subtest in subtests) {
				create_subtest_bundle_config(testconfig, subtest, bundle_dir);
			}
		} else {
			ERR("Failed to parse KCData to plist: %s", nsError.localizedDescription.UTF8String);
		}
	}
}

static void
execute_export(void)
{
	void * raw_buf  = NULL;
	size_t raw_size = 0;
	retrieve_test_data(&raw_buf, &raw_size);
	switch (g_output_format) {
	case OUTPUT_FORMAT_PLIST_XML:
		export_to_plist(raw_buf, raw_size);
		break;
	case OUTPUT_FORMAT_RESULTBUNDLE:
		export_to_resultbundle(raw_buf, raw_size);
		break;
	case OUTPUT_FORMAT_RAW:
	default:
		export_raw(raw_buf, raw_size);
		break;
	}

	FREE_BUF(raw_buf);
}

int
main(int argc, char * argv[])
{
	parse_options(argc, argv);
	switch (g_command) {
	case COMMAND_EXPORT:
		execute_export();
		break;
	default:
		usage();
		exit(EX_USAGE);
		break;
	}

	return 0;
}
