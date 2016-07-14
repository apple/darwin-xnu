/*
 * persona_mgr.c
 * Tool to manage personas
 *
 * Jeremy C. Andrus <jeremy_andrus@apple.com>
 *
 */
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <libgen.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <mach/mach.h>
#include <mach/task.h>
#include <mach/vm_param.h>
#include <sys/kauth.h>
#include <sys/queue.h>
#include <sys/sysctl.h>
#include <sys/types.h>

#include "persona_test.h"

/* internal */
#include <libproc.h>
#include <spawn_private.h>
#include <sys/persona.h>
#include <sys/proc_info.h>
#include <sys/spawn_internal.h>

#define PROG_NAME   "Persona Manager"
#define PROG_VMAJOR 0
#define PROG_VMINOR 1

enum {
	PERSONA_OP_CREATE  = 1,
	PERSONA_OP_DESTROY = 2,
	PERSONA_OP_LOOKUP  = 3,
	PERSONA_OP_MAX     = 3,
};

static struct mgr_config {
	int verbose;
} g;


static int persona_op_create(struct kpersona_info *ki)
{
	int ret;
	uid_t persona_id = 0;

	info("Creating persona...");
	ki->persona_info_version = PERSONA_INFO_V1;
	ret = kpersona_alloc(ki, &persona_id);
	if (ret == 0) {
		info("Created persona %d:", persona_id);
		dump_kpersona(NULL, ki);
	} else {
		err("kpersona_alloc return %d (errno:%d)", ret, errno);
	}

	return ret;
}

static int persona_op_destroy(struct kpersona_info *ki)
{
	int ret;

	info("Destroying Persona %d...", ki->persona_id);
	ki->persona_info_version = PERSONA_INFO_V1;
	ret = kpersona_dealloc(ki->persona_id);
	if (ret < 0)
		err_print("destroy failed!");

	return ret;
}

static int persona_op_lookup(struct kpersona_info *ki, pid_t pid, uid_t uid)
{
	int ret;

	info("Looking up persona (pid:%d, uid:%d)", pid, uid);
	if (pid > 0) {
		ki->persona_info_version = PERSONA_INFO_V1;
		ret = kpersona_pidinfo(pid, ki);
		if (ret < 0)
			err_print("pidinfo failed!");
		else
			dump_kpersona("Persona-for-pid:", ki);
	} else {
		int np = 0;
		uid_t personas[128];
		size_t npersonas = ARRAY_SZ(personas);
		const char *name = NULL;
		if (ki->persona_name[0] != 0)
			name = ki->persona_name;

		np = kpersona_find(name, uid, personas, &npersonas);
		if (np < 0)
			err("kpersona_find returned %d (errno:%d)", np, errno);
		info("Found %zu persona%c", npersonas, npersonas != 1 ? 's' : ' ');
		np = npersonas;
		while (np--) {
			info("\tpersona[%d]=%d...", np, personas[np]);
			ki->persona_info_version = PERSONA_INFO_V1;
			ret = kpersona_info(personas[np], ki);
			if (ret < 0)
				err("kpersona_info failed (errno:%d) for persona[%d]", errno, personas[np]);
			dump_kpersona(NULL, ki);
		}
	}

	return ret;
}


/* = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 *
 * Main Entry Point
 *
 * = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = = =
 */
static void usage_main(const char *progname, const char *msg, int verbose)
{
	const char *nm = basename((char *)progname);

	if (msg)
		printf("%s\n\n", msg);

	printf("%s v%d.%d\n", PROG_NAME, PROG_VMAJOR, PROG_VMINOR);
	printf("usage: %s [op] [-v] [-i id] [-t type] [-p pid] [-u uid] [-g gid] [-l login] [-G {groupspec}] [-m gmuid]\n", nm);
	if (!verbose)
		exit(1);

	printf("\t%-15s\tOne of: create | destroy | lookup\n", "[op]");
	printf("\t%-15s\tBe verbose\n", "-v");

	printf("\t%-15s\tID of the persona\n", "-i id");
	printf("\t%-15s\tType of the persona\n", "-t type");
	printf("\t%-15s\tPID of the process whose persona info to lookup\n", "-p pid");
	printf("\t%-15s\tUID to use in lookup\n", "-u uid");
	printf("\t%-15s\tGID of the persona\n", "-g gid");
	printf("\t%-15s\tLogin name of the persona\n", "-l login");
	printf("\t%-15s\tGroups to which the persona will belong\n", "-G {groupspec}");
	printf("\t%-15s\tgroupspec: G1{,G2,G3...}\n", " ");
	printf("\t%-15s\tUID used for memberd lookup (opt-in to memberd)\n", "-m gmuid");

	printf("\n");
	exit(1);
}

int main(int argc, char **argv)
{
	char ch;
	int ret;

	const char *op_str = NULL;
	int persona_op = 0;
	struct kpersona_info kinfo;
	uid_t uid = (uid_t)-1;
	pid_t pid = (pid_t)-1;

	/*
	 * Defaults
	 */
	g.verbose = 0;

	if (geteuid() != 0)
		err("%s must be run as root", argv[0] ? basename(argv[0]) : PROG_NAME);

	if (argc < 2)
		usage_main(argv[0], "Not enough arguments", 0);

	op_str = argv[1];

	if (strcmp(op_str, "create") == 0)
		persona_op = PERSONA_OP_CREATE;
	else if (strcmp(op_str, "destroy") == 0)
		persona_op = PERSONA_OP_DESTROY;
	else if (strcmp(op_str, "lookup") == 0)
		persona_op = PERSONA_OP_LOOKUP;
	else if (strcmp(op_str, "help") == 0 || strcmp(op_str, "-h") == 0)
		usage_main(argv[0], NULL, 1);

	if (persona_op <= 0 || persona_op > PERSONA_OP_MAX)
		usage_main(argv[0], "Invalid [op]", 0);

	memset(&kinfo, 0, sizeof(kinfo));
	kinfo.persona_gmuid = KAUTH_UID_NONE;

	/*
	 * Argument parse
	 */
	optind = 2;
	while ((ch = getopt(argc, argv, "vi:t:p:u:g:l:G:m:h")) != -1) {
		switch (ch) {
		case 'i':
			ret = atoi(optarg);
			if (ret <= 0)
				err("Invalid Persona ID: %s", optarg);
			kinfo.persona_id = (uid_t)ret;
			break;
		case 't':
			ret = atoi(optarg);
			if (ret <= PERSONA_INVALID || ret > PERSONA_TYPE_MAX)
				err("Invalid type specification: %s", optarg);
			kinfo.persona_type = ret;
			break;
		case 'p':
			ret = atoi(optarg);
			if (ret <= 0)
				err("Invalid PID: %s", optarg);
			pid = (pid_t)ret;
			break;
		case 'u':
			ret = atoi(optarg);
			if (ret <= 0)
				err("Invalid UID: %s", optarg);
			uid = (uid_t)ret;
			break;
		case 'g':
			kinfo.persona_gid = (gid_t)atoi(optarg);
			if (kinfo.persona_gid <= 500)
				err("Invalid GID: %d", kinfo.persona_gid);
			break;
		case 'l':
			strncpy(kinfo.persona_name, optarg, MAXLOGNAME);
			break;
		case 'G':
			ret = parse_groupspec(&kinfo, optarg);
			if (ret < 0)
				err("Invalid groupspec: \"%s\"", optarg);
			break;
		case 'm':
			ret = atoi(optarg);
			if (ret < 0)
				err("Invalid group membership ID: %s", optarg);
			kinfo.persona_gmuid = (uid_t)ret;
			break;
		case 'v':
			g.verbose = 1;
			break;
		case 'h':
		case '?':
			usage_main(argv[0], NULL, 1);
		case ':':
		default:
			printf("Invalid option: '%c'\n", ch);
			usage_main(argv[0], NULL, 0);
		}
	}

	if (uid == (uid_t)-1)
		uid = kinfo.persona_id;

	if (kinfo.persona_gmuid && kinfo.persona_ngroups == 0) {
		/*
		 * In order to set the group membership UID, we need to set at
		 * least one group: make it equal to either the GID or UID
		 */
		kinfo.persona_ngroups = 1;
		if (kinfo.persona_gid)
			kinfo.persona_groups[0] = kinfo.persona_gid;
		else
			kinfo.persona_groups[0] = kinfo.persona_id;
	}

	if (g.verbose)
		dump_kpersona("Input persona:", &kinfo);

	switch (persona_op) {
	case PERSONA_OP_CREATE:
		ret = persona_op_create(&kinfo);
		break;
	case PERSONA_OP_DESTROY:
		ret = persona_op_destroy(&kinfo);
		break;
	case PERSONA_OP_LOOKUP:
		ret = persona_op_lookup(&kinfo, pid, uid);
		break;
	default:
		err("Invalid persona op: %d", persona_op);
	}

	return ret;
}
