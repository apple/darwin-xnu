/*
 * persona_test.h
 *
 * Jeremy C. Andrus <jeremy_andrus@apple.com>
 *
 */
#ifndef _PERSONA_TEST_H_
#define _PERSONA_TEST_H_

/* internal */
#include <spawn_private.h>
#include <sys/persona.h>
#include <sys/spawn_internal.h>

//#define DEBUG

enum {
	PA_NONE          = 0x0000,
	PA_CREATE        = 0x0001,
	PA_SHOULD_VERIFY = 0x0002,
	PA_OVERRIDE      = 0x0004,
	PA_HAS_ID        = 0x0100,
	PA_HAS_TYPE      = 0x0200,
	PA_HAS_UID       = 0x0400,
	PA_HAS_GID       = 0x0800,
	PA_HAS_GROUPS    = 0x1000,
	PA_HAS_LOGIN     = 0x2000,
};

struct persona_args {
	uint32_t flags;
	uid_t  override_uid;
	struct kpersona_info kinfo;
};


/*
 * Error codes emitted on failure
 */
#define ERR_SYSTEM          -1
#define ERR_SPAWN            30
#define ERR_SPAWN_ATTR       31
#define ERR_CHILD_FAIL       40
#define ERR_ARGS             98
#define ERR_SETUP            99

#define err(fmt, ...) \
	do { \
		fflush(NULL); \
		fprintf(stderr, "[%4d] [ERROR(%d:%s)] %s:%d: " fmt "\n", \
			getuid(), errno, strerror(errno), \
			__func__, __LINE__, ## __VA_ARGS__ ); \
		fflush(stderr); \
		exit(ERR_SYSTEM); \
	} while (0)

#define errc(code, fmt, ...) \
	do { \
		fflush(NULL); \
		fprintf(stderr, "[%4d] [ERROR(%d)] %s:%d: " fmt "\n", \
			getuid(), code, \
			__func__, __LINE__, ## __VA_ARGS__ ); \
		fflush(stderr); \
		exit(code ? code : ERR_SYSTEM); \
	} while (0)

#define err_print(fmt, ...) \
	do { \
		fflush(NULL); \
		fprintf(stderr, "[%4d] [ERROR(%d:%s)] %s:%d: " fmt "\n", \
			getuid(), errno, strerror(errno), \
			__func__, __LINE__, ## __VA_ARGS__ ); \
		fflush(stderr); \
	} while (0)


#define err__start(fmt, ...) \
	do { \
		fprintf(stderr, "[%4d] [ERROR] " fmt, getuid(), ## __VA_ARGS__); \
		fflush(stderr); \
	} while (0)

#define err__cont(fmt, ...) \
	do { \
		fprintf(stderr, fmt, ## __VA_ARGS__); \
		fflush(stderr); \
	} while (0)

#define err__finish(fmt, ...) \
	do { \
		fprintf(stderr, fmt "\n", ## __VA_ARGS__); \
		fflush(stderr); \
	} while (0)


#ifdef DEBUG
#define dbg(fmt, ...) \
	do { \
		fprintf(stdout, "[%4d] [DEBUG] " fmt "\n", getuid(), ## __VA_ARGS__ ); \
		fflush(NULL); \
	} while (0)
#define warn(fmt, ...) \
	do { \
		fprintf(stdout, "[%4d] [WARN ] " fmt "\n", getuid(), ## __VA_ARGS__ ); \
		fflush(NULL); \
	} while (0)
#else
#define dbg(...)
#define warn(...)
#endif

#define info(fmt, ...) \
	do { \
		fprintf(stdout, "[%4d] [INFO ] " fmt "\n", getuid(), ## __VA_ARGS__ ); \
		fflush(NULL); \
	} while (0)

#define info_start(fmt, ...) \
	do { \
		fprintf(stdout, "[%4d] [INFO ] " fmt, getuid(), ## __VA_ARGS__ ); \
	} while (0)

#define info_cont(fmt, ...) \
	do { \
		fprintf(stdout, fmt, ## __VA_ARGS__ ); \
	} while (0)

#define info_end() \
	do { \
		fprintf(stdout, "\n"); \
		fflush(NULL); \
	} while (0)

#define infov(fmt, ...) \
	if (g.verbose) { \
		fprintf(stdout, "[%4d] [vINFO] " fmt "\n", getuid(), ## __VA_ARGS__ ); \
		fflush(NULL); \
	}

#define ARRAY_SZ(a) \
	(sizeof(a) / sizeof((a)[0]))


static inline void _dump_kpersona(const char *msg, uint32_t flags, const struct kpersona_info *ki)
{
	if (msg)
		info("%s", msg);
	info("\t kpersona_info (v%d) {", ki->persona_info_version);
	info("\t\t     %cid:  %d", flags & PA_HAS_ID ? '+' : '-', ki->persona_id);
	info("\t\t     %ctype:  %d", flags & PA_HAS_TYPE ? '+' : '-', ki->persona_type);
	info("\t\t    %cgid:  %d", flags & PA_HAS_GID ? '+' : '-', ki->persona_gid);

	info_start("\t\t  ngroups:  %d", ki->persona_ngroups);
	for (int i = 0; i < ki->persona_ngroups; i++) {
		if (i == 0) info_cont(" {");
		info_cont(" %d", ki->persona_groups[i]);
	}
	if (ki->persona_ngroups > 0)
		info_cont(" }");
	info_end();

	info("\t\t  %cgmuid: %d (0x%x)", flags & PA_HAS_GROUPS ? '+' : '-',
	     (int)ki->persona_gmuid, ki->persona_gmuid);
	info("\t\t  %clogin: \"%s\"", flags & PA_HAS_LOGIN ? '+' : '-', ki->persona_name);
	info("\t }");
}

#define dump_kpersona(msg, ki) \
	_dump_kpersona(msg, 0xffffffff, ki)

static inline void dump_persona_args(const char *msg, const struct persona_args *pa)
{
	const struct kpersona_info *ki = &pa->kinfo;

	if (msg)
		info("%s", msg);
	info("\t flags: 0x%x", pa->flags);
	info("\t %cuid: %d", pa->flags & PA_HAS_UID ? '+' : '-', pa->override_uid);
	_dump_kpersona(NULL, pa->flags, ki);
}

static int parse_groupspec(struct kpersona_info *kinfo, char *spec)
{
	int idx = 0;
	int grp;
	char *s, *e;

	if (!spec)
		return -1;
	s = e = spec;
	while (*s) {
		int comma = 0;
		e = s;
		while (*e && *e != ',')
			e++;
		if (*e)
			comma = 1;
		*e = 0;
		grp = atoi(s);
		if (comma) {
			*e = ',';
			s = e + 1;
		} else {
			s = e;
		}
		if (grp < 0)
			return -1;
		kinfo->persona_groups[idx] = grp;
		idx++;
	}
	kinfo->persona_ngroups = idx;

	return 0;
}

#endif /* _PERSONA_TEST_H_ */
