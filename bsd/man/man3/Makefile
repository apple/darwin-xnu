export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	queue.3 \
	posix_spawn_file_actions_addclose.3  \
	posix_spawn_file_actions_init.3  \
	posix_spawnattr_init.3  \
	posix_spawnattr_setarchpref_np.3  \
	posix_spawnattr_setbinpref_np.3  \
	posix_spawnattr_setflags.3  \
	posix_spawnattr_setpgroup.3  \
	posix_spawnattr_setsigdefault.3  \
	posix_spawnattr_setsigmask.3  \
	posix_spawnattr_setspecialport_np.3 \
	getiopolicy_np.3

INSTALL_MAN_LIST = ${DATAFILES}

INSTALL_MAN_LINKS = \
	queue.3 CIRCLEQ_ENTRY.3 \
	queue.3 CIRCLEQ_HEAD.3 \
	queue.3 CIRCLEQ_INIT.3 \
	queue.3 CIRCLEQ_INSERT_AFTER.3 \
	queue.3 CIRCLEQ_INSERT_BEFORE.3 \
	queue.3 CIRCLEQ_INSERT_HEAD.3 \
	queue.3 CIRCLEQ_INSERT_TAIL.3 \
	queue.3 CIRCLEQ_REMOVE.3 \
	queue.3 LIST_ENTRY.3 \
	queue.3 LIST_HEAD.3 \
	queue.3 LIST_INIT.3 \
	queue.3 LIST_INSERT_AFTER.3 \
	queue.3 LIST_INSERT_BEFORE.3 \
	queue.3 LIST_INSERT_HEAD.3 \
	queue.3 LIST_REMOVE.3 \
	queue.3 TAILQ_ENTRY.3 \
	queue.3 TAILQ_HEAD.3 \
	queue.3 TAILQ_INIT.3 \
	queue.3 TAILQ_INSERT_AFTER.3 \
	queue.3 TAILQ_INSERT_BEFORE.3 \
	queue.3 TAILQ_INSERT_HEAD.3 \
	queue.3 TAILQ_INSERT_TAIL.3 \
	queue.3 TAILQ_REMOVE.3 \
	posix_spawn_file_actions_addclose.3 posix_spawn_file_actions_addopen.3 \
	posix_spawn_file_actions_addclose.3 posix_spawn_file_actions_adddup2.3 \
	posix_spawn_file_actions_addclose.3 posix_spawn_file_actions_addinherit_np.3 \
	posix_spawn_file_actions_addclose.3 posix_spawn_file_actions_addchdir_np.3 \
	posix_spawn_file_actions_addclose.3 posix_spawn_file_actions_addfchdir_np.3 \
	posix_spawn_file_actions_init.3 posix_spawn_file_actions_destroy.3 \
	posix_spawnattr_init.3 posix_spawnattr_destroy.3 \
	posix_spawnattr_setarchpref_np.3 posix_spawnattr_getarchpref_np.3 \
	posix_spawnattr_setbinpref_np.3 posix_spawnattr_getbinpref_np.3 \
	posix_spawnattr_setflags.3 posix_spawnattr_getflags.3 \
	posix_spawnattr_setpgroup.3 posix_spawnattr_getpgroup.3 \
	posix_spawnattr_setsigdefault.3 posix_spawnattr_getsigdefault.3 \
	posix_spawnattr_setsigmask.3 posix_spawnattr_getsigmask.3 \
	posix_spawnattr_setspecialport_np.3 posix_spawnattr_setexceptionports_np.3 \
	getiopolicy_np.3 setiopolicy_np.3

INSTALL_MAN_DIR = man3

include $(MakeInc_rule)
include $(MakeInc_dir)
