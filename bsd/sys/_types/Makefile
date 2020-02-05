export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

INSTINC_SUBDIRS =

EXPINC_SUBDIRS =

# Installs header file for user level -
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/Headers
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
#	  $(DSTROOT)/usr/include/
DATAFILES = \
	_blkcnt_t.h \
	_blksize_t.h \
	_caddr_t.h \
	_clock_t.h \
	_ct_rune_t.h \
	_dev_t.h \
	_errno_t.h \
	_fd_clr.h \
	_fd_copy.h \
	_fd_def.h \
	_fd_isset.h \
	_fd_set.h \
	_fd_setsize.h \
	_fd_zero.h \
	_filesec_t.h \
	_fsblkcnt_t.h \
	_fsfilcnt_t.h \
	_fsid_t.h \
	_fsobj_id_t.h \
	_gid_t.h \
	_guid_t.h \
	_id_t.h \
	_in_addr_t.h \
	_in_port_t.h \
	_ino64_t.h \
	_ino_t.h \
	_int16_t.h \
	_int32_t.h \
	_int64_t.h \
	_int8_t.h \
	_intptr_t.h \
	_iovec_t.h \
	_key_t.h \
	_mach_port_t.h \
	_mbstate_t.h \
	_mode_t.h \
	_nlink_t.h \
	_null.h \
	_o_dsync.h \
	_o_sync.h \
	_off_t.h \
	_offsetof.h \
	_os_inline.h \
	_pid_t.h \
	_posix_vdisable.h \
	_ptrdiff_t.h \
	_rsize_t.h \
	_rune_t.h \
	_s_ifmt.h \
	_sa_family_t.h \
	_seek_set.h \
	_sigaltstack.h \
	_sigset_t.h \
	_size_t.h \
	_socklen_t.h \
	_ssize_t.h \
	_suseconds_t.h \
	_time_t.h \
	_timespec.h \
	_timeval.h \
	_timeval32.h \
	_timeval64.h \
	_ucontext.h \
	_ucontext64.h \
	_uid_t.h \
	_u_char.h \
	_u_int.h \
	_u_int16_t.h \
	_u_int32_t.h \
	_u_int64_t.h \
	_u_int8_t.h \
	_u_short.h \
	_uintptr_t.h \
	_useconds_t.h \
	_uuid_t.h \
	_va_list.h \
	_wchar_t.h \
	_wint_t.h \
	_user32_timex.h \
	_user64_timex.h \
	_user32_ntptimeval.h \
	_user64_ntptimeval.h \

# Installs header file for DriverKit drivers -
#	  $(DSTROOT)/System/DriverKit/System/usr/include/
DRIVERKIT_DATAFILES = \
	_ct_rune_t.h \
	_errno_t.h \
	_int16_t.h \
	_int32_t.h \
	_int64_t.h \
	_int8_t.h \
	_intptr_t.h \
	_mbstate_t.h \
	_null.h \
	_offsetof.h \
	_os_inline.h \
	_ptrdiff_t.h \
	_rsize_t.h \
	_rune_t.h \
	_size_t.h \
	_ssize_t.h \
	_u_int16_t.h \
	_u_int32_t.h \
	_u_int64_t.h \
	_u_int8_t.h \
	_uintptr_t.h \
	_uuid_t.h \
	_va_list.h \
	_wchar_t.h \
	_wint_t.h \

# Installs header file for Apple internal use in user level -
#	  $(DSTROOT)/System/Library/Frameworks/System.framework/PrivateHeaders
PRIVATE_DATAFILES = \

# Installs header file for kernel extensions -
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/Headers
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
KERNELFILES = ${DATAFILES} \
	_user_timespec.h \
	_user64_timespec.h \
	_user32_timespec.h \
	_user_timeval.h \
	_user64_timeval.h \
	_user32_timeval.h \
	_user64_itimerval.h \
	_user32_itimerval.h \

# Installs header file for Apple internal use for kernel extensions -
#	  $(DSTROOT)/System/Library/Frameworks/Kernel.framework/PrivateHeaders
PRIVATE_KERNELFILES = \

# /System/Library/Frameworks/System.framework/Headers and /usr/include
INSTALL_MI_LIST	= ${DATAFILES}

INSTALL_DRIVERKIT_MI_LIST = ${DRIVERKIT_DATAFILES}

INSTALL_MI_GEN_LIST =

INSTALL_MI_DIR = sys/_types

EXPORT_MI_LIST	= ${KERNELFILES} ${PRIVATE_KERNELFILES}

EXPORT_MI_GEN_LIST =

EXPORT_MI_DIR = sys/_types

# /System/Library/Frameworks/System.framework/PrivateHeaders
INSTALL_MI_LCL_LIST = ${PRIVATE_DATAFILES}

# /System/Library/Frameworks/Kernel.framework/PrivateHeaders
INSTALL_KF_MI_LCL_LIST =  ${KERNELFILES} ${PRIVATE_KERNELFILES}

INSTALL_KF_MI_LCL_GEN_LIST =

# /System/Library/Frameworks/Kernel.framework/Headers
INSTALL_KF_MI_LIST = ${KERNELFILES}

INSTALL_KF_MI_GEN_LIST =

include $(MakeInc_rule)
include $(MakeInc_dir)
