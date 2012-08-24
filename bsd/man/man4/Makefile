export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

include $(MakeInc_cmd)
include $(MakeInc_def)

DATAFILES = \
	aio.4	\
	arp.4	\
	audit.4 \
	auditpipe.4	\
	bpf.4	\
	divert.4	\
        dummynet.4 \
	fd.4	\
	gif.4	\
	icmp.4	\
	icmp6.4	\
	ifmib.4 \
	inet.4	\
	inet6.4	\
	ip.4	\
	ip6.4	\
	ipfirewall.4	\
	ipl.4	\
	ipsec.4	\
	lo.4	\
	netintro.4	\
	networking.4	\
	null.4	\
	pty.4	\
	random.4	\
	route.4	\
	stderr.4	\
	stdin.4	\
	stdout.4	\
	stf.4	\
	tcp.4	\
	termios.4	\
	tty.4	\
	udp.4	\
	unix.4	\
	urandom.4	\

INSTALL_MAN_LIST = ${DATAFILES}

INSTALL_MAN_DIR = man4

include $(MakeInc_rule)
include $(MakeInc_dir)

