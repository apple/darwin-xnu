export MakeInc_cmd=${SRCROOT}/makedefs/MakeInc.cmd
export MakeInc_def=${SRCROOT}/makedefs/MakeInc.def
export MakeInc_rule=${SRCROOT}/makedefs/MakeInc.rule
export MakeInc_dir=${SRCROOT}/makedefs/MakeInc.dir

export dp_backing_file.o_CFLAGS_ADD=-Werror -Wshorten-64-to-32
export ubc_subr.o_CFLAGS_ADD=-Wno-discard-qual -Wshorten-64-to-32
export vnode_pager.o_CFLAGS_ADD=-Werror -Wshorten-64-to-32
export vm_unix.o_CFLAGS_ADD=-Werror -Wshorten-64-to-32

export if_mib.o_CFLAGS_ADD=-Wno-unused-parameter
export adsp_Write.o_CFLAGS_ADD=-Wno-sign-compare
export adsp_Packet.o_CFLAGS_ADD=-Wno-sign-compare
export adsp_Control.o_CFLAGS_ADD=-Wno-sign-compare
export adsp_RxAttn.o_CFLAGS_ADD=-Wno-sign-compare
export adsp_attention.o_CFLAGS_ADD=-Wno-sign-compare
export asp_proto.o_CFLAGS_ADD=-Wno-sign-compare
export drv_dep.o_CFLAGS_ADD=-Wno-sign-compare
export ddp_rtmp.o_CFLAGS_ADD=-Wno-sign-compare
export ddp_lap.o_CFLAGS_ADD=-Wno-sign-compare
export radix.o_CFLAGS_ADD=-Wno-sign-compare
export route.o_CFLAGS_ADD=-Wno-sign-compare
export rtsock.o_CFLAGS_ADD=-Wno-sign-compare
export dhcp_options.o_CFLAGS_ADD=-Wno-sign-compare
export igmp.o_CFLAGS_ADD=-Wno-sign-compare
export in_cksum.o_CFLAGS_ADD=-Wno-sign-compare
export ip_divert.o_CFLAGS_ADD=-Wno-sign-compare
export ip_dummynet.o_CFLAGS_ADD=-Wno-sign-compare
export ip_flow.o_CFLAGS_ADD=-Wno-sign-compare
export ip_fw2.o_CFLAGS_ADD=-Wno-sign-compare
export ip_fw2_compat.o_CFLAGS_ADD=-Wno-sign-compare
export ip_icmp.o_CFLAGS_ADD=-Wno-sign-compare
export ip_input.o_CFLAGS_ADD=-Wno-sign-compare
export ip_mroute.o_CFLAGS_ADD=-Wno-sign-compare
export ip_output.o_CFLAGS_ADD=-Wno-sign-compare
export raw_ip.o_CFLAGS_ADD=-Wno-sign-compare
export tcp_input.o_CFLAGS_ADD=-Wno-sign-compare
export tcp_output.o_CFLAGS_ADD=-Wno-sign-compare
export tcp_subr.o_CFLAGS_ADD=-Wno-sign-compare
export tcp_usrreq.o_CFLAGS_ADD=-Wno-sign-compare
export tcp_timer.o_CFLAGS_ADD=-Wno-sign-compare
export udp_usrreq.o_CFLAGS_ADD=-Wno-sign-compare
export ah_input.o_CFLAGS_ADD=-Wno-sign-compare
export ah_core.o_CFLAGS_ADD=-Wno-sign-compare
export ah_output.o_CFLAGS_ADD=-Wno-sign-compare
export esp_core.o_CFLAGS_ADD=-Wno-sign-compare
export esp_input.o_CFLAGS_ADD=-Wno-sign-compare
export esp_output.o_CFLAGS_ADD=-Wno-sign-compare
export esp_rijndael.o_CFLAGS_ADD=-Wno-sign-compare
export ipsec.o_CFLAGS_ADD=-Wno-sign-compare
export dest6.o_CFLAGS_ADD=-Wno-sign-compare
export frag6.o_CFLAGS_ADD=-Wno-sign-compare
export icmp6.o_CFLAGS_ADD=-Wno-sign-compare
export in6.o_CFLAGS_ADD=-Wno-sign-compare
export in6_src.o_CFLAGS_ADD=-Wno-sign-compare
export in6_cksum.o_CFLAGS_ADD=-Wno-sign-compare
export ip6_fw.o_CFLAGS_ADD=-Wno-sign-compare
export ip6_forward.o_CFLAGS_ADD=-Wno-sign-compare
export in6_ifattach.o_CFLAGS_ADD=-Wno-sign-compare
export ip6_input.o_CFLAGS_ADD=-Wno-sign-compare
export ip6_mroute.o_CFLAGS_ADD=-Wno-sign-compare
export ip6_output.o_CFLAGS_ADD=-Wno-sign-compare
export ipcomp_input.o_CFLAGS_ADD=-Wno-sign-compare
export ipcomp_output.o_CFLAGS_ADD=-Wno-sign-compare
export in6_proto.o_CFLAGS_ADD=-Wno-sign-compare
export mld6.o_CFLAGS_ADD=-Wno-sign-compare
export nd6.o_CFLAGS_ADD=-Wno-sign-compare
export nd6_nbr.o_CFLAGS_ADD=-Wno-sign-compare
export nd6_rtr.o_CFLAGS_ADD=-Wno-sign-compare
export raw_ip6.o_CFLAGS_ADD=-Wno-sign-compare
export route6.o_CFLAGS_ADD=-Wno-sign-compare
export scope6.o_CFLAGS_ADD=-Wno-sign-compare
export udp6_usrreq.o_CFLAGS_ADD=-Wno-sign-compare
export key.o_CFLAGS_ADD=-Wno-sign-compare
export keysock.o_CFLAGS_ADD=-Wno-sign-compare
export atp_write.o_CFLAGS_ADD=-Wno-sign-compare
export keydb.o_CFLAGS_ADD=-Wno-sign-compare
export des_setkey.o_CFLAGS_ADD=-Wno-sign-compare
export sys_socket.o_CFLAGS_ADD=-Wno-sign-compare
export sys_glue.o_CFLAGS_ADD=-Wno-sign-compare
export uipc_domain.o_CFLAGS_ADD=-Wno-sign-compare
export uipc_mbuf.o_CFLAGS_ADD=-Wno-sign-compare
export uipc_mbuf2.o_CFLAGS_ADD=-Wno-sign-compare
export uipc_socket.o_CFLAGS_ADD=-Wno-sign-compare
export uipc_socket2.o_CFLAGS_ADD=-Wno-sign-compare

include $(MakeInc_cmd)
include $(MakeInc_def)

SETUP_SUBDIRS = \
	tools

COMP_SUBDIRS = 

INST_SUBDIRS = 

ifndef BSD_KERNEL_CONFIG
export BSD_KERNEL_CONFIG = $(KERNEL_CONFIG)
endif

ifneq ($(MACHINE_CONFIG), DEFAULT)
export COMPOBJROOT=$(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)_$(MACHINE_CONFIG)/$(COMPONENT)
else
export COMPOBJROOT=$(OBJROOT)/$(KERNEL_CONFIG)_$(ARCH_CONFIG)/$(COMPONENT)
endif

$(COMPOBJROOT)/doconf:
	@make build_setup 

$(COMPOBJROOT)/$(BSD_KERNEL_CONFIG)/Makefile :  $(SOURCE)/MASTER  \
	$(SOURCE)/MASTER.$(ARCH_CONFIG_LC) \
	$(SOURCE)/Makefile.template  \
	$(SOURCE)/Makefile.$(ARCH_CONFIG_LC)  \
	$(SOURCE)/files \
	$(SOURCE)/files.$(ARCH_CONFIG_LC) \
	$(COMPOBJROOT)/doconf
	$(_v)(doconf_target=$(addsuffix /conf, $(TARGET)); \
	$(MKDIR) $${doconf_target}; \
	cd $${doconf_target}; \
	rm -f $(notdir $?); \
	cp  $? $${doconf_target}; \
	$(COMPOBJROOT)/doconf -c -cpu $(ARCH_CONFIG_LC) -d  $(TARGET)/$(BSD_KERNEL_CONFIG) $(BSD_KERNEL_CONFIG); \
	);

.ORDER: $(COMPOBJROOT)/$(BSD_KERNEL_CONFIG)/Makefile 

do_setup_conf: $(COMPOBJROOT)/doconf \
		$(COMPOBJROOT)/$(BSD_KERNEL_CONFIG)/Makefile 

do_all: do_setup_conf
	$(_v)next_source=$(subst conf/,,$(SOURCE));			\
	${MAKE} -C $(COMPOBJROOT)/$(BSD_KERNEL_CONFIG)	\
		MAKEFILES=$(TARGET)/$(BSD_KERNEL_CONFIG)/Makefile	\
		SOURCE=$${next_source}			\
		TARGET=$(TARGET)					\
		INCL_MAKEDEP=FALSE	\
		KERNEL_CONFIG=$(BSD_KERNEL_CONFIG)	\
		build_all;

do_build_all: do_all 

include $(MakeInc_rule)
include $(MakeInc_dir)
