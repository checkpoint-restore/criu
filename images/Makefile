proto-obj-y	+= stats.o
proto-obj-y	+= core.o
proto-obj-y	+= core-x86.o
proto-obj-y	+= core-arm.o
proto-obj-y	+= core-aarch64.o
proto-obj-y	+= core-ppc64.o
proto-obj-y	+= core-s390.o
proto-obj-y	+= cpuinfo.o
proto-obj-y	+= inventory.o
proto-obj-y	+= fdinfo.o
proto-obj-y	+= fown.o
proto-obj-y	+= ns.o
proto-obj-y	+= regfile.o
proto-obj-y	+= ghost-file.o
proto-obj-y	+= fifo.o
proto-obj-y	+= remap-file-path.o
proto-obj-y	+= eventfd.o
proto-obj-y	+= eventpoll.o
proto-obj-y	+= fh.o
proto-obj-y	+= fsnotify.o
proto-obj-y	+= signalfd.o
proto-obj-y	+= fs.o
proto-obj-y	+= pstree.o
proto-obj-y	+= pipe.o
proto-obj-y	+= tcp-stream.o
proto-obj-y	+= sk-packet.o
proto-obj-y	+= mnt.o
proto-obj-y	+= pipe-data.o
proto-obj-y	+= sa.o
proto-obj-y	+= timer.o
proto-obj-y	+= timerfd.o
proto-obj-y	+= mm.o
proto-obj-y	+= sk-opts.o
proto-obj-y	+= sk-unix.o
proto-obj-y	+= sk-inet.o
proto-obj-y	+= tun.o
proto-obj-y	+= sk-netlink.o
proto-obj-y	+= packet-sock.o
proto-obj-y	+= ipc-var.o
proto-obj-y	+= ipc-desc.o
proto-obj-y	+= ipc-shm.o
proto-obj-y	+= ipc-msg.o
proto-obj-y	+= ipc-sem.o
proto-obj-y	+= utsns.o
proto-obj-y	+= creds.o
proto-obj-y	+= vma.o
proto-obj-y	+= netdev.o
proto-obj-y	+= tty.o
proto-obj-y	+= file-lock.o
proto-obj-y	+= rlimit.o
proto-obj-y	+= pagemap.o
proto-obj-y	+= siginfo.o
proto-obj-y	+= rpc.o
proto-obj-y	+= ext-file.o
proto-obj-y	+= cgroup.o
proto-obj-y	+= userns.o
proto-obj-y	+= google/protobuf/descriptor.o # To make protoc-c happy and compile opts.proto
proto-obj-y	+= opts.o
proto-obj-y	+= seccomp.o
proto-obj-y	+= binfmt-misc.o
proto-obj-y	+= time.o
proto-obj-y	+= sysctl.o
proto-obj-y	+= autofs.o
proto-obj-y	+= macvlan.o
proto-obj-y	+= sit.o

CFLAGS		+= -iquote $(obj)/

#
# Generates a set of names from protobuf "import" directive.
# The names are bare, ie no suffixes.
define gen-proto-dep-names
$(shell grep "^[[:blank:]]*import[[:blank:]]" $(1)      |       \
        sed     -e 's/[[:blank:]]*import[[:blank:]]*//'         \
                -e 's/[\";]//g'                                 \
                -e 's/\.proto//g'                       |       \
        sort | uniq)
endef

makefile-deps := Makefile $(obj)/Makefile

#
# Generates rules needed to compile protobuf files.
define gen-proto-rules
$(obj)/$(1).pb-c.c $(obj)/$(1).pb-c.h: $(obj)/$(1).proto $(addsuffix .pb-c.c,$(addprefix $(obj)/,$(2))) $(makefile-deps)
	$$(E) "  PBCC    " $$@
	$$(Q) protoc-c --proto_path=$(obj)/ --c_out=$(obj)/ $$<
ifeq ($(PROTOUFIX),y)
	$$(Q) sed -i -e 's/4294967295/0xFFFFFFFF/g' $$@
	$$(Q) sed -i -e 's/4294967295/0xFFFFFFFF/g' $$(patsubst %.c,%.h,$$@)
	$$(Q) sed -i -e 's/4294967295/0xFFFFFFFF/g' $$(patsubst %.h,%.c,$$@)
endif
$(obj)/$(1).pb-c.d: $(obj)/$(1).pb-c.c $(addsuffix .pb-c.d,$(addprefix $(obj)/,$(2))) $(makefile-deps)
	$$(E) "  DEP     " $$@
	$$(Q) $$(CC) -M -MT $$@ -MT $(patsubst %.d,%.o,$$@) $$(CFLAGS) $$< -o $$@
endef

$(foreach file, $(proto-obj-y),                                                 \
        $(eval $(call gen-proto-rules,$(file:.o=),                              \
                        $(call gen-proto-dep-names,                             \
                                $(addprefix $(obj)/,$(file:.o=.proto))))))

$(obj)/%.o: $(obj)/%.pb-c.c $(obj)/%.pb-c.h
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

$(obj)/built-in.o: $(addprefix $(obj)/,$(proto-obj-y))
	$(E) "  LINK    " $@
	$(Q) $(LD) $(ldflags-y) -r -o $@ $^
cleanup-y += $(obj)/built-in.o

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(MAKECMDGOALS),mrproper)
-include $(addprefix $(obj)/,$(proto-obj-y:.o=.pb-c.d))
endif
endif

cleanup-y += $(call cleanify,$(addprefix $(obj)/,$(proto-obj-y)))
cleanup-y += $(call cleanify,$(addprefix $(obj)/,$(proto-obj-y:.o=.pb-c.o)))
mrproper-y += $(addprefix $(obj)/,$(proto-obj-y:.o=.pb-c.c))
mrproper-y += $(addprefix $(obj)/,$(proto-obj-y:.o=.pb-c.h))
