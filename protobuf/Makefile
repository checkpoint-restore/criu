PROTO_LIBRARY	:= protobuf-lib.o

PROTO_FILES	+= core-x86.proto
PROTO_FILES	+= core-arm.proto
PROTO_FILES	+= core.proto
PROTO_FILES	+= inventory.proto
PROTO_FILES	+= fdinfo.proto
PROTO_FILES	+= fown.proto
PROTO_FILES	+= regfile.proto
PROTO_FILES	+= ghost-file.proto
PROTO_FILES	+= fifo.proto
PROTO_FILES	+= remap-file-path.proto
PROTO_FILES	+= eventfd.proto
PROTO_FILES	+= eventpoll.proto
PROTO_FILES	+= fh.proto
PROTO_FILES	+= fsnotify.proto
PROTO_FILES	+= signalfd.proto
PROTO_FILES	+= fs.proto
PROTO_FILES	+= pstree.proto
PROTO_FILES	+= pipe.proto
PROTO_FILES	+= tcp-stream.proto
PROTO_FILES	+= sk-packet.proto
PROTO_FILES	+= mnt.proto
PROTO_FILES	+= pipe-data.proto
PROTO_FILES	+= sa.proto
PROTO_FILES	+= itimer.proto
PROTO_FILES	+= mm.proto
PROTO_FILES	+= sk-opts.proto
PROTO_FILES	+= sk-unix.proto
PROTO_FILES	+= sk-inet.proto
PROTO_FILES	+= packet-sock.proto
PROTO_FILES	+= ipc-var.proto
PROTO_FILES	+= ipc-desc.proto
PROTO_FILES	+= ipc-shm.proto
PROTO_FILES	+= ipc-msg.proto
PROTO_FILES	+= ipc-sem.proto
PROTO_FILES	+= utsns.proto
PROTO_FILES	+= creds.proto
PROTO_FILES	+= vma.proto
PROTO_FILES	+= netdev.proto
PROTO_FILES	+= tty.proto
PROTO_FILES	+= file-lock.proto
PROTO_FILES	+= rlimit.proto

PROTO_DEPS	:= $(patsubst %.proto,%.proto.d,$(PROTO_FILES))
PROTO_CDEP	:= $(patsubst %.proto,%.d,$(PROTO_FILES))
PROTO_HDRS	:= $(patsubst %.proto,%.pb-c.h,$(PROTO_FILES))
PROTO_SRCS	:= $(patsubst %.proto,%.pb-c.c,$(PROTO_FILES))
PROTO_OBJS	:= $(patsubst %.c,%.o,$(PROTO_SRCS))

.DEFAULT_GOAL	:= protobuf

%.proto.d: %.proto
	$(E) "  PROTOBUF DEPS "$@
	$(Q) grep "import" $^ | sed	  			  \
		-e 's/^import//' 				  \
		-e 's/[\";]//g'					  \
		-e 's/.*/$^:&/'					| \
		uniq > $@

%.d: %.proto
	$(E) "  PROTOBUF ORDS "$@
	$(Q) grep "import" $^ | sed	  			  \
		-e 's/^import//'	  			  \
		-e 's/.proto/.pb-c.c/'	  			  \
		-e 's/[\";]//g'		  			  \
		-e 's/.*/$(subst .proto,.pb-c.c,$^):&/'		| \
		uniq > $@

%.pb-c.c %.pb-c.h: %.proto %.proto.d
	$(E) "  PROTOBUF "$@
	$(Q) protoc-c --c_out=./ $<
ifeq ($(ARCH),arm)
	$(Q) sed -i 's/4294967295/0xFFFFFFFF/g' $@ $(patsubst %c,%h,$@)
endif

%.o: %.c %.h
	$(E) "  CC       "$@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

.SECONDARY:

$(PROTO_LIBRARY): $(PROTO_OBJS)
	$(E) "  LINK     "$@
	$(Q) $(LD) -r -o $@ $(PROTO_OBJS)

.PHONY: protobuf

protobuf: $(PROTO_LIBRARY) $(PROTO_SRCS) $(PROTO_HDRS)

clean:
	$(E) "  CLEAN PROTOBUF"
	$(Q) rm -f $(PROTO_SRCS) $(PROTO_HDRS) $(PROTO_OBJS) $(PROTO_LIBRARY)
	$(Q) rm -f $(PROTO_DEPS) $(PROTO_CDEP)

ifneq ($(MAKECMDGOALS),clean)
-include $(PROTO_DEPS)
-include $(PROTO_CDEP)
endif
