include ../Makefile.inc

PROTO_LIBRARY	:= protobuf-lib.o

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
PROTO_FILES	+= inotify.proto
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
PROTO_FILES	+= core.proto
PROTO_FILES	+= netdev.proto
PROTO_FILES	+= tty.proto

PROTO_HDRS	:= $(patsubst %.proto,%.pb-c.h,$(PROTO_FILES))
PROTO_SRCS	:= $(patsubst %.proto,%.pb-c.c,$(PROTO_FILES))
PROTO_OBJS	:= $(patsubst %.c,%.o,$(PROTO_SRCS))

.DEFAULT_GOAL	:= protobuf

%.pb-c.c %.pb-c.h: %.proto
	$(E) "  PROTOBUF "$@
	$(Q) protoc-c --c_out=./ $<

%.o: %.c %.h
	$(E) "  CC       "$@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

.SECONDARY:

$(PROTO_LIBRARY): $(PROTO_OBJS)
	$(E) "  LINK     "$@
	$(Q) ld -r -o $@ $(PROTO_OBJS)

.PHONY: protobuf

protobuf: $(PROTO_LIBRARY) $(PROTO_SRCS) $(PROTO_HDRS)

clean:
	$(E) "  CLEAN PROTOBUF"
	$(Q) rm -f $(PROTO_SRCS) $(PROTO_HDRS) $(PROTO_OBJS) $(PROTO_LIBRARY)
