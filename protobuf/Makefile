-include ../Makefile.inc

CFLAGS		+= -I./include
CFLAGS		+= -O0 -ggdb3

DEFINES		+= -D_FILE_OFFSET_BITS=64
DEFINES		+= -D_GNU_SOURCE

ifneq ($(WERROR),0)
	WARNINGS += -Werror
endif

ifeq ($(DEBUG),1)
	DEFINES += -DCR_DEBUG
endif

WARNINGS	+= -Wall
CFLAGS		+= $(WARNINGS) $(DEFINES)

LIBRARY		:= protobuf-lib.o

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
PROTO_FILES	+= fs.proto
PROTO_FILES	+= pstree.proto
PROTO_FILES	+= pipe.proto
PROTO_FILES	+= tcp-stream.proto
PROTO_FILES	+= sk-packet.proto
PROTO_FILES	+= mnt.proto
PROTO_FILES	+= pipe-data.proto
PROTO_FILES	+= sa.proto
PROTO_FILES	+= itimer.proto

HDRS	:= $(patsubst %.proto,%.pb-c.h,$(PROTO_FILES))
SRCS	:= $(patsubst %.proto,%.pb-c.c,$(PROTO_FILES))
OBJS	:= $(patsubst %.c,%.o,$(SRCS))

.DEFAULT_GOAL	:= all

%.pb-c.c: %.proto
	$(E) "  PROTOBUF "$@
	$(Q) protoc-c --c_out=./ $<

%.o: %.c
	$(E) "  CC       "$@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

.SECONDARY:

$(LIBRARY): $(OBJS)
	$(E) "  LINK     "$@
	$(Q) ld -r -o $@ $(OBJS)

.PHONY: all clean

all: $(LIBRARY)

clean:
	$(E) "  CLEAN PROTOBUF"
	$(Q) rm -f $(SRCS) $(HDRS) $(OBJS) $(LIBRARY)

