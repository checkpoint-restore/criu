##
##
## Unfortunately protobuf-c compiler is extremely dumb
## one, and I'm that ->.<- close to rewrite it on plain
## C language.
##
## Meanwhile, we need to carry own rules instead of reusing
## our build farm.

CFLAGS		+= -I$(obj)/

proto-obj-y	+= stats.o
proto-obj-y	+= core.o
proto-obj-y	+= core-x86.o
proto-obj-y	+= core-arm.o
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

proto		:= $(proto-obj-y:.o=)
proto-c		:= $(proto-obj-y:.o=.pb-c.c)
proto-h		:= $(proto-obj-y:.o=.pb-c.h)

.SECONDARY:

$(obj)/%.proto.d: $(obj)/%.proto
	$(E) "  PB DDEP " $@
	$(Q) grep "^[[:blank:]]*import[[:blank:]]" $^ | sed	  		  \
		-e 's/[[:blank:]]*import[[:blank:]]*//' 			  \
		-e 's/[\";]//g'							  \
		-e 's/.*/$(subst /,\/,$^):$(obj)\/&/'				| \
		uniq > $@

$(obj)/%.proto.c.d: $(obj)/%.proto | $(obj)/%.proto.d
	$(E) "  PB DEP  " $@
	$(Q) grep "^[[:blank:]]*import[[:blank:]]" $< | sed	  		  \
		-e 's/[[:blank:]]*import[[:blank:]]*//' 			  \
		-e 's/.proto/.pb-c.c/'	  					  \
		-e 's/[\";]//g'		  					  \
		-e 's/.*/$(subst .proto,.pb-c.c,$(subst /,\/,$<)):$(obj)\/&/'	| \
		uniq > $@

$(obj)/%.pb-c.c $(obj)/%.pb-c.h: $(obj)/%.proto $(obj)/%.proto.c.d
	$(E) "  PBCC    " $@
	$(Q) protoc-c --proto_path=$(obj)/ --c_out=$(obj)/ $<
ifeq ($(ARCH),arm)
	$(Q) sed -i -e 's/4294967295/0xFFFFFFFF/g' $@ $(patsubst %.h,%.c,$@)
endif

$(obj)/%.o: $(obj)/%.pb-c.c $(obj)/%.pb-c.h
	$(E) "  CC      " $@
	$(Q) $(CC) -c $(CFLAGS) $< -o $@

$(obj)/%.d: $(obj)/%.pb-c.c $(obj)/%.pb-c.h
	$(E) "  DEP     " $@
	$(Q) $(CC) -M -MT $@ -MT $(patsubst %.d,%.o,$@) $(CFLAGS) $< -o $@

$(obj)/%.i: $(obj)/%.pb-c.c $(obj)/%.pb-c.h
	$(E) "  CC      " $@
	$(Q) $(CC) -E $(CFLAGS) $< -o $@

$(obj)/built-in.o: $(addprefix $(obj)/,$(proto-obj-y))
	$(E) "  LINK    " $@
	$(Q) $(LD) -r -o $@ $^

_all += $(obj)/built-in.o

ifneq ($(MAKECMDGOALS),clean)
-include $(addprefix $(obj)/,$(obj-y:.o=.proto.d))
-include $(addprefix $(obj)/,$(obj-y:.o=.proto.c.d))
endif

cleanup-y += $(obj)/*.c.d $(obj)/*.pb-c.c $(obj)/*.pb-c.h
