OPTS=-ggdb3 -Wall -Werror
export OPTS

CFLAGS			+= -iquote include
CFLAGS			+= -iquote flog/include
CFLAGS			+= -iquote flog/include/uapi

include $(__nmk_dir)msg.mk

$(eval $(call gen-built-in,src))

flog:
	$(Q) $(MAKE) $(build)=$(obj)/src all
.PHONY: flog

clean-flog:
	$(call msg-gen, $@)
	$(Q) $(MAKE) $(build)=$(obj)/src clean
	$(Q) $(RM) built-in.o
.PHONY: clean-flog

clean: clean-flog
mrproper: clean

test:
	./tests/test00

all-y += flog

