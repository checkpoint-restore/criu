include ../../../../criu/Makefile.versions

TESTS += test_sub
TESTS += test_self
TESTS += test_notify
TESTS += test_rpc_config
TESTS += test_iters
TESTS += test_errno
TESTS += test_join_ns
TESTS += test_pre_dump
TESTS += test_check
TESTS += test_feature_check

all: $(TESTS)
.PHONY: all

run: all
	./run.sh
.PHONY: run

define genb
$(1): $(1).o lib.o
	gcc $$^ -L ../../../../criu/lib/c/ -L ../../../../criu/images/ -lcriu -o $$@
endef

$(foreach t, $(TESTS), $(eval $(call genb, $(t))))

%.o: %.c
	gcc -c $^ -iquote ../../../../criu/criu/include -I../../../../criu/lib/c/ -I../../../../criu/images/ -o $@ -Werror

clean: libcriu_clean
	rm -rf $(TESTS) $(TESTS:%=%.o) lib.o
.PHONY: clean

libcriu_clean:
	rm -f libcriu.so.${CRIU_SO_VERSION_MAJOR}
.PHONY: libcriu_clean

libcriu:
	ln -s ../../../../criu/lib/c/libcriu.so libcriu.so.${CRIU_SO_VERSION_MAJOR}
.PHONY: libcriu
