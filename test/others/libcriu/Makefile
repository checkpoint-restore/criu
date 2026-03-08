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

# Install libcriu (headers and library) into a local staging directory so
# that nothing from the non-test part of the repo is referenced directly
# during the build or at runtime.
INSTALL_DIR:= $(CURDIR)/.install
CRIU_INCLUDE:= $(INSTALL_DIR)/include/criu
CRIU_LIB:= $(INSTALL_DIR)/lib

CFLAGS:= -I$(CRIU_INCLUDE)
LDFLAGS:= -L$(CRIU_LIB) -lcriu

all: $(TESTS)
.PHONY: all

run: all
	./run.sh
.PHONY: run

$(CRIU_LIB)/libcriu.so:
	$(MAKE) -C ../../../../criu install-lib \
		DESTDIR=$(INSTALL_DIR) PREFIX=/ LIBDIR=/lib \
		SKIP_PIP_INSTALL=1

$(CRIU_INCLUDE): $(CRIU_LIB)/libcriu.so
	@:

define genb
$(1): $(1).o lib.o
	gcc $$^ $(LDFLAGS) -o $$@
endef

$(foreach t, $(TESTS), $(eval $(call genb, $(t))))

%.o: %.c | $(CRIU_INCLUDE)
	gcc -c $< $(CFLAGS) -o $@ -Werror

clean:
	rm -rf $(TESTS) $(TESTS:%=%.o) lib.o $(INSTALL_DIR)
.PHONY: clean
