LIBDIR := ../../../../test/zdtm/lib
LIB := $(LIBDIR)/libzdtmtst.a
LDLIBS += $(LIB)
CPPFLAGS += -I$(LIBDIR)

# CPU-only CUDA plugin variants reuse ordinary ZDTM workloads.
TST_NOFILE := \
	cuda_mock_driver00 \
	cuda_mock_cli00

TST := $(TST_NOFILE)
SRC := $(TST:%=%.c)
OBJ := $(SRC:%.c=%.o)
DEP := $(SRC:%.c=%.d)

include ../../../../test/zdtm/Makefile.inc

all: $(TST)

$(TST_NOFILE:%=%.pid): %.pid: %
	$(TEST_ENV) $(<D)/$(<F) --pidfile=$@ --outfile=$<.out

$(TST): | $(LIB)

THREADED_TST := \
	cuda_mock_driver00 \
	cuda_mock_cli00

$(THREADED_TST): LDLIBS += -pthread

$(LIB): force
	$(Q) $(MAKE) -C $(LIBDIR)

.PHONY: all force
