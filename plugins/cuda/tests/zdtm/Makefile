LIBDIR := ../../../../test/zdtm/lib
LIB := $(LIBDIR)/libzdtmtst.a
LDLIBS += $(LIB)
CPPFLAGS += -I$(LIBDIR)

# CPU-only CUDA plugin variants reuse ordinary ZDTM workloads.
TST_NOFILE := \
	cuda_mock_driver00 \
	cuda_mock_driver_unseized00 \
	cuda_mock_cli_unseized00 \
	cuda_mock_driver_rollback00 \
	cuda_mock_driver_checkpoint_error00 \
	cuda_mock_driver_inventory_error00 \
	cuda_mock_driver_finish_hook00 \
	cuda_mock_driver_finish_restore00 \
	cuda_mock_driver_finish_unlock00 \
	cuda_mock_driver_timeout_max00 \
	cuda_mock_driver_mapping00 \
	cuda_mock_cli00 \
	cuda_mock_cli_rollback00 \
	cuda_mock_cli_checkpoint_error00 \
	cuda_mock_cli_inventory_error00 \
	cuda_mock_cli_finish_hook00 \
	cuda_mock_cli_finish_restore00 \
	cuda_mock_cli_finish_unlock00 \
	cuda_mock_cli_timeout_max00 \
	cuda_mock_cli_mapping00 \
	cuda_mock_options00 \
	cuda_mock_fallback00 \
	cuda_mock_discovery_invalid00 \
	cuda_mock_discovery_uninitialized00 \
	cuda_mock_discovery_mixed00 \
	cuda_mock_discovery_error00 \
	cuda_mock_driver_unavailable00 \
	cuda_mock_cli_unavailable00 \
	cuda_mock_probe_error00 \
	cuda_mock_restore_fallback00 \
	cuda_mock_restore_unavailable00 \
	cuda_mock_mapping_unavailable00 \
	cuda_mock_helper_hang_finite00 \
	cuda_mock_helper_hang_closed_output_finite00 \
	cuda_mock_helper_exit_unlimited00 \
	cuda_mock_helper_signal_unlimited00 \
	cuda_mock_helper_delay_unlimited00 \
	cuda_mock_helper_delay_closed_output_unlimited00 \
	cuda_mock_freezing_open_output_finite00 \
	cuda_mock_freezing_closed_output_unlimited00 \
	cuda_mock_freezing_locked_unlimited00 \
	cuda_mock_freezing_locked_closed_output_finite00 \
	cuda_mock_driver_post_dump00 \
	cuda_mock_driver_post_dump_error00 \
	cuda_mock_cli_post_dump00 \
	cuda_mock_cli_post_dump_error00

TST_FILE := \
	cuda_mock_driver_clone_child00 \
	cuda_mock_driver_clone_thread00 \
	cuda_mock_cli_clone_child00 \
	cuda_mock_cli_clone_thread00

TST := $(TST_NOFILE) $(TST_FILE)
SRC := $(TST:%=%.c)
OBJ := $(SRC:%.c=%.o)
DEP := $(SRC:%.c=%.d)

include ../../../../test/zdtm/Makefile.inc

all: $(TST)

$(TST_NOFILE:%=%.pid): %.pid: %
	$(TEST_ENV) $(<D)/$(<F) --pidfile=$@ --outfile=$<.out

$(TST_FILE:%=%.pid): %.pid: %
	$(TEST_ENV) $(<D)/$(<F) --pidfile=$@ --outfile=$<.out --filename=$<.test

$(TST): | $(LIB)

THREADED_TST := \
	cuda_mock_driver00 \
	cuda_mock_cli00 \
	cuda_mock_driver_rollback00 \
	cuda_mock_cli_rollback00 \
	cuda_mock_driver_finish_restore00 \
	cuda_mock_driver_finish_unlock00 \
	cuda_mock_discovery_mixed00

$(THREADED_TST): LDLIBS += -pthread
cuda_mock_driver_clone_thread00: CFLAGS += -DCUDA_MOCK_THREAD
cuda_mock_cli_clone_thread00: CFLAGS += -DCUDA_MOCK_THREAD

$(LIB): force
	$(Q) $(MAKE) -C $(LIBDIR)

.PHONY: all force
