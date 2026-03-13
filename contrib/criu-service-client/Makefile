CC ?= gcc

CFLAGS ?= -Wall -Wextra -O2
LDFLAGS ?=
LDLIBS := -lcriu

TARGET := criu-service-client
SRC := criu-service-client.c
OBJ := $(SRC:.c=.o)

# By default, build libcriu from source into a local staging directory.
# Set LOCAL=0 to use the system-installed libcriu and criu instead:
#   make LOCAL=0
LOCAL ?= 1

INSTALL_DIR := $(CURDIR)/.install
ifeq ($(LOCAL),1)
CRIU_INCLUDE := $(INSTALL_DIR)/include
CRIU_LIB := $(INSTALL_DIR)/lib
CFLAGS += -I$(CRIU_INCLUDE)
LDFLAGS += -L$(CRIU_LIB)
endif

all: $(TARGET)
.PHONY: all

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

ifeq ($(LOCAL),1)
%.o: %.c | $(CRIU_INCLUDE)
	$(CC) $(CFLAGS) -c -o $@ $<

$(CRIU_LIB)/libcriu.so:
	$(MAKE) -C ../../ install-lib \
		DESTDIR=$(INSTALL_DIR) PREFIX=/ LIBDIR=/lib \
		SKIP_PIP_INSTALL=1

$(CRIU_INCLUDE): $(CRIU_LIB)/libcriu.so
	@:
else
%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<
endif

ifeq ($(LOCAL),1)
CRIU_BIN := $(CURDIR)/../../criu/criu
else
CRIU_BIN := criu
endif

CRIU_SERVICE_SOCKET ?= $(CURDIR)/criu-service.socket
CRIU_SERVICE_LOG ?= $(CURDIR)/criu-service.log
CRIU_SERVICE_PIDFILE ?= $(CURDIR)/criu-service.pid

start-service:
	$(CRIU_BIN) service --address $(CRIU_SERVICE_SOCKET) \
		--log-file $(CRIU_SERVICE_LOG) \
		--pidfile $(CRIU_SERVICE_PIDFILE) -d -v4
	@echo "CRIU service started on $(CRIU_SERVICE_SOCKET) (PID $$(cat $(CRIU_SERVICE_PIDFILE)))"
.PHONY: start-service

stop-service:
	@if [ -s $(CRIU_SERVICE_PIDFILE) ]; then \
		kill $$(cat $(CRIU_SERVICE_PIDFILE)) 2>/dev/null || true; \
		rm -f $(CRIU_SERVICE_PIDFILE); \
	else \
		echo "CRIU service not running (no pidfile at $(CRIU_SERVICE_PIDFILE))"; \
	fi
.PHONY: stop-service

clean:
	rm -f $(TARGET) $(OBJ)
.PHONY: clean

distclean: clean
	rm -rf $(INSTALL_DIR)
.PHONY: distclean
