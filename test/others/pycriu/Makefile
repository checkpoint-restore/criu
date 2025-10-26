.SHELLFLAGS := -eu -o pipefail -c
.ONESHELL:

CRIU ?= ../../../criu/criu
BUILD_DIR ?= build
SOCKET_NAME ?= criu_service.socket
PIDFILE_NAME ?= pidfile
SERVICE_LOG ?= service.log
PYTHON ?= python3

PIDFILE := $(BUILD_DIR)/$(PIDFILE_NAME)
CRIU_SOCKET := $(BUILD_DIR)/$(SOCKET_NAME)
STATUS_FIFO := $(BUILD_DIR)/startup.status
STATUS_FD := 200

run: start
	cleanup() { $(MAKE) --no-print-directory stop || true; }
	trap cleanup EXIT INT TERM
	"$(PYTHON)" test_check.py
	"$(PYTHON)" test_check_fail.py
	"$(PYTHON)" test_check_images_dir.py
	"$(PYTHON)" test_check_work_dir_fd.py

start:
	mkdir -p "$(BUILD_DIR)"
	if [ -s "$(PIDFILE)" ] && kill -0 "$$(cat "$(PIDFILE)")" 2>/dev/null; then
		echo "Service running (PID $$(cat "$(PIDFILE)"))."
		exit 0
	fi
	if ! command -v "$(CRIU)" >/dev/null 2>&1; then
		echo "CRIU not found at $(CRIU)"
		exit 1
	fi
	mkfifo "$(STATUS_FIFO)"
	exec $(STATUS_FD)<>"$(STATUS_FIFO)"
	"$(CRIU)" service \
		-v4 \
		-W "$(BUILD_DIR)" \
		--address "$(SOCKET_NAME)" \
		-d \
		--pidfile "$(PIDFILE_NAME)" \
		-o "$(SERVICE_LOG)" \
		--status-fd "$(STATUS_FD)"
	"$(PYTHON)" read.py "$(STATUS_FIFO)"

stop:
	if [ ! -s "$(PIDFILE)" ]; then
		echo "pidfile missing or empty"
		exit 1
	fi
	pid=$$(cat "$(PIDFILE)")
	if kill -0 "$$pid" 2>/dev/null; then
		kill -9 "$$pid" || true
	fi
	rm -f "$(PIDFILE)" "$(CRIU_SOCKET)" "$(STATUS_FIFO)"

clean:
	if [ -s "$(PIDFILE)" ] && kill -0 "$$(cat "$(PIDFILE)")" 2>/dev/null; then
		kill -9 "$$(cat "$(PIDFILE)")" || true
	fi
	rm -rf "$(BUILD_DIR)"

.PHONY: start stop clean run