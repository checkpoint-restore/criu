# When LOCAL=1, use libcriu and criu built from the source tree.
# Set LOCAL=0 to use the system-installed versions.
LOCAL ?= 1
LOOP_SRC := ../../../test/others/loop.c

all: loop
.PHONY: all

loop: $(LOOP_SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) -o $@ $< $(LDFLAGS)

run: all
	LOCAL=$(LOCAL) ./run.sh
	LOCAL=$(LOCAL) ./run-shell-job.py
	LOCAL=$(LOCAL) ./run-service.sh
.PHONY: run

clean:
	rm -f loop
.PHONY: clean
