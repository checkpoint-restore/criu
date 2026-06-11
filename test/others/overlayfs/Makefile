CC ?= cc

inotify_test: inotify_test.c
	$(CC) -Wall -o $@ $<

run: run-inotify
	./run.sh

run-inotify: inotify_test
	./run-inotify.sh

clean:
	umount -f overlay_test/z 2>/dev/null || true
	umount -f ovl_inotify/merged 2>/dev/null || true
	rm -rf overlay_test ovl_inotify output checkpoint inotify_test

.PHONY: run run-inotify clean
