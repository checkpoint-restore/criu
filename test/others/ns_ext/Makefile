CRIU ?= ../../../criu/criu

run: run_pidns run_net run_pid run_threaded_pidns

run_net:
	./run.sh net

run_pid:
	./run.sh pid

run_pidns:
	unshare -fp -m --mount-proc --propagation private ./run_pidns.sh

threaded.so: threaded.c
	$(CC) -g -Werror -Wall -shared -nostartfiles -fPIC -pthread $< -o $@ -iquote ../../../criu/include

run_threaded_pidns: threaded.so
	./test-threaded-pidns.py --criu $(CRIU)

clean:
	rm -rf images output  pidfile  pidfile2  pidfile3 threaded.so
.PHONY: clean run run_threaded_pidns
