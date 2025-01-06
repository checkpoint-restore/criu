run: run_pidns run_net run_pid

run_net:
	./run.sh net

run_pid:
	./run.sh pid

run_pidns:
	unshare -fp -m --mount-proc --propagation private ./run_pidns.sh

clean:
	rm -rf images output  pidfile  pidfile2  pidfile3
.PHONY: clean run
