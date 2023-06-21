all: test-c rpc_pb2.py criu
.PHONY: all

CFLAGS += -g -Werror -Wall -I.
LDLIBS +=  -lprotobuf-c

PYTHON ?= python3

run: all
	@make -C .. loop
	mkdir -p build
	chmod a+rwx build
	rm -f build/status
	sudo -g '#1000' -u '#1000' mkfifo build/status
	@# Need to start the criu daemon here to access the pidfile.
	@# The script read.py is used to wait until 'criu service'
	@# is ready. As 'read -n 1' in some releases has a bug and does
	@# not read correctly a \0, using python is a workaround.
	sudo -g '#1000' -u '#1000' -- bash -c "exec 200<>build/status; \
		./criu service -v4 -W build --address criu_service.socket \
		-d --pidfile pidfile -o service.log --status-fd 200; \
		$(PYTHON) read.py build/status"
	rm -f build/status
	chmod a+rw build/pidfile
	sudo -g '#1000' -u '#1000' ./run.sh
	sudo -g '#1000' -u '#1000' ./version.py
	# run the configuration file via RPC test cases
	./config_file.py build

criu: ../../../criu/criu
	cp ../../../criu/criu $@
	chmod u+s $@

test-c: rpc.pb-c.o test-c.o

test-c.o: test-c.c rpc.pb-c.c

rpc_pb2.py: rpc.proto
	protoc --proto_path=. --python_out=. rpc.proto

rpc.pb-c.c: rpc.proto
	protoc-c --proto_path=. --c_out=. rpc.proto

clean:
	rm -rf build rpc.pb-c.o test-c.o test-c rpc.pb-c.c rpc.pb-c.h rpc_pb2.py rpc_pb2.pyc criu
.PHONY: clean
