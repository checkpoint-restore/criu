all: test-c rpc_pb2.py criu
.PHONY: all

CFLAGS += -g -Werror -Wall -I.
LDLIBS +=  -lprotobuf-c

run: all
	mkdir -p build
	chmod a+rwx build
	@# need to start the criu daemon here to access the pidfile
	sudo -g '#1000' -u '#1000' ./criu service -v4 -W build -o service.log --address criu_service.socket -d --pidfile pidfile
	# Give the criu daemon some time to start up
	sleep 0.5
	chmod a+rw build/pidfile
	sudo -g '#1000' -u '#1000' ./run.sh
	sudo -g '#1000' -u '#1000' ./version.py

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
