all: test-c rpc_pb2.py criu
.PHONY: all

CFLAGS += -g -Werror -Wall -I.
LDLIBS +=  -lprotobuf-c

run: all
	mkdir -p build
	chmod a+rwx build
	sudo -g '#1000' -u '#1000' ./run.sh

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
