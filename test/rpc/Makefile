all: test-c rpc_pb2.py

test-c: rpc.pb-c.o test.o
	gcc $^ -o $@ -lprotobuf-c

test.o: test.c
	gcc -c $< -I ./

rpc_pb2.py: rpc.proto
	protoc --proto_path=. --python_out=. rpc.proto

rpc.pb-c.c: rpc.proto
	protoc-c --proto_path=. --c_out=. rpc.proto

clean:
	rm -rf build rpc.pb-c.o test.o test-c rpc.pb-c.c rpc.pb-c.h rpc_pb2.py
