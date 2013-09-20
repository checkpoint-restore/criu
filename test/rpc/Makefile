all: test-c rpc_pb2.py

test-c: rpc.pb-c.o test.o
	gcc $^ -o $@ -lprotobuf-c

test.o: ../test.c
	gcc -c $< -I ./

rpc_pb2.py: ${PROTODIR}/rpc.proto
	protoc --proto_path=${PROTODIR} --python_out=. ${PROTODIR}/rpc.proto

rpc.pb-c.c: ${PROTODIR}/rpc.proto
	protoc-c --proto_path=${PROTODIR} --c_out=. ${PROTODIR}/rpc.proto

clean:
	rm -rf build
