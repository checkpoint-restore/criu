all: test

test: rpc
	GOPATH=$(shell pwd):/usr/share/gocode go build -o test test

rpc:
	mkdir -p src/rpc/
	protoc --go_out=src/rpc/ --proto_path=../../images/ ../../images/rpc.proto
