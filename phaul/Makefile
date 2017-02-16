all: test piggie

test: stats
	GOPATH=$(shell pwd):$(shell pwd)/../lib/go/:/usr/share/gocode go build -o test test

stats:
	mkdir -p src/stats/
	protoc --go_out=src/stats/ --proto_path=../images/ ../images/stats.proto

piggie: piggie.c
	gcc piggie.c -o piggie
