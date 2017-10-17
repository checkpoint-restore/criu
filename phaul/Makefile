all: test piggie

test: stats
	go build -o test test

stats:
	mkdir -p src/stats/
	protoc --go_out=src/stats/ --proto_path=../images/ ../images/stats.proto

piggie: piggie.c
	gcc piggie.c -o piggie
