all: test piggie

test: stats
	make -C src/test

stats:
	mkdir -p src/stats/
	protoc --go_out=src/stats/ --proto_path=../images/ ../images/stats.proto

piggie: piggie.c
	gcc piggie.c -o piggie

clean:
	rm -rf test_images/

run_test: piggie test
	unshare -fpm --mount-proc ./test.sh
