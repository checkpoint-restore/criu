all: test piggie

test:
	make -C src/test

stats:
	mkdir -p src/stats/
	protoc --go_out=src/stats/ --proto_path=../images/ ../images/stats.proto

piggie: piggie.c
	gcc piggie.c -o piggie

clean:
	rm -rf test_images/

run_test: test piggie
	unshare -fpm --mount-proc ./test.sh
