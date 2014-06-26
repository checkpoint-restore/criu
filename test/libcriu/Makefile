all: test_sub test_self test_notify
.PHONY: all

run: all
	./run.sh

test_sub: test_sub.o lib.o
	gcc $^ -L ../../lib -lcriu -o $@

test_sub.o: test_sub.c
	gcc -c $^ -I ../../lib -o $@

test_self: test_self.o lib.o
	gcc $^ -L ../../lib -lcriu -o $@

test_self.o: test_self.c
	gcc -c $^ -I ../../lib -o $@

test_notify: test_notify.o lib.o
	gcc $^ -L ../../lib -lcriu -o $@

test_notify.o: test_notify.c
	gcc -c $^ -I ../../lib -o $@

lib.o: lib.c
	gcc -c $^ -I ../../lib -o $@

clean:
	rm -rf test_sub test_sub.o test_self test_sub.o test_notify test_notify.o
.PHONY: clean
