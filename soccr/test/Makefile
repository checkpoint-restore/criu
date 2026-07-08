CFLAGS += -Wall -g -I../../ -I../../include
LDFLAGS += -L../ -lsoccr ../libsoccr.a -lnet

RUN ?= tcp-constructor

run:
	./local.sh

tcp-constructor: tcp-constructor.c ../libsoccr.a
	$(CC) $(CFLAGS) tcp-constructor.c -o tcp-constructor $(LDFLAGS)

clean:
	@rm -f tcp-constructor tcp-conn tcp-conn-v6

tcp-conn: tcp-conn.c
	$(CC) $(CFLAGS) tcp-conn.c -o tcp-conn $(LDFLAGS)

tcp-conn-v6: tcp-conn-v6.c
	$(CC) $(CFLAGS) -DTEST_IPV6 tcp-conn-v6.c -o tcp-conn-v6 $(LDFLAGS)

# Do not call this target directly. Use "make run" instead, which
# sets up the network namespace that tcp-constructor requires.
test: tcp-constructor tcp-conn tcp-conn-v6
	unshare -n sh -c "ip link set up dev lo; ./tcp-conn"
	unshare -n sh -c "ip link set up dev lo; ./tcp-conn-v6"
	python3 run.py ./$(RUN)

.PHONY: test
