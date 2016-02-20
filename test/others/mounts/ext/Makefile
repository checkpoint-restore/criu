all: ext-mount.so ns_init

ext-mount.so: ext-mount.c
	gcc -g -Werror -Wall -shared -nostartfiles ext-mount.c -o ext-mount.so -iquote ../../../include -fPIC

ns_init: ns_init.o
	gcc -static $< -o $@

ns_init.o: ns_init.c
	gcc -c $< -o $@

run: all
	./run.sh
