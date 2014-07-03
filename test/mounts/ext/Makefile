all: ext-mount.so

ext-mount.so: ext-mount.c
	gcc -g -Werror -Wall -shared -nostartfiles ext-mount.c -o ext-mount.so -iquote ../../../include -fPIC

run: all
	./run.sh
