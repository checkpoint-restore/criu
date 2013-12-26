all: mvlink.so

mvlink.so: mvlink.c
	gcc -g -Werror -Wall -shared -nostartfiles mvlink.c -o mvlink.so -iquote ../../include -fPIC
