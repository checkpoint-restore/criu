all: mvlink.so

mvlink.so: mvlink.c
	gcc -g -Werror -Wall -shared -nostartfiles mvlink.c -o mvlink.so -iquote ../../../criu/include -fPIC

fallback.so: fallback.c
	$(CC) -g -Werror -Wall -shared -nostartfiles $< -o $@ -iquote ../../../criu/include -fPIC

test-fallback: fallback.so
	python3 test-fallback.py --restore

.PHONY: test-fallback
