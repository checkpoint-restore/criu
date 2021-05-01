all: kfd_plugin.so

criu-kfd.pb-c.c: criu-kfd.proto
		protoc-c --proto_path=. --c_out=. criu-kfd.proto

kfd_plugin.so: kfd_plugin.c criu-kfd.pb-c.c
	gcc -g -Werror -D _GNU_SOURCE -Wall -shared -nostartfiles kfd_plugin.c criu-kfd.pb-c.c -o kfd_plugin.so -iquote ../../../criu/include -I ../../../../criu/include -fPIC

clean:
	rm kfd_plugin.so criu-kfd.pb-c.c criu-kfd.pb-c.h

install:
	mkdir -p /var/lib/criu && cp kfd_plugin.so /var/lib/criu/
