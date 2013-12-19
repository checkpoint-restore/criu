all: unix-lib.so unix-server unix-client syslog-lib.so

unix.pb-c.c: unix.proto
	protoc-c --proto_path=. --c_out=. unix.proto

unix-lib.so: unix-lib.c unix.pb-c.c
	gcc -g -Werror -Wall -shared -nostartfiles unix-lib.c unix.pb-c.c -o unix-lib.so -iquote ../../include -fPIC

syslog-lib.so: syslog-lib.c
	gcc -g -Werror -Wall -shared -nostartfiles syslog-lib.c -o syslog-lib.so -iquote ../../include -fPIC

unix-server: unix-server.c
	gcc -Werror -Wall -o unix-server unix-server.c

unix-client: unix-client.c
	gcc -Werror -Wall -o unix-client unix-client.c

clean:
	rm -rf data unix-lib.so unix-server unix-client syslog-lib.so output pid unix.pb-c.*
