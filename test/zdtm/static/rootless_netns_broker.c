#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

#include "zdtmtst.h"

const char *test_doc = "Check brokered netns socket collection in userns restore";
const char *test_author = "Deepak Anand <deepakanand1300@gmail.com>";

int main(int argc, char **argv)
{
	char c = 'N';
	int accepted, client;
	int port = 23456;
	int server = -1;

	test_init(argc, argv);

	if (system("ip link set lo up")) {
		fail("Can't set lo up");
		return 1;
	}

	server = tcp_init_server(AF_INET, &port);
	if (server < 0) {
		fail("Can't create TCP server");
		return 1;
	}

	test_daemon();
	test_waitsig();

	client = tcp_init_client(AF_INET, "127.0.0.1", port);
	if (client < 0) {
		fail("Can't connect to restored TCP server");
		goto err_server;
	}

	accepted = tcp_accept_server(server);
	if (accepted < 0) {
		fail("Can't accept on restored TCP server");
		goto err_client;
	}

	if (write(client, &c, sizeof(c)) != sizeof(c)) {
		fail("Can't write to restored TCP connection");
		goto err_accepted;
	}

	c = '\0';
	if (read(accepted, &c, sizeof(c)) != sizeof(c)) {
		fail("Can't read from restored TCP connection");
		goto err_accepted;
	}

	if (c != 'N') {
		fail("Unexpected byte from restored TCP connection: %c", c);
		goto err_accepted;
	}

	close(accepted);
	close(client);
	close(server);

	pass();
	return 0;

err_accepted:
	close(accepted);
err_client:
	close(client);
err_server:
	close(server);
	return 1;
}
