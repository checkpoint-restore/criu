#include <unistd.h>

int main(int argc, char **argv)
{
	int i;

	while (1) {
		if (read(0, &i, sizeof(i)) != sizeof(i))
			break;

		i = getsid(0);
		write(1, &i, sizeof(i));
	}

	return 0;
}
