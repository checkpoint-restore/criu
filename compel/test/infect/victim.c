#include <unistd.h>

int main(int argc, char **argv)
{
	int i;

	while (1) {
		if (read(0, &i, sizeof(i)) != sizeof(i))
			break;

		write(1, &i, sizeof(i));
	}

	return 0;
}
