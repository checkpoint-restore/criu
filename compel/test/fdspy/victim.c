#include <unistd.h>

int main(int argc, char **argv)
{
	int i, aux;

	do {
		i = read(0, &aux, 1);
	} while (i > 0);

	return 0;
}
