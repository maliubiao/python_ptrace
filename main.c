#include <stdio.h>
#include <time.h>
#include <unistd.h>

char *msg[] = {"Hello world"};

int main(int argc, char **argv)
{
	printf("pid: %d\n", getpid());
	printf("msg: 0x%x\n", *msg);
	while (1) {
		sleep(1);
	}
	return 0;
}
