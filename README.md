python-ptrace
=============

python library for ptrace


###Usage
####read_memory(pid, addr, len)
```c
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
```
```shell
$: ./main
pid: 3185
msg: 0x4006e4 

In [1]: import ptrace

In [2]: ptrace.attach(3185)

In [4]: ptrace.read_memory(3185, 0x4006e4, 12)
Out[4]: 'Hello world\x00'

In [5]: ptrace.detach(3185)
```
####write_memory(pid, addr, len) 
```shell
$: ./main
pid: 3185
msg: 0x4006e4 

In [1]: import ptrace

In [2]: ptrace.attach(3185)

In [3]: ptrace.write_memory(3185, 0x4006e4, "123456")

In [4]: ptrace.read_memory(3185, 0x4006e4, 12)
Out[4]: '123456world\x00'

In [5]: ptrace.detach(3185)

```shell
