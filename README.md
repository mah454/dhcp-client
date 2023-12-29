# Simple DHCP Client

#### install dependencies :
```shell
> sudo apt-get update
> sudo apt install libc6-dev 
```

#### compile & run :

```shell
> make
dhcp-client build options:
CFLAGS   = -Wall -Wextra -pedantic -std=c99 -D_DEFAULT_SOURCE
LDFLAGS  = -s
CC       = cc
CC dhcp-client.c
CC compat.c

> file dhcp-client
dhcp-client: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=21d1c1976bc1a997733438b8cda071ba96ef58be, for GNU/Linux 3.2.0, stripped

> ./dhcp-client
```

#### Note:

by default work on interface wlan0

```c
int main() {
discover_dhcp_ip("wlan0");
}
```