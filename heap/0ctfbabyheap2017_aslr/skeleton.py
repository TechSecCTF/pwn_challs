from pwn import *

r = process("./0ctfbabyheap")
if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
    gdb.attach(r, """set disassembly-flavor intel
    b main
    """)

def alloc(size):
    r.sendline('1')
    r.sendlineafter(': ', str(size))
    print r.recvuntil(': ', timeout=1)

def fill(idx, data):
    r.sendline('2')
    r.sendlineafter(': ', str(idx))
    r.sendlineafter(': ', str(len(data)))
    r.sendafter(': ', data)
    r.recvuntil(': ')

def free(idx):
    r.sendline('3')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': ')

def dump(idx):
    r.sendline('4')
    r.sendlineafter(': ', str(idx))
    r.recvuntil(': \n')
    data = r.recvline()
    r.recvuntil(': ')
    return data
