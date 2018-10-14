from pwn import *

context.log_level= 'debug'
context.terminal = ['tmux', 'splitw', '-h']

p = process("./babyheap")
if len(sys.argv) > 1 and sys.argv[1] == 'gdb':
    gdb.attach(p, """
          set disassembly-flavor intel
           """)
           # b *(0x555555554000 + 0x119b)
           # b *(0x555555554000 + 0xe88)
           # b *(0x555555554000 + 0xfa9)
           # b *(0x555555554000 + 0xd54) 
           # b *(0x555555554000 + 0x10C2) 
               
def alloc(size):
    p.recvuntil("Command: ")
    p.sendline("1")
    p.sendline(str(size))

def update(idx, size, content):
    p.recvuntil("Command: ")
    p.sendline("2")
    p.sendline(str(idx))
    p.sendline(str(size))
    p.sendline(content)

def delete(idx):
    p.recvuntil("Command: ")
    p.sendline("3")
    p.sendline(str(idx))

def view(index):
    p.readuntil("Command: ")
    p.sendline("4")
    p.readuntil("Index: ")
    p.sendline(str(index))
    p.readuntil("Chunk[" + str(index) + "]: ")
    content = p.readline()
    return content
