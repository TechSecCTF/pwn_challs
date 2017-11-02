# pwn_challs

a panoply of pwn problems for pedagogical purposes

Suggested order of completion:

  * `stack` (Stack-based buffer overflows, shellcoding)
    * `bof` [pwnable.kr]
    * `asm` [pwnable.kr]
    * Suggested reading:
      * https://github.com/TechSecCTF/meeting_notes/tree/master/04-03-17_stack_smashing
      * http://insecure.org/stf/smashstack.html
    * Tooling:
      * [gdb](https://www.gnu.org/software/gdb/)
      * [pwntools](https://github.com/Gallopsled/pwntools)
  * `rop` (Return-oriented programming, memory leaks)
    * `rop` [rpisec]
    * `leakRop` [rpisec]
    * `makeLeak` [rpisec]
    * Suggested reading:
      * http://codearcana.com/posts/2013/05/28/introduction-to-return-oriented-programming-rop.html
      * https://github.com/TechSecCTF/CTF-pwn-tips/wiki/Shared-Libraries
      * https://systemoverlord.com/2017/03/19/got-and-plt-for-pwning.html
    * Tooling:
      * [pwndbg](https://github.com/pwndbg/pwndbg)
      * [ROPgadget](https://github.com/JonathanSalwan/ROPgadget)
  * `got` (Global-offset table overwrites)
    * `passcode` [pwnable.kr]
    * Suggested reading:
      * http://tk-blog.blogspot.com/2009/02/relro-not-so-well-known-memory.html
  * `heap` (Heap vulnerabilities)
    * `unlink` [pwnable.kr]
    * `0ctfbabyheap` [how2heap/0ctf]
    * `0ctfbabyheap_aslr` [how2heap/0ctf]
    * `tw2017parrot` [Tokyo Westerns]
    * Suggested reading:
      * https://heap-exploitation.dhavalkapil.com/
    * Tooling:
      * [voltron](https://github.com/snare/voltron)
      * [angelheap](https://github.com/scwuaptx/Pwngdb/tree/master/angelheap)

