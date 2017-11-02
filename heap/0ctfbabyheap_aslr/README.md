Now, re-enable ASLR:

```
echo 2 | sudo tee /proc/sys/kernel/randomize_va_space
```
