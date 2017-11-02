This challenge is from 0ctf Quals 2017. Make sure you have ASLR disabled for part 1:

```
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

We've provided you with a pwntools skeleton file and an IDA database.
