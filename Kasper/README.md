# Insights
1. map malicious code to verified image. (TO-DO: not working always)
2. free hacked dll before return to new eip/rip
3. return to verified image.

# Implement
  When hijack loading happend, firstly we run our malicious code with new thread.
  Then we craft a shellcode which could free our DLL and sleep the main thread once
  we inject the shellcode with ROP (to the return address for current stack), so that
  that we can free the malicious DLL and let our malicious thread run free.

```
FreeDll -- to craft the shellcode mentioned above.
Kasper	-- the loader.
```

# Further ???
[https://bbs.kanxue.com/thread-248050.htm] 