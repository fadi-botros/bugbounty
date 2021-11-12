## Remote Code/Command Execution (RCE) Checklist



- Server Side Request Forgery (SSRF) to RCE:

  - [ ] if you found an SSRF try to escalate it to RCE by interacting with internal services, to do this you can craft a Gopher payload to interact with services like MySQL, you can use [Gopherus](https://github.com/tarunkant/Gopherus)

- File Upload to RCE:

  - [ ] if you found an unrestricted file upload vulnerability try to upload a malicious file to get a reverse shell

    ```php
    <?php system($_GET["cmd"]);?>
    ```

- Dependency Confusion Attack:

  - [ ] Search for packages that may be used internally by your target, then register a malicious public package with the same name, you can use [confused](https://github.com/visma-prodsec/confused) tool

- Server Side Template Injection (SSTI) to RCE:

  - [ ] if you found and SSTI you can exploit it with [tplmap](https://github.com/epinna/tplmap) to get an RCE

- SQL Injection To RCE:

  - [ ] if you found an SQL injection, you can craft a special query to write an arbitrary file on the system, [SQL Injection shell](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection#shell)

- Latex Injection To RCE:

  - [ ] if you found a web-based Latex Compiler, test If it is vulnerable to RCE, Latex to [command execution](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/LaTeX%20Injection#command-execution)

- Local File Inclusion (LFI) to RCE:

  - [ ] if you found an LFI try to escalate it to RCE via these [methods](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion#lfi-to-rce-via-procfd) and you can automate the process using [liffy](https://github.com/mzfr/liffy)

- Insecure deserialization to RCE:

  - [ ] check if the application is vulnerable to Insecure deserialization
  - [ ] how to identify if the app is vulnerable:
    - try to find out the language used to build the application
    - learn about the methods used to serialize and deserialize data in this language
    - by analyzing the data that comes from the application you can identify the method
    - try to craft a special payload to get and RCE
  - [ ] check this [cheatsheet](https://cheatsheetseries.owasp.org/cheatsheets/Deserialization_Cheat_Sheet.html) 
  - [ ] [Java Deserialization Scanner](https://github.com/PortSwigger/java-deserialization-scanner) : a Burp Suite plugin to detect and exploit Java deserialization vulnerabilities

- Memory corruption to RCE:

  - [ ] check if the application is vulnerable to memory corruption
    - try to find out the language used to build the application
      - languages vulnerable are mostly: `C`, `C++`, `Objective-C` and `Swift`
      - some languages allow **Unsafe** programming, this would add `C#`, `GoLang`, and `Rust` to languages that can have memory corruption
      - if the language is `Java`, it would be easy (if you have the binary), to know whether the package `sun.misc.Unsafe` is used or not
      - regardless of the language, any link to an unsafe language via **FFI** or any other method, can have memory corruption
    - try to know whether there is any mark-and-sweep Garbage Collection used or not
      - if there is a proven one used, like the JVM old GCs, it is almost impossible to find memory corruption
      - other than the JVM old GCs, may have memory corruption, but very unlikely, check its CVE to know common vulnerabilities
    - memory corruption is either:
      1. [Buffer Overflow](https://tcm-sec.com/buffer-overflows-made-easy/)
        - This is the easiest and maybe most abundant vulnerability to find in unsafe programs
      2. Use-After-Free
      3. Double-Free
      4. Dangling pointers (pointers that point to random places, either due to uninitialized pointers)
      5. Multithreading based dangling pointers (multithreading issue that caused a use-after-free or a dangling pointer)
    - try to exploit either of those, mostly by specially crafted inputs
