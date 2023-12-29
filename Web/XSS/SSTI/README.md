Server Side Template Injection (SSTI) is a vulnerability that allows an attacker to inject code into a server-side template, which is then executed server-side. This can lead to Remote Code Execution (RCE).

* Jinja2 - [HackTricks](https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection/jinja2-ssti)

    Jinja2 is a template engine for Python, notably used in Flask. It can be used to create HTML pages from a template. Even though it uses a sandbox to process data, some tricks allows for RCE on the server.