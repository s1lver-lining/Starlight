
* `Magic Hashes` - [CheatSheet](https://github.com/spaze/hashes)

	In [PHP](https://en.wikipedia.org/wiki/PHP), the `==` applies type juggling, so if the hash starts with `0e`, then the hash will be evaluated as 0 (scientific notation). This can be used to bypass authentication.

	Since 1/256 hashes have this property, it is relatively easy to bruteforce strings with selected characters.

	example: `md5("240610708") = 0e462097431906509019562988736854`


* `preg_replace` - [Manual](http://php.net/manual/en/function.preg-replace.php)

	A bug in older versions of [PHP](https://en.wikipedia.org/wiki/PHP) where the user could get remote code execution


* `phpdc.phpr` - [GitHub](https://github\.com/lighttpd/xcache/blob/master/bin/phpdc.phpr)

	A command-line tool to decode [`bcompiler`](http://php.net/manual/en/book.bcompiler.php) compiled [PHP](https://en.wikipedia.org/wiki/PHP) code.


* `php://filter for Local File Inclusion` - [Website](https://www.idontplaydarts.com/2011/02/using-php-filter-for-local-file-inclusion/) 

	A bug in [PHP](https://en.wikipedia.org/wiki/PHP) where if GET HTTP variables in the URL are controlling the navigation of the web page, perhaps the source code is `include`-ing other files to be served to the user. This can be manipulated by using [PHP filters](http://php.net/manual/en/filters.php) to potentially retrieve source code. Example like so:

	```
	http://example.com/index.php?m=php://filter/convert.base64-encode/resource=index
	```


* `data://text/plain;base64` :heart:

	A [PHP](https://en.wikipedia.org/wiki/PHP) stream that can be taken advantage of if used and evaluated as an `include` resource or evaluated. Can be used for RCE: check out this writeup: [https://ctftime.org/writeup/8868](https://ctftime.org/writeup/8868)

	```
	http://dommain.net?cmd=whoami&page=data://text/plain;base64,PD9waHAgZWNobyBzeXN0ZW0oJF9HRVRbJ2NtZCddKTsgPz4=
	```


* `PHP Generic Gadget Chains` - [GitHub](https://github\.com/ambionics/phpggc)

	Payloads for Object injection in `unserialize` on different frameworks.