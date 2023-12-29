Occurs when user input is not properly sanitized and is used directly in a SQL query. This can be used to bypass authentication, read sensitive data, or even execute arbitrary code on the database server.

The most common one to use is the `"OR 1=1--` injection. This will always return true on a `WHERE` clause.

The application will then see the query as:
```sql
SELECT * FROM users WHERE username = 'admin' AND password = "" OR 1=1--"
```

* SQL `IF` and `SLEEP` statements for Blind SQL Injection

	Used to exfiltrate data when the target does not provide the result of the vulnerable query. If the provided condition is true, the query will take a certain amount of time to execute. If the condition is false, the query will execute faster.

	```sql
	/* Check if the first character of the password is 'a' */
	SELECT IF(substr(password, 1, 1) = 'a', SLEEP(5), 1); 

	/* Check if the second character of the password is 'b' */
	SELECT IF(substr(password, 2, 1) = 'b', SLEEP(5), 1); 
	
	/* etc for all position and letters */
	```


* `sqlmap` - [GitHub](https://github\.com/sqlmapproject/sqlmap)

	A command-line tool written in [Python](https://www.python.org/) to automatically detect and exploit vulnerable SQL injection points.