Dorking is the process of using search engines to find information about a target.


* `Google Dorks` - [Wikipedia](https://en.wikipedia.org/wiki/Google_hacking) [CheatSheet](https://gist.github.com/sundowndev/283efaddbcf896ab405488330d1bbc06) 

    Use Google's search engine to find indexed pages that contain specific information.
    provides detailed information about Google Dorks.

    The most common ones are:
    ```bash
    site:example.com           # Search for a specific domain
    inurl: "ViewerFrame?Mode=" # Search for a specific string in the URL (exposed webcams)
    intitle: "index of"        # Search for a specific string in the title of the page (exposed dirs)
    filetype:pdf               # Search for a specific file type
    ```

* `Github Dorks`

    Use Github's search engine to find indexed files that contain specific information. [This documentation](https://docs.github.com/en/search-github/searching-on-github) can be used to craft search queries.

    Github users can be tracked using [Gitive](https://github.com/mxrch/GitFive).

    The most common dork keywords are:
    ```bash
    filename:passwords.txt     # Search for a specific filename
    extension:txt              # Search for a specific file extension
    owner:username             # Search for a specific username
    
    # In commits
    author-name:username       # Search for a specific commit author
    author-email:u@ex.com      # Search for a specific commit author email
    committer-name:username    # Search for a specific committer
    committer-email:u@ex.com   # Search for a specific committer email
    ```

    