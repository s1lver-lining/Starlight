**Git** is a version control system that is used to track changes in a file system. When present, it is possble to view the history of changes, revert to previous versions, and work on different versions of the same file.

Many tutorials and guides are available online, such as [GitHub's tutorial](https://docs.github.com/en/get-started/getting-started-with-git/set-up-git) or [the visual git guide](http://marklodato.github.io/visual-git-guide/index-en.html).

## Basic usage

* `git commit`

    This command is used to save changes to the local repository. 
    
    Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `-m "message"` | Use the given message as the commit message. |
    | `-a` | Automatically stage files that have been modified and deleted. |
    | `--date="Thu Jan 04 2024 13:33:37 GMT+0100"` | Use the given date as the commit date. **This only sets the `author date` but not the `commiter date`** |

* `git commit --amend`

    This command is used to modify the last commit. It opens the default text editor to modify the commit message. It is also possible to add or remove files from the commit.

    Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `--no-edit` | Use the previous commit message. |
    | `--reset-author` | Use the current user as the author of the commit. |
    | `--date="Thu Jan 04 2024 13:33:37 GMT+0100"` | Use the given date as the commit date. **This only sets the `author date` but not the `commiter date`** |

* `git reset <commit>`

    Undoes all commits after the given commit, but keeps the changes in the working directory. Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `--soft` | Keep the changes in the staging area. |
    | `--hard` | Discard the changes in the staging area. |

* `git log`

    This command is used to view the history of the repository. Here are some useful options:
    | Option | Description |
    | --- | --- |
    | `--oneline` | Show each commit on a single line. |
    | `--graph` | Show the commit history as a graph. |
    | `--all` | Show the history of all branches. |
    | `--since="3 days ago"` | Show commits since the given date. |
    | `--author="name"` | Show commits by the given author. |
    | `--grep="pattern"` | Show commits that match the given pattern. |


## Tricks

* Change the commiter date to the author date

    *Warning:* This command rewrites the history of the repository. It should only be used on commits that have not been pushed to a remote repository.

    ```bash
    # On the current branch
    git filter-branch --env-filter 'export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"'

    # On specific commits
    git filter-branch --env-filter 'if [ $GIT_COMMIT = "commit_hash" ]; then export GIT_COMMITTER_DATE="$GIT_AUTHOR_DATE"; fi'
    ```

* The `HEAD` pointer

    The `HEAD` pointer is a reference to the current commit. It is possible to move the `HEAD` pointer to a different commit using the `git checkout` command. This is useful to view the state of the repository at a specific commit.

    ```bash
    # Move the HEAD pointer to the given commit
    git checkout commit_hash
    ```

    It is possible to reference the parent of the current commit using the `^` symbol. For example, `HEAD^` references the parent of the current commit, and `HEAD^^` references the grandparent of the current commit.