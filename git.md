# Git

## Initialize local repository

Initialize repository in current directory
```
git init
```

Start tracking existing files
```
git add README.md
git add *.py
```

Initial commit
```
git commit -m 'initial commit'
```


## Clone remote repository

Clone remote repository into directory named as the repository
```
git clone https://github.com/username/repository.git
```

Clone remote repository into specific directory
```
git clone https://github.com/username/repository.git dir-name
```

Clone remote repository including submodules
```
git clone --recurse-submodules https://github.com/username/repository.git 
```

Clone as submodule (add submodule)
```
git submodule add https://github.com/username/repository.git 
```

## Show status

Show files to be commited, and modified and untracked files
```
git status
```

## Show changes

Show unstaged changes - what you've changed but not added yet (diff between working directory and staging area)
```
git diff
```

Show staged changes - what you've added (staged) but not commited yet (diff between staged version and last commit)
```
git diff --staged
```

Press `q` to exit

## Show commit history - log

```
git log
git log --stat
git log --pretty=oneline
git log --graph
```

## Ignoring files

## Commiting
```
git commit -m 'commit message'
```

## Remote repos

Show current remote servers (short names)
```
git remote
```

Show current remote servers with URLs
```
git remote -v
```

Add new remote server
```
git remote add <shortname> <url>
git remote add origin https://github.com/username/repo
```

Push the current branch and set the remote as upstream
```
git push -u origin master
```

Change remote URL
```
git remote set-url origin <url>
```

## Pushing

Push to remote server
```
git push origin master
```

## Branches

Show current branch
```
git branch
```

Show all branches
```
show branch -a
```

Switch to a branch (checkout)
```
git checkout BRANCHNAME
```
