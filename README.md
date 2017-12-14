Release:

```
master> git archive --format=tar master | gzip > ../evocheck_<VERSION>.orig.tar.gz
master> pristine-tar commit ../evocheck_<VERSION>.orig.tar.gz master
```

Debian release:

```
debian-sid> git merge master
debian-sid> dch -v <VERSION>-1
debian-sid> git-buildpackage -us -uc --git-pristine-tar --git-upstream-branch=master --git-debian-branch=debian-sid
```