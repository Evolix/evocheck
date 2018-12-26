# Evocheck

This program scans the machine it is run on and verifies if it
adheres to the Evolix standard,  non-compliance warnings are outputted
on standard out.

It is currently adapted for Debian and OpenBSD systems.

Configure by modifying evocheck.cf and use the VagrantFile to test
it.

# How to build the package for a new Debian release

On the master branch, add the last stable version with a release tag.
```
git tag -s v<VERSION> -m 'New release'
git push --tags
```

Checkout the branch debian, merge the master branch.

```
git checkout debian
git merge master --no-ff
dch -v <VERSION>-1
gbp buildpackage --git-debian-branch=debian --git-upstream-tree=master --git-export-dir=/tmp/build-area --git-ignore-new
```

If the build is OK, you can now build the final package.

```
dch -D stretch -r
gbp buildpackage --git-debian-branch=debian --git-upstream-tree=master --git-export-dir=/tmp/build-area --git-tag --git-sign --git-keyid=<KEY>
```
