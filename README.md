
# How to build the package for a new release

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
gbp buildpackage --git-debian-branch=debian --git-upstream-tree=master --git-ignore-new
```

If the build is OK, you can now build the final package.

```
dch -D stretch -r
gbp buildpackage --git-debian-branch=debian --git-upstream-tree=master --git-tag --git-sign --git-keyid=<KEY>
```
