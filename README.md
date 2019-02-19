# Evocheck

It runs many compliance checks of the server with Evolix conventions.
Non-compliance warnings are printed on standard output.

It supports Debian and OpenBSD systems.

Some checks can be disabled in the `/etc/evocheck.cf` config file.

Tests can be run with Vagrant and the provided `VagrantFile`.

## How to build the package for a new Debian release

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

## Testing

Evocheck can be tested with Vagrant, if you don't have installed it yet :

~~~
apt install vagrant vagrant-libvirt
~~~

You can now start your Vagrant machine and connect to it :

~~~
vagrant up
vagrant ssh
sudo -i
~~~

Evocheck can be run with :

~~~
/usr/share/scripts/evocheck.sh
~~~

### Deployment

Launch **vagrant rsync-auto** in a terminal to automatically synchronise
your local code with the Vagrant VM :

~~~
vagrant rsync-auto
~~~

## License

This is an [Evolix](https://evolix.com) project and is licensed
under the GPLv3, see the [LICENSE](LICENSE) file for details.
