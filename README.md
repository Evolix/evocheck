# Evocheck

It runs many compliance checks of the server with Evolix conventions.
Non-compliance warnings are printed on standard output.

It supports Debian and OpenBSD systems.

Some checks can be disabled in the `/etc/evocheck.cf` config file.

Tests can be run with Vagrant and the provided `VagrantFile`.

## How to contribute

- Write your commits English
- Always do a Merge Request
- Try to respect the following conventions:

### Use the verbose mode to explain errors

The `failed` function takes a mandatory first argument for the check name and a secondary optional argument for the message to display in verbose mode. Example :

```shell
test -f /path/to/file || failed "IS_FILE_EXISTS" "Missing file \`/path/to/file'"
```

If the test is in a loop and might yield multiple errors, It's better to print a single error in normal mode and every error in verbose mode.

```shell
for user in $users; do
    if ! groups "$user" | grep -q adm; then
        failed "IS_USERINADMGROUP" "User $user doesn't belong to \`adm' group"
        test "${VERBOSE}" = 1 || break
    fi
done
```

In a single check with multiple conditions, the verbose message helps determine which condition failed. Example :

```shell
if [ "$last_upgrade" -eq 0 ]; then
    [ "$install_date" -lt "$limit" ] && failed "IS_NOTUPGRADED" "The system has never been updated"
else
    [ "$last_upgrade" -lt "$limit" ] && failed "IS_NOTUPGRADED" "The system hasn't been updated for too long"
fi
```

### Use existing predicates

There are a few predicate functions that help making conditionals.

For Debian versions : `is_debian`, `is_debian_stretch`, `is_debian_jessie`…
For packs : `is_pack_web`, `is_pack_samba`.
For installed packages : `is_installed <package> [<package>]`.

### Extract variables

It's better not to inline function calls inside tests. Instead of this :

```shell
test "$(stat --format "%a" $MINIFW_FILE)" = "600" || failed "IS_MINIFWPERMS"
```

… prefer that :

```shell
actual=$(stat --format "%a" $MINIFW_FILE)
expected="600"
test "$expected" = "$actual" || failed "IS_MINIFWPERMS"
```

### Verify assumptions

It's better to verify that a file, a directory or a command is present before using it, even if it's true in more than 99% of situations.


## How to build the package for a new Debian release

Pre-tasks:

* Execute shellcheck on scripts `*.sh` and fix or disable the relevant checks.
* Prepare `linux/CHANGELOG` and `openbsd/CHANGELOG` for release.
* Update version number is scripts :

```
sed -i 's/VERSION=".*"/VERSION="<MAJOR>.<MINOR>"/g' */evocheck*.sh
```

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
