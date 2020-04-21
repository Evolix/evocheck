#!/bin/sh

# EvoCheck
# Script to verify compliance of an OpenBSD server powered by Evolix

readonly VERSION="20.04.1"

# Disable LANG*

export LANG=C
export LANGUAGE=C


# Default return code : 0 = no error
RC=0

# Verbose function
verbose() {
    msg="${1:-$(cat /dev/stdin)}"
    [ "${VERBOSE}" -eq 1 ] && [ -n "${msg}" ] && echo "${msg}"
}

# Source configuration file
test -f /etc/evocheck.cf && . /etc/evocheck.cf

# Functions

show_version() {
    cat <<END
evocheck version ${VERSION}

Copyright 2009-2019 Evolix <info@evolix.fr>,
                    Romain Dessort <rdessort@evolix.fr>,
                    Benoit Série <bserie@evolix.fr>,
                    Gregory Colpart <reg@evolix.fr>,
                    Jérémy Lecour <jlecour@evolix.fr>,
                    Tristan Pilat <tpilat@evolix.fr>,
                    Victor Laborie <vlaborie@evolix.fr>
                    and others.

evocheck comes with ABSOLUTELY NO WARRANTY.  This is free software,
and you are welcome to redistribute it under certain conditions.
See the GNU General Public License v3.0 for details.
END
}

show_help() {
    cat <<END
evocheck is a script that verifies Evolix conventions on OpenBSD servers.

Usage: evocheck
  or   evocheck --cron
  or   evocheck --quiet
  or   evocheck --verbose

Options
     --cron                  disable a few checks
 -v, --verbose               increase verbosity of checks
 -q, --quiet                 nothing is printed on stdout nor stderr
 -h, --help                  print this message and exit
     --version               print version and exit
END
}

is_installed(){
    for pkg in "$@"; do
	pkg_info | grep -q $pkg || return 1
    done
}

# logging
failed() {
    check_name=$1
    shift
    check_comments=$*

    RC=1
    if [ "${QUIET}" != 1 ]; then
        if [ -n "${check_comments}" ] && [ "${VERBOSE}" = 1 ]; then
            printf "%s FAILED! %s\n" "${check_name}" "${check_comments}" 2>&1
        else
            printf "%s FAILED!\n" "${check_name}" 2>&1
        fi
    fi
}

# Parse options
# based on https://gist.github.com/deshion/10d3cb5f88a21671e17a
while :; do
    case $1 in
        -h|-\?|--help)
            show_help
            exit 0
            ;;
        --version)
            show_version
            exit 0
            ;;
        --cron)
            IS_KERNELUPTODATE=0
            IS_UPTIME=0
            ;;
        -v|--verbose)
            VERBOSE=1
            ;;
        -q|--quiet)
            QUIET=1
            VERBOSE=0
            ;;
        --)
            # End of all options.
            shift
            break
            ;;
        -?*|[[:alnum:]]*)
            # ignore unknown options
            printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
            ;;
        *)
            # Default case: If no more options then break out of the loop.
            break
            ;;
    esac

    shift
done

# If --cron is passed, ignore some checks.
if [ "$1" = "--cron" ]; then
    IS_KERNELUPTODATE=0
    IS_UPTIME=0
fi

if [ "$IS_UMASKSUDOERS" = 1 ]; then
    grep -E -qr "umask=0077" /etc/sudoers* || failed "IS_UMASKSUDOERS" "sudoers must set umask to 0077"
fi

if [ "$IS_TMPNOEXEC" = 1 ]; then
    mount | grep "on /tmp" | grep -q noexec || failed "IS_TMPNOEXEC" "/tmp should be mounted with the noexec option"
fi

if [ "$IS_TMOUTPROFILE" = 1 ]; then
    grep -q TMOUT= /etc/skel/.profile /root/.profile || failed "IS_TMOUTPROFILE" "In order to fix, add 'export TMOUT=36000' to both /etc/skel/.profile and /root/.profile files"
fi

# Check RAID state (bioctl)
#if [ "$IS_RAIDOK" = 1 ]; then
# TODO
#fi

# Check Evoackup installation
if [ "$IS_EVOBACKUP" = 1 ]; then
    if [ -f /etc/daily.local ]; then
        grep -qE "^sh /usr/share/scripts/zzz_evobackup" /etc/daily.local || failed "IS_EVOBACKUP" "Make sure 'sh /usr/share/scripts/zzz_evobackup' is present and activated in /etc/daily.local"
    else
        failed "IS_EVOBACKUP" "Make sure /etc/daily.local exists and 'sh /usr/share/scripts/zzz_evobackup' is present and activated in /etc/daily.local"
    fi
fi

# Check whether the system should be restarted (after a kernel update)
#if [ "$IS_KERNELUPTODATE" = 1 ]; then
# TODO
#fi

# Check if the server is running for more than a year.
if [ "$IS_UPTIME" = 1 ]; then
    if [ $(uptime | cut -d" " -f 4) -gt 365 ]; then
        failed "IS_UPTIME" "The server is running for more than a year!"
    fi
fi

# Check if files in /home/backup/ are up-to-date
#if [ "$IS_BACKUPUPTODATE" = 1 ]; then
# TODO
#fi

# Check if /etc/.git/ has read/write permissions for root only.
if [ "$IS_GITPERMS" = 1 ]; then
    test -d /etc/.git && [ "$(stat -f %p /etc/.git/)" = "40700" ] || failed "IS_GITPERMS" "The directiry /etc/.git sould be in 700"
fi

#if [ "$IS_OLD_HOME_DIR" = 1 ]; then
#fi

if [ "$IS_ADVBASE" = 1 ]; then
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        for advbase in $(ifconfig carp | grep advbase | awk -F 'advbase' '{print $2}' | awk '{print $1}' | xargs); do
        if [[ "$advbase" -gt 1 ]]; then
            failed "IS_ADVBASE" "At least one CARP interface has advbase greater than 5 seconds!"
        fi
        done
    fi
fi

if [ "$IS_PREEMPT" = 1 ]; then
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        preempt=$(sysctl net.inet.carp.preempt | cut -d"=" -f2)
        if [[ "$preempt" -ne 1 ]]; then
            failed "IS_PREEMPT" "The preempt function is not activated! Please type 'sysctl net.inet.carp.preempt=1' in"
        fi
        if [ -f /etc/sysctl.conf ]; then
            grep -qE "^net.inet.carp.preempt=1" /etc/sysctl.conf || failed "IS_PREEMPT" "The preempt parameter is not permanently activated! Please add 'net.inet.carp.preempt=1' in /etc/sysctl.conf"
        else
	    failed "IS_PREEMPT" "Make sure /etc/sysctl.conf exists and contains the line 'net.inet.carp.preempt=1'"
        fi
    fi
fi

if [ "$IS_REBOOTMAIL" = 1 ]; then
    if [ -f /etc/rc.local ]; then
        grep -qE '^date \| mail -s "boot/reboot of' /etc/rc.local || failed "IS_REBOOTMAIL" "Make sure the line 'date | mail -s \"boot/reboot of \$hostname' is present in the /etc/rc.local file!"
    else
        failed "IS_REBOOTMAIL" "Make sure /etc/rc.local exist and 'date | mail -s \"boot/reboot of \$hostname' is present!"
    fi
fi

#if [ "$IS_PFENABLED" = 1 ]; then
# TODO
#fi

#if [ "$IS_PFCUSTOM" = 1 ]; then
# TODO
#fi

if [ "$IS_SOFTDEP" = 1 ]; then
    grep -q "softdep" /etc/fstab || failed "IS_SOFTDEP" ""
fi

if [ "$IS_WHEEL" = 1 ]; then
    if [ -f /etc/sudoers ]; then
        grep -qE "^%wheel.*$" /etc/sudoers || failed "IS_WHEEL" ""
    fi
fi

if [ "$IS_PKGMIRROR" = 1 ]; then
    grep -qE "^https://cdn\.openbsd\.org/pub/OpenBSD" /etc/installurl || failed "IS_PKGMIRROR" "Check whether the right repo is present in the /etc/installurl file"
fi

if [ "$IS_HISTORY" = 1 ]; then
    file=/root/.profile
    grep -qE "^HISTFILE=\$HOME/.histfile" $file && grep -qE "^export HISTSIZE=10000" $file || failed "IS_HISTORY" "Make sure both 'HISTFILE=$HOME/.histfile' and 'export HISTSIZE=10000' are present in /root/.profile"
fi

if [ "$IS_VIM" = 1 ]; then
    if ! is_installed vim; then
    	failed "IS_VIM" "vim is not installed! Please add with pkg_add vim"
    fi
fi

if [ "$IS_TTYC0SECURE" = 1 ]; then
    grep -Eqv "^ttyC0.*secure$" /etc/ttys || failed "IS_TTYC0SECURE" "First tty should be secured"
fi

if [ "$IS_CUSTOMSYSLOG" = 1 ]; then
    grep -q Evolix /etc/newsyslog.conf || failed "IS_CUSTOMSYSLOG" ""
fi

if [ "$IS_SUDOMAINT" = 1 ]; then
    f=/etc/sudoers
    grep -q "Cmnd_Alias MAINT = /usr/share/scripts/evomaintenance.sh" $f \
    && grep -q "ADMIN ALL=NOPASSWD: MAINT" $f \
    || failed "IS_SUDOMAINT" ""
fi

if [ "$IS_POSTGRESQL" = 1 ]; then
    if ! is_installed postgresql-client; then
    	failed "IS_POSTGRESQL" "postgresql-client is not installed! Please add with pkg_add postgresql-client"
    fi
fi

if [ "$IS_NRPE" = 1 ]; then
    if ! is_installed monitoring-plugins || ! is_installed nrpe; then
    	failed "IS_NRPE" "nrpe and/or monitoring-plugins are not installed! Please add with pkg_add nrpe monitoring-plugins"
    fi
fi

if [ "$IS_RSYNC" = 1 ]; then
    if ! is_installed rsync; then
    	failed "IS_RSYNC" "rsync is not installed! Please add with pkg_add rsync"
    fi
fi

if [ "$IS_CRONPATH" = 1 ]; then
    grep -q "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin" /var/cron/tabs/root || failed "IS_CRONPATH" ""
fi

if [ "$IS_TMP_1777" = 1 ]; then
    ls -ld /tmp | grep -q drwxrwxrwt || failed "IS_TMP_1777" ""
fi

if [ "$IS_ROOT_0700" = 1 ]; then
    ls -ld /root | grep -q drwx------ || failed "IS_ROOT_0700" ""
fi

if [ "$IS_USRSHARESCRIPTS" = 1 ]; then
    ls -ld /usr/share/scripts | grep -q drwx------ || failed "IS_USRSHARESCRIPTS" ""
fi

if [ "$IS_SSHPERMITROOTNO" = 1 ]; then
    grep -qE ^PermitRoot /etc/ssh/sshd_config && ( grep -E -qi "PermitRoot.*no" /etc/ssh/sshd_config || failed "IS_SSHPERMITROOTNO" "" )
fi

if [ "$IS_EVOMAINTENANCEUSERS" = 1 ]; then
    # Can be changed in evocheck.cf
    homeDir=${homeDir:-/home}
    sudoers="/etc/sudoers"
    for i in $( (grep "^User_Alias *ADMIN" $sudoers | cut -d= -f2 | tr -d " "; grep ^sudo /etc/group |cut -d: -f 4) | tr "," "\n" |sort -u); do
        grep -qs "^trap.*sudo.*evomaintenance.sh" ${homeDir}/${i}/.*profile
        if [ $? != 0 ]; then
            failed "IS_EVOMAINTENANCEUSERS" "$i doesn't have evomaintenance trap!"
        fi
    done
fi

# Verification de la configuration d'evomaintenance
if [ "$IS_EVOMAINTENANCECONF" = 1 ]; then
    f=/etc/evomaintenance.cf
    ( test -e $f \
    && test $(stat -f %p $f) = "100600" \
    && grep "^export PGPASSWORD" $f |grep -qv "your-passwd" \
    && grep "^PGDB" $f |grep -qv "your-db" \
    && grep "^PGTABLE" $f |grep -qv "your-table" \
    && grep "^PGHOST" $f |grep -qv "your-pg-host" \
    && grep "^FROM" $f |grep -qv "jdoe@example.com" \
    && grep "^FULLFROM" $f |grep -qv "John Doe <jdoe@example.com>" \
    && grep "^URGENCYFROM" $f |grep -qv "mama.doe@example.com" \
    && grep "^URGENCYTEL" $f |grep -qv "06.00.00.00.00" \
    && grep "^REALM" $f |grep -qv "example.com" ) || failed "IS_EVOMAINTENANCECONF" ""
fi
