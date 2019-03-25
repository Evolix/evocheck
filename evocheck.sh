#!/bin/sh

# EvoCheck
# Script to verify compliance of a OpenBSD server powered by Evolix

# Disable LANG*

export LANG=C
export LANGUAGE=C

# Default configuration values

IS_CUSTOMSUDOERS=1
IS_TMPNOEXEC=1
IS_TMOUTPROFILE=1
IS_RAIDOK=1
IS_EVOBACKUP=1
IS_KERNELUPTODATE=1
IS_UPTIME=1
IS_BACKUPUPTODATE=1
IS_GITPERMS=1
IS_OLD_HOME_DIR=1
IS_ADVBASE=1
IS_PREEMPT=1
IS_REBOOTMAIL=1
IS_PFENABLED=1
IS_PFCUSTOM=1
IS_SOFTDEP=1
IS_WHEEL=1
IS_PKGMIRROR=1
IS_HISTORY=1
IS_VIM=1
IS_TTYC0SECURE=1
IS_CUSTOMSYSLOG=1
IS_SUDOMAINT=1
IS_POSTGRESQL=1
IS_NRPE=1
IS_RSYNC=1
IS_CRONPATH=1
IS_TMP_1777=1
IS_ROOT_0700=1
IS_USRSHARESCRIPTS=1
IS_SSHPERMITROOTNO=1
IS_EVOMAINTENANCEUSERS=1
IS_EVOMAINTENANCECONF=1

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
        dpkg -l "$pkg" 2> /dev/null | grep -q -E '^(i|h)i' || return 1
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

if [ "$IS_CUSTOMSUDOERS" = 1 ]; then
    grep -E -qr "umask=0077" /etc/sudoers* || echo 'IS_CUSTOMSUDOERS FAILED!'
fi

if [ "$IS_TMPNOEXEC" = 1 ]; then
    mount | grep "on /tmp" | grep -q noexec || echo 'IS_TMPNOEXEC FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "/tmp should be mounted with the noexec option"
    fi
fi

if [ "$IS_TMOUTPROFILE" = 1 ]; then
    grep -q TMOUT= /etc/skel/.profile /root/.profile || echo 'IS_TMOUTPROFILE FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "In order to fix, add 'export TMOUT=36000' to both /etc/skel/.profile and /root/.profile files"
    fi
fi

# Check RAID state (bioctl)
#if [ "$IS_RAIDOK" = 1 ]; then
# TODO
#fi

# Check Evoackup installation
if [ "$IS_EVOBACKUP" = 1 ]; then
    if [ -f /etc/daily.local ]; then
        grep -qE "^sh /usr/share/scripts/zzz_evobackup" /etc/daily.local || echo 'IS_EVOBACKUP FAILED!'
    else
        echo 'IS_EVOBACKUP FAILED!'
        if [[ "$VERBOSE" == 1 ]]; then
            echo "Make sure /etc/daily.local exist and 'sh /usr/share/scripts/zzz_evobackup' is present and activated in /etc/daily.local"
        fi
    fi
fi

# Check whether the system should be restarted (after a kernel update)
#if [ "$IS_KERNELUPTODATE" = 1 ]; then
# TODO
#fi

# Check if the server is running for more than a year.
if [ "$IS_UPTIME" = 1 ]; then
    if [ $(uptime | cut -d" " -f 4) -gt 365 ]; then
        echo 'IS_UPTIME FAILED!'
    fi
fi

# Check if files in /home/backup/ are up-to-date
#if [ "$IS_BACKUPUPTODATE" = 1 ]; then
# TODO
#fi

# Check if /etc/.git/ has read/write permissions for root only.
if [ "$IS_GITPERMS" = 1 ]; then
    test -d /etc/.git && [ "$(stat -f %p /etc/.git/)" = "40700" ] || echo 'IS_GITPERMS FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "The directiry /etc/.git sould be in 700"
    fi
fi

#if [ "$IS_OLD_HOME_DIR" = 1 ]; then
#fi

if [ "$IS_ADVBASE" = 1 ]; then
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        for advbase in $(ifconfig carp | grep advbase | awk -F 'advbase' '{print $2}' | awk '{print $1}' | xargs); do
        if [[ "$advbase" -gt 1 ]]; then
            echo 'IS_ADVBASE FAILED!'
            if [[ "$VERBOSE" == 1 ]]; then
                    echo "At least one CARP interface has advbase greater than 5 seconds!" 
            fi
        fi
        done
    fi
fi

if [ "$IS_PREEMPT" = 1 ]; then
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        preempt=$(sysctl net.inet.carp.preempt | cut -d"=" -f2)
        if [[ "$preempt" -ne 1 ]]; then
            echo 'IS_PREEMPT FAILED!'
            if [[ "$VERBOSE" == 1 ]]; then
                echo "The preempt function is not activated! Please type 'sysctl net.inet.carp.preempt=1' in"
            fi
        fi
        if [ -f /etc/sysctl.conf ]; then
            grep -qE "^net.inet.carp.preempt=1" /etc/sysctl.conf || echo 'IS_PREEMPT FAILED!'
        else
            echo 'IS_PREEMPT FAILED!'
            if [[ "$VERBOSE" == 1 ]]; then
                echo "The preempt parameter is not permanently activated! Please add 'net.inet.carp.preempt=1' in /etc/sysctl.conf"
            fi
        fi
    fi
fi

if [ "$IS_REBOOTMAIL" = 1 ]; then
    if [ -f /etc/rc.local ]; then
        grep -qE '^date \| mail -s "boot/reboot of' /etc/rc.local || echo 'IS_REBOOTMAIL FAILED!'
    else
        echo 'IS_REBOOTMAIL FAILED!'
        if [[ "$VERBOSE" == 1 ]]; then
            echo "Make sure /etc/rc.local exist and 'date | mail -s \"boot/reboot of \$hostname' is present!"
        fi
    fi
fi

#if [ "$IS_PFENABLED" = 1 ]; then
# TODO
#fi

#if [ "$IS_PFCUSTOM" = 1 ]; then
# TODO
#fi

if [ "$IS_SOFTDEP" = 1 ]; then
    grep -q "softdep" /etc/fstab || echo 'IS_SOFTDEP FAILED!'
fi

if [ "$IS_WHEEL" = 1 ]; then
    if [ -f /etc/sudoers ]; then
        grep -qE "^%wheel.*$" /etc/sudoers || echo 'IS_WHEEL FAILED!'
    fi
fi

if [ "$IS_PKGMIRROR" = 1 ]; then
    grep -qE "^https://cdn\.openbsd\.org/pub/OpenBSD" /etc/installurl || echo 'IS_PKGMIRROR FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "Check whether the right repo is present in the /etc/installurl file"
    fi
fi

if [ "$IS_HISTORY" = 1 ]; then
    file=/root/.profile
    grep -qE "^HISTFILE=\$HOME/.histfile" $file && grep -qE "^export HISTSIZE=10000" $file || echo 'IS_HISTORY FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "Make sure both 'HISTFILE=$HOME/.histfile' and 'export HISTSIZE=10000' are present in /root/.profile"
    fi
fi

if [ "$IS_VIM" = 1 ]; then
    pkg_info | grep -q vim || echo 'IS_VIM FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "vim is not installed! Please add with pkg_add vim"
    fi
fi

if [ "$IS_TTYC0SECURE" = 1 ]; then
    grep -Eqv "^ttyC0.*secure$" /etc/ttys || echo 'IS_TTYC0SECURE FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "First tty should be secured"
    fi
fi

if [ "$IS_CUSTOMSYSLOG" = 1 ]; then
    grep -q Evolix /etc/newsyslog.conf || echo 'IS_CUSTOMSYSLOG FAILED!'
fi

if [ "$IS_SUDOMAINT" = 1 ]; then
    f=/etc/sudoers
    grep -q "Cmnd_Alias MAINT = /usr/share/scripts/evomaintenance.sh" $f \
    && grep -q "ADMIN ALL=NOPASSWD: MAINT" $f \
    || echo 'IS_SUDOMAINT FAILED!'
fi

if [ "$IS_POSTGRESQL" = 1 ]; then
    pkg_info | grep -q postgresql-client || echo 'IS_POSTGRESQL FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "postgresql-client is not installed! Please add with pkg_add postgresql-client"
    fi
fi

if [ "$IS_NRPE" = 1 ]; then
    ( pkg_info | grep -q monitoring-plugins && pkg_info | grep -q nrpe ) || echo 'IS_NRPE FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "nrpe and/or monitoring-plugins are not installed! Please add with pkg_add nrpe monitoring-plugins"
    fi
fi

if [ "$IS_RSYNC" = 1 ]; then
    pkg info | grep -q rsync || echo 'IS_RSYNC FAILED!'
    if [[ "$VERBOSE" == 1 ]]; then
        echo "rsync is not installed! Please add with pkg_add rsync"
    fi
fi

if [ "$IS_CRONPATH" = 1 ]; then
    grep -q "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin" /var/cron/tabs/root || echo 'IS_CRONPATH FAILED!'
fi

if [ "$IS_TMP_1777" = 1 ]; then
    ls -ld /tmp | grep -q drwxrwxrwt || echo 'IS_TMP_1777 FAILED!'
fi

if [ "$IS_ROOT_0700" = 1 ]; then
    ls -ld /root | grep -q drwx------ || echo 'IS_ROOT_0700 FAILED!'
fi

if [ "$IS_USRSHARESCRIPTS" = 1 ]; then
    ls -ld /usr/share/scripts | grep -q drwx------ || echo 'IS_USRSHARESCRIPTS FAILED!'
fi

if [ "$IS_SSHPERMITROOTNO" = 1 ]; then
    grep -qE ^PermitRoot /etc/ssh/sshd_config && ( grep -E -qi "PermitRoot.*no" /etc/ssh/sshd_config || echo 'IS_SSHPERMITROOTNO FAILED!' )
fi

if [ "$IS_EVOMAINTENANCEUSERS" = 1 ]; then
    # Can be changed in evocheck.cf
    homeDir=${homeDir:-/home}
    if ! is_debianversion stretch; then
        if [ -f /etc/sudoers.d/evolinux ]; then
            sudoers="/etc/sudoers.d/evolinux"
        else
            sudoers="/etc/sudoers"
        fi
        for i in $( (grep "^User_Alias *ADMIN" $sudoers | cut -d= -f2 | tr -d " "; grep ^sudo /etc/group |cut -d: -f 4) | tr "," "\n" |sort -u); do
            grep -qs "^trap.*sudo.*evomaintenance.sh" ${homeDir}/${i}/.*profile
            if [ $? != 0 ]; then
                echo 'IS_EVOMAINTENANCEUSERS FAILED!'
                if [ "$VERBOSE" = 1 ]; then
                    echo "$i doesn't have evomaintenance trap!"
                else
                    break
                fi
            fi
        done
    else
        for i in $(getent group evolinux-sudo | cut -d':' -f4 | tr ',' ' '); do
            grep -qs "^trap.*sudo.*evomaintenance.sh" ${homeDir}/$i/.*profile
            if [ $? != 0 ]; then
                echo 'IS_EVOMAINTENANCEUSERS FAILED!'
                if [ "$VERBOSE" = 1 ]; then
                    echo "$i doesn't have evomaintenance trap!"
                else
                    break
                fi
            fi
        done
    fi
fi

# Verification de la configuration d'evomaintenance
if [ "$IS_EVOMAINTENANCECONF" = 1 ]; then
    f=/etc/evomaintenance.cf
    ( test -e $f \
    && test $(stat -c "%a" $f) = "600" \
    && grep "^export PGPASSWORD" $f |grep -qv "your-passwd" \
    && grep "^PGDB" $f |grep -qv "your-db" \
    && grep "^PGTABLE" $f |grep -qv "your-table" \
    && grep "^PGHOST" $f |grep -qv "your-pg-host" \
    && grep "^FROM" $f |grep -qv "jdoe@example.com" \
    && grep "^FULLFROM" $f |grep -qv "John Doe <jdoe@example.com>" \
    && grep "^URGENCYFROM" $f |grep -qv "mama.doe@example.com" \
    && grep "^URGENCYTEL" $f |grep -qv "06.00.00.00.00" \
    && grep "^REALM" $f |grep -qv "example.com" ) || echo 'IS_EVOMAINTENANCECONF FAILED!'
fi
