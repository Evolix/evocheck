#!/bin/sh

# EvoCheck
# Script to verify compliance of an OpenBSD server powered by Evolix

readonly VERSION="6.7.3"

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

show_help() {
    cat <<END
NAME:
   evocheck - a system configuration verification tool

VERSION:
   ${VERSION}

DESCRIPTION:
   A script that verifies Evolix conventions on OpenBSD servers

AUTHORS:
   Benoit Serie <bserie@evolix.fr>
   Gregory Colpart <reg@evolix.fr>
   Jeremy Dubois <jdubois@evolix.fr>
   Jeremy Lecour <jlecour@evolix.fr>
   Ludovic Poujol <lpoujol@evolix.fr>
   Romain Dessort <rdessort@evolix.fr>
   Tristan Pilat <tpilat@evolix.fr>
   Victor Laborie <vlaborie@evolix.fr>

USAGE: evocheck
   or  evocheck --cron 
   or  evocheck --quiet 
   or  evocheck --verbose 

OPTIONS:
       --cron                  disable a few checks
   -v, --verbose               increase verbosity of checks
   -q, --quiet                 nothing is printed on stdout nor stderr
   -h, --help, --version       print this message and exit

COPYRIGHT:
   evocheck comes with ABSOLUTELY NO WARRANTY. This is free software,
   and you are welcome to redistribute it under certain conditions.
   See the GNU General Public License v3.0 for details. 2009-2020
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


# If --cron is passed, ignore some checks.
if [ "$1" = "--cron" ]; then
    IS_KERNELUPTODATE=0
    IS_UPTIME=0
fi

check_umasksudoers(){
    grep -E -qr "umask=0077" /etc/sudoers* || failed "IS_UMASKSUDOERS" "sudoers must set umask to 0077"
}

check_tmpnoexec(){
    mount | grep "on /tmp" | grep -q noexec || failed "IS_TMPNOEXEC" "/tmp should be mounted with the noexec option"
}

check_tmoutprofile(){
    grep -q TMOUT= /etc/skel/.profile /root/.profile || failed "IS_TMOUTPROFILE" "In order to fix, add 'export TMOUT=36000' to both /etc/skel/.profile and /root/.profile files"
}

check_raidok(){
    egrep 'sd.*RAID' /var/run/dmesg.boot 1> /dev/null 2>&1
    RESULT=$?
    if [ $RESULT -eq 0 ]; then
        raid_device=$(egrep 'sd.*RAID' /var/run/dmesg.boot | awk '{ print $1 }')
        raid_status=$(bioctl $raid_device | grep softraid | awk '{ print $3 }')
        if [ $raid_status != "Online" ]; then
            failed "IS_RAIDOK" "One of the RAID disk members is faulty. Use bioctl -h $raid_device for more informations"
        fi
    fi
}

check_evobackup(){
    if [ -f /etc/daily.local ]; then
        grep -qE "^sh /usr/share/scripts/zzz_evobackup" /etc/daily.local || failed "IS_EVOBACKUP" "Make sure 'sh /usr/share/scripts/zzz_evobackup' is present and activated in /etc/daily.local"
    else
        failed "IS_EVOBACKUP" "Make sure /etc/daily.local exists and 'sh /usr/share/scripts/zzz_evobackup' is present and activated in /etc/daily.local"
    fi
}

check_uptodate(){
    if [ -f $(command -v syspatch) ]; then
        if syspatch -c | egrep "." 1> /dev/null 2>&1; then
            failed "IS_UPTODATE" "Security update available! Update with syspatch(8)!"
        fi
    fi
}

check_uptime(){
    if [ $(uptime | cut -d" " -f 4) -gt 365 ]; then
        failed "IS_UPTIME" "The server is running for more than a year!"
    fi
}

check_backuptodate(){
}

check_gitperms(){
    test -d /etc/.git && [ "$(stat -f %p /etc/.git/)" = "40700" ] || failed "IS_GITPERMS" "The directiry /etc/.git sould be in 700"
}

check_advbase(){
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        bad_advbase=0
        for advbase in $(ifconfig carp | grep advbase | awk -F 'advbase' '{print $2}' | awk '{print $1}' | xargs); do
        if [[ "$advbase" -gt 5 ]]; then
            bad_advbase=1
        fi
        done
        if [[ "$bad_advbase" -eq 1 ]]; then
            failed "IS_ADVBASE" "At least one CARP interface has advbase greater than 5 seconds!"
        fi
    fi
}

check_preempt(){
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
}

check_rebootmail(){
    if [ -f /etc/rc.local ]; then
        grep -qE '^date \| mail -s "boot/reboot of' /etc/rc.local || failed "IS_REBOOTMAIL" "Make sure the line 'date | mail -s \"boot/reboot of \$hostname' is present in the /etc/rc.local file!"
    else
        failed "IS_REBOOTMAIL" "Make sure /etc/rc.local exist and 'date | mail -s \"boot/reboot of \$hostname' is present!"
    fi
}

check_pfenabled(){
    if pfctl -si | grep Disabled 1> /dev/null 2>&1; then
        failed "IS_PFENABLED" "PF is disabled! Make sure pf=NO is absent from /etc/rc.conf.local and carefully run pfctl -e"
    fi
}

check_pfcustom(){
}

check_softdep(){
    grep -q "softdep" /etc/fstab || failed "IS_SOFTDEP" ""
}

check_wheel(){
    if [ -f /etc/sudoers ]; then
        grep -qE "^%wheel.*$" /etc/sudoers || failed "IS_WHEEL" ""
    fi
}

check_pkgmirror(){
    grep -qE "^https://cdn\.openbsd\.org/pub/OpenBSD" /etc/installurl || failed "IS_PKGMIRROR" "Check whether the right repo is present in the /etc/installurl file"
}

check_history(){
    file=/root/.profile
    grep -qE "^HISTFILE=\$HOME/.histfile" $file && grep -qE "^export HISTSIZE=10000" $file || failed "IS_HISTORY" "Make sure both 'HISTFILE=$HOME/.histfile' and 'export HISTSIZE=10000' are present in /root/.profile"
}

check_vim(){
    if ! is_installed vim; then
        failed "IS_VIM" "vim is not installed! Please add with pkg_add vim"
    fi
}

check_ttyc0secure(){
    grep -Eqv "^ttyC0.*secure$" /etc/ttys || failed "IS_TTYC0SECURE" "First tty should be secured"
}

check_customsyslog(){
    grep -q EvoBSD /etc/newsyslog.conf || failed "IS_CUSTOMSYSLOG" ""
}

check_sudomaint(){
    file=/etc/sudoers
    grep -q "Cmnd_Alias MAINT = /usr/share/scripts/evomaintenance.sh" $file \
    && grep -q "%wheel ALL=NOPASSWD: MAINT" $file \
    || failed "IS_SUDOMAINT" ""
}

check_nrpe(){
    if ! is_installed monitoring-plugins || ! is_installed nrpe; then
        failed "IS_NRPE" "nrpe and/or monitoring-plugins are not installed! Please add with pkg_add nrpe monitoring-plugins"
    fi 
}

check_rsync(){
    if ! is_installed rsync; then
        failed "IS_RSYNC" "rsync is not installed! Please add with pkg_add rsync"
    fi
}

check_cronpath(){
    grep -q "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/share/scripts" /var/cron/tabs/root || failed "IS_CRONPATH" ""
}

check_tmp1777(){
    ls -ld /tmp | grep -q drwxrwxrwt || failed "IS_TMP_1777" ""
}

check_root0700(){
    ls -ld /root | grep -q drwx------ || failed "IS_ROOT_0700" ""
}

check_usrsharescripts(){
    ls -ld /usr/share/scripts | grep -q drwx------ || failed "IS_USRSHARESCRIPTS" ""
}

check_sshpermitrootno() {
    grep -qE ^PermitRoot /etc/ssh/sshd_config && ( grep -E -qi "PermitRoot.*no" /etc/ssh/sshd_config || failed "IS_SSHPERMITROOTNO" "" )
}

check_evomaintenanceusers(){
    # Can be changed in evocheck.cf
    homeDir=${homeDir:-/home}
    sudoers="/etc/sudoers"
    for i in $( (grep "^User_Alias *ADMIN" $sudoers | cut -d= -f2 | tr -d " "; grep ^sudo /etc/group |cut -d: -f 4) | tr "," "\n" |sort -u); do
        grep -qs "^trap.*sudo.*evomaintenance.sh" ${homeDir}/${i}/.*profile
        if [ $? != 0 ]; then
            failed "IS_EVOMAINTENANCEUSERS" "$i doesn't have evomaintenance trap!"
        fi
    done 
}

check_evomaintenanceconf(){
    file=/etc/evomaintenance.cf
    ( test -e $file \
    && test $(stat -f %p $file) = "100600" \
    && grep "^export PGPASSWORD" $file |grep -qv "your-passwd" \
    && grep "^PGDB" $file |grep -qv "your-db" \
    && grep "^PGTABLE" $file |grep -qv "your-table" \
    && grep "^PGHOST" $file |grep -qv "your-pg-host" \
    && grep "^FROM" $file |grep -qv "jdoe@example.com" \
    && grep "^FULLFROM" $file |grep -qv "John Doe <jdoe@example.com>" \
    && grep "^URGENCYFROM" $file |grep -qv "mama.doe@example.com" \
    && grep "^URGENCYTEL" $file |grep -qv "06.00.00.00.00" \
    && grep "^REALM" $file |grep -qv "example.com" ) || failed "IS_EVOMAINTENANCECONF" ""
}

check_sync(){
    if ifconfig carp | grep carp 1> /dev/null 2>&1; then
        sync_script=/usr/share/scripts/sync.sh
        if [ ! -f $sync_script ]; then
            failed "IS_SYNC" "The sync.sh script is absent! As a carp member, a sync.sh script should be present in /usr/share/scripts"
        fi
    fi
}

check_defaultroute(){
    if [ -f /etc/mygate ]; then
        file_route=$(cat /etc/mygate)
        used_route=$(route -n show -priority 8 | grep default | awk '{print $2}')
        if [ "$file_route" != "$used_route" ]; then
            failed "IS_DEFAULTROUTE" "The default route in /etc/mygate is different from the one currently used"
        fi
    else
        failed "IS_DEFAULTROUTE" "The file /etc/mygate does not exist. Make sure you have the same default route in this file as the one currently in use."
    fi
}

check_ntp(){
    if grep -q "server ntp.evolix.net" /etc/ntpd.conf; then
        if [ $(wc -l /etc/ntpd.conf | awk '{print $1}') -ne 1 ]; then
            failed "IS_NTP" "The /etc/ntpd.conf file should only contains \"server ntp.evolix.net\"."
        fi
    else
        failed "IS_NTP" "The configuration in /etc/ntpd.conf is not compliant. It should contains \"server ntp.evolix.net\"."
    fi
}


main() {
    # Default return code : 0 = no error
    RC=0

    test "${IS_UMASKSUDOERS:=1}" = 1 && check_umasksudoers
    test "${IS_TMPNOEXEC:=1}" = 1 && check_tmpnoexec
    test "${IS_TMOUTPROFILE:=1}" = 1 && check_tmoutprofile
    test "${IS_RAIDOK:=1}" = 1 && check_raidok
    test "${IS_EVOBACKUP:=1}" = 1 && check_evobackup
    test "${IS_UPTODATE:=1}" = 1 && check_uptodate
    test "${IS_UPTIME:=1}" = 1 && check_uptime
    test "${IS_BACKUPUPTODATE:=1}" = 1 && check_backuptodate
    test "${IS_GITPERMS:=1}" = 1 && check_gitperms
    test "${IS_ADVBASE:=1}" = 1 && check_advbase
    test "${IS_PREEMPT:=1}" = 1 && check_preempt
    test "${IS_REBOOTMAIL:=1}" = 1 && check_rebootmail
    test "${IS_PFENABLED:=1}" = 1 && check_pfenabled
    test "${IS_PFCUSTOM:=1}" = 1 && check_pfcustom
    test "${IS_SOFTDEP:=1}" = 1 && check_softdep
    test "${IS_WHEEL:=1}" = 1 && check_wheel
    test "${IS_PKGMIRROR:=1}" = 1 && check_pkgmirror
    test "${IS_HISTORY:=1}" = 1 && check_history
    test "${IS_VIM:=1}" = 1 && check_vim
    test "${IS_TTYC0SECURE:=1}" = 1 && check_ttyc0secure
    test "${IS_CUSTOMSYSLOG:=1}" = 1 && check_customsyslog
    test "${IS_SUDOMAINT:=1}" = 1 && check_sudomaint
    test "${IS_NRPE:=1}" = 1 && check_nrpe
    test "${IS_RSYNC:=1}" = 1 && check_rsync
    test "${IS_CRONPATH:=1}" = 1 && check_cronpath
    test "${IS_TMP_1777:=1}" = 1 && check_tmp1777
    test "${IS_ROOT_0700:=1}" = 1 && check_root0700
    test "${IS_USRSHARESCRIPTS:=1}" = 1 && check_usrsharescripts
    test "${IS_SSHPERMITROOTNO:=1}" = 1 && check_sshpermitrootno
    test "${IS_EVOMAINTENANCEUSERS:=1}" = 1 && check_evomaintenanceusers
    test "${IS_EVOMAINTENANCECONF:=1}" = 1 && check_evomaintenanceconf
    test "${IS_SYNC:=1}" = 1 && check_sync
    test "${IS_DEFAULTROUTE:=1}" = 1 && check_defaultroute
    test "${IS_NTP:=1}" = 1 && check_ntp

    exit ${RC}
}
# Parse options
# based on https://gist.github.com/deshion/10d3cb5f88a21671e17a
while :; do
    case $1 in
        -h|-\?|--help|--version)
            show_help
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

main ${ARGS}
