#!/bin/sh

# EvoCheck
# Script to verify compliance of an OpenBSD server powered by Evolix

readonly VERSION="22.11"

# base functions

show_version() {
    cat <<END
evocheck version ${VERSION}

Copyright 2009-2021 Evolix <info@evolix.fr>,
                    Romain Dessort <rdessort@evolix.fr>,
                    Benoit Série <bserie@evolix.fr>,
                    Gregory Colpart <reg@evolix.fr>,
                    Jérémy Lecour <jlecour@evolix.fr>,
                    Tristan Pilat <tpilat@evolix.fr>,
                    Victor Laborie <vlaborie@evolix.fr>,
                    Jérémy Dubois <jdubois@evolix.fr>
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
        pkg_info | grep -q "$pkg" || return 1
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

# check functions

check_umasksudoers(){
    grep -Rq "^Defaults.*umask=0077" /etc/sudoers* || failed "IS_UMASKSUDOERS" "sudoers must set umask to 0077"
}
check_tmpnoexec(){
    mount | grep "on /tmp" | grep -q noexec || failed "IS_TMPNOEXEC" "/tmp should be mounted with the noexec option"
}
check_softdep(){
    if [ "$(grep -c softdep /etc/fstab)" -ne "$(grep -c ffs /etc/fstab)" ]; then
        failed "IS_SOFTDEP" "All partitions should have the softdep option"
    fi
}
check_noatime(){
    if [ "$(mount | grep -c noatime)" -ne "$(grep ffs /etc/fstab | grep -vc ^\#)" ]; then
        failed "IS_NOATIME" "All partitions should be mounted with the noatime option"
    fi
}
check_tmoutprofile(){
    if [ -f /etc/skel/.profile ]; then
        grep -q TMOUT= /etc/skel/.profile /root/.profile || failed "IS_TMOUTPROFILE" "Add 'export TMOUT=36000' to both /etc/skel/.profile and /root/.profile files"
    else
        failed "IS_TMOUTPROFILE" "File /etc/skel/.profile does not exist. Both /etc/skel/.profile and /root/.profile should contain at least 'export TMOUT=36000'"
    fi
}
check_raidok(){
    grep -E 'sd.*RAID' /var/run/dmesg.boot 1> /dev/null 2>&1
    RESULT=$?
    if [ $RESULT -eq 0 ]; then
        raid_device=$(grep -E 'sd.*RAID' /var/run/dmesg.boot | awk '{ print $1 }' | tail -1)
        raid_status=$(bioctl "$raid_device" | grep softraid | awk '{ print $3 }')
        if [ "$raid_status" != "Online" ]; then
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
    if [ "$(command -v syspatch)" ]; then
        if syspatch -c | grep -E "." 1> /dev/null 2>&1; then
            failed "IS_UPTODATE" "Security update available! Update with syspatch(8)!"
        fi
    fi
}
check_uptime(){
    uptime=$(($(date +"%s") - $(sysctl -n kern.boottime)))
    if [ "$uptime" -gt "$(( 2*365*24*60*60 ))" ]; then
        failed "IS_UPTIME" "The server has an uptime of more than 2 years, reboot on new kernel advised"
    fi
}
check_backupuptodate(){
    backup_dir="/home/backup"
    if [ -d "${backup_dir}" ]; then
        if [ -n "$(ls -A ${backup_dir})" ]; then
            find "${backup_dir}" -maxdepth 1 -type f | while read -r file; do
                limit=$(($(date +"%s") - 172800))
                updated_at=$(stat -f "%m" "$file")

                if [ -f "$file" ] && [ "$limit" -gt "$updated_at" ]; then
                    failed "IS_BACKUPUPTODATE" "$file has not been backed up"
                    test "${VERBOSE}" = 1 || break;
                fi
            done
        else
            failed "IS_BACKUPUPTODATE" "${backup_dir}/ is empty"
        fi
    else
        failed "IS_BACKUPUPTODATE" "${backup_dir}/ is missing"
    fi
}
check_gitperms() {
    GIT_DIR="/etc/.git"
    if test -d $GIT_DIR; then
        expected="40700"
        actual=$(stat -f "%p" $GIT_DIR)
        [ "$expected" = "$actual" ] || failed "IS_GITPERMS" "$GIT_DIR must be 700"
    fi
}
check_carpadvbase(){
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        bad_advbase=0
        for advbase in $(ifconfig carp | grep advbase | awk -F 'advbase' '{print $2}' | awk '{print $1}' | xargs); do
        if [ "$advbase" -gt 5 ]; then
            bad_advbase=1
        fi
        done
        if [ "$bad_advbase" -eq 1 ]; then
            failed "IS_CARPADVBASE" "At least one CARP interface has advbase greater than 5 seconds!"
        fi
    fi
}
check_carppreempt(){
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        preempt=$(sysctl net.inet.carp.preempt | cut -d"=" -f2)
        if [ "$preempt" -ne 1 ]; then
            failed "IS_CARPPREEMPT" "The preempt function is not activated! Please type 'sysctl net.inet.carp.preempt=1' in"
        fi
        if [ -f /etc/sysctl.conf ]; then
            grep -qE "^net.inet.carp.preempt=1" /etc/sysctl.conf || failed "IS_CARPPREEMPT" "The preempt parameter is not permanently activated! Please add 'net.inet.carp.preempt=1' in /etc/sysctl.conf"
        else
        failed "IS_CARPPREEMPT" "Make sure /etc/sysctl.conf exists and contains the line 'net.inet.carp.preempt=1'"
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
check_wheel(){
    if [ -f /etc/sudoers ]; then
        grep -qE "^%wheel.*$" /etc/sudoers || failed "IS_WHEEL" ""
    fi
}
check_pkgmirror(){
    grep -qE "^https?://ftp\.evolix\.org/openbsd/" /etc/installurl || failed "IS_PKGMIRROR" "Check whether the right repo is present in the /etc/installurl file"
}
check_history(){
    file=/root/.profile
    # shellcheck disable=SC2015
    grep -qE "^HISTFILE=\$HOME/.histfile" $file && grep -qE "^export HISTSIZE=100000" $file || failed "IS_HISTORY" "Make sure both 'HISTFILE=\$HOME/.histfile' and 'export HISTSIZE=100000' are present in /root/.profile"
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
    # shellcheck disable=SC2015
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
    grep -q "/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:/usr/share/scripts" /var/cron/tabs/root || failed "IS_CRONPATH" ""
}
check_tmp_1777(){
    actual=$(stat -f "%p" /tmp)
    expected="41777"
    test "$expected" = "$actual" || failed "IS_TMP_1777" "/tmp must be 1777"
}
check_root_0700(){
    actual=$(stat -f "%p" /root)
    expected="40700"
    test "$expected" = "$actual" || failed "IS_ROOT_0700" "/root must be 700"
}
check_usrsharescripts(){
    actual=$(stat -f "%p" /usr/share/scripts)
    expected="40700"
    test "$expected" = "$actual" || failed "IS_USRSHARESCRIPTS" "/usr/share/scripts must be 700"
}
check_sshpermitrootno() {
    if ! (sshd -T -C addr=,user=,host=,laddr=,lport=0,rdomain= 2> /dev/null | grep -qi 'permitrootlogin no'); then
       failed "IS_SSHPERMITROOTNO" "PermitRoot should be set to no"
    fi
}
check_evomaintenanceusers(){
    users=$(getent group evolinux-sudo | cut -d':' -f4 | tr ',' ' ')
    for user in $users; do
        user_home=$(getent passwd "$user" | cut -d: -f6)
        if [ -n "$user_home" ] && [ -d "$user_home" ]; then
            if ! grep -qs "^trap.*doas.*evomaintenance.sh" "${user_home}"/.*profile; then
                echo "IS_EVOMAINTENANCEUSERS" "${user} doesn't have an evomaintenance trap"
                test "${VERBOSE}" = 1 || break
            fi
        fi
    done
}
check_evomaintenanceconf(){
    f=/etc/evomaintenance.cf
    if [ -e "$f" ]; then
        perms=$(stat -f "%p" $f)
        test "$perms" = "100600" || echo "IS_EVOMAINTENANCECONF" "Wrong permissions on \`$f' ($perms instead of 100600)"

        { grep "^export PGPASSWORD" $f | grep -qv "your-passwd" \
            && grep "^PGDB" $f | grep -qv "your-db" \
            && grep "^PGTABLE" $f | grep -qv "your-table" \
            && grep "^PGHOST" $f | grep -qv "your-pg-host" \
            && grep "^FROM" $f | grep -qv "jdoe@example.com" \
            && grep "^FULLFROM" $f | grep -qv "John Doe <jdoe@example.com>" \
            && grep "^URGENCYFROM" $f | grep -qv "mama.doe@example.com" \
            && grep "^URGENCYTEL" $f | grep -qv "06.00.00.00.00" \
            && grep "^REALM" $f | grep -qv "example.com"
        } || echo "IS_EVOMAINTENANCECONF" "evomaintenance is not correctly configured"
    else
        echo "IS_EVOMAINTENANCECONF" "Configuration file \`$f' is missing"
    fi
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
    if grep -q "servers ntp.evolix.net" /etc/ntpd.conf; then
        if [ "$(wc -l /etc/ntpd.conf | awk '{print $1}')" -ne 1 ]; then
            failed "IS_NTP" "The /etc/ntpd.conf file should only contains \"servers ntp.evolix.net\"."
        fi
    else
        failed "IS_NTP" "The configuration in /etc/ntpd.conf is not compliant. It should contains \"servers ntp.evolix.net\"."
    fi
}
check_openvpncronlog(){
    if /etc/rc.d/openvpn check > /dev/null 2>&1; then
        # shellcheck disable=SC2016
        grep -q 'cp /var/log/openvpn.log /var/log/openvpn.log.$(date +\\%F) && echo "$(date +\\%F. .\\%R) - logfile turned over via cron" > /var/log/openvpn.log && gzip /var/log/openvpn.log.$(date +\\%F) && find /var/log/ -type f -name "openvpn.log.\*" -mtime .365 -exec rm {} \\+' /var/cron/tabs/root || failed "IS_OPENVPNCRONLOG" "OpenVPN is enabled but there is no log rotation in the root crontab, or the cron is not up to date (OpenVPN log rotation in newsyslog is not used because a restart is needed)."
    fi
}
check_carpadvskew(){
    if ls /etc/hostname.carp* 1> /dev/null 2>&1; then
        for carp in $(ifconfig carp | grep ^carp | awk '{print $1}' | tr -d ":"); do
            ifconfig "$carp" | grep -q master
            master=$?
            ifconfig "$carp" | grep -q backup
            backup=$?
            advskew=$(ifconfig "$carp" | grep advbase | awk -F 'advskew' '{print $2}' | awk '{print $1}')
            if [ "$master" -eq 0 ]; then
                if [ "$advskew" -lt 1 ] || [ "$advskew" -gt 50 ]; then
                    failed "IS_CARPADVSKEW" "Interface $carp is master : advskew must be between 1 and 50, and must remain lower than that of the backup - current value : $advskew"
                fi
            elif [ "$backup" -eq 0 ]; then
                if [ "$advskew" -lt 100 ] || [ "$advskew" -gt 150 ]; then
                    failed "IS_CARPADVSKEW" "Interface $carp is backup : advskew must be between 100 and 150, and must remain greater than that of the master - current value : $advskew"
                fi
            else
                failed "IS_CARPADVSKEW" "Interface $carp is neither master nor backup. Check interface state."
            fi
        done
    fi
}
check_nrpeopensmtpd() {
    grep -Rq "^command.*check_mailq.pl -M opensmtpd" /etc/nrpe.* || failed "IS_NRPE_OPENSMTPD" "NRPE \"check_mailq\" is not configured for opensmtpd."
}
check_sshallowusers() {
    grep -E -qir "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config || failed "IS_SSHALLOWUSERS" "Missing AllowUsers or AllowGroups directive in sshd_config"
}
check_evobackup_exclude_mount() {
    excludes_file=$(mktemp)
    files_to_cleanup="${files_to_cleanup} ${excludes_file}"

    # shellcheck disable=SC2013
    for evobackup_file in $(grep -Eo "/usr/share/scripts/zzz_evobackup.*" /etc/daily.local | grep -v "^#" | awk '{print $1}'); do
        # if the file seems to be a backup script, with an Rsync invocation
        if grep -q "^\s*rsync" "${evobackup_file}"; then
            # If rsync is not limited by "one-file-system"
            # then we verify that every mount is excluded
            if ! grep -q -- "^\s*--one-file-system" "${evobackup_file}"; then
                grep -- "--exclude " "${evobackup_file}" | grep -E -o "\"[^\"]+\"" | tr -d '"' > "${excludes_file}"
                not_excluded=$(findmnt --type nfs,nfs4,fuse.sshfs, -o target --noheadings | grep -v -f "${excludes_file}")
                for mount in ${not_excluded}; do
                    failed "IS_EVOBACKUP_EXCLUDE_MOUNT" "${mount} is not excluded from ${evobackup_file} backup script"
                done
            fi
        fi
    done
    rm -rf "${excludes_file}"
}
check_etcgit() {
    export GIT_DIR="/etc/.git" GIT_WORK_TREE="/etc"
    git rev-parse --is-inside-work-tree > /dev/null 2>&1 || failed "IS_ETCGIT" "/etc is not a git repository"
}
check_evolinuxsudogroup() {
    if grep -q "^evolinux-sudo:" /etc/group; then
        grep -qE "^%evolinux-sudo ALL ?= ?\(ALL\) SETENV: ALL" /etc/sudoers || failed "IS_EVOLINUXSUDOGROUP" "Missing evolinux-sudo directive in sudoers file"
    fi
}
check_bind9munin() {
    if is_installed isc-bind; then
        { test -L /etc/munin/plugins/bind9 \
            && test -e /etc/munin/plugin-conf.d/bind9;
        } || failed "IS_BIND9MUNIN" "missing bind plugin for munin"
    fi
}
check_evolix_user() {
    grep -q -E "^evolix:" /etc/passwd && failed "IS_EVOLIX_USER" "evolix user should not exist"
}
download_versions() {
    # shellcheck disable=SC2039
    local file
    file=${1:-}

    ## The file is supposed to list programs : each on a line, then its latest version number
    ## Examples:
    # evoacme 21.06
    # evomaintenance 0.6.4

    versions_url="https://upgrades.evolix.org/versions-openbsd"

    # fetch timeout, in seconds
    timeout=10

    if command -v curl > /dev/null; then
        curl -k --max-time ${timeout} --fail --silent --output "${versions_file}" "${versions_url}"
        # "-k" required until OpenBSD 6.8
    elif command -v wget > /dev/null; then
        wget --timeout=${timeout} --quiet "${versions_url}" -O "${versions_file}"
    elif command -v GET; then
        GET -t ${timeout}s "${versions_url}" > "${versions_file}"
    else
        failed "IS_CHECK_VERSIONS" "failed to find curl, wget or GET"
    fi
    test "$?" -eq 0 || failed "IS_CHECK_VERSIONS" "failed to download ${versions_url} to ${versions_file}"
}
get_command() {
    # shellcheck disable=SC2039
    local program
    program=${1:-}

    case "${program}" in
        ## Special cases where the program name is different than the command name
        evocheck) echo "${0}" ;;
        evomaintenance) command -v "evomaintenance.sh" ;;
        motd-carp-state) command -v "motd-carp-state.sh" ;;
        
        ## General case, where the program name is the same as the command name
        *) command -v "${program}" ;;
    esac
}
get_version() {
    # shellcheck disable=SC2039
    local program
    # shellcheck disable=SC2039
    local command
    program=${1:-}
    command=${2:-}

    case "${program}" in
        ## Special case if `command --version => 'command` is not the standard way to get the version
        # my_command)
        #    /path/to/my_command --get-version 
        #    ;;

        motd-carp-state)
            grep '^VERSION=' "${command}" | head -1 | cut -d '=' -f 2
            ;;
        ## General case to get the version
        *) ${command} --version 2> /dev/null | head -1 | cut -d ' ' -f 3 ;;
    esac
}
get_lower_version() {
    # shellcheck disable=SC2039
    local actual_version
    # shellcheck disable=SC2039
    local expected_version
    actual_version=${1:-}
    expected_version=${2:-}

    printf "%s\n%s" "${actual_version}" "${expected_version}" | sort -V | head -n 1
}
check_version() {
    # shellcheck disable=SC2039
    local program
    # shellcheck disable=SC2039
    local expected_version
    program=${1:-}
    expected_version=${2:-}

    command=$(get_command "${program}")
    if [ -n "${command}" ]; then
        actual_version=$(get_version "${program}" "${command}")
        # printf "program:%s expected:%s actual:%s\n" "${program}" "${expected_version}" "${actual_version}"
        if [ -z "${actual_version}" ]; then
            failed "IS_CHECK_VERSIONS" "failed to lookup actual version of ${program}"
        elif [ "${actual_version}" = "${expected_version}" ]; then
            : # Version check OK ; to check first because of the way the check works
        elif [ "$(get_lower_version "${actual_version}" "${expected_version}")" = "${actual_version}" ]; then
            failed "IS_CHECK_VERSIONS" "${program} version ${actual_version} is older than expected version ${expected_version}"
        elif [ "$(get_lower_version "${actual_version}" "${expected_version}")" = "${expected_version}" ]; then
            failed "IS_CHECK_VERSIONS" "${program} version ${actual_version} is newer than expected version ${expected_version}, you should update your index."
        fi
    fi
}
add_to_path() {
    # shellcheck disable=SC2039
    local new_path
    new_path=${1:-}

    echo "$PATH" | grep -qF "${new_path}" || export PATH="${PATH}:${new_path}"
}
check_versions() {
    versions_file=$(mktemp -p /tmp "evocheck-versions.XXXXXXXX")
    files_to_cleanup="${files_to_cleanup} ${versions_file}"

    download_versions "${versions_file}"
    add_to_path "/usr/share/scripts"

    grep -v '^ *#' < "${versions_file}" | while IFS= read -r line; do
        # shellcheck disable=SC2039
        local program
        # shellcheck disable=SC2039
        local version
        program=$(echo "${line}" | cut -d ' ' -f 1)
        version=$(echo "${line}" | cut -d ' ' -f 2)

        if [ -n "${program}" ]; then
            if [ -n "${version}" ]; then
                check_version "${program}" "${version}"
            else
                failed "IS_CHECK_VERSIONS" "failed to lookup expected version for ${program}"
            fi
        fi
    done

    rm -f "${versions_file}"
}
check_root_user() {
    if [ "$(grep "^root:" /etc/master.passwd | awk -F":" '{print $2}')" != "*************" ]; then
        failed "IS_ROOT_USER" "root user should not have a password ; replace the password field with 'vipw' for the root user with '*************' (exactly 13 asterisks) "
    fi
}

main() {
    # Default return code : 0 = no error
    RC=0

    test "${IS_UMASKSUDOERS:=1}" = 1 && check_umasksudoers
    test "${IS_TMPNOEXEC:=1}" = 1 && check_tmpnoexec
    test "${IS_SOFTDEP:=1}" = 1 && check_softdep
    test "${IS_NOATIME:=1}" = 1 && check_noatime
    test "${IS_TMOUTPROFILE:=1}" = 1 && check_tmoutprofile
    test "${IS_RAIDOK:=1}" = 1 && check_raidok
    test "${IS_EVOBACKUP:=1}" = 1 && check_evobackup
    test "${IS_UPTODATE:=1}" = 1 && check_uptodate
    test "${IS_UPTIME:=1}" = 1 && check_uptime
    test "${IS_BACKUPUPTODATE:=1}" = 1 && check_backupuptodate
    test "${IS_GITPERMS:=1}" = 1 && check_gitperms
    test "${IS_CARPADVBASE:=1}" = 1 && check_carpadvbase
    test "${IS_CARPPREEMPT:=1}" = 1 && check_carppreempt
    test "${IS_REBOOTMAIL:=1}" = 1 && check_rebootmail
    test "${IS_PFENABLED:=1}" = 1 && check_pfenabled
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
    test "${IS_TMP_1777:=1}" = 1 && check_tmp_1777
    test "${IS_ROOT_0700:=1}" = 1 && check_root_0700
    test "${IS_USRSHARESCRIPTS:=1}" = 1 && check_usrsharescripts
    test "${IS_SSHPERMITROOTNO:=1}" = 1 && check_sshpermitrootno
    test "${IS_EVOMAINTENANCEUSERS:=1}" = 1 && check_evomaintenanceusers
    test "${IS_EVOMAINTENANCECONF:=1}" = 1 && check_evomaintenanceconf
    test "${IS_SYNC:=1}" = 1 && check_sync
    test "${IS_DEFAULTROUTE:=1}" = 1 && check_defaultroute
    test "${IS_NTP:=1}" = 1 && check_ntp
    test "${IS_OPENVPNCRONLOG:=1}" = 1 && check_openvpncronlog
    test "${IS_CARPADVSKEW:=1}" = 1 && check_carpadvskew
    test "${IS_NRPE_OPENSMTPD:=1}" = 1 && check_nrpeopensmtpd
    test "${IS_SSHALLOWUSERS:=1}" = 1 && check_sshallowusers
    test "${IS_EVOBACKUP_EXCLUDE_MOUNT:=1}" = 1 && check_evobackup_exclude_mount
    test "${IS_ETCGIT:=1}" = 1 && check_etcgit
    test "${IS_EVOLINUXSUDOGROUP:=1}" = 1 && check_evolinuxsudogroup
    test "${IS_BIND9MUNIN:=1}" = 1 && check_bind9munin
    test "${IS_EVOLIX_USER:=1}" = 1 && check_evolix_user
    test "${IS_CHECK_VERSIONS:=1}" = 1 && check_versions
    test "${IS_ROOT_USER:=1}" = 1 && check_root_user

    exit ${RC}
}
cleanup_temp_files() {
    # shellcheck disable=SC2086
    rm -f ${files_to_cleanup}
}

# Disable LANG*
export LANG=C
export LANGUAGE=C

files_to_cleanup=""
trap cleanup_temp_files 0

# Source configuration file
# shellcheck disable=SC1091
test -f /etc/evocheck.cf && . /etc/evocheck.cf

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
            IS_UPTIME=0
            IS_CHECK_VERSIONS=0
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

# shellcheck disable=SC2086
main ${ARGS}
