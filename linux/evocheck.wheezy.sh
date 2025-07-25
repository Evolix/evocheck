#!/bin/bash

# EvoCheck
# Script to verify compliance of a Linux (Debian 7 only) server
# powered by Evolix

VERSION="25.07"
readonly VERSION

# base functions

show_version() {
    cat <<END
evocheck version ${VERSION} (Wheezy)

Copyright 2009-2025 Evolix <info@evolix.fr>,
                    Romain Dessort <rdessort@evolix.fr>,
                    Benoit Série <bserie@evolix.fr>,
                    Gregory Colpart <reg@evolix.fr>,
                    Jérémy Lecour <jlecour@evolix.fr>,
                    Tristan Pilat <tpilat@evolix.fr>,
                    Victor Laborie <vlaborie@evolix.fr>,
                    Alexis Ben Miloud--Josselin <abenmiloud@evolix.fr>,
                    and others.

evocheck comes with ABSOLUTELY NO WARRANTY.  This is free software,
and you are welcome to redistribute it under certain conditions.
See the GNU General Public License v3.0 for details.
END
}
show_help() {
    cat <<END
evocheck is a script that verifies Evolix conventions on Linux (Debian) servers.

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

detect_os() {
    # OS detection
    DEBIAN_RELEASE=""
    LSB_RELEASE_BIN=$(command -v lsb_release)

    if [ -e /etc/debian_version ]; then
        DEBIAN_MAIN_VERSION=$(cut -d "." -f 1 < /etc/debian_version)

        if [ "${DEBIAN_MAIN_VERSION}" -ne "7" ]; then
            echo "Debian ${DEBIAN_MAIN_VERSION} is incompatible with this version of evocheck." >&2 
            echo "This version is built for Debian 7 only." >&2
            exit
        fi

        if [ -x "${LSB_RELEASE_BIN}" ]; then
            DEBIAN_RELEASE=$(${LSB_RELEASE_BIN} --codename --short)
        else
            case ${DEBIAN_MAIN_VERSION} in
                5) DEBIAN_RELEASE="lenny";;
                6) DEBIAN_RELEASE="squeeze";;
                7) DEBIAN_RELEASE="wheezy";;
            esac
        fi
    fi
}

is_debian_lenny() {
    test "${DEBIAN_RELEASE}" = "lenny"
}
is_debian_squeeze() {
    test "${DEBIAN_RELEASE}" = "squeeze"
}
is_debian_wheezy() {
    test "${DEBIAN_RELEASE}" = "wheezy"
}

is_pack_web(){
    test -e /usr/share/scripts/web-add.sh || test -e /usr/share/scripts/evoadmin/web-add.sh
}
is_pack_samba(){
    test -e /usr/share/scripts/add.pl
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
            printf "%s FAILED! %s\n" "${check_name}" "${check_comments}" >> "${main_output_file}"
        else
            printf "%s FAILED!\n" "${check_name}" >> "${main_output_file}"
        fi
    fi
}

# check functions

check_lsbrelease(){
    if [ -x "${LSB_RELEASE_BIN}" ]; then
        ## only the major version matters
        lhs=$(${LSB_RELEASE_BIN} --release --short | cut -d "." -f 1)
        rhs=$(cut -d "." -f 1 < /etc/debian_version)
        test "$lhs" = "$rhs" || failed "IS_LSBRELEASE" "release is not consistent between lsb_release (${lhs}) and /etc/debian_version (${rhs})"
    else
        failed "IS_LSBRELEASE" "lsb_release is missing or not executable"
    fi
}
check_dpkgwarning() {
    if [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ]; then
        test -e /etc/apt/apt.conf.d/80evolinux \
            || failed "IS_DPKGWARNING" "/etc/apt/apt.conf.d/80evolinux is missing"
        test -e /etc/apt/apt.conf \
            && failed "IS_DPKGWARNING" "/etc/apt/apt.conf is missing"
    fi
}
# Verifying check_mailq in Nagios NRPE config file. (Option "-M postfix" need to be set if the MTA is Postfix)
check_nrpepostfix() {
    if is_installed postfix; then
        { test -e /etc/nagios/nrpe.cfg \
            && grep -qr "^command.*check_mailq -M postfix" /etc/nagios/nrpe.*;
        } || failed "IS_NRPEPOSTFIX" "NRPE \"check_mailq\" for postfix is missing"
    fi
}
# Check if mod-security config file is present
check_modsecurity() {
    if is_installed libapache2-modsecurity; then
        test -e /etc/apache2/conf.d/mod-security2.conf || failed "IS_MODSECURITY" "missing configuration file"
    fi
}
check_customsudoers() {
    grep -E -qr "umask=0077" /etc/sudoers* || failed "IS_CUSTOMSUDOERS" "missing umask=0077 in sudoers file"
}
check_vartmpfs() {
    FINDMNT_BIN=$(command -v findmnt)
    if [ -x "${FINDMNT_BIN}" ]; then
        ${FINDMNT_BIN} /var/tmp --type tmpfs --noheadings > /dev/null || failed "IS_VARTMPFS" "/var/tmp is not a tmpfs"
    else
        df /var/tmp | grep -q tmpfs || failed "IS_VARTMPFS" "/var/tmp is not a tmpfs"
    fi
}
check_serveurbase() {
    is_installed serveur-base || failed "IS_SERVEURBASE" "serveur-base package is not installed"
}
check_logrotateconf() {
    test -e /etc/logrotate.d/zsyslog || failed "IS_LOGROTATECONF" "missing zsyslog in logrotate.d"
}
check_syslogconf() {
    grep -q "^# Syslog for Pack Evolix serveur" /etc/*syslog.conf \
        || failed "IS_SYSLOGCONF" "syslog evolix config file missing"
}
check_debiansecurity() {
    # Look for enabled "Debian-Security" sources from the "Debian" origin
    apt-cache policy | grep "\bl=Debian-Security\b" | grep "\bo=Debian\b" | grep --quiet "\bc=main\b"
    test $? -eq 0 || failed "IS_DEBIANSECURITY" "missing Debian-Security repository"
}
check_aptitudeonly() {
    test -e /usr/bin/apt-get && failed "IS_APTITUDEONLY" \
        "only aptitude may be enabled on Debian <=7, apt-get should be disabled"
}

check_apticron() {
    status="OK"
    test -e /etc/cron.d/apticron || status="fail"
    test -e /etc/cron.daily/apticron && status="fail"
    test "$status" = "fail" || test -e /usr/bin/apt-get.bak || status="fail"

    test "$status" = "fail" && failed "IS_APTICRON" "apticron must be in cron.d not cron.daily"
}
check_usrro() {
    grep /usr /etc/fstab | grep -qE "\bro\b" || failed "IS_USRRO" "missing ro directive on fstab for /usr"
}
check_tmpnoexec() {
    FINDMNT_BIN=$(command -v findmnt)
    if [ -x "${FINDMNT_BIN}" ]; then
        options=$(${FINDMNT_BIN} --noheadings --first-only --output OPTIONS /tmp)
        echo "${options}" | grep -qE "\bnoexec\b" || failed "IS_TMPNOEXEC" "/tmp is not mounted with 'noexec'"
    else
        mount | grep "on /tmp" | grep -qE "\bnoexec\b" || failed "IS_TMPNOEXEC" "/tmp is not mounted with 'noexec' (WARNING: findmnt(8) is not found)"
    fi
}
check_mountfstab() {
    # Test if lsblk available, if not skip this test...
    LSBLK_BIN=$(command -v lsblk)
    if test -x "${LSBLK_BIN}"; then
        for mountPoint in $(${LSBLK_BIN} -o MOUNTPOINT -l -n | grep '/'); do
            grep -Eq "$mountPoint\W" /etc/fstab \
                || failed "IS_MOUNT_FSTAB" "partition(s) detected mounted but no presence in fstab"
        done
    fi
}
check_listchangesconf() {
    if [ -e "/etc/apt/listchanges.conf" ]; then
        lines=$(grep -cE "(which=both|confirm=1)" /etc/apt/listchanges.conf)
        if [ "$lines" != 2 ]; then
            failed "IS_LISTCHANGESCONF" "apt-listchanges config is incorrect"
        fi
    else
        failed "IS_LISTCHANGESCONF" "apt-listchanges config is missing"
    fi
}
check_customcrontab() {
    found_lines=$(grep -c -E "^(17 \*|25 6|47 6|52 6)" /etc/crontab)
    test "$found_lines" = 4 && failed "IS_CUSTOMCRONTAB" "missing custom field in crontab"
}
check_sshallowusers() {
    grep -E -qir "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d \
        || failed "IS_SSHALLOWUSERS" "missing AllowUsers or AllowGroups directive in sshd_config"
}
check_diskperf() {
    perfFile="/root/disk-perf.txt"
    test -e $perfFile || failed "IS_DISKPERF" "missing ${perfFile}"
}
check_tmoutprofile() {
    grep -sq "TMOUT=" /etc/profile /etc/profile.d/evolinux.sh || failed "IS_TMOUTPROFILE" "TMOUT is not set"
}
check_alert5boot() {
    if [ -n "$(find /etc/rc2.d/ -name 'S*alert5')" ]; then
        grep -q "^date" /etc/rc2.d/S*alert5 || failed "IS_ALERT5BOOT" "boot mail is not sent by alert5 init script"
    elif [ -n "$(find /etc/init.d/ -name 'alert5')" ]; then
        grep -q "^date" /etc/init.d/alert5 || failed "IS_ALERT5BOOT" "boot mail is not sent by alert5 int script"
    else
        failed "IS_ALERT5BOOT" "alert5 init script is missing"
    fi
}
check_alert5minifw() {
    if [ -n "$(find /etc/rc2.d/ -name 'S*alert5')" ]; then
        grep -q "^/etc/init.d/minifirewall" /etc/rc2.d/S*alert5 \
            || failed "IS_ALERT5MINIFW" "Minifirewall is not started by alert5 init script"
    elif [ -n "$(find /etc/init.d/ -name 'alert5')" ]; then
        grep -q "^/etc/init.d/minifirewall" /etc/init.d/alert5 \
            || failed "IS_ALERT5MINIFW" "Minifirewall is not started by alert5 init script"
    else
        failed "IS_ALERT5MINIFW" "alert5 init script is missing"
    fi
}
check_minifw() {
    /sbin/iptables -L -n | grep -q -E "^ACCEPT\s*all\s*--\s*31\.170\.8\.4\s*0\.0\.0\.0/0\s*$" \
        || failed "IS_MINIFW" "minifirewall seems not started"
}
check_nrpeperms() {
    if [ -d /etc/nagios ]; then
        nagiosDir="/etc/nagios"
        actual=$(stat --format "%a" $nagiosDir)
        expected="750"
        test "$expected" = "$actual" || failed "IS_NRPEPERMS" "${nagiosDir} must be ${expected}"
    fi
}
check_minifwperms() {
    if [ -f "/etc/firewall.rc" ]; then
        actual=$(stat --format "%a" "/etc/firewall.rc")
        expected="600"
        test "$expected" = "$actual" || failed "IS_MINIFWPERMS" "/etc/firewall.rc must be ${expected}"
    fi
}
check_nrpedisks() {
    NRPEDISKS=$(grep command.check_disk /etc/nagios/nrpe.cfg | grep "^command.check_disk[0-9]" | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
    DFDISKS=$(df -Pl | grep -c -E -v "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)")
    test "$NRPEDISKS" = "$DFDISKS" || failed "IS_NRPEDISKS" "there must be $DFDISKS check_disk in nrpe.cfg"
}
check_nrpepid() {
    { test -e /etc/nagios/nrpe.cfg \
        && grep -q "^pid_file=/var/run/nagios/nrpe.pid" /etc/nagios/nrpe.cfg;
    } || failed "IS_NRPEPID" "missing or wrong pid_file directive in nrpe.cfg"
}
check_grsecprocs() {
    if uname -a | grep -q grsec; then
        { grep -q "^command.check_total_procs..sudo" /etc/nagios/nrpe.cfg \
            && grep -A1 "^\[processes\]" /etc/munin/plugin-conf.d/munin-node | grep -q "^user root";
        } || failed "IS_GRSECPROCS" "missing munin's plugin processes directive for grsec"
    fi
}
check_apachemunin() {
    if test -e /etc/apache2/apache2.conf; then
        pattern="/server-status-[[:alnum:]]{4,}"
        { grep -r -q -s -E "^env.url.*${pattern}" /etc/munin/plugin-conf.d \
            && { grep -q -s -E "${pattern}" /etc/apache2/apache2.conf \
                || grep -q -s -E "${pattern}" /etc/apache2/mods-enabled/status.conf;
            };
        } || failed "IS_APACHEMUNIN" "server status is not properly configured"
    fi
}
# Verification mytop + Munin si MySQL
check_mysqlutils() {
    MYSQL_ADMIN=${MYSQL_ADMIN:-mysqladmin}
    if is_installed mysql-server; then
        # You can configure MYSQL_ADMIN in evocheck.cf
        if ! grep -qs "^user *= *${MYSQL_ADMIN}" /root/.my.cnf; then
            failed "IS_MYSQLUTILS" "${MYSQL_ADMIN} missing in /root/.my.cnf"
        fi
        if ! test -x /usr/bin/mytop; then
            if ! test -x /usr/local/bin/mytop; then
                failed "IS_MYSQLUTILS" "mytop binary missing"
            fi
        fi
        if ! grep -qs '^user *=' /root/.mytop; then
            failed "IS_MYSQLUTILS" "credentials missing in /root/.mytop"
        fi
    fi
}
# Verification de la configuration du raid soft (mdadm)
check_raidsoft() {
    if test -e /proc/mdstat && grep -q md /proc/mdstat; then
        { grep -q "^AUTOCHECK=true" /etc/default/mdadm \
            && grep -q "^START_DAEMON=true" /etc/default/mdadm \
            && grep -qv "^MAILADDR ___MAIL___" /etc/mdadm/mdadm.conf;
        } || failed "IS_RAIDSOFT" "missing or wrong config for mdadm"
    fi
}
# Verification du LogFormat de AWStats
check_awstatslogformat() {
    if is_installed apache2 awstats; then
        awstatsFile="/etc/awstats/awstats.conf.local"
        grep -qE '^LogFormat=1' $awstatsFile \
            || failed "IS_AWSTATSLOGFORMAT" "missing or wrong LogFormat directive in $awstatsFile"
    fi
}
# Verification de la présence de la config logrotate pour Munin
check_muninlogrotate() {
    { test -e /etc/logrotate.d/munin-node \
        && test -e /etc/logrotate.d/munin;
    } || failed "IS_MUNINLOGROTATE" "missing lorotate file for munin"
}
# Verification de l'activation de Squid dans le cas d'un pack mail
check_squid() {
    squidconffile="/etc/squid*/squid.conf"
    if is_pack_web && (is_installed squid || is_installed squid3); then
        host=$(hostname -i)
        # shellcheck disable=SC2086
        http_port=$(grep -E "^http_port\s+[0-9]+" $squidconffile | awk '{ print $2 }')
        { grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT" "/etc/firewall.rc" \
            && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d $host -j ACCEPT" "/etc/firewall.rc" \
            && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d 127.0.0.(1|0/8) -j ACCEPT" "/etc/firewall.rc" \
            && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port.* $http_port" "/etc/firewall.rc";
        } || grep -qE "^PROXY='?on'?" "/etc/firewall.rc" \
          || failed "IS_SQUID" "missing squid rules in minifirewall"
    fi
}
check_evomaintenance_fw() {
    if [ -f "/etc/firewall.rc" ]; then
        hook_db=$(grep -E '^\s*HOOK_DB' /etc/evomaintenance.cf | tr -d ' ' | cut -d= -f2)
        rulesNumber=$(grep -c "/sbin/iptables -A INPUT -p tcp --sport 5432 --dport 1024:65535 -s .* -m state --state ESTABLISHED,RELATED -j ACCEPT" "/etc/firewall.rc")
        if [ "$hook_db" = "1" ] && [ "$rulesNumber" -lt 2 ]; then
            failed "IS_EVOMAINTENANCE_FW" "HOOK_DB is enabled but missing evomaintenance rules in minifirewall"
        fi
    fi
}
# Verification de la conf et de l'activation de mod-deflate
check_moddeflate() {
    f=/etc/apache2/mods-enabled/deflate.conf
    if is_installed apache2.2; then
        { test -e $f && grep -q "AddOutputFilterByType DEFLATE text/html text/plain text/xml" $f \
            && grep -q "AddOutputFilterByType DEFLATE text/css" $f \
            && grep -q "AddOutputFilterByType DEFLATE application/x-javascript application/javascript" $f;
        } || failed "IS_MODDEFLATE" "missing AddOutputFilterByType directive for apache mod deflate"
    fi
}
# Verification de la conf log2mail
check_log2mailrunning() {
    if is_pack_web && is_installed log2mail; then
        pgrep log2mail >/dev/null || failed "IS_LOG2MAILRUNNING" "log2mail is not running"
    fi
}
check_log2mailapache() {
    conf=/etc/log2mail/config/default
    if is_pack_web && is_installed log2mail; then
        grep -s -q "^file = /var/log/apache2/error.log" $conf \
            || failed "IS_LOG2MAILAPACHE" "missing log2mail directive for apache"
    fi
}
check_log2mailmysql() {
    if is_pack_web && is_installed log2mail; then
        grep -s -q "^file = /var/log/syslog" /etc/log2mail/config/{default,mysql,mysql.conf} \
            || failed "IS_LOG2MAILMYSQL" "missing log2mail directive for mysql"
    fi
}
check_log2mailsquid() {
    if is_pack_web && is_installed log2mail; then
        grep -s -q "^file = /var/log/squid.*/access.log" /etc/log2mail/config/* \
            || failed "IS_LOG2MAILSQUID" "missing log2mail directive for squid"
    fi
}
# Verification si bind est chroote
check_bindchroot() {
    if is_installed bind9; then
        if netstat -utpln | grep "/named" | grep :53 | grep -qvE "(127.0.0.1|::1)"; then
            if grep -q '^OPTIONS=".*-t' /etc/default/bind9 && grep -q '^OPTIONS=".*-u' /etc/default/bind9; then
                md5_original=$(md5sum /usr/sbin/named | cut -f 1 -d ' ')
                md5_chrooted=$(md5sum /var/chroot-bind/usr/sbin/named | cut -f 1 -d ' ')
                if [ "$md5_original" != "$md5_chrooted" ]; then
                    failed "IS_BINDCHROOT" "the chrooted bind binary is different than the original binary"
                fi
            else
                failed "IS_BINDCHROOT" "bind process is not chrooted"
            fi
        fi
    fi
}
# /etc/network/interfaces should be present, we don't manage systemd-network yet
check_network_interfaces() {
    if ! test -f /etc/network/interfaces; then
        IS_AUTOIF=0
        IS_INTERFACESGW=0
        IS_INTERFACESNETMASK=0
        failed "IS_NETWORK_INTERFACES" "systemd network configuration is not supported yet"
    fi
}
# Verify if all if are in auto
check_autoif() {
    interfaces=$(/sbin/ifconfig -s | tail -n +2 | grep -E -v "^(lo|vnet|docker|veth|tun|tap|macvtap|vrrp)" | cut -d " " -f 1 |tr "\n" " ")
    for interface in $interfaces; do
        if grep -Rq "^iface $interface" /etc/network/interfaces* && ! grep -Rq "^auto $interface" /etc/network/interfaces*; then
            failed "IS_AUTOIF" "Network interface \`${interface}' is statically defined but not set to auto"
            test "${VERBOSE}" = 1 || break
        fi
    done
}
# Network conf verification
check_interfacesgw() {
    number=$(grep -Ec "^[^#]*gateway [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" /etc/network/interfaces)
    test "$number" -gt 1 && failed "IS_INTERFACESGW" "there is more than 1 IPv4 gateway"
    number=$(grep -Ec "^[^#]*gateway [0-9a-fA-F]+:" /etc/network/interfaces)
    test "$number" -gt 1 && failed "IS_INTERFACESGW" "there is more than 1 IPv6 gateway"
}
check_interfacesnetmask() {
    addresses_number=$(grep "address" /etc/network/interfaces | grep -cv -e "hwaddress" -e "#")
    symbol_netmask_number=$(grep address /etc/network/interfaces | grep -v "#" | grep -c "/")
    text_netmask_number=$(grep "netmask" /etc/network/interfaces | grep -cv -e "#" -e "route add" -e "route del")
    if [ "$((symbol_netmask_number + text_netmask_number))" -ne "$addresses_number" ]; then
        failed "IS_INTERFACESNETMASK" "the number of addresses configured is not equal to the number of netmask configured : one netmask is missing or duplicated"
    fi
}
# Verification de la mise en place d'evobackup
check_evobackup() {
    evobackup_found=$(find /etc/cron* -name '*evobackup*' | wc -l)
    test "$evobackup_found" -gt 0 || failed "IS_EVOBACKUP" "missing evobackup cron"
}
# Vérification de l'exclusion des montages (NFS) dans les sauvegardes
check_evobackup_exclude_mount() {
    excludes_file=$(mktemp --tmpdir="${TMPDIR:-/tmp}" "evocheck.evobackup_exclude_mount.XXXXX")
    files_to_cleanup="${files_to_cleanup} ${excludes_file}"

    # shellcheck disable=SC2044
    for evobackup_file in $(find /etc/cron* -name '*evobackup*' | grep -v -E ".disabled$"); do
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
}
# Verification de la presence du userlogrotate
check_userlogrotate() {
    if is_pack_web; then
        test -x /etc/cron.weekly/userlogrotate || failed "IS_USERLOGROTATE" "missing userlogrotate cron"
    fi
}
# Verification de la syntaxe de la conf d'Apache
check_apachectl() {
    if is_installed apache2; then
        /usr/sbin/apache2ctl configtest 2>&1 | grep -q "^Syntax OK$" \
            || failed "IS_APACHECTL" "apache errors detected, run a configtest"
    fi
}
# Check if there is regular files in Apache sites-enabled.
check_apachesymlink() {
    if is_installed apache2; then
        apacheFind=$(find /etc/apache2/sites-enabled ! -type l -type f -print)
        nbApacheFind=$(wc -m <<< "$apacheFind")
        if [[ $nbApacheFind -gt 1 ]]; then
            if [[ $VERBOSE == 1 ]]; then
                while read -r line; do
                    failed "IS_APACHESYMLINK" "Not a symlink: $line"
                done <<< "$apacheFind"
            else
                failed "IS_APACHESYMLINK"
            fi
        fi
    fi
}
# Check if there is real IP addresses in Allow/Deny directives (no trailing space, inline comments or so).
check_apacheipinallow() {
    # Note: Replace "exit 1" by "print" in Perl code to debug it.
    if is_installed apache2; then
        grep -IrE "^[^#] *(Allow|Deny) from" /etc/apache2/ \
            | grep -iv "from all" \
            | grep -iv "env=" \
            | perl -ne 'exit 1 unless (/from( [\da-f:.\/]+)+$/i)' \
            || failed "IS_APACHEIPINALLOW" "bad (Allow|Deny) directives in apache"
    fi
}
# Check if default Apache configuration file for munin is absent (or empty or commented).
check_muninapacheconf() {
    muninconf="/etc/apache2/conf.d/munin"
    if is_installed apache2; then
        test -e $muninconf && grep -vEq "^( |\t)*#" "$muninconf" \
            && failed "IS_MUNINAPACHECONF" "default munin configuration may be commented or disabled"
    fi
}
# Check if default Apache configuration file for phpMyAdmin is absent (or empty or commented).
check_phpmyadminapacheconf() {
    phpmyadminconf0="/etc/apache2/conf-available/phpmyadmin.conf"
    phpmyadminconf1="/etc/apache2/conf-enabled/phpmyadmin.conf"
    if is_installed apache2; then
        test -e $phpmyadminconf0 && grep -vEq "^( |\t)*#" "$phpmyadminconf0" \
            && failed "IS_PHPMYADMINAPACHECONF" "default phpmyadmin configuration ($phpmyadminconf0) may be commented or disabled"
        test -e $phpmyadminconf1 && grep -vEq "^( |\t)*#" "$phpmyadminconf1" \
            && failed "IS_PHPMYADMINAPACHECONF" "default phpmyadmin configuration ($phpmyadminconf1) may be commented or disabled"
    fi
}
# Verification si le système doit redémarrer suite màj kernel.
check_kerneluptodate() {
    if is_installed linux-image*; then
        # shellcheck disable=SC2012
        kernel_installed_at=$(date -d "$(ls --full-time -lcrt /boot/*lin* | tail -n1 | awk '{print $6}')" +%s)
        last_reboot_at=$(($(date +%s) - $(cut -f1 -d '.' /proc/uptime)))
        if [ "$kernel_installed_at" -gt "$last_reboot_at" ]; then
            failed "IS_KERNELUPTODATE" "machine is running an outdated kernel, reboot advised"
        fi
    fi
}
# Check if the server is running for more than a year.
check_uptime() {
    if is_installed linux-image*; then
        limit=$(date -d "now - 2 year" +%s)
        last_reboot_at=$(($(date +%s) - $(cut -f1 -d '.' /proc/uptime)))
        if [ "$limit" -gt "$last_reboot_at" ]; then
            failed "IS_UPTIME" "machine has an uptime of more than 2 years, reboot on new kernel advised"
        fi
    fi
}
# Check if munin-node running and RRD files are up to date.
check_muninrunning() {
    if ! pgrep munin-node >/dev/null; then
        failed "IS_MUNINRUNNING" "Munin is not running"
    elif [ -d "/var/lib/munin/" ] && [ -d "/var/cache/munin/" ]; then
        limit=$(date +"%s" -d "now - 10 minutes")

        if [ -n "$(find /var/lib/munin/ -name '*load-g.rrd')" ]; then
            updated_at=$(stat -c "%Y" /var/lib/munin/*/*load-g.rrd |sort |tail -1)
            [ "$limit" -gt "$updated_at" ] && failed "IS_MUNINRUNNING" "Munin load RRD has not been updated in the last 10 minutes"
        else
            failed "IS_MUNINRUNNING" "Munin is not installed properly (load RRD not found)"
        fi

        if [ -n "$(find  /var/cache/munin/www/ -name 'load-day.png')" ]; then
            updated_at=$(stat -c "%Y" /var/cache/munin/www/*/*/load-day.png |sort |tail -1)
            grep -sq "^graph_strategy cron" /etc/munin/munin.conf && [ "$limit" -gt "$updated_at" ] && failed "IS_MUNINRUNNING" "Munin load PNG has not been updated in the last 10 minutes"
        else
            failed "IS_MUNINRUNNING" "Munin is not installed properly (load PNG not found)"
        fi
    else
        failed "IS_MUNINRUNNING" "Munin is not installed properly (main directories are missing)"
    fi
}
# Check if files in /home/backup/ are up-to-date
check_backupuptodate() {
    backup_dir="/home/backup"
    if [ -d "${backup_dir}" ]; then
        if [ -n "$(ls -A ${backup_dir})" ]; then
            find "${backup_dir}" -maxdepth 1 -type f | while read -r file; do
                limit=$(date +"%s" -d "now - 2 day")
                updated_at=$(stat -c "%Y" "$file")

                if [ "$limit" -gt "$updated_at" ]; then
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
check_etcgit() {
    export GIT_DIR="/etc/.git" GIT_WORK_TREE="/etc"
    git rev-parse --is-inside-work-tree > /dev/null 2>&1 \
        || failed "IS_ETCGIT" "/etc is not a git repository"
}
# Check if /etc/.git/ has read/write permissions for root only.
check_gitperms() {
    GIT_DIR="/etc/.git"
    if test -d $GIT_DIR; then
        expected="700"
        actual=$(stat -c "%a" $GIT_DIR)
        [ "$expected" = "$actual" ] || failed "IS_GITPERMS" "$GIT_DIR must be $expected"
    fi
}
# Check if no package has been upgraded since $limit.
check_notupgraded() {
    last_upgrade=0
    upgraded=false
    for log in /var/log/dpkg.log*; do
        if zgrep -qsm1 upgrade "$log"; then
            # There is at least one upgrade
            upgraded=true
            break
        fi
    done
    if $upgraded; then
        last_upgrade=$(date +%s -d "$(zgrep -h upgrade /var/log/dpkg.log* | sort -n | tail -1 | cut -f1 -d ' ')")
    fi
    if grep -qs '^mailto="listupgrade-todo@' /etc/evolinux/listupgrade.cnf \
        || grep -qs -E '^[[:digit:]]+[[:space:]]+[[:digit:]]+[[:space:]]+[^\*]' /etc/cron.d/listupgrade; then
        # Manual upgrade process
        limit=$(date +%s -d "now - 180 days")
    else
        # Regular process
        limit=$(date +%s -d "now - 90 days")
    fi
    install_date=0
    if [ -d /var/log/installer ]; then
        install_date=$(stat -c %Z /var/log/installer)
    fi
    # Check install_date if the system never received an upgrade
    if [ "$last_upgrade" -eq 0 ]; then
        [ "$install_date" -lt "$limit" ] && failed "IS_NOTUPGRADED" "The system has never been updated"
    else
        [ "$last_upgrade" -lt "$limit" ] && failed "IS_NOTUPGRADED" "The system hasn't been updated for too long"
    fi
}
# Check if reserved blocks for root is at least 5% on every mounted partitions.
check_tune2fs_m5() {
    min=5
    parts=$(grep -E "ext(3|4)" /proc/mounts | cut -d ' ' -f1 | tr -s '\n' ' ')
    FINDMNT_BIN=$(command -v findmnt)
    for part in $parts; do
        blockCount=$(dumpe2fs -h "$part" 2>/dev/null | grep -e "Block count:" | grep -Eo "[0-9]+")
        # If buggy partition, skip it.
        if [ -z "$blockCount" ]; then
            continue
        fi
        reservedBlockCount=$(dumpe2fs -h "$part" 2>/dev/null | grep -e "Reserved block count:" | grep -Eo "[0-9]+")
        # Use awk to have a rounded percentage
        # python is slow, bash is unable and bc rounds weirdly
        percentage=$(awk "BEGIN { pc=100*${reservedBlockCount}/${blockCount}; i=int(pc); print (pc-i<0.5)?i:i+1 }")

        if [ "$percentage" -lt "${min}" ]; then
            if [ -x "${FINDMNT_BIN}" ]; then
                mount=$(${FINDMNT_BIN} --noheadings --first-only --output TARGET "${part}")
            else
                mount="unknown mount point"
            fi
            failed "IS_TUNE2FS_M5" "Partition ${part} (${mount}) has less than ${min}% reserved blocks (${percentage}%)"
        fi
    done
}

check_broadcomfirmware() {
    LSPCI_BIN=$(command -v lspci)
    if [ -x "${LSPCI_BIN}" ]; then
        if ${LSPCI_BIN} | grep -q 'NetXtreme II'; then
            { is_installed firmware-bnx2 \
                && grep -q "^deb http://mirror.evolix.org/debian.* non-free" /etc/apt/sources.list;
            } || failed "IS_BROADCOMFIRMWARE" "missing non-free repository"
        fi
    else
        failed "IS_BROADCOMFIRMWARE" "lspci not found in ${PATH}"
    fi
}
check_hardwareraidtool() {
    LSPCI_BIN=$(command -v lspci)
    if [ -x "${LSPCI_BIN}" ]; then
        if ${LSPCI_BIN} | grep -q 'MegaRAID'; then
            # shellcheck disable=SC2015
            is_installed megacli && { is_installed megaclisas-status || is_installed megaraidsas-status; } \
                || failed "IS_HARDWARERAIDTOOL" "Mega tools not found"
        fi
        if ${LSPCI_BIN} | grep -q 'Hewlett-Packard Company Smart Array'; then
            is_installed cciss-vol-status || failed "IS_HARDWARERAIDTOOL" "cciss-vol-status not installed"
        fi
    else
        failed "IS_HARDWARERAIDTOOL" "lspci not found in ${PATH}"
    fi
}
check_sql_backup() {
    if (is_installed "mysql-server" || is_installed "mariadb-server"); then
        # You could change the default path in /etc/evocheck.cf
        SQL_BACKUP_PATH=${SQL_BACKUP_PATH:-"/home/backup/mysql.bak.gz"}
        for backup_path in ${SQL_BACKUP_PATH}; do
            if [ ! -f "${backup_path}" ]; then
                failed "IS_SQL_BACKUP" "MySQL dump is missing (${backup_path})"
                test "${VERBOSE}" = 1 || break
            fi
        done
    fi
}
check_postgres_backup() {
    if is_installed "postgresql-9*" || is_installed "postgresql-1*"; then
        # If you use something like barman, you should disable this check
        # You could change the default path in /etc/evocheck.cf
        POSTGRES_BACKUP_PATH=${POSTGRES_BACKUP_PATH:-"/home/backup/pg.dump.bak*"}
        for backup_path in ${POSTGRES_BACKUP_PATH}; do
            if [ ! -f "${backup_path}" ]; then
                failed "IS_POSTGRES_BACKUP" "PostgreSQL dump is missing (${backup_path})"
                test "${VERBOSE}" = 1 || break
            fi
        done
    fi
}
check_mongo_backup() {
    if is_installed "mongodb-org-server"; then
        # You could change the default path in /etc/evocheck.cf
        MONGO_BACKUP_PATH=${MONGO_BACKUP_PATH:-"/home/backup/mongodump"}
        if [ -d "$MONGO_BACKUP_PATH" ]; then
            for file in "${MONGO_BACKUP_PATH}"/*/*.{json,bson}*; do
                # Skip indexes file.
                if ! [[ "$file" =~ indexes ]]; then
                    limit=$(date +"%s" -d "now - 2 day")
                    updated_at=$(stat -c "%Y" "$file")
                    if [ -f "$file" ] && [ "$limit" -gt "$updated_at"  ]; then
                        failed "IS_MONGO_BACKUP" "MongoDB hasn't been dumped for more than 2 days"
                        break
                    fi
                fi
            done
        else
            failed "IS_MONGO_BACKUP" "MongoDB dump directory is missing (${MONGO_BACKUP_PATH})"
        fi
    fi
}
check_ldap_backup() {
    if is_installed slapd; then
        # You could change the default path in /etc/evocheck.cf
        LDAP_BACKUP_PATH=${LDAP_BACKUP_PATH:-"/home/backup/ldap.bak"}
        test -f "$LDAP_BACKUP_PATH" || failed "IS_LDAP_BACKUP" "LDAP dump is missing (${LDAP_BACKUP_PATH})"
    fi
}
check_redis_backup() {
    if is_installed redis-server; then
        # You could change the default path in /etc/evocheck.cf
        # REDIS_BACKUP_PATH may contain space-separated paths, example:
        # REDIS_BACKUP_PATH='/home/backup/redis-instance1/dump.rdb /home/backup/redis-instance2/dump.rdb'
        REDIS_BACKUP_PATH=${REDIS_BACKUP_PATH:-"/home/backup/redis/dump.rdb"}
        for file in ${REDIS_BACKUP_PATH}; do
            test -f "${file}" || failed "IS_REDIS_BACKUP" "Redis dump is missing (${file})"
        done
    fi
}
check_elastic_backup() {
    if is_installed elasticsearch; then
        # You could change the default path in /etc/evocheck.cf
        ELASTIC_BACKUP_PATH=${ELASTIC_BACKUP_PATH:-"/home/backup-elasticsearch"}
        test -d "$ELASTIC_BACKUP_PATH" || failed "IS_ELASTIC_BACKUP" "Elastic snapshot is missing (${ELASTIC_BACKUP_PATH})"
    fi
}
check_duplicate_fs_label() {
    # Do it only if thereis blkid binary
    BLKID_BIN=$(command -v blkid)
    if [ -n "$BLKID_BIN" ]; then
        tmpFile=$(mktemp --tmpdir="${TMPDIR:-/tmp}" "evocheck.duplicate_fs_label.XXXXX")
        files_to_cleanup="${files_to_cleanup} ${tmpFile}"

        parts=$($BLKID_BIN -c /dev/null | grep -ve raid_member -e EFI_SYSPART | grep -Eo ' LABEL=".*"' | cut -d'"' -f2)
        for part in $parts; do
            echo "$part" >> "$tmpFile"
        done
        tmpOutput=$(sort < "$tmpFile" | uniq -d)
        # If there is no duplicate, uniq will have no output
        # So, if $tmpOutput is not null, there is a duplicate
        if [ -n "$tmpOutput" ]; then
            # shellcheck disable=SC2086
            labels=$(echo -n $tmpOutput | tr '\n' ' ')
            failed "IS_DUPLICATE_FS_LABEL" "Duplicate labels: $labels"
        fi
    else
        failed "IS_DUPLICATE_FS_LABEL" "blkid not found in ${PATH}"
    fi
}
check_evolix_user() {
    grep -q -E "^evolix:" /etc/passwd \
        && failed "IS_EVOLIX_USER" "evolix user should be deleted, used only for install"
}
check_old_home_dir() {
    homeDir=${homeDir:-/home}
    for dir in "$homeDir"/*; do
        statResult=$(stat -c "%n has owner %u resolved as %U" "$dir" \
            | grep -Eve '.bak' -e '\.[0-9]{2}-[0-9]{2}-[0-9]{4}' \
            | grep "UNKNOWN")
        # There is at least one dir matching
        if [[ -n "$statResult" ]]; then
            failed "IS_OLD_HOME_DIR" "$statResult"
            test "${VERBOSE}" = 1 || break
        fi
    done
}
check_tmp_1777() {
    actual=$(stat --format "%a" /tmp)
    expected="1777"
    test "$expected" = "$actual" || failed "IS_TMP_1777" "/tmp must be $expected"
}
check_root_0700() {
    actual=$(stat --format "%a" /root)
    expected="700"
    test "$expected" = "$actual" || failed "IS_ROOT_0700" "/root must be $expected"
}
check_usrsharescripts() {
    actual=$(stat --format "%a" /usr/share/scripts)
    expected="700"
    test "$expected" = "$actual" || failed "IS_USRSHARESCRIPTS" "/usr/share/scripts must be $expected"
}
check_sshpermitrootno() {
    # shellcheck disable=SC2086
    if ! (sshd -T 2> /dev/null | grep -qi 'permitrootlogin no'); then
        failed "IS_SSHPERMITROOTNO" "PermitRoot should be set to no"
    fi
}
check_evomaintenanceusers() {
    if [ -f /etc/sudoers.d/evolinux ]; then
        sudoers="/etc/sudoers.d/evolinux"
    else
        sudoers="/etc/sudoers"
    fi
    # combine users from User_Alias and sudo group
    users=$({ grep "^User_Alias *ADMIN" $sudoers | cut -d= -f2 | tr -d " "; grep "^sudo" /etc/group | cut -d: -f 4; } | tr "," "\n" | sort -u)

    for user in $users; do
        user_home=$(getent passwd "$user" | cut -d: -f6)
        if [ -n "$user_home" ] && [ -d "$user_home" ]; then
            if ! grep -qs "^trap.*sudo.*evomaintenance.sh" "${user_home}"/.*profile; then
                failed "IS_EVOMAINTENANCEUSERS" "${user} doesn't have an evomaintenance trap"
                test "${VERBOSE}" = 1 || break
            fi
        fi
    done
}
check_evomaintenanceconf() {
    f=/etc/evomaintenance.cf
    if [ -e "$f" ]; then
        perms=$(stat -c "%a" $f)
        test "$perms" = "600" || failed "IS_EVOMAINTENANCECONF" "Wrong permissions on \`$f' ($perms instead of 600)"

        { grep "^export PGPASSWORD" $f | grep -qv "your-passwd" \
            && grep "^PGDB" $f | grep -qv "your-db" \
            && grep "^PGTABLE" $f | grep -qv "your-table" \
            && grep "^PGHOST" $f | grep -qv "your-pg-host" \
            && grep "^FROM" $f | grep -qv "jdoe@example.com" \
            && grep "^FULLFROM" $f | grep -qv "John Doe <jdoe@example.com>" \
            && grep "^URGENCYFROM" $f | grep -qv "mama.doe@example.com" \
            && grep "^URGENCYTEL" $f | grep -qv "06.00.00.00.00" \
            && grep "^REALM" $f | grep -qv "example.com"
        } || failed "IS_EVOMAINTENANCECONF" "evomaintenance is not correctly configured"
    else
        failed "IS_EVOMAINTENANCECONF" "Configuration file \`$f' is missing"
    fi
}
check_privatekeyworldreadable() {
    # a simple globbing fails if directory is empty
    if [ -n "$(ls -A /etc/ssl/private/)" ]; then
        for f in /etc/ssl/private/*; do
            perms=$(stat -L -c "%a" "$f")
            if [ "${perms: -1}" != 0 ]; then
                failed "IS_PRIVKEYWOLRDREADABLE" "$f is world-readable"
                test "${VERBOSE}" = 1 || break
            fi
        done
    fi
}
check_evobackup_incs() {
    if is_installed bkctld; then
        bkctld_cron_file=${bkctld_cron_file:-/etc/cron.d/bkctld}
        if [ -f "${bkctld_cron_file}" ]; then
            root_crontab=$(grep -v "^#" "${bkctld_cron_file}")
            echo "${root_crontab}" | grep -q "bkctld inc" || failed "IS_EVOBACKUP_INCS" "\`bkctld inc' is missing in ${bkctld_cron_file}"
            echo "${root_crontab}" | grep -qE "(check-incs.sh|bkctld check-incs)" || failed "IS_EVOBACKUP_INCS" "\`check-incs.sh' is missing in ${bkctld_cron_file}"
        else
            failed "IS_EVOBACKUP_INCS" "Crontab \`${bkctld_cron_file}' is missing"
        fi
    fi
}

check_osprober() {
    if is_installed os-prober qemu-kvm; then
        failed "IS_OSPROBER" \
            "Removal of os-prober package is recommended as it can cause serious issue on KVM server"
    fi
}

check_apt_valid_until() {
    aptvalidFile="/etc/apt/apt.conf.d/99no-check-valid-until"
    aptvalidText="Acquire::Check-Valid-Until no;"
    if grep -qs "archive.debian.org" /etc/apt/sources.list /etc/apt/sources.list.d/*; then
        if ! grep -qs "$aptvalidText" /etc/apt/apt.conf.d/*; then
            failed "IS_APT_VALID_UNTIL" \
                "As you use archive.mirror.org you need ${aptvalidFile}: ${aptvalidText}"
        fi
    fi
}

check_chrooted_binary_uptodate() {
    # list of processes to check
    process_list="sshd"
    for process_name in ${process_list}; do
        # what is the binary path?
        original_bin=$(command -v "${process_name}")
        for pid in $(pgrep ${process_name}); do
            process_bin=$(realpath "/proc/${pid}/exe")
            # Is the process chrooted?
            real_root=$(realpath "/proc/${pid}/root")
            if [ "${real_root}" != "/" ]; then
                chrooted_md5=$(md5sum "${process_bin}" | cut -f 1 -d ' ')
                original_md5=$(md5sum "${original_bin}" | cut -f 1 -d ' ')
                # compare md5 checksums
                if [ "$original_md5" != "$chrooted_md5" ]; then
                    failed "IS_CHROOTED_BINARY_UPTODATE" "${process_bin} (${pid}) is different than ${original_bin}."
                    test "${VERBOSE}" = 1 || break
                fi
            fi
        done
    done
}

check_lxc_container_resolv_conf() {
    if is_installed lxc; then
        container_list=$(lxc-ls)
        current_resolvers=$(grep nameserver /etc/resolv.conf | sed 's/nameserver//g' )

       for container in $container_list; do
            if [ -f "/var/lib/lxc/${container}/rootfs/etc/resolv.conf" ]; then

                while read -r resolver; do
                    if ! grep -qE "^nameserver\s+${resolver}" "/var/lib/lxc/${container}/rootfs/etc/resolv.conf"; then
                        failed "IS_LXC_CONTAINER_RESOLV_CONF" "resolv.conf miss-match beween host and container : missing nameserver ${resolver} in container ${container} resolv.conf"
                    fi
                done <<< "${current_resolvers}"

            else
                failed "IS_LXC_CONTAINER_RESOLV_CONF" "resolv.conf missing in container ${container}"
            fi
        done 
    fi
}
download_versions() {
    local file
    file=${1:-}

    ## The file is supposed to list programs : each on a line, then its latest version number
    ## Examples:
    # evoacme 21.06
    # evomaintenance 0.6.4

    versions_url="https://upgrades.evolix.org/versions-${DEBIAN_RELEASE}"

    # fetch timeout, in seconds
    timeout=10

    if command -v curl > /dev/null; then
        curl --max-time ${timeout} --fail --silent --output "${versions_file}" "${versions_url}"
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
    local program
    program=${1:-}

    case "${program}" in
        ## Special cases where the program name is different than the command name
        evocheck) echo "${0}" ;;
        evomaintenance) command -v "evomaintenance.sh" ;;
        listupgrade) command -v "evolistupgrade.sh" ;;
        old-kernel-autoremoval) command -v "old-kernel-autoremoval.sh" ;;
        mysql-queries-killer) command -v "mysql-queries-killer.sh" ;;
        minifirewall) echo "/etc/init.d/minifirewall" ;;

        ## General case, where the program name is the same as the command name
        *) command -v "${program}" ;;
    esac
}
get_version() {
    local program
    local command
    program=${1:-}
    command=${2:-}

    case "${program}" in
        ## Special case if `command --version => 'command` is not the standard way to get the version
        # my_command)
        #    /path/to/my_command --get-version 
        #    ;;

        add-vm)
            grep '^VERSION=' "${command}" | head -1 | cut -d '=' -f 2
            ;;
        minifirewall)
            ${command} version | head -1 | cut -d ' ' -f 3
            ;;
        ## Let's try the --version flag before falling back to grep for the constant
        kvmstats)
            if ${command} --version > /dev/null 2> /dev/null; then
                 ${command} --version 2> /dev/null | head -1 | cut -d ' ' -f 3
            else
                grep '^VERSION=' "${command}" | head -1 | cut -d '=' -f 2
            fi
            ;;

        ## General case to get the version
        *) ${command} --version 2> /dev/null | head -1 | cut -d ' ' -f 3 ;;
    esac
}
check_version() {
    local program
    local expected_version
    program=${1:-}
    expected_version=${2:-}

    command=$(get_command "${program}")
    if [ -n "${command}" ]; then
        # shellcheck disable=SC2086
        actual_version=$(get_version "${program}" "${command}")
        # printf "program:%s expected:%s actual:%s\n" "${program}" "${expected_version}" "${actual_version}"
        if [ -z "${actual_version}" ]; then
            failed "IS_CHECK_VERSIONS" "failed to lookup actual version of ${program}"
        elif dpkg --compare-versions "${actual_version}" lt "${expected_version}"; then
            failed "IS_CHECK_VERSIONS" "${program} version ${actual_version} is older than expected version ${expected_version}"
        elif dpkg --compare-versions "${actual_version}" gt "${expected_version}"; then
            failed "IS_CHECK_VERSIONS" "${program} version ${actual_version} is newer than expected version ${expected_version}, you should update your index."
        else
            : # Version check OK
        fi
    fi
}
add_to_path() {
    local new_path
    new_path=${1:-}

    echo "$PATH" | grep -qF "${new_path}" || export PATH="${PATH}:${new_path}"
}
check_versions() {
    versions_file=$(mktemp --tmpdir="${TMPDIR:-/tmp}" "evocheck.versions.XXXXX")
    files_to_cleanup="${files_to_cleanup} ${versions_file}"

    download_versions "${versions_file}"
    add_to_path "/usr/share/scripts"

    grep -v '^ *#' < "${versions_file}" | while IFS= read -r line; do
        local program
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
}

main() {
    # Default return code : 0 = no error
    RC=0
    # Detect operating system name, version and release
    detect_os

    main_output_file=$(mktemp --tmpdir="${TMPDIR:-/tmp}" "evocheck.main.XXXXX")
    files_to_cleanup="${files_to_cleanup} ${main_output_file}"

    test "${IS_TMP_1777:=1}" = 1 && check_tmp_1777
    test "${IS_ROOT_0700:=1}" = 1 && check_root_0700
    test "${IS_USRSHARESCRIPTS:=1}" = 1 && check_usrsharescripts
    test "${IS_SSHPERMITROOTNO:=1}" = 1 && check_sshpermitrootno
    test "${IS_EVOMAINTENANCEUSERS:=1}" = 1 && check_evomaintenanceusers
    # Verification de la configuration d'evomaintenance
    test "${IS_EVOMAINTENANCECONF:=1}" = 1 && check_evomaintenanceconf
    test "${IS_PRIVKEYWOLRDREADABLE:=1}" = 1 && check_privatekeyworldreadable

    test "${IS_LSBRELEASE:=1}" = 1 && check_lsbrelease
    test "${IS_DPKGWARNING:=1}" = 1 && check_dpkgwarning
    test "${IS_NRPEPOSTFIX:=1}" = 1 && check_nrpepostfix
    test "${IS_MODSECURITY:=1}" = 1 && check_modsecurity
    test "${IS_CUSTOMSUDOERS:=1}" = 1 && check_customsudoers
    test "${IS_VARTMPFS:=1}" = 1 && check_vartmpfs
    test "${IS_SERVEURBASE:=1}" = 1 && check_serveurbase
    test "${IS_LOGROTATECONF:=1}" = 1 && check_logrotateconf
    test "${IS_SYSLOGCONF:=1}" = 1 && check_syslogconf
    test "${IS_DEBIANSECURITY:=1}" = 1 && check_debiansecurity
    test "${IS_APTITUDEONLY:=1}" = 1 && check_aptitudeonly
    test "${IS_APTICRON:=0}" = 1 && check_apticron
    test "${IS_USRRO:=1}" = 1 && check_usrro
    test "${IS_TMPNOEXEC:=1}" = 1 && check_tmpnoexec
    test "${IS_MOUNT_FSTAB:=1}" = 1 && check_mountfstab
    test "${IS_LISTCHANGESCONF:=1}" = 1 && check_listchangesconf
    test "${IS_CUSTOMCRONTAB:=1}" = 1 && check_customcrontab
    test "${IS_SSHALLOWUSERS:=1}" = 1 && check_sshallowusers
    test "${IS_DISKPERF:=0}" = 1 && check_diskperf
    test "${IS_TMOUTPROFILE:=1}" = 1 && check_tmoutprofile
    test "${IS_ALERT5BOOT:=1}" = 1 && check_alert5boot
    test "${IS_ALERT5MINIFW:=1}" = 1 && check_alert5minifw
    test "${IS_ALERT5MINIFW:=1}" = 1 && test "${IS_MINIFW:=1}" = 1 && check_minifw
    test "${IS_NRPEPERMS:=1}" = 1 && check_nrpeperms
    test "${IS_MINIFWPERMS:=1}" = 1 && check_minifwperms
    test "${IS_NRPEDISKS:=0}" = 1 && check_nrpedisks
    test "${IS_NRPEPID:=1}" = 1 && check_nrpepid
    test "${IS_GRSECPROCS:=1}" = 1 && check_grsecprocs
    test "${IS_APACHEMUNIN:=1}" = 1 && check_apachemunin
    test "${IS_MYSQLUTILS:=1}" = 1 && check_mysqlutils
    test "${IS_RAIDSOFT:=1}" = 1 && check_raidsoft
    test "${IS_AWSTATSLOGFORMAT:=1}" = 1 && check_awstatslogformat
    test "${IS_MUNINLOGROTATE:=1}" = 1 && check_muninlogrotate
    test "${IS_SQUID:=1}" = 1 && check_squid
    test "${IS_EVOMAINTENANCE_FW:=1}" = 1 && check_evomaintenance_fw
    test "${IS_MODDEFLATE:=1}" = 1 && check_moddeflate
    test "${IS_LOG2MAILRUNNING:=1}" = 1 && check_log2mailrunning
    test "${IS_LOG2MAILAPACHE:=1}" = 1 && check_log2mailapache
    test "${IS_LOG2MAILMYSQL:=1}" = 1 && check_log2mailmysql
    test "${IS_LOG2MAILSQUID:=1}" = 1 && check_log2mailsquid
    test "${IS_BINDCHROOT:=1}" = 1 && check_bindchroot
    test "${IS_NETWORK_INTERFACES:=1}" = 1 && check_network_interfaces
    test "${IS_AUTOIF:=1}" = 1 && check_autoif
    test "${IS_INTERFACESGW:=1}" = 1 && check_interfacesgw
    test "${IS_INTERFACESNETMASK:=1}" = 1 && check_interfacesnetmask
    test "${IS_EVOBACKUP:=1}" = 1 && check_evobackup
    test "${IS_EVOBACKUP_EXCLUDE_MOUNT:=1}" = 1 && check_evobackup_exclude_mount
    test "${IS_USERLOGROTATE:=1}" = 1 && check_userlogrotate
    test "${IS_APACHECTL:=1}" = 1 && check_apachectl
    test "${IS_APACHESYMLINK:=1}" = 1 && check_apachesymlink
    test "${IS_APACHEIPINALLOW:=1}" = 1 && check_apacheipinallow
    test "${IS_MUNINAPACHECONF:=1}" = 1 && check_muninapacheconf
    test "${IS_PHPMYADMINAPACHECONF:=1}" = 1 && check_phpmyadminapacheconf
    test "${IS_KERNELUPTODATE:=1}" = 1 && check_kerneluptodate
    test "${IS_UPTIME:=1}" = 1 && check_uptime
    test "${IS_MUNINRUNNING:=1}" = 1 && check_muninrunning
    test "${IS_BACKUPUPTODATE:=1}" = 1 && check_backupuptodate
    test "${IS_ETCGIT:=1}" = 1 && check_etcgit
    test "${IS_GITPERMS:=1}" = 1 && check_gitperms
    test "${IS_NOTUPGRADED:=1}" = 1 && check_notupgraded
    test "${IS_TUNE2FS_M5:=1}" = 1 && check_tune2fs_m5
    test "${IS_BROADCOMFIRMWARE:=1}" = 1 && check_broadcomfirmware
    test "${IS_HARDWARERAIDTOOL:=1}" = 1 && check_hardwareraidtool
    test "${IS_SQL_BACKUP:=1}" = 1 && check_sql_backup
    test "${IS_POSTGRES_BACKUP:=1}" = 1 && check_postgres_backup
    test "${IS_MONGO_BACKUP:=1}" = 1 && check_mongo_backup
    test "${IS_LDAP_BACKUP:=1}" = 1 && check_ldap_backup
    test "${IS_REDIS_BACKUP:=1}" = 1 && check_redis_backup
    test "${IS_ELASTIC_BACKUP:=1}" = 1 && check_elastic_backup
    test "${IS_DUPLICATE_FS_LABEL:=1}" = 1 && check_duplicate_fs_label
    test "${IS_EVOLIX_USER:=1}" = 1 && check_evolix_user
    test "${IS_OLD_HOME_DIR:=0}" = 1 && check_old_home_dir
    test "${IS_EVOBACKUP_INCS:=1}" = 1 && check_evobackup_incs
    test "${IS_OSPROBER:=1}" = 1 && check_osprober
    test "${IS_APT_VALID_UNTIL:=1}" = 1 && check_apt_valid_until
    test "${IS_CHROOTED_BINARY_UPTODATE:=1}" = 1 && check_chrooted_binary_uptodate
    test "${IS_CHECK_VERSIONS:=1}" = 1 && check_versions

    if [ -f "${main_output_file}" ]; then
        lines_found=$(wc -l < "${main_output_file}")
        # shellcheck disable=SC2086
        if [ ${lines_found} -gt 0 ]; then

            cat "${main_output_file}" 2>&1
        fi
    fi

    exit ${RC}
}
cleanup_temp_files() {
    # shellcheck disable=SC2086
    rm -f ${files_to_cleanup}
}

PROGNAME=$(basename "$0")
# shellcheck disable=SC2034
readonly PROGNAME

# shellcheck disable=SC2124
ARGS=$@
readonly ARGS

# Disable LANG*
export LANG=C
export LANGUAGE=C

files_to_cleanup=""
# shellcheck disable=SC2064
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
            IS_KERNELUPTODATE=0
            IS_UPTIME=0
            IS_MELTDOWN_SPECTRE=0
            IS_CHECK_VERSIONS=0
            IS_NETWORKING_SERVICE=0
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
            if [ "${QUIET}" != 1 ]; then
                printf 'WARN: Unknown option (ignored): %s\n' "$1" >&2
            fi
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
