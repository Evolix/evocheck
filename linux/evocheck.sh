#!/bin/bash

# EvoCheck
# Script to verify compliance of a Linux (Debian 10+) server
# powered by Evolix

#set -x

VERSION="25.07"
readonly VERSION

# base functions

show_version() {
    cat <<END
evocheck version ${VERSION}

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

is_pack_web(){
    test -e /usr/share/scripts/web-add.sh || test -e /usr/share/scripts/evoadmin/web-add.sh
}
is_pack_samba(){
    test -e /usr/share/scripts/add.pl
}
is_installed(){
    for pkg in "$@"; do
        dpkg -l "$pkg" 2> /dev/null | grep --quiet --extended-regexp '^(i|h)i' || return 1
    done
}

# logging

log() {
    date=$(/bin/date +"${DATE_FORMAT}")
    if [ "${1}" != '' ]; then
        printf "[%s] %s: %s\\n" "$date" "${PROGNAME}" "${1}" >> "${LOGFILE}"
    else
        while read line; do
            printf "[%s] %s: %s\\n" "$date" "${PROGNAME}" "${line}" >> "${LOGFILE}"
        done < /dev/stdin
    fi
}

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

    # Always log verbose
    log "${check_name} FAILED! ${check_comments}"
}

# check functions

check_lsbrelease(){
    if evo::os-release::is_debian 13 lt; then
        LSB_RELEASE_BIN=$(command -v lsb_release)
        if [ -x "${LSB_RELEASE_BIN}" ]; then
            ## only the major version matters
            lhs=$(${LSB_RELEASE_BIN} --release --short | cut -d "." -f 1)
            rhs=$(cut -d "." -f 1 < /etc/debian_version)
            test "$lhs" = "$rhs" || failed "IS_LSBRELEASE" "release is not consistent between lsb_release (${lhs}) and /etc/debian_version (${rhs})"
        else
            failed "IS_LSBRELEASE" "lsb_release is missing or not executable"
        fi
    fi
}
check_dpkgwarning() {
    test -e /etc/apt/apt.conf.d/z-evolinux.conf \
        || failed "IS_DPKGWARNING" "/etc/apt/apt.conf.d/z-evolinux.conf is missing"
}
# Check if localhost, localhost.localdomain and localhost.$mydomain are set in Postfix mydestination option.
check_postfix_mydestination() {
    # shellcheck disable=SC2016
    if ! grep mydestination /etc/postfix/main.cf | grep --quiet --extended-regexp 'localhost([[:blank:]]|$)'; then
        failed "IS_POSTFIX_MYDESTINATION" "'localhost' is missing in Postfix mydestination option."
    fi
    if ! grep mydestination /etc/postfix/main.cf | grep --quiet --fixed-strings 'localhost.localdomain'; then
        failed "IS_POSTFIX_MYDESTINATION" "'localhost.localdomain' is missing in Postfix mydestination option."
    fi
    if ! grep mydestination /etc/postfix/main.cf | grep --quiet --fixed-strings 'localhost.$mydomain'; then
        failed "IS_POSTFIX_MYDESTINATION" "'localhost.\$mydomain' is missing in Postfix mydestination option."
    fi
}
# Verifying check_mailq in Nagios NRPE config file. (Option "-M postfix" need to be set if the MTA is Postfix)
check_nrpepostfix() {
    if is_installed postfix; then
        { test -e /etc/nagios/nrpe.cfg \
            && grep --quiet --recursive "^command.*check_mailq -M postfix" /etc/nagios/nrpe.*;
        } || failed "IS_NRPEPOSTFIX" "NRPE \"check_mailq\" for postfix is missing"
    fi
}
# Check if mod-security config file is present
check_customsudoers() {
    grep --extended-regexp --quiet --recursive "umask=0077" /etc/sudoers* || failed "IS_CUSTOMSUDOERS" "missing umask=0077 in sudoers file"
}
check_vartmpfs() {
    if evo::os-release::is_debian 13 lt; then
        FINDMNT_BIN=$(command -v findmnt)
        if [ -x "${FINDMNT_BIN}" ]; then
            ${FINDMNT_BIN} /var/tmp --type tmpfs --noheadings > /dev/null || failed "IS_VARTMPFS" "/var/tmp is not a tmpfs"
        else
            df /var/tmp | grep --quiet tmpfs || failed "IS_VARTMPFS" "/var/tmp is not a tmpfs"
        fi
    fi
}
check_serveurbase() {
    is_installed serveur-base || failed "IS_SERVEURBASE" "serveur-base package is not installed"
}
check_logrotateconf() {
    test -e /etc/logrotate.d/zsyslog || failed "IS_LOGROTATECONF" "missing zsyslog in logrotate.d"
}
check_syslogconf() {
    # Test for modern servers
    if [ ! -f /etc/rsyslog.d/10-evolinux-default.conf ]; then
        # Fallback test for legacy servers
        if ! grep --quiet --ignore-case "Syslog for Pack Evolix" /etc/*syslog*/*.conf /etc/*syslog.conf; then
            failed "IS_SYSLOGCONF" "Evolix syslog config is missing"
        fi
    fi
}
check_debiansecurity() {
    # Look for enabled "Debian-Security" sources from the "Debian" origin
    apt-cache policy | grep "\bl=Debian-Security\b" | grep "\bo=Debian\b" | grep --quiet "\bc=main\b"
    test $? -eq 0 || failed "IS_DEBIANSECURITY" "missing Debian-Security repository"
}
check_debiansecurity_lxc() {
    if is_installed lxc; then
        lxc_path=$(lxc-config lxc.lxcpath)
        container_list=$(lxc-ls -1 --active)
        for container_name in ${container_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                if [ -f "${rootfs}/etc/debian_version" ]; then
                    DEBIAN_LXC_VERSION=$(cut -d "." -f 1 < "${rootfs}/etc/debian_version")
                    if [ "${DEBIAN_LXC_VERSION}" -ge 9 ]; then
                        lxc-attach --name "${container_name}" apt-cache policy | grep "\bl=Debian-Security\b" | grep "\bo=Debian\b" | grep --quiet "\bc=main\b"
                        test $? -eq 0 || failed "IS_DEBIANSECURITY_LXC" "missing Debian-Security repository in container ${container_name}"
                    fi
                fi
            fi
        done
    fi
}
check_backports_version() {
    local os_codename
    os_codename=$( evo::os-release::get_version_codename )

    # Look for enabled "Debian Backports" sources from the "Debian" origin
    apt-cache policy | grep "\bl=Debian Backports\b" | grep "\bo=Debian\b" | grep --quiet "\bc=main\b"
    test $? -eq 1 || ( \
        apt-cache policy | grep "\bl=Debian Backports\b" | grep --quiet "\bn=${os_codename}-backports\b" && \
        test $? -eq 0 || failed "IS_BACKPORTS_VERSION" "Debian Backports enabled for another release than ${os_codename}" )
}
check_oldpub() {
    # Look for enabled pub.evolix.net sources (supersed by pub.evolix.org since Stretch)
    apt-cache policy | grep --quiet pub.evolix.net
    test $? -eq 1 || failed "IS_OLDPUB" "Old pub.evolix.net repository is still enabled"
}
check_oldpub_lxc() {
    # Look for enabled pub.evolix.net sources (supersed by pub.evolix.org since Buster as Sury safeguard)
    if is_installed lxc; then
        container_list=$( lxc-ls -1 --active )
        for container_name in ${container_list}; do
            APT_CACHE_BIN=$(lxc-attach --name "${container_name}" -- bash -c "command -v apt-cache")
            if [ -x "${APT_CACHE_BIN}" ]; then
                lxc-attach --name "${container_name}" apt-cache policy | grep --quiet pub.evolix.net
                test $? -eq 1 || failed "IS_OLDPUB_LXC" "Old pub.evolix.net repository is still enabled in container ${container_name}"
            fi
        done
    fi
}
check_newpub() {
    # Look for enabled pub.evolix.org sources
    apt-cache policy | grep "\bl=Evolix\b" | grep --quiet --invert-match php
    test $? -eq 0 || failed "IS_NEWPUB" "New pub.evolix.org repository is missing"
}
check_sury() {
    # Look for enabled packages.sury.org sources
    apt-cache policy | grep --quiet packages.sury.org
    if [ $? -eq 0 ]; then
         apt-cache policy | grep "\bl=Evolix\b" | grep --quiet php
         test $? -eq 0 || failed "IS_SURY" "packages.sury.org is present but our safeguard pub.evolix.org repository is missing"
    fi
}
check_sury_lxc() {
    if is_installed lxc; then
        container_list=$( lxc-ls -1 --active )
        for container_name in ${container_list}; do
            APT_CACHE_BIN=$(lxc-attach --name "${container_name}" -- bash -c "command -v apt-cache")
            if [ -x "${APT_CACHE_BIN}" ]; then
                lxc-attach --name "${container_name}" apt-cache policy | grep --quiet packages.sury.org
                if [ $? -eq 0 ]; then
                    lxc-attach --name "${container_name}" apt-cache policy | grep "\bl=Evolix\b" | grep --quiet php
                    test $? -eq 0 || failed "IS_SURY_LXC" "packages.sury.org is present but our safeguard pub.evolix.org repository is missing in container ${container_name}"
                fi
            fi
        done
    fi
}
check_not_deb822() {
    if evo::os-release::is_debian 12 ge; then
        for source in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
            test -f "${source}" && grep --quiet '^deb' "${source}" && \
                failed "IS_NOT_DEB822" "${source} contains a one-line style sources.list entry, and should be converted to deb822 format"
	    done
    fi
}
check_no_signed_by() {
    if evo::os-release::is_debian 12 ge; then
        for source in /etc/apt/sources.list.d/*.sources; do
            if [ -f "${source}" ]; then
                ( grep --quiet '^Signed-by' "${source}" && \
                    failed "IS_NO_SIGNED_BY" "${source} contains a Source-by entry that should be capitalized as Signed-By" ) || \
                ( grep --quiet '^Signed-By' "${source}" || \
                    failed "IS_NO_SIGNED_BY" "${source} has no Signed-By entry" )
            fi
        done
    fi
}
check_aptitude() {
    test -e /usr/bin/aptitude && failed "IS_APTITUDE" "aptitude may not be installed on Debian >=8"
}
check_aptgetbak() {
    test -e /usr/bin/apt-get.bak && failed "IS_APTGETBAK" "prohibit the installation of apt-get.bak with dpkg-divert(1)"
}
check_usrro() {
    grep /usr /etc/fstab | grep --quiet --extended-regexp "\bro\b" || failed "IS_USRRO" "missing ro directive on fstab for /usr"
}
check_tmpnoexec() {
    FINDMNT_BIN=$(command -v findmnt)
    if [ -x "${FINDMNT_BIN}" ]; then
        options=$(${FINDMNT_BIN} --noheadings --first-only --output OPTIONS /tmp)
        echo "${options}" | grep --quiet --extended-regexp "\bnoexec\b" || failed "IS_TMPNOEXEC" "/tmp is not mounted with 'noexec'"
    else
        mount | grep "on /tmp" | grep --quiet --extended-regexp "\bnoexec\b" || failed "IS_TMPNOEXEC" "/tmp is not mounted with 'noexec' (WARNING: findmnt(8) is not found)"
    fi
}
check_homenoexec() {
    FINDMNT_BIN=$(command -v findmnt)
    if [ -x "${FINDMNT_BIN}" ]; then
        options=$(${FINDMNT_BIN} --noheadings --first-only --output OPTIONS /home)
        echo "${options}" | grep --quiet --extended-regexp "\bnoexec\b" || \
           ( grep --quiet --extended-regexp "/home.*noexec" /etc/fstab && \
	   failed "IS_HOMENOEXEC" "/home is mounted with 'exec' but /etc/fstab document it as 'noexec'" )
    else
        mount | grep "on /home" | grep --quiet --extended-regexp "\bnoexec\b" || \
           ( grep --quiet --extended-regexp "/home.*noexec" /etc/fstab && \
	   failed "IS_HOMENOEXEC" "/home is mounted with 'exec' but /etc/fstab document it as 'noexec' (WARNING: findmnt(8) is not found)" )
    fi
}
check_mountfstab() {
    # Test if lsblk available, if not skip this test...
    LSBLK_BIN=$(command -v lsblk)
    if test -x "${LSBLK_BIN}"; then
        for mountPoint in $(${LSBLK_BIN} -o MOUNTPOINT -l -n | grep '/'); do
            grep --quiet --extended-regexp "$mountPoint\W" /etc/fstab \
                || failed "IS_MOUNT_FSTAB" "partition(s) detected mounted but no presence in fstab"
        done
    fi
}
check_listchangesconf() {
    if is_installed apt-listchanges; then
        failed "IS_LISTCHANGESCONF" "apt-listchanges must not be installed on Debian >=9"
    fi
}
check_customcrontab() {
    found_lines=$(grep --count --extended-regexp "^(17 \*|25 6|47 6|52 6)" /etc/crontab)
    test "$found_lines" = 4 && failed "IS_CUSTOMCRONTAB" "missing custom field in crontab"
}
check_sshallowusers() {
    if evo::os-release::is_debian 12 ge; then
        if [ -d /etc/ssh/sshd_config.d/ ]; then
            # AllowUsers or AllowGroups should be in /etc/ssh/sshd_config.d/
            grep --extended-regexp --quiet --ignore-case --recursive "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config.d/ \
                || failed "IS_SSHALLOWUSERS" "missing AllowUsers or AllowGroups directive in sshd_config.d/*"
        fi
        # AllowUsers or AllowGroups should not be in /etc/ssh/sshd_config
        grep --extended-regexp --quiet --ignore-case "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config \
            && failed "IS_SSHALLOWUSERS" "AllowUsers or AllowGroups directive present in sshd_config"
    else
        # AllowUsers or AllowGroups should be in /etc/ssh/sshd_config or /etc/ssh/sshd_config.d/
        if [ -d /etc/ssh/sshd_config.d/ ]; then
            grep --extended-regexp --quiet --ignore-case --recursive "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ \
                || failed "IS_SSHALLOWUSERS" "missing AllowUsers or AllowGroups directive in sshd_config"
        else
            grep --extended-regexp --quiet --ignore-case "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config \
                || failed "IS_SSHALLOWUSERS" "missing AllowUsers or AllowGroups directive in sshd_config"
        fi
    fi
}
check_sshconfsplit() {
    if evo::os-release::is_debian 12 ge; then
        ls /etc/ssh/sshd_config.d/* > /dev/null 2> /dev/null \
            || failed "IS_SSHCONFSPLIT" "No files under /etc/ssh/sshd_config.d"
        diff /usr/share/openssh/sshd_config /etc/ssh/sshd_config > /dev/null 2> /dev/null \
            || failed "IS_SSHCONFSPLIT" "Files /etc/ssh/sshd_config and /usr/share/openssh/sshd_config differ"
        for f in /etc/ssh/sshd_config.d/z-evolinux-defaults.conf /etc/ssh/sshd_config.d/zzz-evolinux-custom.conf; do
            test -f "${f}" || failed "IS_SSHCONFSPLIT" "${f} is not a regular file"
        done
    fi
}
check_sshlastmatch() {
    if evo::os-release::is_debian 12 ge; then
        for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/zzz-evolinux-custom.conf; do
            if ! test -f "${f}"; then
                continue
            fi
            if ! awk 'BEGIN { last = "all" } tolower($1) == "match" { last = tolower($2) } END { if (last != "all") exit 1 }' "${f}"; then
                failed "IS_SSHLASTMATCH" "last Match directive is not \"Match all\" in ${f}"
            fi
        done
    fi
}
check_diskperf() {
    perfFile="/root/disk-perf.txt"
    test -e $perfFile || failed "IS_DISKPERF" "missing ${perfFile}"
}
check_tmoutprofile() {
    grep --no-messages --quiet "TMOUT=" /etc/profile /etc/profile.d/evolinux.sh || failed "IS_TMOUTPROFILE" "TMOUT is not set"
}
check_alert5boot() {
    grep --quiet --no-messages "^date" /usr/share/scripts/alert5.sh || failed "IS_ALERT5BOOT" "boot mail is not sent by alert5 init script"
    if [ -f /etc/systemd/system/alert5.service ]; then
        systemctl is-enabled alert5.service -q || failed "IS_ALERT5BOOT" "alert5 unit is not enabled"
    else
        failed "IS_ALERT5BOOT" "alert5 unit file is missing"
    fi
}
check_alert5minifw() {
    grep --quiet --no-messages "^/etc/init.d/minifirewall" /usr/share/scripts/alert5.sh \
        || failed "IS_ALERT5MINIFW" "Minifirewall is not started by alert5 script or script is missing"
}
check_minifw() {
    {
        if [ -f /etc/systemd/system/minifirewall.service ]; then
            systemctl is-active minifirewall > /dev/null 2>&1
        else
            if test -x /usr/share/scripts/minifirewall_status; then
                /usr/share/scripts/minifirewall_status > /dev/null 2>&1
            else
                /sbin/iptables -L -n 2> /dev/null | grep --quiet --extended-regexp "^(DROP\s+(udp|17)|ACCEPT\s+(icmp|1))\s+--\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0\s*$"
            fi
        fi
    } || failed "IS_MINIFW" "minifirewall seems not started"
}
check_minifw_includes() {
    if evo::os-release::is_debian 11 ge; then
        if grep --quiet --regexp '/sbin/iptables' --regexp '/sbin/ip6tables' "/etc/default/minifirewall"; then
            failed "IS_MINIFWINCLUDES" "minifirewall has direct iptables invocations in /etc/default/minifirewall that should go in /etc/minifirewall.d/"
        fi
    fi
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
    if [ -f "/etc/default/minifirewall" ]; then
        actual=$(stat --format "%a" "/etc/default/minifirewall")
        expected="600"
        test "$expected" = "$actual" || failed "IS_MINIFWPERMS" "/etc/default/minifirewall must be ${expected}"
    fi
}
check_nrpedisks() {
    NRPEDISKS=$(grep command.check_disk /etc/nagios/nrpe.cfg | grep "^command.check_disk[0-9]" | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
    DFDISKS=$(df -Pl | grep --count --extended-regexp --invert-match "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)")
    test "$NRPEDISKS" = "$DFDISKS" || failed "IS_NRPEDISKS" "there must be $DFDISKS check_disk in nrpe.cfg"
}
check_nrpepid() {
    if evo::os-release::is_debian 11 lt; then
        { test -e /etc/nagios/nrpe.cfg \
            && grep --quiet "^pid_file=/var/run/nagios/nrpe.pid" /etc/nagios/nrpe.cfg;
        } || failed "IS_NRPEPID" "missing or wrong pid_file directive in nrpe.cfg"
    else
        { test -e /etc/nagios/nrpe.cfg \
            && grep --quiet "^pid_file=/run/nagios/nrpe.pid" /etc/nagios/nrpe.cfg;
        } || failed "IS_NRPEPID" "missing or wrong pid_file directive in nrpe.cfg"
    fi
}
check_grsecprocs() {
    if uname -a | grep --quiet grsec; then
        { grep --quiet "^command.check_total_procs..sudo" /etc/nagios/nrpe.cfg \
            && grep --after-context=1 "^\[processes\]" /etc/munin/plugin-conf.d/munin-node | grep --quiet "^user root";
        } || failed "IS_GRSECPROCS" "missing munin's plugin processes directive for grsec"
    fi
}
check_apachemunin() {
    if test -e /etc/apache2/apache2.conf; then
        { test -h /etc/apache2/mods-enabled/status.load \
            && test -h /etc/munin/plugins/apache_accesses \
            && test -h /etc/munin/plugins/apache_processes \
            && test -h /etc/munin/plugins/apache_volume;
        } || failed "IS_APACHEMUNIN" "missing munin plugins for Apache"
    fi
}
# Verification mytop + Munin si MySQL
check_mysqlutils() {
    MYSQL_ADMIN=${MYSQL_ADMIN:-mysqladmin}
    if is_installed mysql-server; then
        # With Debian 11 and later, root can connect to MariaDB with the socket
        if evo::os-release::is_debian 11 lt; then
            # You can configure MYSQL_ADMIN in evocheck.cf
            if ! grep --quiet --no-messages "^user *= *${MYSQL_ADMIN}" /root/.my.cnf; then
                failed "IS_MYSQLUTILS" "${MYSQL_ADMIN} missing in /root/.my.cnf"
            fi
        fi
        if ! test -x /usr/bin/mytop; then
            if ! test -x /usr/local/bin/mytop; then
                failed "IS_MYSQLUTILS" "mytop binary missing"
            fi
        fi
        if ! grep --quiet --no-messages '^user *=' /root/.mytop; then
            failed "IS_MYSQLUTILS" "credentials missing in /root/.mytop"
        fi
    fi
}
# Verification de la configuration du raid soft (mdadm)
check_raidsoft() {
    if test -e /proc/mdstat && grep --quiet md /proc/mdstat; then
        { grep --quiet "^AUTOCHECK=true" /etc/default/mdadm \
            && grep --quiet "^START_DAEMON=true" /etc/default/mdadm \
            && grep --quiet --invert-match "^MAILADDR ___MAIL___" /etc/mdadm/mdadm.conf;
        } || failed "IS_RAIDSOFT" "missing or wrong config for mdadm"
    fi
}
# Verification du LogFormat de AWStats
check_awstatslogformat() {
    if is_installed apache2 awstats; then
        awstatsFile="/etc/awstats/awstats.conf.local"
        grep --quiet --extended-regexp '^LogFormat=1' $awstatsFile \
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
    squidconffile="/etc/squid/evolinux-custom.conf"
    if is_pack_web && (is_installed squid || is_installed squid3); then
        host=$(hostname -i)
        # shellcheck disable=SC2086
        http_port=$(grep --extended-regexp "^http_port\s+[0-9]+" $squidconffile | awk '{ print $2 }')
        { grep --quiet --extended-regexp "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT" "/etc/default/minifirewall" \
            && grep --quiet --extended-regexp "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d $host -j ACCEPT" "/etc/default/minifirewall" \
            && grep --quiet --extended-regexp "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d 127.0.0.(1|0/8) -j ACCEPT" "/etc/default/minifirewall" \
            && grep --quiet --extended-regexp "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port.* $http_port" "/etc/default/minifirewall";
        } || grep --quiet --extended-regexp "^PROXY='?on'?" "/etc/default/minifirewall" \
          || failed "IS_SQUID" "missing squid rules in minifirewall"
    fi
}
check_evomaintenance_fw() {
    if [ -f "/etc/default/minifirewall" ]; then
        hook_db=$(grep --extended-regexp '^\s*HOOK_DB' /etc/evomaintenance.cf | tr -d ' ' | cut -d= -f2)
        rulesNumber=$(grep --count --extended-regexp "/sbin/iptables -A INPUT -p tcp --sport 5432 --dport 1024:65535 -s .* -m state --state ESTABLISHED(,RELATED)? -j ACCEPT" "/etc/default/minifirewall")
        if [ "$hook_db" = "1" ] && [ "$rulesNumber" -lt 2 ]; then
            failed "IS_EVOMAINTENANCE_FW" "HOOK_DB is enabled but missing evomaintenance rules in minifirewall"
        fi
    fi
}
# Verification de la conf et de l'activation de mod-deflate
check_moddeflate() {
    f=/etc/apache2/mods-enabled/deflate.conf
    if is_installed apache2.2; then
        { test -e $f && grep --quiet "AddOutputFilterByType DEFLATE text/html text/plain text/xml" $f \
            && grep --quiet "AddOutputFilterByType DEFLATE text/css" $f \
            && grep --quiet "AddOutputFilterByType DEFLATE application/x-javascript application/javascript" $f;
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
    conf=/etc/log2mail/config/apache
    if is_pack_web && is_installed log2mail; then
        grep --no-messages --quiet "^file = /var/log/apache2/error.log" $conf \
            || failed "IS_LOG2MAILAPACHE" "missing log2mail directive for apache"
    fi
}
check_log2mailmysql() {
    if is_pack_web && is_installed log2mail; then
        grep --no-messages --quiet "^file = /var/log/syslog" /etc/log2mail/config/{default,mysql,mysql.conf} \
            || failed "IS_LOG2MAILMYSQL" "missing log2mail directive for mysql"
    fi
}
check_log2mailsquid() {
    if is_pack_web && is_installed log2mail; then
        grep --no-messages --quiet "^file = /var/log/squid.*/access.log" /etc/log2mail/config/* \
            || failed "IS_LOG2MAILSQUID" "missing log2mail directive for squid"
    fi
}
# Verification si bind est chroote
check_bindchroot() {
    if is_installed bind9; then
        if netstat -utpln | grep "/named" | grep :53 | grep --quiet --invert-match --extended-regexp "(127.0.0.1|::1)"; then
            default_conf=/etc/default/named
            if evo::os-release::is_debian 10; then
                default_conf=/etc/default/bind9
            fi
            if grep --quiet '^OPTIONS=".*-t' "${default_conf}" && grep --quiet '^OPTIONS=".*-u' "${default_conf}"; then
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
    interfaces=$(/sbin/ip address show up | grep "^[0-9]*:" | grep --extended-regexp --invert-match "(lo|vnet|docker|veth|tun|tap|macvtap|vrrp|lxcbr|wg)" | cut -d " " -f 2 | tr -d : | cut -d@ -f1 | tr "\n" " ")
    for interface in $interfaces; do
        if grep --quiet --dereference-recursive "^iface $interface" /etc/network/interfaces* && ! grep --quiet --dereference-recursive "^auto $interface" /etc/network/interfaces*; then
            failed "IS_AUTOIF" "Network interface \`${interface}' is statically defined but not set to auto"
            test "${VERBOSE}" = 1 || break
        fi
    done
}
# Network conf verification
check_interfacesgw() {
    number=$(grep --extended-regexp --count "^[^#]*gateway [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" /etc/network/interfaces)
    test "$number" -gt 1 && failed "IS_INTERFACESGW" "there is more than 1 IPv4 gateway"
    number=$(grep --extended-regexp --count "^[^#]*gateway [0-9a-fA-F]+:" /etc/network/interfaces)
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
# Verification de l’état du service networking
check_networking_service() {
    if systemctl is-enabled networking.service > /dev/null; then
        if ! systemctl is-active networking.service > /dev/null; then
            failed "IS_NETWORKING_SERVICE" "networking.service is not active"
        fi
    fi
}
# Verification de la mise en place d'evobackup
check_evobackup() {
    evobackup_found=$(find /etc/cron* -name '*evobackup*' | wc -l)
    test "$evobackup_found" -gt 0 || failed "IS_EVOBACKUP" "missing evobackup cron"
}
# Vérification de la mise en place d'un cron de purge de la base SQLite de Fail2ban
check_fail2ban_purge() {
    # Nécessaire seulement en Debian 9 ou 10
    if evo::os-release::is_debian 11 lt; then
      if is_installed fail2ban; then
        test -f /etc/cron.daily/fail2ban_dbpurge || failed "IS_FAIL2BAN_PURGE" "missing script fail2ban_dbpurge cron"
      fi
    fi
}
# Vérification qu'il ne reste pas des jails nommées ssh non renommées en sshd
check_ssh_fail2ban_jail_renamed() {
    if is_installed fail2ban && [ -f /etc/fail2ban/jail.local ]; then
        if grep --quiet --fixed-strings "[ssh]" /etc/fail2ban/jail.local; then
            failed "IS_SSH_FAIL2BAN_JAIL_RENAMED" "Jail ssh must be renamed sshd in fail2ban >= 0.9."
        fi
    fi
}
# Vérification de l'exclusion des montages (NFS) dans les sauvegardes
check_evobackup_exclude_mount() {
    excludes_file=$(mktemp --tmpdir "evocheck.evobackup_exclude_mount.XXXXX")
    files_to_cleanup+=("${excludes_file}")

    # shellcheck disable=SC2044
    for evobackup_file in $(find /etc/cron* -name '*evobackup*' | grep --invert-match --extended-regexp ".disabled$"); do
        # if the file seems to be a backup script, with an Rsync invocation
        if grep --quiet "^\s*rsync" "${evobackup_file}"; then
            # If rsync is not limited by "one-file-system"
            # then we verify that every mount is excluded
            if ! grep --quiet -- "^\s*--one-file-system" "${evobackup_file}"; then
                # old releases of evobackups don't have version
                if grep --quiet  "^VERSION=" "${evobackup_file}" && dpkg --compare-versions "$(sed -E -n 's/VERSION="(.*)"/\1/p' "${evobackup_file}")" ge 22.12 ; then
                  sed -En '/RSYNC_EXCLUDES="/,/"/ {s/(RSYNC_EXCLUDES=|")//g;p}' "${evobackup_file}" > "${excludes_file}"
                else
                  grep -- "--exclude " "${evobackup_file}" | grep --extended-regexp --only-matching "\"[^\"]+\"" | tr -d '"' > "${excludes_file}"
                fi
                not_excluded=$(findmnt --type nfs,nfs4,fuse.sshfs, -o target --noheadings | grep --invert-match --file="${excludes_file}")
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
        /usr/sbin/apache2ctl configtest 2>&1 | grep --quiet "^Syntax OK$" \
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
        grep -I --recursive --extended-regexp "^[^#] *(Allow|Deny) from" /etc/apache2/ \
            | grep --ignore-case --invert-match "from all" \
            | grep --ignore-case --invert-match "env=" \
            | perl -ne 'exit 1 unless (/from( [\da-f:.\/]+)+$/i)' \
            || failed "IS_APACHEIPINALLOW" "bad (Allow|Deny) directives in apache"
    fi
}
# Check if default Apache configuration file for munin is absent (or empty or commented).
check_muninapacheconf() {
    muninconf="/etc/apache2/conf-available/munin.conf"
    if is_installed apache2; then
        test -e $muninconf && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "$muninconf" \
            && failed "IS_MUNINAPACHECONF" "default munin configuration may be commented or disabled"
    fi
}
# Check if default Apache configuration file for phpMyAdmin is absent (or empty or commented).
check_phpmyadminapacheconf() {
    phpmyadminconf0="/etc/apache2/conf-available/phpmyadmin.conf"
    phpmyadminconf1="/etc/apache2/conf-enabled/phpmyadmin.conf"
    if is_installed apache2; then
        test -e $phpmyadminconf0 && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "$phpmyadminconf0" \
            && failed "IS_PHPMYADMINAPACHECONF" "default phpmyadmin configuration ($phpmyadminconf0) should be commented or disabled"
        test -e $phpmyadminconf1 && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "$phpmyadminconf1" \
            && failed "IS_PHPMYADMINAPACHECONF" "default phpmyadmin configuration ($phpmyadminconf1) should be commented or disabled"
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
            grep --no-messages --quiet "^graph_strategy cron" /etc/munin/munin.conf && [ "$limit" -gt "$updated_at" ] && failed "IS_MUNINRUNNING" "Munin load PNG has not been updated in the last 10 minutes"
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
check_etcgit_lxc() {
    if is_installed lxc; then
        lxc_path=$(lxc-config lxc.lxcpath)
        container_list=$(lxc-ls -1 --active)
        for container_name in ${container_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                export GIT_DIR="${rootfs}/etc/.git"
                export GIT_WORK_TREE="${rootfs}/etc"
                git rev-parse --is-inside-work-tree > /dev/null 2>&1 \
                    || failed "IS_ETCGIT_LXC" "/etc is not a git repository in container ${container_name}"
            fi
        done
    fi
}
# Check if /etc/.git/ has read/write permissions for root only.
check_gitperms() {
    GIT_DIR="/etc/.git"
    if [ -d "${GIT_DIR}" ]; then
        expected="700"
        actual=$(stat -c "%a" $GIT_DIR)
        [ "${expected}" = "${actual}" ] || failed "IS_GITPERMS" "${GIT_DIR} must be ${expected}"
    fi
}
check_gitperms_lxc() {
    if is_installed lxc; then
        lxc_path=$(lxc-config lxc.lxcpath)
        container_list=$(lxc-ls -1 --active)
        for container_name in ${container_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                GIT_DIR="${rootfs}/etc/.git"
                if test -d $GIT_DIR; then
                    expected="700"
                    actual=$(stat -c "%a" $GIT_DIR)
                    [ "$expected" = "$actual" ] || failed "IS_GITPERMS_LXC" "$GIT_DIR must be $expected (in container ${container_name})"
                fi
            fi
        done
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
        last_upgrade=$(date +%s -d "$(zgrep --no-filename --no-messages upgrade /var/log/dpkg.log* | sort -n | tail -1 | cut -f1 -d ' ')")
    fi
    if grep --quiet --no-messages '^mailto="listupgrade-todo@' /etc/evolinux/listupgrade.cnf \
        || grep --quiet --no-messages --extended-regexp '^[[:digit:]]+[[:space:]]+[[:digit:]]+[[:space:]]+[^\*]' /etc/cron.d/listupgrade; then
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
    parts=$(grep --extended-regexp "ext(3|4)" /proc/mounts | cut -d ' ' -f1 | tr -s '\n' ' ')
    FINDMNT_BIN=$(command -v findmnt)
    for part in $parts; do
        blockCount=$(dumpe2fs -h "$part" 2>/dev/null | grep --regexp "Block count:" | grep --extended-regexp --only-matching "[0-9]+")
        # If buggy partition, skip it.
        if [ -z "$blockCount" ]; then
            continue
        fi
        reservedBlockCount=$(dumpe2fs -h "$part" 2>/dev/null | grep --regexp "Reserved block count:" | grep --extended-regexp --only-matching "[0-9]+")
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
check_evolinuxsudogroup() {
    if grep --quiet "^evolinux-sudo:" /etc/group; then
        if [ -f /etc/sudoers.d/evolinux ]; then
            grep --quiet --extended-regexp '^%evolinux-sudo +ALL ?= ?\(ALL:ALL\) ALL' /etc/sudoers.d/evolinux \
                || failed "IS_EVOLINUXSUDOGROUP" "missing evolinux-sudo directive in sudoers file"
        fi
    fi
}
check_userinadmgroup() {
    users=$(grep "^evolinux-sudo:" /etc/group | awk -F: '{print $4}' | tr ',' ' ')
    for user in $users; do
        if ! groups "$user" | grep --quiet adm; then
            failed "IS_USERINADMGROUP" "User $user doesn't belong to \`adm' group"
            test "${VERBOSE}" = 1 || break
        fi
    done
}
check_apache2evolinuxconf() {
    if is_installed apache2; then
        { test -L /etc/apache2/conf-enabled/z-evolinux-defaults.conf \
            && test -L /etc/apache2/conf-enabled/zzz-evolinux-custom.conf \
            && test -f /etc/apache2/ipaddr_whitelist.conf;
        } || failed "IS_APACHE2EVOLINUXCONF" "missing custom evolinux apache config"
    fi
}
check_backportsconf() {
    grep --quiet --no-messages --extended-regexp "^[^#].*backports" /etc/apt/sources.list \
        && failed "IS_BACKPORTSCONF" "backports can't be in main sources list"
}
check_bind9munin() {
    if is_installed bind9; then
        { test -L /etc/munin/plugins/bind9 \
            && test -e /etc/munin/plugin-conf.d/bind9;
        } || failed "IS_BIND9MUNIN" "missing bind plugin for munin"
    fi
}
check_bind9logrotate() {
    if is_installed bind9; then
        test -e /etc/logrotate.d/bind9 || failed "IS_BIND9LOGROTATE" "missing bind logrotate file"
    fi
}
check_drbd_two_primaries() {
    if is_installed drbd-utils; then
        if command -v drbd-overview >/dev/null; then
            if drbd-overview 2>&1 | grep --quiet "Primary/Primary"; then
                failed "IS_DRBDTWOPRIMARIES" "Some DRBD ressources have two primaries, you risk a split brain!"
            fi
        elif command -v drbdadm >/dev/null; then
            if drbdadm role all 2>&1 | grep --quiet 'Primary/Primary'; then
                failed "IS_DRBDTWOPRIMARIES" "Some DRBD ressources have two primaries, you risk a split brain!"
            fi
        fi
    fi
}
check_broadcomfirmware() {
    LSPCI_BIN=$(command -v lspci)
    if [ -x "${LSPCI_BIN}" ]; then
        if ${LSPCI_BIN} | grep --quiet 'NetXtreme II'; then
            { is_installed firmware-bnx2 \
                && apt-cache policy | grep "\bl=Debian\b" | grep --quiet -v "\b,c=non-free\b"
            } || failed "IS_BROADCOMFIRMWARE" "missing non-free repository"
        fi
    else
        failed "IS_BROADCOMFIRMWARE" "lspci not found in ${PATH}"
    fi
}
check_hardwareraidtool() {
    LSPCI_BIN=$(command -v lspci)
    if [ -x "${LSPCI_BIN}" ]; then
        if ${LSPCI_BIN} | grep --quiet 'MegaRAID'; then
            if ! { command -v perccli || command -v perccli2; } >/dev/null  ; then
                # shellcheck disable=SC2015
                is_installed megacli && { is_installed megaclisas-status || is_installed megaraidsas-status; } \
                    || failed "IS_HARDWARERAIDTOOL" "Mega tools not found"
            fi
        fi
        if ${LSPCI_BIN} | grep --quiet 'Hewlett-Packard Company Smart Array'; then
            is_installed cciss-vol-status || failed "IS_HARDWARERAIDTOOL" "cciss-vol-status not installed"
        fi
    else
        failed "IS_HARDWARERAIDTOOL" "lspci not found in ${PATH}"
    fi
}
check_log2mailsystemdunit() {
    systemctl -q is-active log2mail.service \
        || failed "IS_LOG2MAILSYSTEMDUNIT" "log2mail unit not running"
    test -f /etc/systemd/system/log2mail.service \
        || failed "IS_LOG2MAILSYSTEMDUNIT" "missing log2mail unit file"
    test -f /etc/init.d/log2mail \
        && failed "IS_LOG2MAILSYSTEMDUNIT" "/etc/init.d/log2mail may be deleted (use systemd unit)"
}
check_listupgrade() {
    test -f /etc/cron.d/listupgrade \
        || failed "IS_LISTUPGRADE" "missing listupgrade cron"
    test -x /usr/local/sbin/listupgrade.sh || test -x /usr/share/scripts/listupgrade.sh \
        || failed "IS_LISTUPGRADE" "missing listupgrade script or not executable"
}
check_mariadbevolinuxconf() {
    if is_installed mariadb-server; then
        { test -f /etc/mysql/mariadb.conf.d/z-evolinux-defaults.cnf \
            && test -f /etc/mysql/mariadb.conf.d/zzz-evolinux-custom.cnf;
        } || failed "IS_MARIADBEVOLINUXCONF" "missing mariadb custom config"
        fi
}
check_sql_backup() {
    if (is_installed "mysql-server" || is_installed "mariadb-server"); then
        backup_dir="/home/backup"
        if [ -d "${backup_dir}" ]; then
            # You could change the default path in /etc/evocheck.cf
            SQL_BACKUP_PATH="${SQL_BACKUP_PATH:-$(find "${backup_dir}" \( -iname "mysql.bak.gz" -o -iname "mysql.sql.gz" -o -iname "mysqldump.sql.gz" \))}"
            for backup_path in ${SQL_BACKUP_PATH}; do
                if [ ! -f "${backup_path}" ]; then
                    failed "IS_SQL_BACKUP" "MySQL dump is missing (${backup_path})"
                    test "${VERBOSE}" = 1 || break
                fi
            done
        else
            failed "IS_SQL_BACKUP" "${backup_dir}/ is missing"
        fi
    fi
}
check_postgres_backup() {
    if is_installed "postgresql-9*" || is_installed "postgresql-1*"; then
        backup_dir="/home/backup"
        if [ -d "${backup_dir}" ]; then
            # If you use something like barman, you should disable this check
            # You could change the default path in /etc/evocheck.cf
            POSTGRES_BACKUP_PATH="${POSTGRES_BACKUP_PATH:-$(find "${backup_dir}" -iname "pg.dump.bak*")}"
            for backup_path in ${POSTGRES_BACKUP_PATH}; do
                if [ ! -f "${backup_path}" ]; then
                    failed "IS_POSTGRES_BACKUP" "PostgreSQL dump is missing (${backup_path})"
                    test "${VERBOSE}" = 1 || break
                fi
            done
        else
            failed "IS_POSTGRES_BACKUP" "${backup_dir}/ is missing"
        fi
    fi
}
check_mongo_backup() {
    if is_installed "mongodb-org-server"; then
        backup_dir="/home/backup"
        if [ -d "${backup_dir}" ]; then
            # You could change the default path in /etc/evocheck.cf
            MONGO_BACKUP_PATH=${MONGO_BACKUP_PATH:-"${backup_dir}/mongodump"}
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
        else
            failed "IS_MONGO_BACKUP" "${backup_dir}/ is missing"
        fi
    fi
}
check_ldap_backup() {
    if is_installed slapd; then
        backup_dir="/home/backup"
        if [ -d "${backup_dir}" ]; then
            # You could change the default path in /etc/evocheck.cf
            LDAP_BACKUP_PATH="${LDAP_BACKUP_PATH:-$(find "${backup_dir}" -iname "ldap.bak")}"
            test -f "$LDAP_BACKUP_PATH" || failed "IS_LDAP_BACKUP" "LDAP dump is missing (${LDAP_BACKUP_PATH})"
        else
            failed "LDAP_BACKUP_PATH" "${backup_dir}/ is missing"
        fi
    fi
}
check_redis_backup() {
    if is_installed redis-server; then
        backup_dir="/home/backup"
            if [ -d "${backup_dir}" ]; then
            # You could change the default path in /etc/evocheck.cf
            # REDIS_BACKUP_PATH may contain space-separated paths, for example:
            # REDIS_BACKUP_PATH='/home/backup/redis-instance1/dump.rdb /home/backup/redis-instance2/dump.rdb'
            # Warning : this script doesn't handle spaces in file paths !

            REDIS_BACKUP_PATH="${REDIS_BACKUP_PATH:-$(find "${backup_dir}" -iname "*.rdb*")}"

            # Check number of dumps
            n_instances=$(pgrep 'redis-server' | wc -l)
            n_dumps=$(echo $REDIS_BACKUP_PATH | wc -w)
            if [ ${n_dumps} -lt ${n_instances} ]; then
                failed "IS_REDIS_BACKUP" "Missing Redis dump : ${n_instances} instance(s) found versus ${n_dumps} dump(s) found."
            fi

            # Check last dump date
            age_threshold=$(date +"%s" -d "now - 2 days")
            for dump in ${REDIS_BACKUP_PATH}; do
                last_update=$(stat -c "%Z" $dump)
                if [ "${last_update}" -lt "${age_threshold}" ]; then
                    failed "IS_REDIS_BACKUP" "Redis dump ${dump} is older than 2 days."
                fi
            done
        else
            failed "IS_REDIS_BACKUP" "${backup_dir}/ is missing"
        fi
    fi
}
check_elastic_backup() {
    if is_installed elasticsearch; then
        # You could change the default path in /etc/evocheck.cf
        ELASTIC_BACKUP_PATH=${ELASTIC_BACKUP_PATH:-"/home/backup-elasticsearch"}
        test -d "$ELASTIC_BACKUP_PATH" || failed "IS_ELASTIC_BACKUP" "Elastic snapshot is missing (${ELASTIC_BACKUP_PATH})"
    fi
}
check_mariadbsystemdunit() {
    # TODO: check if it is still needed for bullseye
    if evo::os-release::is_debian 11 lt; then
        if is_installed mariadb-server; then
            if systemctl -q is-active mariadb.service; then
                test -f /etc/systemd/system/mariadb.service.d/evolinux.conf \
                    || failed "IS_MARIADBSYSTEMDUNIT" "missing systemd override for mariadb unit"
            fi
        fi
    fi
}
check_mysqlmunin() {
    if is_installed mariadb-server; then
        for file in mysql_bytes mysql_queries mysql_slowqueries \
            mysql_threads mysql_connections mysql_files_tables \
            mysql_innodb_bpool mysql_innodb_bpool_act mysql_innodb_io \
            mysql_innodb_log mysql_innodb_rows mysql_innodb_semaphores \
            mysql_myisam_indexes mysql_qcache mysql_qcache_mem \
            mysql_sorts mysql_tmp_tables; do

            if [[ ! -L /etc/munin/plugins/$file ]]; then
                failed "IS_MYSQLMUNIN" "missing munin plugin '$file'"
                test "${VERBOSE}" = 1 || break
            fi
        done
        munin-run mysql_commands 2> /dev/null > /dev/null
        test $? -eq 0 || failed "IS_MYSQLMUNIN" "Munin plugin mysql_commands returned an error"
    fi
}
check_mysqlnrpe() {
    if is_installed mariadb-server; then
        nagios_file=~nagios/.my.cnf
        if ! test -f ${nagios_file}; then
            failed "IS_MYSQLNRPE" "${nagios_file} is missing"
        elif [ "$(stat -c %U ${nagios_file})" != "nagios" ] \
            || [ "$(stat -c %a ${nagios_file})" != "600" ]; then
            failed "IS_MYSQLNRPE" "${nagios_file} has wrong permissions"
        else
            grep --quiet --extended-regexp "command\[check_mysql\]=.*/usr/lib/nagios/plugins/check_mysql" /etc/nagios/nrpe.d/evolix.cfg \
            || failed "IS_MYSQLNRPE" "check_mysql is missing"
        fi
    fi
}
check_phpevolinuxconf() {
    evo::os-release::is_debian 10 && phpVersion="7.3"
    evo::os-release::is_debian 11 && phpVersion="7.4"
    evo::os-release::is_debian 12 && phpVersion="8.2"
    evo::os-release::is_debian 13 && phpVersion="8.4"

    if is_installed php; then
        { test -f "/etc/php/${phpVersion}/cli/conf.d/z-evolinux-defaults.ini" \
            && test -f "/etc/php/${phpVersion}/cli/conf.d/zzz-evolinux-custom.ini"
        } || failed "IS_PHPEVOLINUXCONF" "missing php evolinux config"
    fi
}
check_squidlogrotate() {
    if is_installed squid; then
        grep --quiet --regexp monthly --regexp daily /etc/logrotate.d/squid \
            || failed "IS_SQUIDLOGROTATE" "missing squid logrotate file"
    fi
}
check_squidevolinuxconf() {
    if is_installed squid; then
        { grep --quiet --no-messages "^CONFIG=/etc/squid/evolinux-defaults.conf$" /etc/default/squid \
            && test -f /etc/squid/evolinux-defaults.conf \
            && test -f /etc/squid/evolinux-whitelist-defaults.conf \
            && test -f /etc/squid/evolinux-whitelist-custom.conf \
            && test -f /etc/squid/evolinux-acl.conf \
            && test -f /etc/squid/evolinux-httpaccess.conf \
            && test -f /etc/squid/evolinux-custom.conf;
        } || failed "IS_SQUIDEVOLINUXCONF" "missing squid evolinux config"
    fi
}
check_duplicate_fs_label() {
    # Do it only if thereis blkid binary
    BLKID_BIN=$(command -v blkid)
    if [ -n "$BLKID_BIN" ]; then
        tmpFile=$(mktemp --tmpdir "evocheck.duplicate_fs_label.XXXXX")
        files_to_cleanup+=("${tmpFile}")

        parts=$($BLKID_BIN -c /dev/null | grep --invert-match --regexp raid_member --regexp EFI_SYSPART | grep --extended-regexp --only-matching ' LABEL=".*"' | cut -d'"' -f2)
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
    grep --quiet --extended-regexp "^evolix:" /etc/passwd \
        && failed "IS_EVOLIX_USER" "evolix user should be deleted, used only for install"
}
check_evoacme_cron() {
    if [ -f "/usr/local/sbin/evoacme" ]; then
        # Old cron file, should be deleted
        test -f /etc/cron.daily/certbot && failed "IS_EVOACME_CRON" "certbot cron is incompatible with evoacme"
        # evoacme cron file should be present
        test -f /etc/cron.daily/evoacme || failed "IS_EVOACME_CRON" "evoacme cron is missing"
    fi
}
check_evoacme_livelinks() {
    EVOACME_BIN=$(command -v evoacme)
    if [ -x "$EVOACME_BIN" ]; then
        # Sometimes evoacme is installed but no certificates has been generated
        numberOfLinks=$(find /etc/letsencrypt/ -type l | wc -l)
        if [ "$numberOfLinks" -gt 0 ]; then
            for live in /etc/letsencrypt/*/live; do
                actualLink=$(readlink -f "$live")
                actualVersion=$(basename "$actualLink")

                certDir=$(dirname "$live")
                certName=$(basename "$certDir")
                # shellcheck disable=SC2012
                lastCertDir=$(ls -ds "${certDir}"/[0-9]* | tail -1)
                lastVersion=$(basename "$lastCertDir")

                if [[ "$lastVersion" != "$actualVersion" ]]; then
                    failed "IS_EVOACME_LIVELINKS" "Certificate \`$certName' hasn't been updated"
                    test "${VERBOSE}" = 1 || break
                fi
            done
        fi
    fi
}
check_apache_confenabled() {
    # Starting from Jessie and Apache 2.4, /etc/apache2/conf.d/
    # must be replaced by conf-available/ and config files symlinked
    # to conf-enabled/
    if [ -f /etc/apache2/apache2.conf ]; then
        test -d /etc/apache2/conf.d/ \
            && failed "IS_APACHE_CONFENABLED" "apache's conf.d directory must not exists"
        grep --quiet 'Include conf.d' /etc/apache2/apache2.conf \
            && failed "IS_APACHE_CONFENABLED" "apache2.conf must not Include conf.d"
    fi
}
check_meltdown_spectre() {
    # /sys/devices/system/cpu/vulnerabilities/
    for vuln in meltdown spectre_v1 spectre_v2; do
        test -f "/sys/devices/system/cpu/vulnerabilities/$vuln" \
            || failed "IS_MELTDOWN_SPECTRE" "vulnerable to $vuln"
        test "${VERBOSE}" = 1 || break
    done
}
check_old_home_dir() {
    homeDir=${homeDir:-/home}
    for dir in "$homeDir"/*; do
        statResult=$(stat -c "%n has owner %u resolved as %U" "$dir" \
            | grep --invert-match --extended-regexp --regexp '.bak' --regexp '\.[0-9]{2}-[0-9]{2}-[0-9]{4}' \
            | grep "UNKNOWN")
        # There is at least one dir matching
        if [[ -n "$statResult" ]]; then
            failed "IS_OLD_HOME_DIR" "$statResult"
            test "${VERBOSE}" = 1 || break
        fi
    done
}
check_tmp_1777() {
    expected="1777"

    actual=$(stat --format "%a" /tmp)
    test "${expected}" = "${actual}" || failed "IS_TMP_1777" "/tmp must be ${expected}"
    test "${VERBOSE}" = 1 || return

    if is_installed lxc; then
        lxc_path=$(lxc-config lxc.lxcpath)
        container_list=$(lxc-ls -1 --active)

        for container_name in ${container_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                if [ -d "${rootfs}/tmp" ]; then
                    actual=$(stat --format "%a" "${rootfs}/tmp")
                    test "${expected}" = "${actual}" || failed "IS_TMP_1777" "${rootfs}/tmp must be ${expected}"
                    test "${VERBOSE}" = 1 || break
                fi
            fi
        done
    fi
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
    # You could change the SSH port in /etc/evocheck.cf
    sshd_args="-C addr=,user=,host=,laddr=,lport=${SSH_PORT:-22}"
    if evo::os-release::is_debian 10; then
        sshd_args="${sshd_args},rdomain="
    fi
    # shellcheck disable=SC2086
    if ! (sshd -T ${sshd_args} 2> /dev/null | grep --quiet --ignore-case 'permitrootlogin no'); then
        failed "IS_SSHPERMITROOTNO" "PermitRoot should be set to no"
    fi
}
check_evomaintenanceusers() {
    users=$(getent group evolinux-sudo | cut -d':' -f4 | tr ',' ' ')
    for user in $users; do
        user_home=$(getent passwd "$user" | cut -d: -f6)
        if [ -n "$user_home" ] && [ -d "$user_home" ]; then
            if ! grep --quiet --no-messages "^trap.*sudo.*evomaintenance.sh" "${user_home}"/.*profile; then
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

        { grep "^export PGPASSWORD" $f | grep --quiet --invert-match "your-passwd" \
            && grep "^PGDB" $f | grep --quiet --invert-match "your-db" \
            && grep "^PGTABLE" $f | grep --quiet --invert-match "your-table" \
            && grep "^PGHOST" $f | grep --quiet --invert-match "your-pg-host" \
            && grep "^FROM" $f | grep --quiet --invert-match "jdoe@example.com" \
            && grep "^FULLFROM" $f | grep --quiet --invert-match "John Doe <jdoe@example.com>" \
            && grep "^URGENCYFROM" $f | grep --quiet --invert-match "mama.doe@example.com" \
            && grep "^URGENCYTEL" $f | grep --quiet --invert-match "06.00.00.00.00" \
            && grep "^REALM" $f | grep --quiet --invert-match "example.com"
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
            echo "${root_crontab}" | grep --quiet "bkctld inc" || failed "IS_EVOBACKUP_INCS" "'bkctld inc' is missing in ${bkctld_cron_file}"
            echo "${root_crontab}" | grep --quiet --extended-regexp "(check-incs.sh|bkctld check-incs)" || failed "IS_EVOBACKUP_INCS" "'check-incs.sh' is missing in ${bkctld_cron_file}"
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
    if grep --quiet --no-messages "archive.debian.org" /etc/apt/sources.list /etc/apt/sources.list.d/*; then
        if ! grep --quiet --no-messages "$aptvalidText" /etc/apt/apt.conf.d/*; then
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
        for pid in $(pgrep "${process_name}"); do
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
check_nginx_letsencrypt_uptodate() {
    if [ -d /etc/nginx ]; then
        snippets=$(find /etc/nginx -type f -name "letsencrypt.conf")
        if [ -n "${snippets}" ]; then
            while read -r snippet; do
                if grep --quiet --extended-regexp "^\s*alias\s+/.+/\.well-known/acme-challenge" "${snippet}"; then
                    failed "IS_NGINX_LETSENCRYPT_UPTODATE" "Nginx snippet ${snippet} is not compatible with Nginx on Debian 9+."
                fi
            done <<< "${snippets}"
        fi
    fi
}
check_lxc_container_resolv_conf() {
    if is_installed lxc; then
        current_resolvers=$(grep ^nameserver /etc/resolv.conf | sed 's/nameserver//g' )
        lxc_path=$(lxc-config lxc.lxcpath)
        container_list=$(lxc-ls -1 --active)

        for container_name in ${container_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                if [ -f "${rootfs}/etc/resolv.conf" ]; then

                    while read -r resolver; do
                        if ! grep --quiet --extended-regexp "^nameserver\s+${resolver}" "${rootfs}/etc/resolv.conf"; then
                            failed "IS_LXC_CONTAINER_RESOLV_CONF" "resolv.conf miss-match beween host and container : missing nameserver ${resolver} in container ${container_name} resolv.conf"
                        fi
                    done <<< "${current_resolvers}"

                else
                    failed "IS_LXC_CONTAINER_RESOLV_CONF" "resolv.conf missing in container ${container_name}"
                fi
            fi
        done
    fi
}
# Check that there are containers if lxc is installed.
check_no_lxc_container() {
    if is_installed lxc; then
        containers_count=$(lxc-ls -1 --active | wc -l)
        if [ "${containers_count}" -eq 0 ]; then
            failed "IS_NO_LXC_CONTAINER" "LXC is installed but have no active container. Consider removing it."
        fi
    fi
}
# Check that in LXC containers, phpXX-fpm services have UMask set to 0007.
check_lxc_php_fpm_service_umask_set() {
    if is_installed lxc; then
        containers_list=$(lxc-ls -1 --active --filter php)
        missing_umask=""
        for container_name in ${containers_list}; do
            # Translate container name in service name
            if [ "${container_name}" = "php56" ]; then
                service="php5-fpm"
            else
                service="${container_name:0:4}.${container_name:4:1}-fpm"
            fi
            umask=$(lxc-attach --name "${container_name}" -- systemctl show -p UMask "$service" | cut -d "=" -f2)
            if [ "$umask" != "0007" ]; then
                missing_umask="${missing_umask} ${container_name}"
            fi
        done
        if [ -n "${missing_umask}" ]; then
            failed "IS_LXC_PHP_FPM_SERVICE_UMASK_SET" "UMask is not set to 0007 in PHP-FPM services of theses containers : ${missing_umask}."
        fi
    fi
}
# Check that LXC containers have the proper Debian version.
check_lxc_php_bad_debian_version() {
    if is_installed lxc; then
        lxc_path=$(lxc-config lxc.lxcpath)
        containers_list=$(lxc-ls -1 --active --filter php)
        missing_umask=""
        for container_name in ${containers_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                if [ "$container_name" = "php56" ]; then
                    grep --quiet 'VERSION_ID="8"' "${rootfs}/etc/os-release" || failed "IS_LXC_PHP_BAD_DEBIAN_VERSION" "Container ${container_name} should use Jessie"
                elif [ "$container_name" = "php70" ]; then
                    grep --quiet 'VERSION_ID="9"' "${rootfs}/etc/os-release" || failed "IS_LXC_PHP_BAD_DEBIAN_VERSION" "Container ${container_name} should use Stretch"
                elif [ "$container_name" = "php73" ]; then
                    grep --quiet 'VERSION_ID="10"' "${rootfs}/etc/os-release" || failed "IS_LXC_PHP_BAD_DEBIAN_VERSION" "Container ${container_name} should use Buster"
                elif [ "$container_name" = "php74" ]; then
                    grep --quiet 'VERSION_ID="11"' "${rootfs}/etc/os-release" || failed "IS_LXC_PHP_BAD_DEBIAN_VERSION" "Container ${container_name} should use Bullseye"
                elif [ "$container_name" = "php82" ]; then
                    grep --quiet 'VERSION_ID="12"' "${rootfs}/etc/os-release" || failed "IS_LXC_PHP_BAD_DEBIAN_VERSION" "Container ${container_name} should use Bookworm"
                elif [ "$container_name" = "php84" ]; then
                    grep --quiet 'VERSION_ID="13"' "${rootfs}/etc/os-release" || failed "IS_LXC_PHP_BAD_DEBIAN_VERSION" "Container ${container_name} should use Trixie"
                fi
            fi
        done
    fi
}
check_lxc_openssh() {
    if is_installed lxc; then
        lxc_path=$(lxc-config lxc.lxcpath)
        container_list=$(lxc-ls -1 --active)
        for container_name in ${containers_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                test -e "${rootfs}/usr/sbin/sshd" && failed "IS_LXC_OPENSSH" "openssh-server should not be installed in container ${container_name}"
            fi
        done
    fi
}
check_lxc_opensmtpd() {
    if is_installed lxc; then
        lxc_path=$(lxc-config lxc.lxcpath)
        container_list=$(lxc-ls -1 --active --filter php)
        for container_name in ${containers_list}; do
            if lxc-info --name "${container_name}" > /dev/null; then
                rootfs="${lxc_path}/${container_name}/rootfs"
                test -e "${rootfs}/usr/sbin/smtpd" || test -e "${rootfs}/usr/sbin/ssmtp" || failed "IS_LXC_OPENSMTPD" "opensmtpd should be installed in container ${container_name}"
            fi
        done
    fi
}

check_monitoringctl() {
    if ! /usr/local/bin/monitoringctl list >/dev/null 2>&1; then
        failed "IS_MONITORINGCTL" "monitoringctl is not installed or has a problem (use 'monitoringctl list' to reproduce)."
    fi
}


download_versions() {
    local file
    file=${1:-}

    local os_codename
    os_codename=$( evo::os-release::get_version_codename )

    ## The file is supposed to list programs : each on a line, then its latest version number
    ## Examples:
    # evoacme 21.06
    # evomaintenance 0.6.4

    versions_url="https://upgrades.evolix.org/versions-${os_codename}"

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

    echo "$PATH" | grep --quiet --fixed-strings "${new_path}" || export PATH="${PATH}:${new_path}"
}
check_versions() {
    versions_file=$(mktemp --tmpdir "evocheck.versions.XXXXX")
    files_to_cleanup+=("${versions_file}")

    download_versions "${versions_file}"
    add_to_path "/usr/share/scripts"

    grep --invert-match '^ *#' < "${versions_file}" | while IFS= read -r line; do
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
check_nrpepressure() {
    # Taken from detect_os function
    DEBIAN_MAIN_VERSION=$(cut -d "." -f 1 < /etc/debian_version)
    if [ "${DEBIAN_MAIN_VERSION}" -ge 12 ]; then
        /usr/local/bin/monitoringctl status pressure_cpu > /dev/null 2>&1
        rc="$?"
        if [ "${rc}" -ne 0 ]; then
            failed "IS_NRPEPRESSURE" "pressure_cpu check not defined or monitoringctl not correctly installed"
        fi
    fi
}
check_postfix_ipv6_disabled() {
    postconf -n 2>/dev/null | grep --no-messages --extended-regex '^inet_protocols\>' | grep --no-messages --invert-match --fixed-strings ipv6 | grep --no-messages --invert-match --fixed-strings all | grep --no-messages --silent --fixed-strings ipv4
    rc="$?"
    if [ "${rc}" -ne 0 ]; then
        failed "IS_POSTFIX_IPV6_DISABLED" "IPv6 must be disabled in Postfix main.cf (inet_protocols = ipv4)"
    fi
}

main() {
    # Default return code : 0 = no error
    RC=0

    main_output_file=$(mktemp --tmpdir "evocheck.main.XXXXX")
    files_to_cleanup+=("${main_output_file}")

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
    test "${IS_POSTFIX_MYDESTINATION:=1}" = 1 && check_postfix_mydestination
    test "${IS_NRPEPOSTFIX:=1}" = 1 && check_nrpepostfix
    test "${IS_CUSTOMSUDOERS:=1}" = 1 && check_customsudoers
    test "${IS_VARTMPFS:=1}" = 1 && check_vartmpfs
    test "${IS_SERVEURBASE:=1}" = 1 && check_serveurbase
    test "${IS_LOGROTATECONF:=1}" = 1 && check_logrotateconf
    test "${IS_SYSLOGCONF:=1}" = 1 && check_syslogconf
    test "${IS_DEBIANSECURITY:=1}" = 1 && check_debiansecurity
    test "${IS_DEBIANSECURITY_LXC:=1}" = 1 && check_debiansecurity_lxc
    test "${IS_BACKPORTS_VERSION:=1}" = 1 && check_backports_version
    test "${IS_OLDPUB:=1}" = 1 && check_oldpub
    test "${IS_OLDPUB_LXC:=1}" = 1 && check_oldpub_lxc
    test "${IS_NEWPUB:=1}" = 1 && check_newpub
    test "${IS_SURY:=1}" = 1 && check_sury
    test "${IS_SURY_LXC:=1}" = 1 && check_sury_lxc
    test "${IS_NOT_DEB822:=0}" = 1 && check_not_deb822
    test "${IS_NO_SIGNED_BY:=0}" = 1 && check_no_signed_by
    test "${IS_APTITUDE:=1}" = 1 && check_aptitude
    test "${IS_APTGETBAK:=1}" = 1 && check_aptgetbak
    test "${IS_USRRO:=1}" = 1 && check_usrro
    test "${IS_TMPNOEXEC:=1}" = 1 && check_tmpnoexec
    test "${IS_HOMENOEXEC:=1}" = 1 && check_homenoexec
    test "${IS_MOUNT_FSTAB:=1}" = 1 && check_mountfstab
    test "${IS_LISTCHANGESCONF:=1}" = 1 && check_listchangesconf
    test "${IS_CUSTOMCRONTAB:=1}" = 1 && check_customcrontab
    test "${IS_SSHALLOWUSERS:=1}" = 1 && check_sshallowusers
    test "${IS_SSHCONFSPLIT:=1}" = 1 && check_sshconfsplit
    test "${IS_SSHLASTMATCH:=0}" = 1 && check_sshlastmatch
    test "${IS_DISKPERF:=0}" = 1 && check_diskperf
    test "${IS_TMOUTPROFILE:=1}" = 1 && check_tmoutprofile
    test "${IS_ALERT5BOOT:=1}" = 1 && check_alert5boot
    test "${IS_ALERT5MINIFW:=1}" = 1 && check_alert5minifw
    test "${IS_ALERT5MINIFW:=1}" = 1 && test "${IS_MINIFW:=1}" = 1 && check_minifw
    test "${IS_NRPEPERMS:=1}" = 1 && check_nrpeperms
    test "${IS_MINIFWPERMS:=1}" = 1 && check_minifwperms
    # Enable when minifirewall is released
    test "${IS_MINIFWINCLUDES:=0}" = 1 && check_minifw_includes
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
    test "${IS_NETWORKING_SERVICE:=1}" = 1 && check_networking_service
    test "${IS_EVOBACKUP:=1}" = 1 && check_evobackup
    test "${IS_FAIL2BAN_PURGE:=1}" = 1 && check_fail2ban_purge
    test "${IS_SSH_FAIL2BAN_JAIL_RENAMED:=1}" = 1 && check_ssh_fail2ban_jail_renamed
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
    test "${IS_ETCGIT_LXC:=1}" = 1 && check_etcgit_lxc
    test "${IS_GITPERMS:=1}" = 1 && check_gitperms
    test "${IS_GITPERMS_LXC:=1}" = 1 && check_gitperms_lxc
    test "${IS_NOTUPGRADED:=1}" = 1 && check_notupgraded
    test "${IS_TUNE2FS_M5:=1}" = 1 && check_tune2fs_m5
    test "${IS_EVOLINUXSUDOGROUP:=1}" = 1 && check_evolinuxsudogroup
    test "${IS_USERINADMGROUP:=1}" = 1 && check_userinadmgroup
    test "${IS_APACHE2EVOLINUXCONF:=1}" = 1 && check_apache2evolinuxconf
    test "${IS_BACKPORTSCONF:=1}" = 1 && check_backportsconf
    test "${IS_BIND9MUNIN:=1}" = 1 && check_bind9munin
    test "${IS_BIND9LOGROTATE:=1}" = 1 && check_bind9logrotate
    test "${IS_DRBDTWOPRIMARIES:=1}" = 1 && check_drbd_two_primaries
    test "${IS_BROADCOMFIRMWARE:=1}" = 1 && check_broadcomfirmware
    test "${IS_HARDWARERAIDTOOL:=1}" = 1 && check_hardwareraidtool
    test "${IS_LOG2MAILSYSTEMDUNIT:=1}" = 1 && check_log2mailsystemdunit
    test "${IS_LISTUPGRADE:=1}" = 1 && check_listupgrade
    test "${IS_MARIADBEVOLINUXCONF:=0}" = 1 && check_mariadbevolinuxconf
    test "${IS_SQL_BACKUP:=1}" = 1 && check_sql_backup
    test "${IS_POSTGRES_BACKUP:=1}" = 1 && check_postgres_backup
    test "${IS_MONGO_BACKUP:=1}" = 1 && check_mongo_backup
    test "${IS_LDAP_BACKUP:=1}" = 1 && check_ldap_backup
    test "${IS_REDIS_BACKUP:=1}" = 1 && check_redis_backup
    test "${IS_ELASTIC_BACKUP:=1}" = 1 && check_elastic_backup
    test "${IS_MARIADBSYSTEMDUNIT:=1}" = 1 && check_mariadbsystemdunit
    test "${IS_MYSQLMUNIN:=1}" = 1 && check_mysqlmunin
    test "${IS_MYSQLNRPE:=1}" = 1 && check_mysqlnrpe
    test "${IS_PHPEVOLINUXCONF:=0}" = 1 && check_phpevolinuxconf
    test "${IS_SQUIDLOGROTATE:=1}" = 1 && check_squidlogrotate
    test "${IS_SQUIDEVOLINUXCONF:=1}" = 1 && check_squidevolinuxconf
    test "${IS_DUPLICATE_FS_LABEL:=1}" = 1 && check_duplicate_fs_label
    test "${IS_EVOLIX_USER:=1}" = 1 && check_evolix_user
    test "${IS_EVOACME_CRON:=1}" = 1 && check_evoacme_cron
    test "${IS_EVOACME_LIVELINKS:=1}" = 1 && check_evoacme_livelinks
    test "${IS_APACHE_CONFENABLED:=1}" = 1 && check_apache_confenabled
    test "${IS_MELTDOWN_SPECTRE:=1}" = 1 && check_meltdown_spectre
    test "${IS_OLD_HOME_DIR:=0}" = 1 && check_old_home_dir
    test "${IS_EVOBACKUP_INCS:=1}" = 1 && check_evobackup_incs
    test "${IS_OSPROBER:=1}" = 1 && check_osprober
    test "${IS_APT_VALID_UNTIL:=1}" = 1 && check_apt_valid_until
    test "${IS_CHROOTED_BINARY_UPTODATE:=1}" = 1 && check_chrooted_binary_uptodate
    test "${IS_NGINX_LETSENCRYPT_UPTODATE:=1}" = 1 && check_nginx_letsencrypt_uptodate
    test "${IS_LXC_CONTAINER_RESOLV_CONF:=1}" = 1 && check_lxc_container_resolv_conf
    test "${IS_NO_LXC_CONTAINER:=1}" = 1 && check_no_lxc_container
    test "${IS_LXC_PHP_FPM_SERVICE_UMASK_SET:=1}" = 1 && check_lxc_php_fpm_service_umask_set
    test "${IS_LXC_PHP_BAD_DEBIAN_VERSION:=1}" = 1 && check_lxc_php_bad_debian_version
    test "${IS_LXC_OPENSSH:=1}" = 1 && check_lxc_openssh
    test "${IS_LXC_OPENSMTPD:=1}" = 1 && check_lxc_opensmtpd
    test "${IS_CHECK_VERSIONS:=1}" = 1 && check_versions
    test "${IS_MONITORINGCTL:=1}" = 1 && check_monitoringctl
    test "${IS_NRPEPRESSURE:=1}" = 1 && check_nrpepressure
    test "${IS_POSTFIX_IPV6_DISABLED:=0}" = 1 && check_postfix_ipv6_disabled

    if [ -f "${main_output_file}" ]; then
        lines_found=$(wc -l < "${main_output_file}")
        # shellcheck disable=SC2086
        if [ ${lines_found} -gt 0 ]; then

            cat "${main_output_file}" 2>&1
        fi
    fi

    exit ${RC}
}
cleanup() {
    # Cleanup tmp files
    # shellcheck disable=SC2068,SC2317
    rm -f ${files_to_cleanup[@]}

    log "$PROGNAME exit."
}

PROGNAME=$(basename "$0")
# shellcheck disable=SC2034
readonly PROGNAME

# shellcheck disable=SC2124
ARGS=$@
readonly ARGS

LOGFILE="/var/log/evocheck.log"
readonly LOGFILE

CONFIGFILE="/etc/evocheck.cf"
readonly CONFIGFILE

DATE_FORMAT="%Y-%m-%d %H:%M:%S"
# shellcheck disable=SC2034
readonly DATEFORMAT

# Disable LANG*
export LANG=C
export LANGUAGE=C

# Source configuration file
# shellcheck disable=SC1091
test -f "${CONFIGFILE}" && . "${CONFIGFILE}"

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

: "${EVOLIBS_SHELL_LIB:=/usr/local/lib/evolibs-shell}"
. "${EVOLIBS_SHELL_LIB}/os-release.sh" || {
    >&2 echo "Unable to load ${EVOLIBS_SHELL_LIB}/os-release.sh"
    exit 1
}

# Keep this after "show_version(); exit 0" which is called by check_versions
# to avoid logging exit twice.
declare -a files_to_cleanup
files_to_cleanup=""
# shellcheck disable=SC2064
trap cleanup EXIT INT TERM

log '-----------------------------------------------'
log "Running ${PROGNAME} ${VERSION}..."

# Log config file content
if [ -f "${CONFIGFILE}" ]; then
    log "Runtime configuration (${CONFIGFILE}):"
    sed -e '/^[[:blank:]]*#/d; s/#.*//; /^[[:blank:]]*$/d' "${CONFIGFILE}" | log
fi

if evo::os-release::is_debian 10 lt; then
    echo "This version of ${PROGNAME} is built for Debian 10 and later." >&2
    exit 1
fi


# shellcheck disable=SC2086
main ${ARGS}

log "End of ${PROGNAME} execution."

