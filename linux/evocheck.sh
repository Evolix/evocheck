#!/bin/bash

# EvoCheck
# Script to verify compliance of a Linux (Debian 10+) server
# powered by Evolix

#set -x

VERSION="25.10.3"
readonly VERSION

# base functions

show_version() {
    cat <<END
evocheck version ${VERSION}

Copyright 2009-2026 Evolix <info@evolix.fr>,
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
  or   evocheck --future
  or   evocheck --quiet
  or   evocheck --verbose
  or   evocheck --min-level 2 --max-level 3

Options
     --cron                  disable a few checks
     --future                enable checks that will be enabled later
 -v, --verbose               display full documentation for failed checks
 -q, --quiet                 nothing is printed on stdout nor stderr
     --min-level X           executes only checkwith level >= X
     --max-level Y           executes only checkwith level <= Y
 -h, --help                  print this message and exit
     --version               print version and exit
END
}

is_quiet() {
    test "${QUIET}" = 1
}
is_verbose() {
    test "${VERBOSE}" = 1
}
is_pack_web() {
    test -e /usr/share/scripts/web-add.sh || test -e /usr/share/scripts/evoadmin/web-add.sh
}
is_installed() {
    for pkg in "$@"; do
        dpkg -l "$pkg" 2> /dev/null | grep --quiet --extended-regexp '^(i|h)i' || return 1
    done
}

# logging

log() {
    local date msg
    date=$(/bin/date +"${DATE_FORMAT}")
    msg="${1:-$(cat /dev/stdin)}"
    
    printf "[%s] %s: %s\\n" "${date}" "${PROGNAME}" "${msg}" >> "${LOGFILE}"
}

failed() {
    local level name comment
    level=$1
    name=$2
    comment=$3

    GLOBAL_RC=1

    case "${level}" in
        "${LEVEL_OPTIONAL}")  tag="OPTIONAL" ;;
        "${LEVEL_STANDARD}")  tag="STANDARD" ;;
        "${LEVEL_IMPORTANT}") tag="IMPORTANT" ;;
        "${LEVEL_MANDATORY}") tag="MANDATORY" ;;
    esac

    if ! is_quiet; then
        if [ -n "${comment}" ]; then
            printf "[%s] %s FAILED! %s\n" "${level}-${tag}" "${name}" "${comment}" >> "${main_output_file}"

        else
            printf "[%s] %s FAILED!\n" "${level}-${tag}" "${name}" >> "${main_output_file}"
        fi
    fi

    # Always log verbose
    printf "[%s] %s FAILED! %s" "${level}-${tag}" "${name}" "${comment}" | log
}
show_doc() {
    local doc
    doc=$1
    if is_verbose && [ -n "${doc}" ]; then
        printf "%s\n" "${doc}" >> "${main_output_file}"
    fi
}
is_level_in_range() {
    test ${LEVEL_STANDARD} -ge ${MIN_LEVEL} && test ${LEVEL_STANDARD} -le ${MAX_LEVEL}
}

# check functions

check_lsbrelease() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LSBRELEASE"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 13 lt; then
            lsb_release_bin=$(command -v lsb_release)
            if [ -x "${lsb_release_bin}" ]; then
                ## only the major version matters
                lhs=$(${lsb_release_bin} --release --short | cut -d "." -f 1)
                rhs=$(cut -d "." -f 1 < /etc/debian_version)
                if [ "$lhs" != "$rhs" ]; then
                    failed "${level}" "${tag}" "release is not consistent between lsb_release (${lhs}) and /etc/debian_version (${rhs})"
                fi
            else
                failed "${level}" "${tag}" "lsb_release is missing or not executable"
            fi
        fi
    # else
    #     echo "${tag} not executed (${level} not in ${MIN_LEVEL}<${MAX_LEVEL})"
    fi
}
check_dpkgwarning() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_DPKGWARNING"

    if is_level_in_range ${level}; then
        test -e /etc/apt/apt.conf.d/z-evolinux.conf \
            || failed "${level}" "${tag}" "/etc/apt/apt.conf.d/z-evolinux.conf is missing"
    fi
}
# Check if localhost, localhost.localdomain and localhost.$mydomain are set in Postfix mydestination option.
check_postfix_mydestination() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_POSTFIX_MYDESTINATION"

    if is_level_in_range ${level}; then
        # shellcheck disable=SC2016
        if ! grep mydestination /etc/postfix/main.cf | grep --quiet --extended-regexp 'localhost([[:blank:]]|$)'; then
            failed "${level}" "${tag}" "'localhost' is missing in Postfix mydestination option."
        fi
        if ! grep mydestination /etc/postfix/main.cf | grep --quiet --fixed-strings 'localhost.localdomain'; then
            failed "${level}" "${tag}" "'localhost.localdomain' is missing in Postfix mydestination option."
        fi
        if ! grep mydestination /etc/postfix/main.cf | grep --quiet --fixed-strings 'localhost.$mydomain'; then
            failed "${level}" "${tag}" "'localhost.\$mydomain' is missing in Postfix mydestination option."
        fi
    fi
}
    # Verifying check_mailq in Nagios NRPE config file. (Option "-M postfix" need to be set if the MTA is Postfix)
check_nrpepostfix() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NRPEPOSTFIX"

    if is_level_in_range ${level}; then
        if is_installed postfix; then
            { test -e /etc/nagios/nrpe.cfg \
                && grep --quiet --recursive "^command.*check_mailq -M postfix" /etc/nagios/nrpe.*;
            } || failed "${level}" "${tag}" "NRPE \"check_mailq\" for postfix is missing"
        fi
    fi
}
# Check if mod-security config file is present
check_customsudoers() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_CUSTOMSUDOERS"

    if is_level_in_range ${level}; then
        grep --extended-regexp --quiet --recursive "umask=0077" /etc/sudoers* || failed "${level}" "${tag}" "missing umask=0077 in sudoers file"
    fi
}
check_vartmpfs() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_VARTMPFS"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 13 lt; then
            findmnt_bin=$(command -v findmnt)
            if [ -x "${findmnt_bin}" ]; then
                ${findmnt_bin} /var/tmp --type tmpfs --noheadings > /dev/null || failed "${level}" "${tag}" "/var/tmp is not a tmpfs"
            else
                df /var/tmp | grep --quiet tmpfs || failed "${level}" "${tag}" "/var/tmp is not a tmpfs"
            fi
        fi
    fi
}
check_serveurbase() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SERVEURBASE"

    if is_level_in_range ${level}; then
        is_installed serveur-base || failed "${level}" "${tag}" "serveur-base package is not installed"
    fi
}
check_logrotateconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LOGROTATECONF"

    if is_level_in_range ${level}; then
        test -e /etc/logrotate.d/zsyslog || failed "${level}" "${tag}" "missing zsyslog in logrotate.d"
    fi
}
check_syslogconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SYSLOGCONF"

    if is_level_in_range ${level}; then
        # Test for modern servers
        if [ ! -f /etc/rsyslog.d/10-evolinux-default.conf ]; then
            # Fallback test for legacy servers
            if ! grep --quiet --ignore-case "Syslog for Pack Evolix" /etc/*syslog*/*.conf /etc/*syslog.conf; then
                failed "${level}" "${tag}" "Evolix syslog config is missing"
            fi
        fi
    fi
}
check_debiansecurity() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_DEBIANSECURITY"

    if is_level_in_range ${level}; then
        # Look for enabled "Debian-Security" sources from the "Debian" origin
        apt-cache policy | grep "\bl=Debian-Security\b" | grep "\bo=Debian\b" | grep --quiet "\bc=main\b"
        test $? -eq 0 || failed "${level}" "${tag}" "missing Debian-Security repository"
    fi
}
check_debiansecurity_lxc() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_DEBIANSECURITY_LXC"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    if [ -f "${rootfs}/etc/debian_version" ]; then
                        debian_lxc_version=$(cut -d "." -f 1 < "${rootfs}/etc/debian_version")
                        if [ "${debian_lxc_version}" -ge 9 ]; then
                            lxc-attach --name "${container_name}" apt-cache policy | grep "\bl=Debian-Security\b" | grep "\bo=Debian\b" | grep --quiet "\bc=main\b"
                            test $? -eq 0 || failed "${level}" "${tag}" "missing Debian-Security repository in container ${container_name}"
                        fi
                    fi
                fi
            done
        fi
    fi
}
check_backports_version() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_BACKPORTS_VERSION"

    if is_level_in_range ${level}; then
        local os_codename
        os_codename=$( evo::os-release::get_version_codename )

        # Look for enabled "Debian Backports" sources from the "Debian" origin
        apt-cache policy | grep "\bl=Debian Backports\b" | grep "\bo=Debian\b" | grep --quiet "\bc=main\b"
        test $? -eq 1 || ( \
            apt-cache policy | grep "\bl=Debian Backports\b" | grep --quiet "\bn=${os_codename}-backports\b" && \
            test $? -eq 0 || failed "${level}" "${tag}" "Debian Backports enabled for another release than ${os_codename}" )
    fi
}
check_oldpub() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_OLDPUB"

    if is_level_in_range ${level}; then
        # Look for enabled pub.evolix.net sources (supersed by pub.evolix.org since Stretch)
        apt-cache policy | grep --quiet pub.evolix.net
        test $? -eq 1 || failed "${level}" "${tag}" "Old pub.evolix.net repository is still enabled"
    fi
}
check_oldpub_lxc() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_OLDPUB_LXC"

    if is_level_in_range ${level}; then
        # Look for enabled pub.evolix.net sources (supersed by pub.evolix.org since Buster as Sury safeguard)
        if is_installed lxc; then
            containers_list=$( lxc-ls -1 --active )
            for container_name in ${containers_list}; do
                apt_cache_bin=$(lxc-attach --name "${container_name}" -- bash -c "command -v apt-cache")
                if [ -x "${apt_cache_bin}" ]; then
                    lxc-attach --name "${container_name}" apt-cache policy | grep --quiet pub.evolix.net
                    test $? -eq 1 || failed "${level}" "${tag}" "Old pub.evolix.net repository is still enabled in container ${container_name}"
                fi
            done
        fi
    fi
}
check_newpub() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NEWPUB"

    if is_level_in_range ${level}; then
        # Look for enabled pub.evolix.org sources
        apt-cache policy | grep "\bl=Evolix\b" | grep --quiet --invert-match php
        test $? -eq 0 || failed "${level}" "${tag}" "New pub.evolix.org repository is missing"
    fi
}
check_sury() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SURY"

    if is_level_in_range ${level}; then
        # Look for enabled packages.sury.org sources
        apt-cache policy | grep --quiet packages.sury.org
        if [ $? -eq 0 ]; then
            apt-cache policy | grep "\bl=Evolix\b" | grep --quiet php
            test $? -eq 0 || failed "${level}" "${tag}" "packages.sury.org is present but our safeguard pub.evolix.org repository is missing"
        fi
    fi
}
check_sury_lxc() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SURY_LXC"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            containers_list=$( lxc-ls -1 --active )
            for container_name in ${containers_list}; do
                apt_cache_bin=$(lxc-attach --name "${container_name}" -- bash -c "command -v apt-cache")
                if [ -x "${apt_cache_bin}" ]; then
                    lxc-attach --name "${container_name}" apt-cache policy | grep --quiet packages.sury.org
                    if [ $? -eq 0 ]; then
                        lxc-attach --name "${container_name}" apt-cache policy | grep "\bl=Evolix\b" | grep --quiet php
                        test $? -eq 0 || failed "${level}" "${tag}" "packages.sury.org is present but our safeguard pub.evolix.org repository is missing in container ${container_name}"
                    fi
                fi
            done
        fi
    fi
}
check_not_deb822() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NOT_DEB822"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 12 ge; then
            for source in /etc/apt/sources.list /etc/apt/sources.list.d/*.list; do
                test -f "${source}" && grep --quiet '^deb' "${source}" && \
                    failed "${level}" "${tag}" "${source} contains a one-line style sources.list entry, and should be converted to deb822 format"
                done
        fi
    fi
}
check_no_signed_by() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NO_SIGNED_BY"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 12 ge; then
            for source in /etc/apt/sources.list.d/*.sources; do
                if [ -f "${source}" ]; then
                    ( grep --quiet '^Signed-by' "${source}" && \
                        failed "${level}" "${tag}" "${source} contains a Source-by entry that should be capitalized as Signed-By" ) || \
                    ( grep --quiet '^Signed-By' "${source}" || \
                        failed "${level}" "${tag}" "${source} has no Signed-By entry" )
                fi
            done
        fi
    fi
}
check_aptitude() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APTITUDE"

    if is_level_in_range ${level}; then
        test -e /usr/bin/aptitude && failed "${level}" "${tag}" "aptitude may not be installed on Debian >=8"
    fi
}
check_aptgetbak() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APTGETBAK"

    if is_level_in_range ${level}; then
        test -e /usr/bin/apt-get.bak && failed "${level}" "${tag}" "prohibit the installation of apt-get.bak with dpkg-divert(1)"
    fi
}
check_usrro() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_USRRO"

    if is_level_in_range ${level}; then
        grep /usr /etc/fstab | grep --quiet --extended-regexp "\bro\b" || failed "${level}" "${tag}" "missing ro directive on fstab for /usr"
    fi
}
check_tmpnoexec() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_TMPNOEXEC"

    if is_level_in_range ${level}; then
        findmnt_bin=$(command -v findmnt)
        if [ -x "${findmnt_bin}" ]; then
            options=$(${findmnt_bin} --noheadings --first-only --output OPTIONS /tmp)
            echo "${options}" | grep --quiet --extended-regexp "\bnoexec\b" || failed "${level}" "${tag}" "/tmp is not mounted with 'noexec'"
        else
            mount | grep "on /tmp" | grep --quiet --extended-regexp "\bnoexec\b" || failed "${level}" "${tag}" "/tmp is not mounted with 'noexec' (WARNING: findmnt(8) is not found)"
        fi
    fi
}
check_homenoexec() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_HOMENOEXEC"

    if is_level_in_range ${level}; then
        findmnt_bin=$(command -v findmnt)
        if [ -x "${findmnt_bin}" ]; then
            options=$(${findmnt_bin} --noheadings --first-only --output OPTIONS /home)
            echo "${options}" | grep --quiet --extended-regexp "\bnoexec\b" || \
            ( grep --quiet --extended-regexp "/home.*noexec" /etc/fstab && \
            failed "${level}" "${tag}" "/home is mounted with 'exec' but /etc/fstab document it as 'noexec'" )
        else
            mount | grep "on /home" | grep --quiet --extended-regexp "\bnoexec\b" || \
            ( grep --quiet --extended-regexp "/home.*noexec" /etc/fstab && \
            failed "${level}" "${tag}" "/home is mounted with 'exec' but /etc/fstab document it as 'noexec' (WARNING: findmnt(8) is not found)" )
        fi
    fi
}
check_mountfstab() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MOUNT_FSTAB"

    if is_level_in_range ${level}; then
        # Test if lsblk available, if not skip this test...
        lsblk_bin=$(command -v lsblk)
        if test -x "${lsblk_bin}"; then
            for mountPoint in $(${lsblk_bin} -o MOUNTPOINT -l -n | grep '/'); do
                grep --quiet --extended-regexp "${mountPoint}\W" /etc/fstab \
                    || failed "${level}" "${tag}" "partition(s) detected mounted but no presence in fstab"
            done
        fi
    fi
}
check_listchangesconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LISTCHANGESCONF"

    if is_level_in_range ${level}; then
        if is_installed apt-listchanges; then
            failed "${level}" "${tag}" "apt-listchanges must not be installed on Debian >=9"
        fi
    fi
}
check_customcrontab() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_CUSTOMCRONTAB"

    if is_level_in_range ${level}; then
        found_lines=$(grep --count --extended-regexp "^(17 \*|25 6|47 6|52 6)" /etc/crontab)
        test "$found_lines" = 4 && failed "${level}" "${tag}" "missing custom field in crontab"
    fi
}
check_sshallowusers() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SSHALLOWUSERS"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 12 ge; then
            if [ -d /etc/ssh/sshd_config.d/ ]; then
                # AllowUsers or AllowGroups should be in /etc/ssh/sshd_config.d/
                grep --extended-regexp --quiet --ignore-case --recursive "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config.d/ \
                    || failed "${level}" "${tag}" "missing AllowUsers or AllowGroups directive in sshd_config.d/*"
            fi
            # AllowUsers or AllowGroups should not be in /etc/ssh/sshd_config
            grep --extended-regexp --quiet --ignore-case "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config \
                && failed "${level}" "${tag}" "AllowUsers or AllowGroups directive present in sshd_config"
        else
            # AllowUsers or AllowGroups should be in /etc/ssh/sshd_config or /etc/ssh/sshd_config.d/
            if [ -d /etc/ssh/sshd_config.d/ ]; then
                grep --extended-regexp --quiet --ignore-case --recursive "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config /etc/ssh/sshd_config.d/ \
                    || failed "${level}" "${tag}" "missing AllowUsers or AllowGroups directive in sshd_config"
            else
                grep --extended-regexp --quiet --ignore-case "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config \
                    || failed "${level}" "${tag}" "missing AllowUsers or AllowGroups directive in sshd_config"
            fi
        fi
    fi
}
check_sshconfsplit() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SSHCONFSPLIT"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 12 ge; then
            ls /etc/ssh/sshd_config.d/* > /dev/null 2> /dev/null \
                || failed "${level}" "${tag}" "No files under /etc/ssh/sshd_config.d"
            diff /usr/share/openssh/sshd_config /etc/ssh/sshd_config > /dev/null 2> /dev/null \
                || failed "${level}" "${tag}" "Files /etc/ssh/sshd_config and /usr/share/openssh/sshd_config differ"
            for f in /etc/ssh/sshd_config.d/z-evolinux-defaults.conf /etc/ssh/sshd_config.d/zzz-evolinux-custom.conf; do
                test -f "${f}" || failed "${level}" "${tag}" "${f} is not a regular file"
            done
        fi
    fi
}
check_sshlastmatch() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SSHLASTMATCH"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 12 ge; then
            for f in /etc/ssh/sshd_config /etc/ssh/sshd_config.d/zzz-evolinux-custom.conf; do
                if ! test -f "${f}"; then
                    continue
                fi
                if ! awk 'BEGIN { last = "all" } tolower($1) == "match" { last = tolower($2) } END { if (last != "all") exit 1 }' "${f}"; then
                    failed "${level}" "${tag}" "last Match directive is not \"Match all\" in ${f}"
                fi
            done
        fi
    fi
}
check_tmoutprofile() {
    local level tag
    level=${LEVEL_STANDARD}
    tag=""

    if is_level_in_range ${level}; then
        grep --no-messages --quiet "TMOUT=" /etc/profile /etc/profile.d/evolinux.sh || failed "${level}" "${tag}"IS_TMOUTPROFILE "TMOUT is not set"
    fi
}
check_alert5boot() {
    local level tag
    level=${LEVEL_STANDARD}
    tag=""

    if is_level_in_range ${level}; then
        grep --quiet --no-messages "^date" /usr/share/scripts/alert5.sh || failed "${level}" "${tag}"IS_ALERT5BOOT "boot mail is not sent by alert5 init script"
        if [ -f /etc/systemd/system/alert5.service ]; then
            systemctl is-enabled alert5.service -q || failed "${level}" "${tag}"IS_ALERT5BOOT "alert5 unit is not enabled"
        else
            failed "${level}" "${tag}"IS_ALERT5BOOT "alert5 unit file is missing"
        fi
    fi
}
is_minifirewall_native_systemd() {
    systemctl list-unit-files minifirewall.service | grep minifirewall.service | grep --quiet --invert-match generated
}
check_alert5minifw() {
    local level tag
    level=${LEVEL_STANDARD}
    tag=""

    if is_level_in_range ${level}; then
        if ! is_minifirewall_native_systemd; then
            grep --quiet --no-messages "^/etc/init.d/minifirewall" /usr/share/scripts/alert5.sh \
                || failed "${level}" "${tag}"IS_ALERT5MINIFW "Minifirewall is not started by alert5 script or script is missing"
        fi
    fi
}
check_minifw() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MINIFW"

    if is_level_in_range ${level}; then
        {
            if is_minifirewall_native_systemd; then
                systemctl is-active minifirewall.service >/dev/null 2>&1
            else
                if test -x /usr/share/scripts/minifirewall_status; then
                    /usr/share/scripts/minifirewall_status > /dev/null 2>&1
                else
                    /sbin/iptables -L -n 2> /dev/null | grep --quiet --extended-regexp "^(DROP\s+(udp|17)|ACCEPT\s+(icmp|1))\s+--\s+0\.0\.0\.0\/0\s+0\.0\.0\.0\/0\s*$"
                fi
            fi
        } || failed "${level}" "${tag}" "minifirewall seems not started"
    fi
}
check_minifw_includes() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MINIFWINCLUDES"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 11 ge; then
            if [ -f "/etc/default/minifirewall" ]; then
                if grep --quiet --extended-regexp --regexp '^\s*/sbin/iptables' --regexp '^\s*/sbin/ip6tables' "/etc/default/minifirewall"; then
                    failed "${level}" "${tag}" "minifirewall has direct iptables invocations in /etc/default/minifirewall that should go in /etc/minifirewall.d/"
                fi
            fi
        fi
    fi
}
check_minifw_related() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MINIFW_RELATED"

    if is_level_in_range ${level}; then
        if [ -f "/etc/default/minifirewall" ] || [ -d "/etc/minifirewall.d/" ]; then
            if grep --no-messages --quiet --fixed-strings "RELATED" "/etc/default/minifirewall" "/etc/minifirewall.d/"*; then
                failed "${level}" "${tag}" "RELATED should not be used in minifirewall configuration"
            fi
        fi
    fi
}
check_nrpeperms() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NRPEPERMS"

    if is_level_in_range ${level}; then
        if [ -d /etc/nagios ]; then
            nagiosDir="/etc/nagios"
            actual=$(stat --format "%a" $nagiosDir)
            expected="750"
            test "$expected" = "$actual" || failed "${level}" "${tag}" "${nagiosDir} must be ${expected}"
        fi
    fi
}
check_minifwperms() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MINIFWPERMS"

    if is_level_in_range ${level}; then
        if [ -f "/etc/default/minifirewall" ]; then
            actual=$(stat --format "%a" "/etc/default/minifirewall")
            expected="600"
            test "$expected" = "$actual" || failed "${level}" "${tag}" "/etc/default/minifirewall must be ${expected}"
        fi
    fi
}
check_nrpepid() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NRPEPID"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 11 lt; then
            { test -e /etc/nagios/nrpe.cfg \
                && grep --quiet "^pid_file=/var/run/nagios/nrpe.pid" /etc/nagios/nrpe.cfg;
            } || failed "${level}" "${tag}" "missing or wrong pid_file directive in nrpe.cfg"
        else
            { test -e /etc/nagios/nrpe.cfg \
                && grep --quiet "^pid_file=/run/nagios/nrpe.pid" /etc/nagios/nrpe.cfg;
            } || failed "${level}" "${tag}" "missing or wrong pid_file directive in nrpe.cfg"
        fi
    fi
}
check_grsecprocs() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_GRSECPROCS"

    if is_level_in_range ${level}; then
        if uname -a | grep --quiet grsec; then
            { grep --quiet "^command.check_total_procs..sudo" /etc/nagios/nrpe.cfg \
                && grep --after-context=1 "^\[processes\]" /etc/munin/plugin-conf.d/munin-node | grep --quiet "^user root";
            } || failed "${level}" "${tag}" "missing munin's plugin processes directive for grsec"
        fi
    fi
}
check_apachemunin() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APACHEMUNIN"

    if is_level_in_range ${level}; then
        if test -e /etc/apache2/apache2.conf; then
            { test -h /etc/apache2/mods-enabled/status.load \
                && test -h /etc/munin/plugins/apache_accesses \
                && test -h /etc/munin/plugins/apache_processes \
                && test -h /etc/munin/plugins/apache_volume;
            } || failed "${level}" "${tag}" "missing munin plugins for Apache"
        fi
    fi
}
# Verification mytop + Munin si MySQL
check_mysqlutils() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MYSQLUTILS"

    if is_level_in_range ${level}; then
        MYSQL_ADMIN=${MYSQL_ADMIN:-mysqladmin}
        if is_installed mysql-server; then
            # With Debian 11 and later, root can connect to MariaDB with the socket
            if evo::os-release::is_debian 11 lt; then
                # You can configure MYSQL_ADMIN in evocheck.cf
                if ! grep --quiet --no-messages "^user *= *${MYSQL_ADMIN}" /root/.my.cnf; then
                    failed "${level}" "${tag}" "${MYSQL_ADMIN} missing in /root/.my.cnf"
                fi
            fi
            if ! test -x /usr/bin/mytop; then
                if ! test -x /usr/local/bin/mytop; then
                    failed "${level}" "${tag}" "mytop binary missing"
                fi
            fi
            if ! grep --quiet --no-messages '^user *=' /root/.mytop; then
                failed "${level}" "${tag}" "credentials missing in /root/.mytop"
            fi
        fi
    fi
}
# Verification de la configuration du raid soft (mdadm)
check_raidsoft() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_RAIDSOFT"

    if is_level_in_range ${level}; then
        if test -e /proc/mdstat && grep --quiet md /proc/mdstat; then
            { grep --quiet "^AUTOCHECK=true" /etc/default/mdadm \
                && grep --quiet "^START_DAEMON=true" /etc/default/mdadm \
                && grep --quiet --invert-match "^MAILADDR ___MAIL___" /etc/mdadm/mdadm.conf;
            } || failed "${level}" "${tag}" "missing or wrong config for mdadm"
        fi
    fi
}
# Verification du LogFormat de AWStats
check_awstatslogformat() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_AWSTATSLOGFORMAT"

    if is_level_in_range ${level}; then
        if is_installed apache2 awstats; then
            awstatsFile="/etc/awstats/awstats.conf.local"
            grep --quiet --extended-regexp '^LogFormat=1' $awstatsFile \
                || failed "${level}" "${tag}" "missing or wrong LogFormat directive in $awstatsFile"
        fi
    fi
}
# Verification de la présence de la config logrotate pour Munin
check_muninlogrotate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MUNINLOGROTATE"

    if is_level_in_range ${level}; then
        { test -e /etc/logrotate.d/munin-node \
            && test -e /etc/logrotate.d/munin;
        } || failed "${level}" "${tag}" "missing lorotate file for munin"
    fi
}    
# Verification de l'activation de Squid dans le cas d'un pack mail
check_squid() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SQUID"

    if is_level_in_range ${level}; then
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
            || failed "${level}" "${tag}" "missing squid rules in minifirewall"
        fi
    fi
}
check_evomaintenance_fw() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOMAINTENANCE_FW"

    if is_level_in_range ${level}; then
        if [ -f "/etc/default/minifirewall" ]; then
            hook_db=$(grep --extended-regexp '^\s*HOOK_DB' /etc/evomaintenance.cf | tr -d ' ' | cut -d= -f2)
            rulesNumber=$(grep --count --extended-regexp "/sbin/iptables -A INPUT -p tcp --sport 5432 --dport 1024:65535 -s .* -m state --state ESTABLISHED(,RELATED)? -j ACCEPT" "/etc/default/minifirewall")
            if [ "$hook_db" = "1" ] && [ "$rulesNumber" -lt 2 ]; then
                failed "${level}" "${tag}" "HOOK_DB is enabled but missing evomaintenance rules in minifirewall"
            fi
        fi
    fi
}
# Verification de la conf et de l'activation de mod-deflate
check_moddeflate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MODDEFLATE"

    if is_level_in_range ${level}; then
        f=/etc/apache2/mods-enabled/deflate.conf
        if is_installed apache2.2; then
            { test -e $f && grep --quiet "AddOutputFilterByType DEFLATE text/html text/plain text/xml" $f \
                && grep --quiet "AddOutputFilterByType DEFLATE text/css" $f \
                && grep --quiet "AddOutputFilterByType DEFLATE application/x-javascript application/javascript" $f;
            } || failed "${level}" "${tag}" "missing AddOutputFilterByType directive for apache mod deflate"
        fi
    fi
}
# Verification de la conf log2mail
check_log2mailrunning() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LOG2MAILRUNNING"

    if is_level_in_range ${level}; then
        if is_pack_web && is_installed log2mail; then
            pgrep log2mail >/dev/null || failed "${level}" "${tag}" "log2mail is not running"
        fi
    fi
}
check_log2mailapache() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LOG2MAILAPACHE"

    if is_level_in_range ${level}; then
        conf=/etc/log2mail/config/apache
        if is_pack_web && is_installed log2mail; then
            grep --no-messages --quiet "^file = /var/log/apache2/error.log" $conf \
                || failed "${level}" "${tag}" "missing log2mail directive for apache"
        fi
    fi
}
check_log2mailmysql() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LOG2MAILMYSQL"

    if is_level_in_range ${level}; then
        if is_pack_web && is_installed log2mail; then
            grep --no-messages --quiet "^file = /var/log/syslog" /etc/log2mail/config/{default,mysql,mysql.conf} \
                || failed "${level}" "${tag}" "missing log2mail directive for mysql"
        fi
    fi
}
check_log2mailsquid() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LOG2MAILSQUID"

    if is_level_in_range ${level}; then
        if is_pack_web && is_installed log2mail; then
            grep --no-messages --quiet "^file = /var/log/squid.*/access.log" /etc/log2mail/config/* \
                || failed "${level}" "${tag}" "missing log2mail directive for squid"
        fi
    fi
}
# Verification si bind est chroote
check_bindchroot() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_BINDCHROOT"

    if is_level_in_range ${level}; then
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
                        failed "${level}" "${tag}" "the chrooted bind binary is different than the original binary"
                    fi
                else
                    failed "${level}" "${tag}" "bind process is not chrooted"
                fi
            fi
        fi
    fi
}
# /etc/network/interfaces should be present, we don't manage systemd-network yet
check_network_interfaces() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NETWORK_INTERFACES"

    if is_level_in_range ${level}; then
        if ! test -f /etc/network/interfaces; then
            failed "${level}" "${tag}" "systemd network configuration is not supported yet"
        fi
    fi
}
# Verify if all if are in auto
check_autoif() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_AUTOIF"

    if is_level_in_range ${level}; then
        if test -f /etc/network/interfaces; then
            interfaces=$(/sbin/ip address show up | grep "^[0-9]*:" | grep --extended-regexp --invert-match "(lo|vnet|docker|veth|tun|tap|macvtap|vrrp|lxcbr|wg)" | cut -d " " -f 2 | tr -d : | cut -d@ -f1 | tr "\n" " ")
            for interface in $interfaces; do
                if grep --quiet --dereference-recursive "^iface $interface" /etc/network/interfaces* && ! grep --quiet --dereference-recursive "^auto $interface" /etc/network/interfaces*; then
                    failed "${level}" "${tag}" "Network interface \`${interface}' is statically defined but not set to auto"
                fi
            done
        fi
    fi
}
# Network conf verification
check_interfacesgw() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_INTERFACESGW"

    if is_level_in_range ${level}; then
        if test -f /etc/network/interfaces; then
            number=$(grep --extended-regexp --count "^[^#]*gateway [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" /etc/network/interfaces)
            test "$number" -gt 1 && failed "${level}" "${tag}" "there is more than 1 IPv4 gateway"
            number=$(grep --extended-regexp --count "^[^#]*gateway [0-9a-fA-F]+:" /etc/network/interfaces)
            test "$number" -gt 1 && failed "${level}" "${tag}" "there is more than 1 IPv6 gateway"
        fi
    fi
}
check_interfacesnetmask() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_INTERFACESNETMASK"

    if is_level_in_range ${level}; then
        if test -f /etc/network/interfaces; then
            addresses_number=$(grep "address" /etc/network/interfaces | grep -cv -e "hwaddress" -e "#")
            symbol_netmask_number=$(grep address /etc/network/interfaces | grep -v "#" | grep -c "/")
            text_netmask_number=$(grep "netmask" /etc/network/interfaces | grep -cv -e "#" -e "route add" -e "route del")
            if [ "$((symbol_netmask_number + text_netmask_number))" -ne "$addresses_number" ]; then
                failed "${level}" "${tag}" "the number of addresses configured is not equal to the number of netmask configured : one netmask is missing or duplicated"
            fi
        fi
    fi
}
# Verification de l’état du service networking
check_networking_service() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NETWORKING_SERVICE"

    if is_level_in_range ${level}; then
        if systemctl is-enabled networking.service > /dev/null; then
            if ! systemctl is-active networking.service > /dev/null; then
                failed "${level}" "${tag}" "networking.service is not active"
            fi
        fi
    fi
}
# Verification de la mise en place d'evobackup
check_evobackup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOBACKUP"

    if is_level_in_range ${level}; then
        evobackup_found=$(find /etc/cron* -name '*evobackup*' | wc -l)
        test "$evobackup_found" -gt 0 || failed "${level}" "${tag}" "missing evobackup cron"
    fi
}
# Vérification de la mise en place d'un cron de purge de la base SQLite de Fail2ban
check_fail2ban_purge() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_FAIL2BAN_PURGE"

    if is_level_in_range ${level}; then
        # Nécessaire seulement en Debian 9 ou 10
        if evo::os-release::is_debian 11 lt; then
        if is_installed fail2ban; then
            test -f /etc/cron.daily/fail2ban_dbpurge || failed "${level}" "${tag}" "missing script fail2ban_dbpurge cron"
        fi
        fi
    fi
}
# Vérification qu'il ne reste pas des jails nommées ssh non renommées en sshd
check_ssh_fail2ban_jail_renamed() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SSH_FAIL2BAN_JAIL_RENAMED"

    if is_level_in_range ${level}; then
        if is_installed fail2ban && [ -f /etc/fail2ban/jail.local ]; then
            if grep --quiet --fixed-strings "[ssh]" /etc/fail2ban/jail.local; then
                failed "${level}" "${tag}" "Jail ssh must be renamed sshd in fail2ban >= 0.9."
            fi
        fi
    fi
}
# Vérification de l'exclusion des montages (NFS) dans les sauvegardes
check_evobackup_exclude_mount() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOBACKUP_EXCLUDE_MOUNT"

    if is_level_in_range ${level}; then
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
                        failed "${level}" "${tag}" "${mount} is not excluded from ${evobackup_file} backup script"
                    done
                fi
            fi
        done
    fi
}
# Verification de la presence du userlogrotate
check_userlogrotate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_USERLOGROTATE"

    if is_level_in_range ${level}; then
        if is_pack_web; then
            test -x /etc/cron.weekly/userlogrotate || failed "${level}" "${tag}" "missing userlogrotate cron"
        fi
    fi
}
# Verification de la syntaxe de la conf d'Apache
check_apachectl() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APACHECTL"

    if is_level_in_range ${level}; then
        if is_installed apache2; then
            /usr/sbin/apache2ctl configtest 2>&1 | grep --quiet "^Syntax OK$" \
                || failed "${level}" "${tag}" "apache errors detected, run a configtest"
        fi
    fi
}
# Check if there is regular files in Apache sites-enabled.
check_apachesymlink() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APACHESYMLINK"

    if is_level_in_range ${level}; then
        if is_installed apache2; then
            apacheFind=$(find /etc/apache2/sites-enabled ! -type l -type f -print)
            nbApacheFind=$(wc -m <<< "$apacheFind")
            if [[ $nbApacheFind -gt 1 ]]; then
                while read -r line; do
                    failed "${level}" "${tag}" "Not a symlink: $line"
                done <<< "$apacheFind"
            fi
        fi
    fi
}
# Check if there is real IP addresses in Allow/Deny directives (no trailing space, inline comments or so).
check_apacheipinallow() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APACHEIPINALLOW"

    if is_level_in_range ${level}; then
        # Note: Replace "exit 1" by "print" in Perl code to debug it.
        if is_installed apache2; then
            grep -I --recursive --extended-regexp "^[^#] *(Allow|Deny) from" /etc/apache2/ \
                | grep --ignore-case --invert-match "from all" \
                | grep --ignore-case --invert-match "env=" \
                | perl -ne 'exit 1 unless (/from( [\da-f:.\/]+)+$/i)' \
                || failed "${level}" "${tag}" "bad (Allow|Deny) directives in apache"
        fi
    fi
}
# Check if default Apache configuration file for munin is absent (or empty or commented).
check_muninapacheconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MUNINAPACHECONF"

    if is_level_in_range ${level}; then
        muninconf="/etc/apache2/conf-available/munin.conf"
        if is_installed apache2; then
            test -e $muninconf && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "$muninconf" \
                && failed "${level}" "${tag}" "default munin configuration may be commented or disabled"
        fi
    fi
}
# Check if default Apache configuration file for phpMyAdmin is absent (or empty or commented).
check_phpmyadminapacheconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_PHPMYADMINAPACHECONF"

    if is_level_in_range ${level}; then
        phpmyadminconf0="/etc/apache2/conf-available/phpmyadmin.conf"
        phpmyadminconf1="/etc/apache2/conf-enabled/phpmyadmin.conf"
        if is_installed apache2; then
            test -e "${phpmyadminconf0}" && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "${phpmyadminconf0}" \
                && failed "${level}" "${tag}" "default phpmyadmin configuration (${phpmyadminconf0}) should be commented or disabled"
            test -e "${phpmyadminconf1}" && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "${phpmyadminconf1}" \
                && failed "${level}" "${tag}" "default phpmyadmin configuration (${phpmyadminconf1}) should be commented or disabled"
        fi
    fi
}
# Check if default Apache configuration file for phpPgAdmin is absent (or empty or commented).
check_phppgadminapacheconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_PHPPGADMINAPACHECONF"

    if is_level_in_range ${level}; then
        phppgadminconf0="/etc/apache2/conf-available/phppgadmin.conf"
        phppgadminconf1="/etc/apache2/conf-enabled/phppgadmin.conf"
        if is_installed apache2; then
            test -e "${phppgadminconf0}" && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "${phppgadminconf0}" \
                && failed "${level}" "${tag}" "default phppgadmin configuration (${phppgadminconf0}) should be commented or disabled"
            test -e "${phppgadminconf1}" && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "${phppgadminconf1}" \
                && failed "${level}" "${tag}" "default phppgadmin configuration (${phppgadminconf1}) should be commented or disabled"
        fi
    fi
}
# Check if default Apache configuration file for phpMyAdmin is absent (or empty or commented).
check_phpldapadminapacheconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_PHPLDAPADMINAPACHECONF"

    if is_level_in_range ${level}; then
        phpldapadminconf0="/etc/apache2/conf-available/phpldapadmin.conf"
        phpldapadminconf1="/etc/apache2/conf-enabled/phpldapadmin.conf"
        if is_installed apache2; then
            test -e "${phpldapadminconf0}" && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "${phpldapadminconf0}" \
                && failed "${level}" "${tag}" "default phpldapadmin configuration (${phpldapadminconf0}) should be commented or disabled"
            test -e "${phpldapadminconf1}" && grep --quiet --invert-match --extended-regexp "^( |\t)*#" "${phpldapadminconf1}" \
                && failed "${level}" "${tag}" "default phpldapadmin configuration (${phpldapadminconf1}) should be commented or disabled"
        fi
    fi
}
# Verification si le système doit redémarrer suite màj kernel.
check_kerneluptodate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_KERNELUPTODATE"

    if is_level_in_range ${level}; then
        if is_installed linux-image*; then
            # shellcheck disable=SC2012
            kernel_installed_at=$(date -d "$(ls --full-time -lcrt /boot/*lin* | tail -n1 | awk '{print $6}')" +%s)
            last_reboot_at=$(($(date +%s) - $(cut -f1 -d '.' /proc/uptime)))
            if [ "$kernel_installed_at" -gt "$last_reboot_at" ]; then
                failed "${level}" "${tag}" "machine is running an outdated kernel, reboot advised"
            fi
        fi
    fi
}
# Check if the server is running for more than a year.
check_uptime() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_UPTIME"

    if is_level_in_range ${level}; then
        if is_installed linux-image*; then
            limit=$(date -d "now - 2 year" +%s)
            last_reboot_at=$(($(date +%s) - $(cut -f1 -d '.' /proc/uptime)))
            if [ "$limit" -gt "$last_reboot_at" ]; then
                failed "${level}" "${tag}" "machine has an uptime of more than 2 years, reboot on new kernel advised"
            fi
        fi
    fi
}
# Check if munin-node running and RRD files are up to date.
check_muninrunning() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MUNINRUNNING"

    if is_level_in_range ${level}; then
        if ! pgrep munin-node >/dev/null; then
            failed "${level}" "${tag}" "Munin is not running"
        elif [ -d "/var/lib/munin/" ] && [ -d "/var/cache/munin/" ]; then
            limit=$(date +"%s" -d "now - 10 minutes")

            if [ -n "$(find /var/lib/munin/ -name '*load-g.rrd')" ]; then
                updated_at=$(stat -c "%Y" /var/lib/munin/*/*load-g.rrd |sort |tail -1)
                [ "$limit" -gt "$updated_at" ] && failed "${level}" "${tag}" "Munin load RRD has not been updated in the last 10 minutes"
            else
                failed "${level}" "${tag}" "Munin is not installed properly (load RRD not found)"
            fi

            if [ -n "$(find  /var/cache/munin/www/ -name 'load-day.png')" ]; then
                updated_at=$(stat -c "%Y" /var/cache/munin/www/*/*/load-day.png |sort |tail -1)
                grep --no-messages --quiet "^graph_strategy cron" /etc/munin/munin.conf && [ "$limit" -gt "$updated_at" ] && failed "${level}" "${tag}" "Munin load PNG has not been updated in the last 10 minutes"
            else
                failed "${level}" "${tag}" "Munin is not installed properly (load PNG not found)"
            fi
        else
            failed "${level}" "${tag}" "Munin is not installed properly (main directories are missing)"
        fi
    fi
}
# Check if files in /home/backup/ are up-to-date
check_backupuptodate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_BACKUPUPTODATE"

    if is_level_in_range ${level}; then
        backup_dir="/home/backup"
        if [ -d "${backup_dir}" ]; then
            if [ -n "$(ls -A ${backup_dir})" ]; then
                find "${backup_dir}" -maxdepth 1 -type f | while read -r file; do
                    limit=$(date +"%s" -d "now - 2 day")
                    updated_at=$(stat -c "%Y" "$file")

                    if [ "$limit" -gt "$updated_at" ]; then
                        failed "${level}" "${tag}" "$file has not been backed up"
                    fi
                done
            else
                failed "${level}" "${tag}" "${backup_dir}/ is empty"
            fi
        else
            failed "${level}" "${tag}" "${backup_dir}/ is missing"
        fi
    fi
}
check_etcgit() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_ETCGIT"

    if is_level_in_range ${level}; then
        export GIT_DIR="/etc/.git" GIT_WORK_TREE="/etc"
        git rev-parse --is-inside-work-tree > /dev/null 2>&1 \
            || failed "${level}" "${tag}" "/etc is not a git repository"
    fi
}
check_etcgit_lxc() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_ETCGIT_LXC"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    export GIT_DIR="${rootfs}/etc/.git"
                    export GIT_WORK_TREE="${rootfs}/etc"
                    git rev-parse --is-inside-work-tree > /dev/null 2>&1 \
                        || failed "${level}" "${tag}" "/etc is not a git repository in container ${container_name}"
                fi
            done
        fi
    fi
}
# Check if /etc/.git/ has read/write permissions for root only.
check_gitperms() {
    local level tag rc
    rc=0
    level=${LEVEL_STANDARD}
    tag="IS_GITPERMS"
    doc=$(cat <<EODOC
# Git repositories must have "700" permissions.
# 
# Fix with:
# ~~~
# chmod 700 /path/to/repository/.git
# ~~~
EODOC
)

    if is_level_in_range ${level}; then
        for git_dir in "/etc/.git" "/etc/bind.git" "/usr/share/scripts/.git"; do
            if [ -d "${git_dir}" ]; then
                expected="700"
                actual=$(stat -c "%a" $git_dir)
                if [ "${expected}" != "${actual}" ]; then
                    rc=1
                    failed "${level}" "${tag}" "${git_dir} must be ${expected}"
                fi
            fi
        done
        test "${rc}" != 0 && show_doc "${doc}"
    fi
}
check_gitperms_lxc() {
    local level tag rc
    rc=0
    level=${LEVEL_STANDARD}
    tag="IS_GITPERMS_LXC"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    git_dir="${rootfs}/etc/.git"
                    if test -d "${git_dir}"; then
                        expected="700"
                        actual=$(stat -c "%a" "${git_dir}")
                        if [ "${expected}" != "${actual}" ]; then
                            failed "${level}" "${tag}" "$git_dir must be $expected (in container ${container_name})"
                        fi
                    fi
                fi
            done
            test ${rc} != 0 && is_verbose && cat <<EODOC
Git repositories must have "700" permissions.

Fix with:
~~~
chmod 700 /path/to/repository/.git
~~~
EODOC
        fi
    fi
}
# Check if no package has been upgraded since $limit.
check_notupgraded() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NOTUPGRADED"

    if is_level_in_range ${level}; then
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
            [ "$install_date" -lt "$limit" ] && failed "${level}" "${tag}" "The system has never been updated"
        else
            [ "$last_upgrade" -lt "$limit" ] && failed "${level}" "${tag}" "The system hasn't been updated for too long"
        fi
    fi
}
# Check if reserved blocks for root is at least 5% on every mounted partitions.
check_tune2fs_m5() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_TUNE2FS_M5"

    if is_level_in_range ${level}; then
        min=5
        parts=$(grep --extended-regexp "ext(3|4)" /proc/mounts | cut -d ' ' -f1 | tr -s '\n' ' ')
        findmnt_bin=$(command -v findmnt)
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
                if [ -x "${findmnt_bin}" ]; then
                    mount=$(${findmnt_bin} --noheadings --first-only --output TARGET "${part}")
                else
                    mount="unknown mount point"
                fi
                failed "${level}" "${tag}" "Partition ${part} (${mount}) has less than ${min}% reserved blocks (${percentage}%)"
            fi
        done
    fi
}
check_evolinuxsudogroup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOLINUXSUDOGROUP"

    if is_level_in_range ${level}; then
        if grep --quiet "^evolinux-sudo:" /etc/group; then
            if [ -f /etc/sudoers.d/evolinux ]; then
                grep --quiet --extended-regexp '^%evolinux-sudo +ALL ?= ?\(ALL:ALL\) ALL' /etc/sudoers.d/evolinux \
                    || failed "${level}" "${tag}" "missing evolinux-sudo directive in sudoers file"
            fi
        fi
    fi
}
check_userinadmgroup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_USERINADMGROUP"

    if is_level_in_range ${level}; then
        users=$(grep "^evolinux-sudo:" /etc/group | awk -F: '{print $4}' | tr ',' ' ')
        for user in $users; do
            if ! groups "$user" | grep --quiet adm; then
                failed "${level}" "${tag}" "User $user doesn't belong to \`adm' group"
            fi
        done
    fi
}
check_apache2evolinuxconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APACHE2EVOLINUXCONF"

    if is_level_in_range ${level}; then
        if is_installed apache2; then
            { test -L /etc/apache2/conf-enabled/z-evolinux-defaults.conf \
                && test -L /etc/apache2/conf-enabled/zzz-evolinux-custom.conf \
                && test -f /etc/apache2/ipaddr_whitelist.conf;
            } || failed "${level}" "${tag}" "missing custom evolinux apache config"
        fi
    fi
}
check_backportsconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_BACKPORTSCONF"

    if is_level_in_range ${level}; then
        grep --quiet --no-messages --extended-regexp "^[^#].*backports" /etc/apt/sources.list \
            && failed "${level}" "${tag}" "backports can't be in main sources list"
    fi
}
check_bind9munin() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_BIND9MUNIN"

    if is_level_in_range ${level}; then
        if is_installed bind9; then
            { test -L /etc/munin/plugins/bind9 \
                && test -e /etc/munin/plugin-conf.d/bind9;
            } || failed "${level}" "${tag}" "missing bind plugin for munin"
        fi
    fi
}
check_bind9logrotate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_BIND9LOGROTATE"

    if is_level_in_range ${level}; then
        if is_installed bind9; then
            test -e /etc/logrotate.d/bind9 || failed "${level}" "${tag}" "missing bind logrotate file"
        fi
    fi
}
check_drbd_two_primaries() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_DRBDTWOPRIMARIES"

    if is_level_in_range ${level}; then
        if is_installed drbd-utils; then
            if command -v drbd-overview >/dev/null; then
                if drbd-overview 2>&1 | grep --quiet "Primary/Primary"; then
                    failed "${level}" "${tag}" "Some DRBD ressources have two primaries, you risk a split brain!"
                fi
            elif command -v drbdadm >/dev/null; then
                if drbdadm role all 2>&1 | grep --quiet 'Primary/Primary'; then
                    failed "${level}" "${tag}" "Some DRBD ressources have two primaries, you risk a split brain!"
                fi
            fi
        fi
    fi
}
check_broadcomfirmware() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_BROADCOMFIRMWARE"

    if is_level_in_range ${level}; then
        lspci_bin=$(command -v lspci)
        if [ -x "${lspci_bin}" ]; then
            if ${lspci_bin} | grep --quiet 'NetXtreme II'; then
                { is_installed firmware-bnx2 \
                    && apt-cache policy | grep "\bl=Debian\b" | grep --quiet -v "\b,c=non-free\b"
                } || failed "${level}" "${tag}" "missing non-free repository"
            fi
        else
            failed "${level}" "${tag}" "lspci not found in ${PATH}"
        fi
    fi
}
check_hardwareraidtool() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_HARDWARERAIDTOOL"

    if is_level_in_range ${level}; then
        lspci_bin=$(command -v lspci)
        if [ -x "${lspci_bin}" ]; then
            if ${lspci_bin} | grep --quiet 'MegaRAID'; then
                if ! { command -v perccli || command -v perccli2; } >/dev/null  ; then
                    # shellcheck disable=SC2015
                    is_installed megacli && { is_installed megaclisas-status || is_installed megaraidsas-status; } \
                        || failed "${level}" "${tag}" "Mega tools not found"
                fi
            fi
            if ${lspci_bin} | grep --quiet 'Hewlett-Packard Company Smart Array'; then
                is_installed cciss-vol-status || failed "${level}" "${tag}" "cciss-vol-status not installed"
            fi
        else
            failed "${level}" "${tag}" "lspci not found in ${PATH}"
        fi
    fi
}
check_log2mailsystemdunit() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LOG2MAILSYSTEMDUNIT"

    if is_level_in_range ${level}; then
        systemctl -q is-active log2mail.service \
            || failed "${level}" "${tag}" "log2mail unit not running"
        test -f /etc/systemd/system/log2mail.service \
            || failed "${level}" "${tag}" "missing log2mail unit file"
    fi
}
check_systemduserunit() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SYSTEMDUSERUNIT"

    if is_level_in_range ${level}; then
        awk 'BEGIN { FS = ":" } { print $1, $6 }' /etc/passwd | while read -r user dir; do
            if ls "${dir}"/.config/systemd/user/*.service > /dev/null 2> /dev/null; then
                failed "${level}" "${tag}" "systemd unit found for user ${user}"
            fi
        done
    fi
}
check_listupgrade() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LISTUPGRADE"

    if is_level_in_range ${level}; then
        test -f /etc/cron.d/listupgrade \
            || failed "${level}" "${tag}" "missing listupgrade cron"
        test -x /usr/local/sbin/listupgrade.sh || test -x /usr/share/scripts/listupgrade.sh \
            || failed "${level}" "${tag}" "missing listupgrade script or not executable"
    fi
}
check_mariadbevolinuxconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MARIADBEVOLINUXCONF"

    if is_level_in_range ${level}; then
        if is_installed mariadb-server; then
            { test -f /etc/mysql/mariadb.conf.d/z-evolinux-defaults.cnf \
                && test -f /etc/mysql/mariadb.conf.d/zzz-evolinux-custom.cnf;
            } || failed "${level}" "${tag}" "missing mariadb custom config"
            fi
    fi
}
check_sql_backup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SQL_BACKUP"

    if is_level_in_range ${level}; then
        if (is_installed "mysql-server" || is_installed "mariadb-server"); then
            backup_dir="/home/backup"
            if [ -d "${backup_dir}" ]; then
                # You could change the default path in /etc/evocheck.cf
                SQL_BACKUP_PATH="${SQL_BACKUP_PATH:-$(find -H "${backup_dir}" \( -iname "mysql.bak.gz" -o -iname "mysql.sql.gz" -o -iname "mysqldump.sql.gz" \))}"
                if [ -z "${SQL_BACKUP_PATH}" ]; then
                    failed "${level}" "${tag}" "No MySQL dump found"
                    return 1
                fi
                for backup_path in ${SQL_BACKUP_PATH}; do
                    if [ ! -f "${backup_path}" ]; then
                        failed "${level}" "${tag}" "MySQL dump is missing (${backup_path})"
                    fi
                done
            else
                failed "${level}" "${tag}" "${backup_dir}/ is missing"
            fi
        fi
    fi
}
check_postgres_backup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_POSTGRES_BACKUP"

    if is_level_in_range ${level}; then
        if is_installed "postgresql-9*" || is_installed "postgresql-1*"; then
            backup_dir="/home/backup"
            if [ -d "${backup_dir}" ]; then
                # If you use something like barman, you should disable this check
                # You could change the default path in /etc/evocheck.cf
                POSTGRES_BACKUP_PATH="${POSTGRES_BACKUP_PATH:-$(find -H "${backup_dir}" -iname "pg.dump.bak*")}"
                for backup_path in ${POSTGRES_BACKUP_PATH}; do
                    if [ ! -f "${backup_path}" ]; then
                        failed "${level}" "${tag}" "PostgreSQL dump is missing (${backup_path})"
                    fi
                done
            else
                failed "${level}" "${tag}" "${backup_dir}/ is missing"
            fi
        fi
    fi
}
check_mongo_backup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MONGO_BACKUP"

    if is_level_in_range ${level}; then
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
                                failed "${level}" "${tag}" "MongoDB hasn't been dumped for more than 2 days"
                                break
                            fi
                        fi
                    done
                else
                    failed "${level}" "${tag}" "MongoDB dump directory is missing (${MONGO_BACKUP_PATH})"
                fi
            else
                failed "${level}" "${tag}" "${backup_dir}/ is missing"
            fi
        fi
    fi
}
check_ldap_backup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LDAP_BACKUP"

    if is_level_in_range ${level}; then
        if is_installed slapd; then
            backup_dir="/home/backup"
            if [ -d "${backup_dir}" ]; then
                # You could change the default path in /etc/evocheck.cf
                LDAP_BACKUP_PATH="${LDAP_BACKUP_PATH:-$(find -H "${backup_dir}" -iname "ldap.bak")}"
                if ! test -f "$LDAP_BACKUP_PATH"; then
                    # In newer versions of zzz_evobackup client, dumps have been split in 3 files /home/backup/ldap/{ldap-config,ldap-data}.bak
                    # Let's check for ldap/ldap-data.bak
                    LDAP_BACKUP_PATH="${backup_dir}/ldap/ldap-data.bak"
                    if ! test -f "$LDAP_BACKUP_PATH"; then
                        failed "${level}" "${tag}" "LDAP dump is missing (${LDAP_BACKUP_PATH})"
                    fi
                fi
            else
                failed "${level}" "${tag}"  "${backup_dir}/ is missing"
            fi
        fi
    fi
}
check_redis_backup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_REDIS_BACKUP"

    if is_level_in_range ${level}; then
        if is_installed redis-server; then
            backup_dir="/home/backup"
                if [ -d "${backup_dir}" ]; then
                # You could change the default path in /etc/evocheck.cf
                # REDIS_BACKUP_PATH may contain space-separated paths, for example:
                # REDIS_BACKUP_PATH='/home/backup/redis-instance1/dump.rdb /home/backup/redis-instance2/dump.rdb'
                # Warning : this script doesn't handle spaces in file paths !

                REDIS_BACKUP_PATH="${REDIS_BACKUP_PATH:-$(find -H "${backup_dir}" -iname "*.rdb*")}"

                # Check number of dumps
                n_instances=$(pgrep 'redis-server' | wc -l)
                n_dumps=$(echo $REDIS_BACKUP_PATH | wc -w)
                if [ ${n_dumps} -lt ${n_instances} ]; then
                    failed "${level}" "${tag}" "Missing Redis dump : ${n_instances} instance(s) found versus ${n_dumps} dump(s) found."
                fi

                # Check last dump date
                age_threshold=$(date +"%s" -d "now - 2 days")
                for dump in ${REDIS_BACKUP_PATH}; do
                    last_update=$(stat -c "%Z" $dump)
                    if [ "${last_update}" -lt "${age_threshold}" ]; then
                        failed "${level}" "${tag}" "Redis dump ${dump} is older than 2 days."
                    fi
                done
            else
                failed "${level}" "${tag}" "${backup_dir}/ is missing"
            fi
        fi
    fi
}
check_elastic_backup() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_ELASTIC_BACKUP"

    if is_level_in_range ${level}; then
        if is_installed elasticsearch; then
            # You could change the default path in /etc/evocheck.cf
            ELASTIC_BACKUP_PATH=${ELASTIC_BACKUP_PATH:-"/home/backup-elasticsearch"}
            test -d "$ELASTIC_BACKUP_PATH" || failed "${level}" "${tag}" "Elastic snapshot is missing (${ELASTIC_BACKUP_PATH})"
        fi
    fi
}
check_mariadbsystemdunit() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MARIADBSYSTEMDUNIT"

    if is_level_in_range ${level}; then
        # TODO: check if it is still needed for bullseye
        if evo::os-release::is_debian 11 lt; then
            if is_installed mariadb-server; then
                if systemctl -q is-active mariadb.service; then
                    test -f /etc/systemd/system/mariadb.service.d/evolinux.conf \
                        || failed "${level}" "${tag}" "missing systemd override for mariadb unit"
                fi
            fi
        fi
    fi
}
check_mysqlmunin() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MYSQLMUNIN"

    if is_level_in_range ${level}; then
        if is_installed mariadb-server; then
            for file in mysql_bytes mysql_queries mysql_slowqueries \
                mysql_threads mysql_connections mysql_files_tables \
                mysql_innodb_bpool mysql_innodb_bpool_act mysql_innodb_io \
                mysql_innodb_log mysql_innodb_rows mysql_innodb_semaphores \
                mysql_myisam_indexes mysql_qcache mysql_qcache_mem \
                mysql_sorts mysql_tmp_tables; do

                if [[ ! -L /etc/munin/plugins/$file ]]; then
                    failed "${level}" "${tag}" "missing munin plugin '$file'"
                fi
            done
            munin-run mysql_commands 2> /dev/null > /dev/null
            test $? -eq 0 || failed "${level}" "${tag}" "Munin plugin mysql_commands returned an error"
        fi
    fi
}
check_mysqlnrpe() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MYSQLNRPE"

    if is_level_in_range ${level}; then
        if is_installed mariadb-server; then
            nagios_file=~nagios/.my.cnf
            if ! test -f ${nagios_file}; then
                failed "${level}" "${tag}" "${nagios_file} is missing"
            elif [ "$(stat -c %U ${nagios_file})" != "nagios" ] \
                || [ "$(stat -c %a ${nagios_file})" != "600" ]; then
                failed "${level}" "${tag}" "${nagios_file} has wrong permissions"
            else
                grep --quiet --extended-regexp "command\[check_mysql\]=.*/usr/lib/nagios/plugins/check_mysql" /etc/nagios/nrpe.d/evolix.cfg \
                || failed "${level}" "${tag}" "check_mysql is missing"
            fi
        fi
    fi
}
check_phpevolinuxconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_PHPEVOLINUXCONF"

    if is_level_in_range ${level}; then
        evo::os-release::is_debian 10 && phpVersion="7.3"
        evo::os-release::is_debian 11 && phpVersion="7.4"
        evo::os-release::is_debian 12 && phpVersion="8.2"
        evo::os-release::is_debian 13 && phpVersion="8.4"

        if is_installed php; then
            { test -f "/etc/php/${phpVersion}/cli/conf.d/z-evolinux-defaults.ini" \
                && test -f "/etc/php/${phpVersion}/cli/conf.d/zzz-evolinux-custom.ini"
            } || failed "${level}" "${tag}" "missing php evolinux config"
        fi
    fi
}
check_squidlogrotate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SQUIDLOGROTATE"

    if is_level_in_range ${level}; then
        if is_installed squid; then
            grep --quiet --regexp monthly --regexp daily /etc/logrotate.d/squid \
                || failed "${level}" "${tag}" "missing squid logrotate file"
        fi
    fi
}
check_squidevolinuxconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SQUIDEVOLINUXCONF"

    if is_level_in_range ${level}; then
        if is_installed squid; then
            { grep --quiet --no-messages "^CONFIG=/etc/squid/evolinux-defaults.conf$" /etc/default/squid \
                && test -f /etc/squid/evolinux-defaults.conf \
                && test -f /etc/squid/evolinux-whitelist-defaults.conf \
                && test -f /etc/squid/evolinux-whitelist-custom.conf \
                && test -f /etc/squid/evolinux-acl.conf \
                && test -f /etc/squid/evolinux-httpaccess.conf \
                && test -f /etc/squid/evolinux-custom.conf;
            } || failed "${level}" "${tag}" "missing squid evolinux config"
        fi
    fi
}
check_duplicate_fs_label() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_DUPLICATE_FS_LABEL"

    if is_level_in_range ${level}; then
        # Do it only if thereis blkid binary
        blkid_bin=$(command -v blkid)
        if [ -n "$blkid_bin" ]; then
            tmpFile=$(mktemp --tmpdir "evocheck.duplicate_fs_label.XXXXX")
            files_to_cleanup+=("${tmpFile}")

            parts=$($blkid_bin -c /dev/null | grep --invert-match --regexp raid_member --regexp EFI_SYSPART --regexp zfs_member --regexp '/dev/zd*' | grep --extended-regexp --only-matching ' LABEL=".*"' | cut -d'"' -f2)
            for part in $parts; do
                echo "$part" >> "$tmpFile"
            done
            tmpOutput=$(sort < "$tmpFile" | uniq -d)
            # If there is no duplicate, uniq will have no output
            # So, if $tmpOutput is not null, there is a duplicate
            if [ -n "$tmpOutput" ]; then
                # shellcheck disable=SC2086
                labels=$(echo -n $tmpOutput | tr '\n' ' ')
                failed "${level}" "${tag}" "Duplicate labels: $labels"
            fi
        else
            failed "${level}" "${tag}" "blkid not found in ${PATH}"
        fi
    fi
}
check_evolix_user() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOLIX_USER"

    if is_level_in_range ${level}; then
        grep --quiet --extended-regexp "^evolix:" /etc/passwd \
            && failed "${level}" "${tag}" "evolix user should be deleted, used only for install"
    fi
}
check_evolix_group() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOLIX_GROUP"

    if is_level_in_range ${level}; then
        users=$(grep ":20..:20..:" /etc/passwd | cut -d ":" -f 1)
        for user in ${users}; do
            grep -E "^evolix:" /etc/group | grep -q -E "\b${user}\b" \
                || failed "${level}" "${tag}" "user \`${user}' should be in \`evolix' group"
        done
    fi
}
check_evoacme_cron() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOACME_CRON"

    if is_level_in_range ${level}; then
        if [ -f "/usr/local/sbin/evoacme" ]; then
            # Old cron file, should be deleted
            test -f /etc/cron.daily/certbot && failed "${level}" "${tag}" "certbot cron is incompatible with evoacme"
            # evoacme cron file should be present
            test -f /etc/cron.daily/evoacme || failed "${level}" "${tag}" "evoacme cron is missing"
        fi
    fi
}
check_evoacme_livelinks() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOACME_LIVELINKS"

    if is_level_in_range ${level}; then
        evoacme_bin=$(command -v evoacme)
        if [ -x "$evoacme_bin" ]; then
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
                        failed "${level}" "${tag}" "Certificate \`$certName' hasn't been updated"
                    fi
                done
            fi
        fi
    fi
}
check_apache_confenabled() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APACHE_CONFENABLED"

    if is_level_in_range ${level}; then
        # Starting from Jessie and Apache 2.4, /etc/apache2/conf.d/
        # must be replaced by conf-available/ and config files symlinked
        # to conf-enabled/
        if [ -f /etc/apache2/apache2.conf ]; then
            test -d /etc/apache2/conf.d/ \
                && failed "${level}" "${tag}" "apache's conf.d directory must not exists"
            grep --quiet 'Include conf.d' /etc/apache2/apache2.conf \
                && failed "${level}" "${tag}" "apache2.conf must not Include conf.d"
        fi
    fi
}
check_meltdown_spectre() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MELTDOWN_SPECTRE"

    if is_level_in_range ${level}; then
        # /sys/devices/system/cpu/vulnerabilities/
        for vuln in meltdown spectre_v1 spectre_v2; do
            test -f "/sys/devices/system/cpu/vulnerabilities/$vuln" \
                || failed "${level}" "${tag}" "vulnerable to $vuln"
        done
    fi
}
check_old_home_dir() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_OLD_HOME_DIR"

    if is_level_in_range ${level}; then
        homeDir=${homeDir:-/home}
        for dir in "$homeDir"/*; do
            statResult=$(stat -c "%n has owner %u resolved as %U" "$dir" \
                | grep --invert-match --extended-regexp --regexp '.bak' --regexp '\.[0-9]{2}-[0-9]{2}-[0-9]{4}' \
                | grep "UNKNOWN")
            # There is at least one dir matching
            if [[ -n "$statResult" ]]; then
                failed "${level}" "${tag}" "$statResult"
            fi
        done
    fi
}
check_tmp_1777() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_TMP_1777"

    if is_level_in_range ${level}; then
        expected="1777"

        actual=$(stat --format "%a" /tmp)
        test "${expected}" = "${actual}" || failed "${level}" "${tag}" "/tmp must be ${expected}"

        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    if [ -d "${rootfs}/tmp" ]; then
                        actual=$(stat --format "%a" "${rootfs}/tmp")
                        test "${expected}" = "${actual}" || failed "${level}" "${tag}" "${rootfs}/tmp must be ${expected}"
                    fi
                fi
            done
        fi
    fi
}
check_root_0700() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_ROOT_0700"

    if is_level_in_range ${level}; then
        actual=$(stat --format "%a" /root)
        expected="700"
        test "$expected" = "$actual" || failed "${level}" "${tag}" "/root must be $expected"
    fi
}
check_usrsharescripts() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_USRSHARESCRIPTS"

    if is_level_in_range ${level}; then
        actual=$(stat --format "%a" /usr/share/scripts)
        expected="700"
        test "$expected" = "$actual" || failed "${level}" "${tag}" "/usr/share/scripts must be $expected"
    fi
}
check_sshpermitrootno() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SSHPERMITROOTNO"

    if is_level_in_range ${level}; then
        # You could change the SSH port in /etc/evocheck.cf
        sshd_args="-C addr=,user=,host=,laddr=,lport=${SSH_PORT:-22}"
        if evo::os-release::is_debian 10; then
            sshd_args="${sshd_args},rdomain="
        fi
        # shellcheck disable=SC2086
        if ! (sshd -T ${sshd_args} 2> /dev/null | grep --quiet --ignore-case 'permitrootlogin no'); then
            failed "${level}" "${tag}" "PermitRoot should be set to no"
        fi
    fi
}
check_evomaintenanceusers() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOMAINTENANCEUSERS"

    if is_level_in_range ${level}; then
        users=$(getent group evolinux-sudo | cut -d':' -f4 | tr ',' ' ')
        for user in $users; do
            user_home=$(getent passwd "$user" | cut -d: -f6)
            if [ -n "$user_home" ] && [ -d "$user_home" ]; then
                if ! grep --quiet --no-messages "^trap.*sudo.*evomaintenance.sh" "${user_home}"/.*profile; then
                    failed "${level}" "${tag}" "${user} doesn't have an evomaintenance trap"
                fi
            fi
        done
    fi
}
check_evomaintenanceconf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOMAINTENANCECONF"

    if is_level_in_range ${level}; then
        f=/etc/evomaintenance.cf
        if [ -e "$f" ]; then
            perms=$(stat -c "%a" $f)
            test "$perms" = "600" || failed "${level}" "${tag}" "Wrong permissions on \`$f' ($perms instead of 600)"

            { grep "^FROM" $f | grep --quiet --invert-match "jdoe@example.com" \
                && grep "^FULLFROM" $f | grep --quiet --invert-match "John Doe <jdoe@example.com>" \
                && grep "^URGENCYFROM" $f | grep --quiet --invert-match "mama.doe@example.com" \
                && grep "^URGENCYTEL" $f | grep --quiet --invert-match "06.00.00.00.00" \
                && grep "^REALM" $f | grep --quiet --invert-match "example.com"
            } || failed "${level}" "${tag}" "evomaintenance is not correctly configured"
        else
            failed "${level}" "${tag}" "Configuration file \`$f' is missing"
        fi
    fi
}
check_privatekeyworldreadable() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_PRIVKEYWOLRDREADABLE"

    if is_level_in_range ${level}; then
        # a simple globbing fails if directory is empty
        if [ -n "$(ls -A /etc/ssl/private/)" ]; then
            for f in /etc/ssl/private/*; do
                perms=$(stat -L -c "%a" "$f")
                if [ "${perms: -1}" != 0 ]; then
                    failed "${level}" "${tag}" "$f is world-readable"
                fi
            done
        fi
    fi
}
check_evobackup_incs() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_EVOBACKUP_INCS"

    if is_level_in_range ${level}; then
        if is_installed bkctld; then
            bkctld_cron_file=${bkctld_cron_file:-/etc/cron.d/bkctld}
            if [ -f "${bkctld_cron_file}" ]; then
                root_crontab=$(grep -v "^#" "${bkctld_cron_file}")
                echo "${root_crontab}" | grep --quiet "bkctld inc" || failed "${level}" "${tag}" "'bkctld inc' is missing in ${bkctld_cron_file}"
                echo "${root_crontab}" | grep --quiet --extended-regexp "(check-incs.sh|bkctld check-incs)" || failed "${level}" "${tag}" "'check-incs.sh' is missing in ${bkctld_cron_file}"
            else
                failed "${level}" "${tag}" "Crontab \`${bkctld_cron_file}' is missing"
            fi
        fi
    fi
}
check_osprober() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_OSPROBER"

    if is_level_in_range ${level}; then
        if is_installed os-prober qemu-kvm; then
            failed "${level}" "${tag}" \
                "Removal of os-prober package is recommended as it can cause serious issue on KVM server"
        fi
    fi
}
check_apt_valid_until() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_APT_VALID_UNTIL"

    if is_level_in_range ${level}; then
        aptvalidFile="/etc/apt/apt.conf.d/99no-check-valid-until"
        aptvalidText="Acquire::Check-Valid-Until no;"
        if grep --quiet --no-messages "archive.debian.org" /etc/apt/sources.list /etc/apt/sources.list.d/*; then
            if ! grep --quiet --no-messages "$aptvalidText" /etc/apt/apt.conf.d/*; then
                failed "${level}" "${tag}" \
                    "As you use archive.mirror.org you need ${aptvalidFile}: ${aptvalidText}"
            fi
        fi
    fi
}
check_chrooted_binary_uptodate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_CHROOTED_BINARY_UPTODATE"

    if is_level_in_range ${level}; then
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
                        failed "${level}" "${tag}" "${process_bin} (${pid}) is different than ${original_bin}."
                    fi
                fi
            done
        done
    fi
}
check_nginx_letsencrypt_uptodate() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NGINX_LETSENCRYPT_UPTODATE"

    if is_level_in_range ${level}; then
        if [ -d /etc/nginx ]; then
            snippets=$(find /etc/nginx -type f -name "letsencrypt.conf")
            if [ -n "${snippets}" ]; then
                while read -r snippet; do
                    if grep --quiet --extended-regexp "^\s*alias\s+/.+/\.well-known/acme-challenge" "${snippet}"; then
                        failed "${level}" "${tag}" "Nginx snippet ${snippet} is not compatible with Nginx on Debian 9+."
                    fi
                done <<< "${snippets}"
            fi
        fi
    fi
}
check_wkhtmltopdf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_WKHTMLTOPDF"

    if is_level_in_range ${level}; then
        is_installed wkhtmltopdf && failed "${level}" "${tag}" "wkhtmltopdf package should not be installed (cf. https://wiki.evolix.org/HowtoWkhtmltopdf)"
    fi
}
check_lxc_wkhtmltopdf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LXC_WKHTMLTOPDF"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    test -e "${rootfs}/usr/bin/wkhtmltopdf" && failed "${level}" "${tag}" "wkhtmltopdf should not be installed in container ${container_name}"
                fi
            done
        fi
    fi
}
check_lxc_container_resolv_conf() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LXC_CONTAINER_RESOLV_CONF"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            current_resolvers=$(grep ^nameserver /etc/resolv.conf | sed 's/nameserver//g' )
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    if [ -f "${rootfs}/etc/resolv.conf" ]; then

                        while read -r resolver; do
                            if ! grep --quiet --extended-regexp "^nameserver\s+${resolver}" "${rootfs}/etc/resolv.conf"; then
                                failed "${level}" "${tag}" "resolv.conf miss-match beween host and container : missing nameserver ${resolver} in container ${container_name} resolv.conf"
                            fi
                        done <<< "${current_resolvers}"

                    else
                        failed "${level}" "${tag}" "resolv.conf missing in container ${container_name}"
                    fi
                fi
            done
        fi
    fi
}
# Check that there are containers if lxc is installed.
check_no_lxc_container() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NO_LXC_CONTAINER"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            containers_count=$(lxc-ls -1 --active | wc -l)
            if [ "${containers_count}" -eq 0 ]; then
                failed "${level}" "${tag}" "LXC is installed but have no active container. Consider removing it."
            fi
        fi
    fi
}
# Check that in LXC containers, phpXX-fpm services have UMask set to 0007.
check_lxc_php_fpm_service_umask_set() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LXC_PHP_FPM_SERVICE_UMASK_SET"

    if is_level_in_range ${level}; then
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
                failed "${level}" "${tag}" "UMask is not set to 0007 in PHP-FPM services of theses containers : ${missing_umask}."
            fi
        fi
    fi
}
# Check that LXC containers have the proper Debian version.
check_lxc_php_bad_debian_version() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LXC_PHP_BAD_DEBIAN_VERSION"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active --filter php)
            missing_umask=""
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    if [ "$container_name" = "php56" ]; then
                        grep --quiet 'VERSION_ID="8"' "${rootfs}/etc/os-release" || failed "${level}" "${tag}" "Container ${container_name} should use Jessie"
                    elif [ "$container_name" = "php70" ]; then
                        grep --quiet 'VERSION_ID="9"' "${rootfs}/etc/os-release" || failed "${level}" "${tag}" "Container ${container_name} should use Stretch"
                    elif [ "$container_name" = "php73" ]; then
                        grep --quiet 'VERSION_ID="10"' "${rootfs}/etc/os-release" || failed "${level}" "${tag}" "Container ${container_name} should use Buster"
                    elif [ "$container_name" = "php74" ]; then
                        grep --quiet 'VERSION_ID="11"' "${rootfs}/etc/os-release" || failed "${level}" "${tag}" "Container ${container_name} should use Bullseye"
                    elif [ "$container_name" = "php82" ]; then
                        grep --quiet 'VERSION_ID="12"' "${rootfs}/etc/os-release" || failed "${level}" "${tag}" "Container ${container_name} should use Bookworm"
                    elif [ "$container_name" = "php84" ]; then
                        grep --quiet 'VERSION_ID="13"' "${rootfs}/etc/os-release" || failed "${level}" "${tag}" "Container ${container_name} should use Trixie"
                    fi
                fi
            done
        fi
    fi
}
check_lxc_openssh() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LXC_OPENSSH"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    test -e "${rootfs}/usr/sbin/sshd" && failed "${level}" "${tag}" "openssh-server should not be installed in container ${container_name}"
                fi
            done
        fi
    fi
}
check_lxc_opensmtpd() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_LXC_OPENSMTPD"

    if is_level_in_range ${level}; then
        if is_installed lxc; then
            lxc_path=$(lxc-config lxc.lxcpath)
            containers_list=$(lxc-ls -1 --active --filter php)
            for container_name in ${containers_list}; do
                if lxc-info --name "${container_name}" > /dev/null; then
                    rootfs="${lxc_path}/${container_name}/rootfs"
                    test -e "${rootfs}/usr/sbin/smtpd" || test -e "${rootfs}/usr/sbin/ssmtp" || failed "${level}" "${tag}" "opensmtpd should be installed in container ${container_name}"
                fi
            done
        fi
    fi
}
check_monitoringctl() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_MONITORINGCTL"

    if is_level_in_range ${level}; then
        if ! /usr/local/bin/monitoringctl list >/dev/null 2>&1; then
            failed "${level}" "${tag}" "monitoringctl is not installed or has a problem (use 'monitoringctl list' to reproduce)."
        fi
    fi
}
check_smartmontools() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_SMARTMONTOOLS"

    if is_level_in_range ${level}; then
        if ( LC_ALL=C lscpu | grep "Hypervisor vendor:" | grep -q -e VMware -e KVM || lscpu | grep -q Oracle ); then
            is_installed smartmontools && failed "${level}" "${tag}" "smartmontools should not be installed on a VM"
        else
            is_installed smartmontools || failed "${level}" "${tag}" "smartmontools should be installed on barematal"
        fi
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
        failed "${level}" "IS_CHECK_VERSIONS" "failed to find curl, wget or GET"
    fi
    test "$?" -eq 0 || failed "${level}" "IS_CHECK_VERSIONS" "failed to download ${versions_url} to ${versions_file}"
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
        minifirewall)
            if [ -f "/usr/local/sbin/minifirewall" ]; then
                echo "/usr/local/sbin/minifirewall"
            elif [ -f "/etc/init.d/minifirewall" ]; then
                echo "/etc/init.d/minifirewall"
            fi
            ;;

        ## General case, where the program name is the same as the command name
        *) command -v "${program}" ;;
    esac
}
get_version() {
    local program command
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
            if [ -n "${command}" ]; then
                ${command} version | head -1 | cut -d ' ' -f 3
            fi
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
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_CHECK_VERSIONS"

    if is_level_in_range ${level}; then
        local program expected_version
        program=${1:-}
        expected_version=${2:-}

        command=$(get_command "${program}")
        if [ -n "${command}" ]; then
            # shellcheck disable=SC2086
            actual_version=$(get_version "${program}" "${command}")
            # printf "program:%s expected:%s actual:%s\n" "${program}" "${expected_version}" "${actual_version}"
            if [ -z "${actual_version}" ]; then
                failed "${level}" "${tag}" "failed to lookup actual version of ${program}"
            elif dpkg --compare-versions "${actual_version}" lt "${expected_version}"; then
                failed "${level}" "${tag}" "${program} version ${actual_version} is older than expected version ${expected_version}"
            elif dpkg --compare-versions "${actual_version}" gt "${expected_version}"; then
                failed "${level}" "${tag}" "${program} version ${actual_version} is newer than expected version ${expected_version}, you should update your index."
            else
                : # Version check OK
            fi
        fi
    fi
}
add_to_path() {
    local new_path
    new_path=${1:-}

    echo "$PATH" | grep --quiet --fixed-strings "${new_path}" || export PATH="${PATH}:${new_path}"
}
check_versions() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_CHECK_VERSIONS"

    if is_level_in_range ${level}; then
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
                    failed "${level}" "${tag}" "failed to lookup expected version for ${program}"
                fi
            fi
        done
    fi
}
check_nrpepressure() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_NRPEPRESSURE"

    if is_level_in_range ${level}; then
        if evo::os-release::is_debian 12 ge; then
            /usr/local/bin/monitoringctl status pressure_cpu > /dev/null 2>&1
            rc="$?"
            if [ "${rc}" -ne 0 ]; then
                failed "${level}" "${tag}" "pressure_cpu check not defined or monitoringctl not correctly installed"
            fi
        fi
    fi
}
check_postfix_ipv6_disabled() {
    local level tag
    level=${LEVEL_STANDARD}
    tag="IS_POSTFIX_IPV6_DISABLED"

    if is_level_in_range ${level}; then
        postconf -n 2>/dev/null | grep --no-messages --extended-regex '^inet_protocols\>' | grep --no-messages --invert-match --fixed-strings ipv6 | grep --no-messages --invert-match --fixed-strings all | grep --no-messages --silent --fixed-strings ipv4
        rc="$?"
        if [ "${rc}" -ne 0 ]; then
            failed "${level}" "${tag}" "IPv6 must be disabled in Postfix main.cf (inet_protocols = ipv4)"
        fi
    fi
}

### MAIN

main() {
    # Default return code : 0 = no error
    GLOBAL_RC=0

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
    test "${IS_TMOUTPROFILE:=1}" = 1 && check_tmoutprofile
    test "${IS_ALERT5BOOT:=1}" = 1 && check_alert5boot
    test "${IS_ALERT5MINIFW:=1}" = 1 && check_alert5minifw
    test "${IS_ALERT5MINIFW:=1}" = 1 && test "${IS_MINIFW:=1}" = 1 && check_minifw
    test "${IS_NRPEPERMS:=1}" = 1 && check_nrpeperms
    test "${IS_MINIFWPERMS:=1}" = 1 && check_minifwperms
    test "${IS_MINIFW_RELATED:=0}" = 1 && check_minifw_related
    test "${IS_MINIFWINCLUDES:=1}" = 1 && check_minifw_includes
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
    test "${IS_PHPPGADMINAPACHECONF:=1}" = 1 && check_phppgadminapacheconf
    test "${IS_PHPLDAPADMINAPACHECONF:=1}" = 1 && check_phpldapadminapacheconf
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
    test "${IS_SYSTEMDUSERUNIT:=0}" = 1 && check_systemduserunit
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
    test "${IS_EVOLIX_GROUP:=0}" = 1 && check_evolix_group
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
    test "${IS_WKHTMLTOPDF:=1}" = 1 && check_wkhtmltopdf
    test "${IS_LXC_WKHTMLTOPDF:=1}" = 1 && check_lxc_wkhtmltopdf
    test "${IS_LXC_CONTAINER_RESOLV_CONF:=1}" = 1 && check_lxc_container_resolv_conf
    test "${IS_NO_LXC_CONTAINER:=1}" = 1 && check_no_lxc_container
    test "${IS_LXC_PHP_FPM_SERVICE_UMASK_SET:=1}" = 1 && check_lxc_php_fpm_service_umask_set
    test "${IS_LXC_PHP_BAD_DEBIAN_VERSION:=1}" = 1 && check_lxc_php_bad_debian_version
    test "${IS_LXC_OPENSSH:=1}" = 1 && check_lxc_openssh
    test "${IS_LXC_OPENSMTPD:=1}" = 1 && check_lxc_opensmtpd
    test "${IS_CHECK_VERSIONS:=1}" = 1 && check_versions
    test "${IS_MONITORINGCTL:=1}" = 1 && check_monitoringctl
    test "${IS_NRPEPRESSURE:=0}" = 1 && check_nrpepressure
    test "${IS_POSTFIX_IPV6_DISABLED:=0}" = 1 && check_postfix_ipv6_disabled
    test "${IS_SMARTMONTOOLS:=0}" = 1 && check_smartmontools

    if [ -f "${main_output_file}" ]; then
        lines_found=$(wc -l < "${main_output_file}")
        # shellcheck disable=SC2086
        if [ ${lines_found} -gt 0 ]; then
            cat "${main_output_file}" 2>&1
        fi
    fi

    exit ${GLOBAL_RC}
}
# shellcheck disable=SC2329
cleanup() {
    # Cleanup tmp files
    # shellcheck disable=SC2068,SC2317
    rm -f ${files_to_cleanup[@]}

    log "End of ${PROGNAME} execution."
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

LEVEL_OPTIONAL=1
readonly LEVEL_OPTIONAL
LEVEL_STANDARD=2
readonly LEVEL_STANDARD
LEVEL_IMPORTANT=3
readonly LEVEL_IMPORTANT
LEVEL_MANDATORY=4
readonly LEVEL_MANDATORY

MIN_LEVEL=0
MAX_LEVEL=9


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
        --future)
            IS_MINIFW_RELATED=1
            IS_NO_SIGNED_BY=1
            IS_NOT_DEB822=1
            IS_POSTFIX_IPV6_DISABLED=1
            IS_NRPEPRESSURE=1
            IS_SMARTMONTOOLS=1
            IS_EVOLIX_GROUP=1
            IS_SYSTEMDUSERUNIT=1
            IS_SSHLASTMATCH=1
            IS_MARIADBEVOLINUXCONF=1
            IS_PHPEVOLINUXCONF=1
            IS_OLD_HOME_DIR=1
            ;;
        -v|--verbose)
            VERBOSE=1
            ;;
        -q|--quiet)
            QUIET=1
            VERBOSE=0
            ;;
        --min-level)
                shift
                case $1 in
                    ${LEVEL_OPTIONAL}|OPTIONAL|optional)    MIN_LEVEL=${LEVEL_OPTIONAL} ;;
                    ${LEVEL_STANDARD}|STANDARD|standard)    MIN_LEVEL=${LEVEL_STANDARD} ;;
                    ${LEVEL_IMPORTANT}|IMPORTANT|important) MIN_LEVEL=${LEVEL_IMPORTANT} ;;
                    ${LEVEL_MANDATORY}|MANDATORY|mandatory) MIN_LEVEL=${LEVEL_MANDATORY} ;;
                    *)
                        printf 'ERROR: invalid value for --min-level option: %s\n' "$1" >&2
                        exit 1
                        ;;
                esac
            ;;
        --max-level)
                shift
                case $1 in
                    ${LEVEL_OPTIONAL}|OPTIONAL|optional)    MAX_LEVEL=${LEVEL_OPTIONAL} ;;
                    ${LEVEL_STANDARD}|STANDARD|standard)    MAX_LEVEL=${LEVEL_STANDARD} ;;
                    ${LEVEL_IMPORTANT}|IMPORTANT|important) MAX_LEVEL=${LEVEL_IMPORTANT} ;;
                    ${LEVEL_MANDATORY}|MANDATORY|mandatory) MAX_LEVEL=${LEVEL_MANDATORY} ;;
                    *)
                        printf 'ERROR: invalid value for --max-level option: %s\n' "$1" >&2
                        exit 1
                        ;;
                esac
            ;;
        --)
            # End of all options.
            shift
            break
            ;;
        -?*|[[:alnum:]]*)
            # ignore unknown options
            if ! is_quiet; then
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
