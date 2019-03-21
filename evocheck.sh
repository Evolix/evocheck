#!/bin/bash

# EvoCheck
# Script to verify compliance of a Debian/OpenBSD server
# powered by Evolix

# Disable LANG*
export LANG=C
export LANGUAGE=C

# Default configuration values
IS_TMP_1777=1
IS_ROOT_0700=1
IS_VARTMPFS=1
IS_USRSHARESCRIPTS=1
IS_SERVEURBASE=1
IS_LOGROTATECONF=1
IS_SYSLOGCONF=1
IS_DEBIANSECURITY=1
IS_APTITUDEONLY=1
IS_APTITUDE=1
IS_APTGETBAK=1
IS_APTICRON=0
IS_USRRO=1
IS_TMPNOEXEC=1
IS_LISTCHANGESCONF=1
IS_DPKGWARNING=1
IS_CUSTOMCRONTAB=1
IS_CUSTOMSUDOERS=1
IS_SSHPERMITROOTNO=1
IS_SSHALLOWUSERS=1
IS_TMOUTPROFILE=1
IS_ALERT5BOOT=1
IS_ALERT5MINIFW=1
IS_MINIFW=1
IS_NRPEPERMS=1
IS_MINIFWPERMS=1
IS_NRPEDISKS=0
IS_NRPEPOSTFIX=1
IS_NRPEPID=1
IS_GRSECPROCS=1
IS_UMASKSUDOERS=1
IS_EVOMAINTENANCEUSERS=1
IS_APACHEMUNIN=1
IS_MYSQLUTILS=1
IS_RAIDSOFT=1
IS_AWSTATSLOGFORMAT=1
IS_MUNINLOGROTATE=1
IS_EVOMAINTENANCECONF=1
#IS_METCHE=1
IS_SQUID=1
IS_MODDEFLATE=1
IS_LOG2MAILRUNNING=1
IS_LOG2MAILAPACHE=1
IS_LOG2MAILMYSQL=1
IS_LOG2MAILSQUID=1
IS_BINDCHROOT=1
IS_REPVOLATILE=1
IS_AUTOIF=1
IS_INTERFACESGW=1
IS_TOOMUCHDEBIANSYSMAINT=1
IS_USERLOGROTATE=1
IS_MODSECURITY=1
IS_APACHECTL=1
IS_APACHESYMLINK=1
IS_APACHEIPINALLOW=1
IS_MUNINAPACHECONF=1
IS_SAMBAPINPRIORITY=1
IS_KERNELUPTODATE=1
IS_UPTIME=1
IS_MUNINRUNNING=1
IS_BACKUPUPTODATE=1
IS_GITPERMS=1
IS_NOTUPGRADED=1
IS_TUNE2FS_M5=1
IS_PRIVKEYWOLRDREADABLE=1
IS_EVOLINUXSUDOGROUP=1
IS_USERINADMGROUP=1
IS_APACHE2EVOLINUXCONF=1
IS_BACKPORTSCONF=1
IS_BIND9MUNIN=1
IS_BIND9LOGROTATE=1
IS_BROADCOMFIRMWARE=1
IS_HARDWARERAIDTOOL=1
IS_LOG2MAILSYSTEMDUNIT=1
IS_LISTUPGRADE=1
IS_MARIADBEVOLINUXCONF=1
IS_MARIADBSYSTEMDUNIT=1
IS_MYSQLMUNIN=1
IS_PHPEVOLINUXCONF=1
IS_SQUIDLOGROTATE=1
IS_SQUIDEVOLINUXCONF=1
IS_SQL_BACKUP=1
IS_POSTGRES_BACKUP=1
IS_LDAP_BACKUP=1
IS_REDIS_BACKUP=1
IS_ELASTIC_BACKUP=1
IS_MONGO_BACKUP=1
IS_MOUNT_FSTAB=1
IS_NETWORK_INTERFACES=1
IS_EVOBACKUP=1
IS_DUPLICATE_FS_LABEL=1
IS_EVOMAINTENANCE_FW=1
IS_EVOLIX_USER=1
IS_EVOACME_CRON=1
IS_EVOACME_LIVELINKS=1
IS_APACHE_CONFENABLED=1
IS_MELTDOWN_SPECTRE=1
IS_OLD_HOME_DIR=1
IS_LSBRELEASE=1

#Proper to OpenBSD
IS_SOFTDEP=1
IS_WHEEL=1
IS_SUDOADMIN=1
IS_PKGMIRROR=1
IS_HISTORY=1
IS_VIM=1
IS_TTYC0SECURE=1
IS_CUSTOMSYSLOG=1
IS_NOINETD=1
IS_SUDOMAINT=1
IS_POSTGRESQL=1
IS_NRPE=1
IS_NRPEDAEMON=1
IS_ALERTBOOT=1
IS_RSYNC=1

DEBIAN_RELEASE=""
LSB_RELEASE_BIN=$(command -v lsb_release)
OPENBSD_RELEASE=""

if [ -e /etc/debian_version ]; then
    DEBIAN_VERSION=$(cut -d "." -f 1 < /etc/debian_version)
    if [ -x ${LSB_RELEASE_BIN} ]; then
        DEBIAN_RELEASE=$(${LSB_RELEASE_BIN} --codename --short)
    else
        case ${DEBIAN_VERSION} in
            5) DEBIAN_RELEASE="lenny";;
            6) DEBIAN_RELEASE="squeeze";;
            7) DEBIAN_RELEASE="wheezy";;
            8) DEBIAN_RELEASE="jessie";;
            9) DEBIAN_RELEASE="stretch";;
        esac
    fi
elif [ "$(uname -s)" = "OpenBSD" ]; then
    # use a better release name
    OPENBSD_RELEASE="OpenBSD"
fi

# Source configuration file
test -f /etc/evocheck.cf && . /etc/evocheck.cf

VERBOSE="${VERBOSE:-0}"

# If --cron is passed, ignore some checks.
if [ "$1" = "--cron" ]; then
    IS_KERNELUPTODATE=0
    IS_UPTIME=0
fi

# logging function
failed() {
    check_name=$1
    shift
    check_comments=$@

    if [ -n "${check_comments}" ] && [ "${VERBOSE}" = 1 ]; then
        printf "%s FAILED! %s\n" "${check_name}" "${check_comments}" 2>&1
    else
        printf "%s FAILED!\n" "${check_name}" 2>&1
    fi
}

# Functions
is_pack_web(){
    test -e /usr/share/scripts/web-add.sh || test -e /usr/share/scripts/evoadmin/web-add.sh
}

is_pack_samba(){
    test -e /usr/share/scripts/add.pl
}

is_installed(){
    for pkg in $*; do
            dpkg -l $pkg 2>/dev/null | grep -q -E '^(i|h)i' || return 1
    done
}

is_debian() {
  test -n "${DEBIAN_RELEASE}"
}
is_debian_lenny() {
    test "${DEBIAN_VERSION}" = "lenny"
}
is_debian_squeeze() {
    test "${DEBIAN_RELEASE}" = "squeeze"
}
is_debian_wheezy() {
    test "${DEBIAN_RELEASE}" = "wheezy"
}
is_debian_jessie() {
    test "${DEBIAN_RELEASE}" = "jessie"
}
is_debian_stretch() {
    test "${DEBIAN_RELEASE}" = "stretch"
}
debian_release() {
    printf "%s" "${DEBIAN_RELEASE}"
}
debian_version() {
    printf "%s" "${DEBIAN_VERSION}"
}
is_openbsd() {
  test -n "${OPENBSD_RELEASE}"
}

is_debian_lenny   && MINIFW_FILE=/etc/firewall.rc
is_debian_squeeze && MINIFW_FILE=/etc/firewall.rc
is_debian_wheezy  && MINIFW_FILE=/etc/firewall.rc
is_debian_jessie  && MINIFW_FILE=/etc/default/minifirewall
is_debian_stretch && MINIFW_FILE=/etc/default/minifirewall

#-----------------------------------------------------------
#Vérifie si c'est une debian et fait les tests appropriés.
#-----------------------------------------------------------

if is_debian; then

    if [ "$IS_LSBRELEASE" = "1" ]; then
        test -x "${LSB_RELEASE_BIN}" || failed "IS_LSBRELEASE" "lsb_release is missing or not executable"
        test "$(${LSB_RELEASE_BIN} --release --short)" = "$(cat /etc/debian_version)" || failed "IS_LSBRELEASE" "release is not consistent between lsb_release and /etc/debian_version"
    fi

    if [ "$IS_DPKGWARNING" = 1 ]; then
        if is_debian_squeeze; then
            if [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ]; then
                count=$(grep -c -E -i "(Pre-Invoke ..echo Are you sure to have rw on|Post-Invoke ..echo Dont forget to mount -o remount)" /etc/apt/apt.conf)
                [ "$count" = "2" ] || failed "IS_DPKGWARNING"
            fi
        elif is_debian_wheezy; then
            if [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ]; then
                test -e /etc/apt/apt.conf.d/80evolinux || failed "IS_DPKGWARNING"
                test -e /etc/apt/apt.conf && failed "IS_DPKGWARNING"
            fi
        elif is_debian_stretch; then
            (test -e /etc/apt/apt.conf.d/z-evolinux.conf || failed "IS_DPKGWARNING")
        fi
    fi

    if [ "$IS_UMASKSUDOERS" = 1 ]; then
        if is_debian_squeeze; then
            ( grep -q "^Defaults.*umask=0077" /etc/sudoers || failed "IS_UMASKSUDOERS" )
        fi
    fi

    # Verifying check_mailq in Nagios NRPE config file. (Option "-M postfix" need to be set if the MTA is Postfix)
    if [ "$IS_NRPEPOSTFIX" = 1 ]; then
        if is_installed postfix; then
            if is_debian_squeeze; then
                grep -q "^command.*check_mailq -M postfix" /etc/nagios/nrpe.cfg \
                    || failed "IS_NRPEPOSTFIX"
            else
                test -e /etc/nagios/nrpe.cfg && grep -qr "^command.*check_mailq -M postfix" /etc/nagios/nrpe.* \
                    || failed "IS_NRPEPOSTFIX"
            fi
        fi
    fi

    # Check if mod-security config file is present
    if [ "$IS_MODSECURITY" = 1 ]; then
        if is_debian_squeeze; then
            if is_installed libapache-mod-security; then
                test -e /etc/apache2/conf.d/mod-security2.conf || failed "IS_MODSECURITY"
            fi
        elif is_debian_wheezy; then
            if is_installed libapache2-modsecurity; then
                test -e /etc/apache2/conf.d/mod-security2.conf || failed "IS_MODSECURITY"
            fi
        fi
    fi

    if [ "$IS_CUSTOMSUDOERS" = 1 ]; then
        grep -E -qr "umask=0077" /etc/sudoers* || failed "IS_CUSTOMSUDOERS"
    fi

    if [ "$IS_VARTMPFS" = 1 ]; then
        df /var/tmp | grep -q tmpfs || failed "IS_VARTMPFS"
    fi

    if [ "$IS_SERVEURBASE" = 1 ]; then
        is_installed serveur-base || failed "IS_SERVEURBASE"
    fi

    if [ "$IS_LOGROTATECONF" = 1 ]; then
        test -e /etc/logrotate.d/zsyslog || failed "IS_LOGROTATECONF"
    fi

    if [ "$IS_SYSLOGCONF" = 1 ]; then
        grep -q "^# Syslog for Pack Evolix serveur" /etc/*syslog.conf \
            || failed "IS_SYSLOGCONF"
    fi

    if [ "$IS_DEBIANSECURITY" = 1 ]; then
        grep -q "^deb.*security" /etc/apt/sources.list \
            || failed "IS_DEBIANSECURITY"
    fi

    if [ "$IS_APTITUDEONLY" = 1 ]; then
        if is_debian_squeeze || is_debian_wheezy; then
            test -e /usr/bin/apt-get && failed "IS_APTITUDEONLY"
        fi
    fi

    if [ "$IS_APTITUDE" = 1 ]; then
        if is_debian_jessie || is_debian_stretch; then
            test -e /usr/bin/aptitude && failed "IS_APTITUDE"
        fi
    fi

    if [ "$IS_APTGETBAK" = 1 ]; then
        if is_debian_jessie || is_debian_stretch; then
            test -e /usr/bin/apt-get.bak && failed "IS_APTGETBAK"
        fi
    fi

    if [ "$IS_APTICRON" = 1 ]; then
        status="OK"
        test -e /etc/cron.d/apticron || status="fail"
        test -e /etc/cron.daily/apticron && status="fail"
        test "$status" = "fail" || test -e /usr/bin/apt-get.bak || status="fail"

        if is_debian_squeeze || is_debian_wheezy; then
            test "$status" = "fail" && failed "IS_APTICRON"
        fi
    fi

    if [ "$IS_USRRO" = 1 ]; then
        grep /usr /etc/fstab | grep -q ro || failed "IS_USRRO"
    fi

    if [ "$IS_TMPNOEXEC" = 1 ]; then
        mount | grep "on /tmp" | grep -q noexec || failed "IS_TMPNOEXEC"
    fi

    if [ "$IS_MOUNT_FSTAB" = 1 ]; then
        # Test if lsblk available, if not skip this test...
        if test -x "$(command -v lsblk)"; then
            for mountPoint in $(lsblk -o MOUNTPOINT -l -n | grep '/'); do
                grep -Eq "$mountPoint\W" /etc/fstab || failed "IS_MOUNT_FSTAB"
            done
        fi
    fi

    if [ "$IS_LISTCHANGESCONF" = 1 ]; then
        if is_debian_stretch; then
            if is_installed apt-listchanges; then
                failed "IS_LISTCHANGESCONF" "apt-listchanges must not be installed on Stretch"
            fi
        else
            if [ -e "/etc/apt/listchanges.conf" ]; then
                lines=$(grep -cE "(which=both|confirm=1)" /etc/apt/listchanges.conf)
                if [ $lines != 2 ]; then
                    failed "IS_LISTCHANGESCONF" "apt-listchanges config is incorrect"
                fi
            else
                failed "IS_LISTCHANGESCONF" "apt-listchanges config is missing"
            fi
        fi
    fi

    if [ "$IS_CUSTOMCRONTAB" = 1 ]; then
        found_lines=$(grep -c -E "^(17 \*|25 6|47 6|52 6)" /etc/crontab)
        test "$found_lines" = "4" && failed "IS_CUSTOMCRONTAB"
    fi

    if [ "$IS_SSHALLOWUSERS" = 1 ]; then
        grep -E -qi "(AllowUsers|AllowGroups)" /etc/ssh/sshd_config || failed "IS_SSHALLOWUSERS"
    fi

    if [ "$IS_DISKPERF" = 1 ]; then
        test -e /root/disk-perf.txt || failed "IS_DISKPERF"
    fi

    if [ "$IS_TMOUTPROFILE" = 1 ]; then
        grep -q TMOUT= /etc/profile /etc/profile.d/evolinux.sh || failed "IS_TMOUTPROFILE"
    fi

    if [ "$IS_ALERT5BOOT" = 1 ]; then
        grep -q "^date" /etc/rc2.d/S*alert5 || failed "IS_ALERT5BOOT"
    fi

    if [ "$IS_ALERT5MINIFW" = 1 ]; then
        grep -q "^/etc/init.d/minifirewall" /etc/rc2.d/S*alert5 \
            || failed "IS_ALERT5MINIFW"
    fi

    if [ "$IS_ALERT5MINIFW" = 1 ] && [ "$IS_MINIFW" = 1 ]; then
        /sbin/iptables -L -n | grep -q -E "^ACCEPT\s*all\s*--\s*31\.170\.8\.4\s*0\.0\.0\.0/0\s*$" \
            || failed "IS_MINIFW"
    fi

    if [ "$IS_NRPEPERMS" = 1 ]; then
        if test -d /etc/nagios; then
            actual=$(stat --format "%A" /etc/nagios)
            expected="drwxr-x---"
            test "$expected" = "$actual" || failed "IS_NRPEPERMS"
        fi
    fi

    if [ "$IS_MINIFWPERMS" = 1 ]; then
        actual=$(stat --format "%A" $MINIFW_FILE)
        expected="-rw-------"
        test "$expected" = "$actual" || failed "IS_MINIFWPERMS"
    fi

    if [ "$IS_NRPEDISKS" = 1 ]; then
        NRPEDISKS=$(grep command.check_disk /etc/nagios/nrpe.cfg | grep "^command.check_disk[0-9]" | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
        DFDISKS=$(df -Pl | grep -E -v "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)" | wc -l)
        [ "$NRPEDISKS" = "$DFDISKS" ] || failed "IS_NRPEDISKS"
    fi

    if [ "$IS_NRPEPID" = 1 ]; then
        if ! is_debian_squeeze; then
            test -e /etc/nagios/nrpe.cfg && grep -q "^pid_file=/var/run/nagios/nrpe.pid" /etc/nagios/nrpe.cfg \
                || failed "IS_NRPEPID"
        fi
    fi

    if [ "$IS_GRSECPROCS" = 1 ]; then
        if uname -a | grep -q grsec; then
            grep -q "^command.check_total_procs..sudo" /etc/nagios/nrpe.cfg && grep -A1 "^\[processes\]" /etc/munin/plugin-conf.d/munin-node | grep -q "^user root" || failed "IS_GRSECPROCS"
        fi
    fi

    if [ "$IS_APACHEMUNIN" = 1 ]; then
        if is_debian_stretch; then
            if test -e /etc/apache2/apache2.conf; then
                ( test -h /etc/apache2/mods-enabled/status.load && test -h /etc/munin/plugins/apache_accesses && test -h /etc/munin/plugins/apache_processes && test -h /etc/munin/plugins/apache_accesses || failed "IS_APACHEMUNIN" )
            fi
        else
            if test -e /etc/apache2/apache2.conf; then
                ( grep -E -q "^env.url.*/server-status-[[:alnum:]]{4}" /etc/munin/plugin-conf.d/munin-node && grep -E -q "/server-status-[[:alnum:]]{4}" /etc/apache2/apache2.conf || grep -E -q "/server-status-[[:alnum:]]{4}" /etc/apache2/apache2.conf /etc/apache2/mods-enabled/status.conf 2>/dev/null || failed "IS_APACHEMUNIN" )
            fi
        fi
    fi

    # Verification mytop + Munin si MySQL
    if [ "$IS_MYSQLUTILS" = 1 ]; then
        MYSQL_ADMIN=${MYSQL_ADMIN:-mysqladmin}
        if is_installed mysql-server; then
            # You can configure MYSQL_ADMIN in evocheck.cf
            if ! grep -qs "$MYSQL_ADMIN" /root/.my.cnf; then
                failed "IS_MYSQLUTILS" "mysqladmin missing in /root/.my.cnf"
            fi
            if ! test -x /usr/bin/mytop; then
                if ! test -x /usr/local/bin/mytop; then
                    failed "IS_MYSQLUTILS" "mytop binary missing"
                fi
            fi
            if ! grep -qs debian-sys-maint /root/.mytop; then
                failed "IS_MYSQLUTILS" "debian-sys-maint missing in /root/.mytop"
            fi
        fi
    fi

    # Verification de la configuration du raid soft (mdadm)
    if [ "$IS_RAIDSOFT" = 1 ]; then
        test -e /proc/mdstat && grep -q md /proc/mdstat && \
            ( grep -q "^AUTOCHECK=true" /etc/default/mdadm \
            && grep -q "^START_DAEMON=true" /etc/default/mdadm \
            && grep -qv "^MAILADDR ___MAIL___" /etc/mdadm/mdadm.conf \
            || failed "IS_RAIDSOFT")
    fi

    # Verification du LogFormat de AWStats
    if [ "$IS_AWSTATSLOGFORMAT" = 1 ]; then
        if is_installed apache2.2-common; then
            grep -qE '^LogFormat=1' /etc/awstats/awstats.conf.local \
                || failed "IS_AWSTATSLOGFORMAT"
        fi
    fi

    # Verification de la présence de la config logrotate pour Munin
    if [ "$IS_MUNINLOGROTATE" = 1 ]; then
        ( test -e /etc/logrotate.d/munin-node && test -e /etc/logrotate.d/munin ) \
            || failed "IS_MUNINLOGROTATE"
    fi

    # Verification de la présence de metche
    #if [ "$IS_METCHE" = 1 ]; then
    #    is_installed metche || failed "IS_METCHE"
    #fi

    # Verification de l'activation de Squid dans le cas d'un pack mail
    if [ "$IS_SQUID" = 1 ]; then
        squidconffile="/etc/squid*/squid.conf"
        is_debian_stretch && squidconffile=/etc/squid/evolinux-custom.conf

        if is_pack_web && (is_installed squid || is_installed squid3); then
            host=$(hostname -i)
            http_port=$(grep http_port $squidconffile | cut -f 2 -d " ")
            grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT" $MINIFW_FILE \
                && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d $host -j ACCEPT" $MINIFW_FILE \
                && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d 127.0.0.(1|0/8) -j ACCEPT" $MINIFW_FILE \
                && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port.* $http_port" $MINIFW_FILE \
                || failed "IS_SQUID"
        fi
    fi

    if [ "$IS_EVOMAINTENANCE_FW" = 1 ]; then
        if [ -f "$MINIFW_FILE" ]; then
            rulesNumber=$(grep -c "/sbin/iptables -A INPUT -p tcp --sport 5432 --dport 1024:65535 -s .* -m state --state ESTABLISHED,RELATED -j ACCEPT" "$MINIFW_FILE")
            if [ "$rulesNumber" -lt 2 ]; then
                failed "IS_EVOMAINTENANCE_FW"
            fi
        fi
    fi

    # Verification de la conf et de l'activation de mod-deflate
    if [ "$IS_MODDEFLATE" = 1 ]; then
        f=/etc/apache2/mods-enabled/deflate.conf
        if is_installed apache2.2; then
            test -e $f && grep -q "AddOutputFilterByType DEFLATE text/html text/plain text/xml" $f \
                && grep -q "AddOutputFilterByType DEFLATE text/css" $f \
                && grep -q "AddOutputFilterByType DEFLATE application/x-javascript application/javascript" $f \
                || failed "IS_MODDEFLATE"
        fi
    fi

    # Verification de la conf log2mail
    if [ "$IS_LOG2MAILRUNNING" = 1 ]; then
        if is_pack_web && is_installed log2mail; then
            pgrep log2mail >/dev/null || failed 'IS_LOG2MAILRUNNING'
        fi
    fi
    if [ "$IS_LOG2MAILAPACHE" = 1 ]; then
        if is_debian_stretch; then
            conf=/etc/log2mail/config/apache
        else
            conf=/etc/log2mail/config/default
        fi
        if is_pack_web && is_installed log2mail; then
            grep -q "^file = /var/log/apache2/error.log" $conf 2>/dev/null \
                || failed "IS_LOG2MAILAPACHE"
        fi
    fi
    if [ "$IS_LOG2MAILMYSQL" = 1 ]; then
        if is_pack_web && is_installed log2mail; then
            grep -q "^file = /var/log/syslog" /etc/log2mail/config/{default,mysql,mysql.conf} 2>/dev/null \
                || failed "IS_LOG2MAILMYSQL"
        fi
    fi
    if [ "$IS_LOG2MAILSQUID" = 1 ]; then
        if is_pack_web && is_installed log2mail; then
            grep -q "^file = /var/log/squid.*/access.log" /etc/log2mail/config/* 2>/dev/null \
                || failed "IS_LOG2MAILSQUID"
        fi
    fi

    # Verification si bind est chroote
    if [ "$IS_BINDCHROOT" = 1 ]; then
        if is_installed bind9 && netstat -utpln | grep "/named" | grep :53 | grep -qvE "(127.0.0.1|::1)"; then
            if grep -q '^OPTIONS=".*-t' /etc/default/bind9 && grep -q '^OPTIONS=".*-u' /etc/default/bind9; then
                md5_original=$(md5sum /usr/sbin/named | cut -f 1 -d ' ')
                md5_chrooted=$(md5sum /var/chroot-bind/usr/sbin/named | cut -f 1 -d ' ')
                if [ "$md5_original" != "$md5_chrooted" ]; then
                    failed "IS_BINDCHROOT"
                fi
            else
                failed "IS_BINDCHROOT"
            fi
        fi
    fi

    # Verification de la présence du depot volatile
    if [ "$IS_REPVOLATILE" = 1 ]; then
        if is_debian_lenny; then
            (grep -qE "^deb http://volatile.debian.org/debian-volatile" /etc/apt/sources.list || failed "IS_REPVOLATILE")
        fi
        if is_debian_squeeze; then
            (grep -qE "^deb.*squeeze-updates" /etc/apt/sources.list || failed "IS_REPVOLATILE")
        fi
    fi

    # /etc/network/interfaces should be present, we don't manage systemd-network yet
    if [ "$IS_NETWORK_INTERFACES" = 1 ]; then
        if ! test -f /etc/network/interfaces; then
            IS_AUTOIF=0
            IS_INTERFACESGW=0
            failed "IS_NETWORK_INTERFACES"
        fi
    fi

    # Verify if all if are in auto
    if [ "$IS_AUTOIF" = 1 ]; then
        if is_debian_stretch; then
            interfaces=$(/sbin/ip address show up | grep "^[0-9]*:" | grep -E -v "(lo|vnet|docker|veth|tun|tap|macvtap)" | cut -d " " -f 2 |tr -d : |cut -d@ -f1 |tr "\n" " ")
        else
            interfaces=$(/sbin/ifconfig -s |tail -n +2 |grep -E -v "^(lo|vnet|docker|veth|tun|tap|macvtap)" |cut -d " " -f 1 |tr "\n" " ")
        fi
        for interface in $interfaces; do
            if ! grep -q "^auto $interface" /etc/network/interfaces; then
                failed "IS_AUTOIF"
                break
            fi
        done
    fi

    # Network conf verification
    if [ "$IS_INTERFACESGW" = 1 ]; then
        number=$(grep -Ec "^[^#]*gateway [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" /etc/network/interfaces)
        test $number -gt 1 && failed "IS_INTERFACESGW"
        number=$(grep -Ec "^[^#]*gateway [0-9a-fA-F]+:" /etc/network/interfaces)
        test $number -gt 1 && failed "IS_INTERFACESGW"
    fi

    # Verification de la mise en place d'evobackup
    if [ "$IS_EVOBACKUP" = 1 ]; then
        ls /etc/cron* |grep -q "evobackup" || failed "IS_EVOBACKUP"
    fi

    # Verification de la presence du userlogrotate
    if [ "$IS_USERLOGROTATE" = 1 ]; then
        if is_pack_web; then
            test -x /etc/cron.weekly/userlogrotate || failed "IS_USERLOGROTATE"
        fi
    fi


    # Verification de la syntaxe de la conf d'Apache
    if [ "$IS_APACHECTL" = 1 ]; then
        if is_installed apache2.2-common; then
            /usr/sbin/apache2ctl configtest 2>&1 |grep -q "^Syntax OK$" || failed "IS_APACHECTL"
        fi
    fi

    # Check if there is regular files in Apache sites-enabled.
    if [ "$IS_APACHESYMLINK" = 1 ]; then
        if is_installed apache2.2-common; then
            stat -c %F /etc/apache2/sites-enabled/* | grep -q regular && failed "IS_APACHESYMLINK"
        fi
    fi

    # Check if there is real IP addresses in Allow/Deny directives (no trailing space, inline comments or so).
    if [ "$IS_APACHEIPINALLOW" = 1 ]; then
        # Note: Replace "exit 1" by "print" in Perl code to debug it.
        if is_installed apache2.2-common; then
            grep -IrE "^[^#] *(Allow|Deny) from" /etc/apache2/ | grep -iv "from all" | grep -iv "env=" | perl -ne 'exit 1 unless (/from( [\da-f:.\/]+)+$/i)' || failed "IS_APACHEIPINALLOW"
        fi
    fi

    # Check if default Apache configuration file for munin is absent (or empty or commented).
    if [ "$IS_MUNINAPACHECONF" = 1 ]; then
        if is_debian_squeeze || is_debian_wheezy; then
            muninconf="/etc/apache2/conf.d/munin"
        else
            muninconf="/etc/apache2/conf-available/munin.conf"
        fi
        if is_installed apache2.2-common; then
            test -e $muninconf && grep -vEq "^( |\t)*#" $muninconf && failed "IS_MUNINAPACHECONF"
        fi
    fi

    # Verification de la priorité du package samba si les backports sont utilisés
    if [ "$IS_SAMBAPINPRIORITY" = 1 ]; then
        if is_pack_samba; then
            grep -qrE "^[^#].*backport" /etc/apt/sources.list{,.d} && ( priority=$(grep -E -A2 "^Package:.*samba" /etc/apt/preferences |grep -A1 "^Pin: release a=lenny-backports" |grep "^Pin-Priority:" |cut -f2 -d" ") && test $priority -gt 500 || failed "IS_SAMBAPINPRIORITY" )
        fi
    fi

    # Verification si le système doit redémarrer suite màj kernel.
    if [ "$IS_KERNELUPTODATE" = 1 ]; then
        if is_installed linux-image*; then
            kernel_installed_at=$(date -d "$(ls --full-time -lcrt /boot | tail -n1 | tr -s " " | cut -d " " -f 6)" +%s)
            last_reboot_at=$(($(date +%s) - $(cut -f1 -d '.' /proc/uptime)))
            if [ $kernel_installed_at -gt $last_reboot_at ]; then
                failed "IS_KERNELUPTODATE"
            fi
        fi
    fi

    # Check if the server is running for more than a year.
    if [ "$IS_UPTIME" = 1 ]; then
        if is_installed linux-image*; then
            limit=$(date -d "now - 2 year" +%s)
            last_reboot_at=$(($(date +%s) - $(cut -f1 -d '.' /proc/uptime)))
            if [ $limit -gt $last_reboot_at ]; then
                failed "IS_UPTIME"
            fi
        fi
    fi

    # Check if munin-node running and RRD files are up to date.
    if [ "$IS_MUNINRUNNING" = 1 ]; then
        pgrep munin-node >/dev/null || failed "IS_MUNINRUNNING"

        limit=$(date +"%s" -d "now - 10 minutes")
        updated_at=$(stat -c "%Y" /var/lib/munin/*/*load-g.rrd |sort |tail -1)
        [ $limit -gt $updated_at ] && failed "IS_MUNINRUNNING"

        updated_at=$(stat -c "%Y" /var/cache/munin/www/*/*/load-day.png |sort |tail -1)
        grep -q "^graph_strategy cron" /etc/munin/munin.conf && [ $limit -gt $updated_at ] && failed "IS_MUNINRUNNING"
    fi

    # Check if files in /home/backup/ are up-to-date
    if [ "$IS_BACKUPUPTODATE" = 1 ]; then
        if [ -d /home/backup/ ]; then
            for file in /home/backup/*; do
                limit=$(date +"%s" -d "now - 2 day")
                updated_at=$(stat -c "%Y" $file)
                if [ $limit -gt $updated_at ]; then
                    failed "IS_BACKUPUPTODATE"
                    break;
                fi
            done
        fi
    fi

    # Check if /etc/.git/ has read/write permissions for root only.
    if [ "$IS_GITPERMS" = 1 ]; then
        if test -d /etc/.git; then
            [ "$(stat -c "%a" /etc/.git/)" = "700" ] || failed "IS_GITPERMS"
        fi
    fi

    # Check if no package has been upgraded since $limit.
    if [ "$IS_NOTUPGRADED" = 1 ]; then
        last_upgrade=0
        upgraded=false
        for log in /var/log/dpkg.log*; do
            zgrep -qsm1 upgrade "$log"
            if [ $? -eq 0 ]; then
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
        if [ $last_upgrade -eq 0 ]; then
            [ $install_date -lt $limit ] && failed "IS_NOTUPGRADED"
        else
            [ $last_upgrade -lt $limit ] && failed "IS_NOTUPGRADED"
        fi
    fi

    # Check if reserved blocks for root is at least 5% on every mounted partitions.
    if [ "$IS_TUNE2FS_M5" = 1 ]; then
        parts=$(grep -E "ext(3|4)" /proc/mounts | cut -d ' ' -f1 | tr -s '\n' ' ')
        for part in $parts; do
            blockCount=$(dumpe2fs -h "$part" 2>/dev/null | grep -e "Block count:" | grep -Eo "[0-9]+")
            # If buggy partition, skip it.
            if [ -z $blockCount ]; then
                continue
            fi
            reservedBlockCount=$(dumpe2fs -h "$part" 2>/dev/null | grep -e "Reserved block count:" | grep -Eo "[0-9]+")
            percentage=$(python -c "print(int(round(float(${reservedBlockCount})/${blockCount}*100)))")
            if [ "$percentage" -lt 5 ]; then
                failed "IS_TUNE2FS_M5" "Partition ${part} has less than 5% reserved blocks!"
            fi
        done
    fi

    if [ "$IS_EVOLINUXSUDOGROUP" = 1 ]; then
        if is_debian_stretch; then
            (grep -q "^evolinux-sudo:" /etc/group \
                && grep -q '^%evolinux-sudo  ALL=(ALL:ALL) ALL' /etc/sudoers.d/evolinux) || failed "IS_EVOLINUXSUDOGROUP"
        fi
    fi

    if [ "$IS_USERINADMGROUP" = 1 ]; then
        if is_debian_stretch; then
            for user in $(grep "^evolinux-sudo:" /etc/group |awk -F: '{print $4}' |tr ',' ' '); do
                groups $user |grep -q adm || failed "IS_USERINADMGROUP"
            done
        fi
    fi

    if [ "$IS_APACHE2EVOLINUXCONF" = 1 ]; then
        if is_debian_stretch && test -d /etc/apache2; then
            (test -L /etc/apache2/conf-enabled/z-evolinux-defaults.conf \
                && test -L /etc/apache2/conf-enabled/zzz-evolinux-custom.conf \
                && test -f /etc/apache2/ipaddr_whitelist.conf) || failed "IS_APACHE2EVOLINUXCONF"
        fi
    fi

    if [ "$IS_BACKPORTSCONF" = 1 ]; then
        if is_debian_stretch; then
            grep -qsE "^[^#].*backports" /etc/apt/sources.list \
                && failed "IS_BACKPORTSCONF" "backports can't be in main sources list"
            if grep -qsE "^[^#].*backports" /etc/apt/sources.list.d/*.list; then
                grep -qsE "^[^#].*backports" /etc/apt/preferences.d/* \
                    || failed "IS_BACKPORTSCONF" "backports must have preferences"
            fi
        fi
    fi

    if [ "$IS_BIND9MUNIN" = 1 ]; then
        if is_debian_stretch && is_installed bind9; then
            (test -L /etc/munin/plugins/bind9 && test -e /etc/munin/plugin-conf.d/bind9) || failed "IS_BIND9MUNIN"
        fi
    fi

    if [ "$IS_BIND9LOGROTATE" = 1 ]; then
        if is_debian_stretch && is_installed bind9; then
            test -e /etc/logrotate.d/bind9 || failed "IS_BIND9LOGROTATE"
        fi
    fi

    if [ "$IS_BROADCOMFIRMWARE" = 1 ]; then
        if lspci | grep -q 'NetXtreme II'; then
            (is_installed firmware-bnx2 && grep -q "^deb http://mirror.evolix.org/debian.* non-free" /etc/apt/sources.list) \
                || failed "IS_BROADCOMFIRMWARE"
        fi
    fi

    if [ "$IS_HARDWARERAIDTOOL" = 1 ]; then
        lspci | grep -q 'MegaRAID SAS' && (is_installed megacli && (is_installed megaclisas-status || is_installed megaraidsas-status) \
            || failed "IS_HARDWARERAIDTOOL")
        lspci | grep -q 'Hewlett-Packard Company Smart Array' && (is_installed cciss-vol-status \
            || failed "IS_HARDWARERAIDTOOL")
    fi

    if [ "$IS_LOG2MAILSYSTEMDUNIT" = 1 ]; then
        if is_debian_stretch; then
            (systemctl -q is-active log2mail.service && test -f /etc/systemd/system/log2mail.service && ! test -f /etc/init.d/log2mail) \
                || failed "IS_LOG2MAILSYSTEMDUNIT"
        fi
    fi

    if [ "$IS_LISTUPGRADE" = 1 ]; then
        (test -f /etc/cron.d/listupgrade && test -x /usr/share/scripts/listupgrade.sh) \
            || failed "IS_LISTUPGRADE"
    fi

    if [ "$IS_MARIADBEVOLINUXCONF" = 1 ]; then
        if is_debian_stretch; then
            if is_installed mariadb-server; then
                (test -f /etc/mysql/mariadb.conf.d/z-evolinux-defaults.cnf \
                    && test -f /etc/mysql/mariadb.conf.d/zzz-evolinux-custom.cnf) \
                    || failed "IS_MARIADBEVOLINUXCONF"
            fi
        fi
    fi

    if [ "$IS_SQL_BACKUP" = 1 ]; then
        if (is_installed "mysql-server" || is_installed "mariadb-server"); then
            # You could change the default path in /etc/evocheck.cf
            SQL_BACKUP_PATH=${SQL_BACKUP_PATH:-"/home/backup/mysql.bak.gz"}
            test -f "$SQL_BACKUP_PATH" || failed "IS_SQL_BACKUP"
        fi
    fi

    if [ "$IS_POSTGRES_BACKUP" = 1 ]; then
        if is_installed "postgresql-9*"; then
            # If you use something like barman, you should deactivate this check
            # You could change the default path in /etc/evocheck.cf
            POSTGRES_BACKUP_PATH=${POSTGRES_BACKUP_PATH:-"/home/backup/pg.dump.bak"}
            test -f "$POSTGRES_BACKUP_PATH" || failed "IS_POSTGRES_BACKUP"
        fi
    fi

    if [ "$IS_MONGO_BACKUP" = 1 ]; then
        if is_installed "mongodb-org-server"; then
            # You could change the default path in /etc/evocheck.cf
            MONGO_BACKUP_PATH=${MONGO_BACKUP_PATH:-"/home/backup/mongodump"}
            if [ -d "$MONGO_BACKUP_PATH" ]; then
                for file in ${MONGO_BACKUP_PATH}/*/*.{json,bson}; do
                    # Skip indexes file.
                    if ! [[ "$file" =~ indexes ]]; then
                        limit=$(date +"%s" -d "now - 2 day")
                        updated_at=$(stat -c "%Y" $file)
                        if [ -f $file ] && [ $limit -gt $updated_at  ]; then
                            failed "IS_MONGO_BACKUP"
                            break
                        fi
                    fi
                done
            else
                failed "IS_MONGO_BACKUP"
            fi
        fi
    fi

    if [ "$IS_LDAP_BACKUP" = 1 ]; then
        if is_installed slapd; then
            # You could change the default path in /etc/evocheck.cf
            LDAP_BACKUP_PATH=${LDAP_BACKUP_PATH:-"/home/backup/ldap.bak"}
            test -f "$LDAP_BACKUP_PATH" || failed "IS_LDAP_BACKUP"
        fi
    fi

    if [ "$IS_REDIS_BACKUP" = 1 ]; then
        if is_installed redis-server; then
            # You could change the default path in /etc/evocheck.cf
            REDIS_BACKUP_PATH=${REDIS_BACKUP_PATH:-"/home/backup/dump.rdb"}
            test -f "$REDIS_BACKUP_PATH" || failed "IS_REDIS_BACKUP"
        fi
    fi

    if [ "$IS_ELASTIC_BACKUP" = 1 ]; then
        if is_installed elasticsearch; then
            # You could change the default path in /etc/evocheck.cf
            ELASTIC_BACKUP_PATH=${ELASTIC_BACKUP_PATH:-"/home/backup/elasticsearch"}
            test -d "$ELASTIC_BACKUP_PATH" || failed "IS_ELASTIC_BACKUP"
        fi
    fi

    if [ "$IS_MARIADBSYSTEMDUNIT" = 1 ]; then
        if is_debian_stretch && is_installed mariadb-server; then
            (systemctl -q is-active mariadb.service && test -f /etc/systemd/system/mariadb.service.d/evolinux.conf) \
                || failed "IS_MARIADBSYSTEMDUNIT"
        fi
    fi

    if [ "$IS_MYSQLMUNIN" = 1 ]; then
        if is_debian_stretch && is_installed mariadb-server; then
            for file in mysql_bytes mysql_queries mysql_slowqueries \
                mysql_threads mysql_connections mysql_files_tables \
                mysql_innodb_bpool mysql_innodb_bpool_act mysql_innodb_io \
                mysql_innodb_log mysql_innodb_rows mysql_innodb_semaphores \
                mysql_myisam_indexes mysql_qcache mysql_qcache_mem \
                mysql_sorts mysql_tmp_tables; do

                if [[ ! -L /etc/munin/plugins/$file ]]; then
                    failed "IS_MYSQLMUNIN"
                    break
                fi
            done
        fi
    fi

    if [ "$IS_MYSQLNRPE" = 1 ]; then
        if is_debian_stretch && is_installed mariadb-server; then
            (test -f ~nagios/.my.cnf \
                && [ "$(stat -c %U ~nagios/.my.cnf)" = "nagios" ] \
                && [ "$(stat -c %a ~nagios/.my.cnf)" = "600" ] \
                && grep -q -F "command[check_mysql]=/usr/lib/nagios/plugins/check_mysql -H localhost  -f ~nagios/.my.cnf") \
                || failed "IS_MYSQLNRPE"
        fi
    fi

    if [ "$IS_PHPEVOLINUXCONF" = 1 ]; then
        if is_debian_stretch && is_installed php; then
            (test -f /etc/php/7.0/cli/conf.d/z-evolinux-defaults.ini \
                && test -f /etc/php/7.0/cli/conf.d/zzz-evolinux-custom.ini) \
                || failed "IS_PHPEVOLINUXCONF"
        fi
    fi

    if [ "$IS_SQUIDLOGROTATE" = 1 ]; then
        if is_debian_stretch && is_installed squid; then
            grep -q monthly /etc/logrotate.d/squid || failed "IS_SQUIDLOGROTATE"
        fi
    fi

    if [ "$IS_SQUIDEVOLINUXCONF" = 1 ]; then
        if is_debian_stretch && is_installed squid; then
            (grep -qs "^CONFIG=/etc/squid/evolinux-defaults.conf$" /etc/default/squid \
                && test -f /etc/squid/evolinux-defaults.conf \
                && test -f /etc/squid/evolinux-whitelist-defaults.conf \
                && test -f /etc/squid/evolinux-whitelist-custom.conf \
                && test -f /etc/squid/evolinux-acl.conf \
                && test -f /etc/squid/evolinux-httpaccess.conf \
                && test -f /etc/squid/evolinux-custom.conf) \
                || failed "IS_SQUIDEVOLINUXCONF"
        fi
    fi

    if [ "$IS_DUPLICATE_FS_LABEL" = 1 ]; then
        # Do it only if thereis blkid binary
        BLKID_BIN=$(command -v blkid)
        if [ -x "$BLKID_BIN" ]; then
            tmpFile=$(mktemp -p /tmp)
            parts=$($BLKID_BIN | grep -ve raid_member -e EFI_SYSPART \
              | grep -Eo ' LABEL=".*"' | cut -d'"' -f2)
            for part in $parts; do
                echo "$part" >> "$tmpFile"
            done
            tmpOutput=$(sort < "$tmpFile" | uniq -d)
            # If there is no duplicate, uniq will have no output
            # So, if $tmpOutput is not null, there is a duplicate
            if [ -n "$tmpOutput" ]; then
                failed "IS_DUPLICATE_FS_LABEL"
                if [ "$VERBOSE" = 1 ]; then
                    echo "Duplicate labels:"
                    echo -e "$tmpOutput\n"
                fi
            fi
            rm $tmpFile
        fi
    fi

    if [ "$IS_EVOLIX_USER" = 1 ]; then
        grep -q "evolix:" /etc/passwd && failed "IS_EVOLIX_USER"
    fi

    if [ "$IS_EVOACME_CRON" = 1 ]; then
        if [ -f "/usr/local/sbin/evoacme" ]; then
            # Old cron file, should be deleted
            test -f /etc/cron.daily/certbot && failed "IS_EVOACME_CRON"
            # evoacme cron file should be present
            test -f /etc/cron.daily/evoacme || failed "IS_EVOACME_CRON"
        fi
    fi

    if [ "$IS_EVOACME_LIVELINKS" = 1 ]; then
        EVOACME_BIN=$(command -v evoacme)
        if [ -x "$EVOACME_BIN" ]; then
            # Sometimes evoacme is installed but no certificates has been generated
            numberOfLinks=$(find /etc/letsencrypt/ -type l | wc -l)
            if [ $numberOfLinks -gt 0 ]; then
                for live in /etc/letsencrypt/*/live; do
                    actualLink=$(ls -lhad $live | tr -s ' ' | cut -d' ' -f 11)
                    actualCertDate=$(cut -d'/' -f5 <<< $actualLink)
                    liveDir=$(ls -lhad $live | tr -s ' ' | cut -d' ' -f 9)
                    certDir=${liveDir%%/live}
                    lastCertDir=$(stat -c %n ${certDir}/[0-9]* | tail -1)
                    lastCertDate=$(cut -d'/' -f5 <<< $lastCertDir)
                    if [[ "$actualCertDate" != "$lastCertDate" ]]; then
                        failed "IS_EVOACME_LIVELINKS"
                        break
                    fi
                done
            fi
        fi
    fi

    if [ "$IS_APACHE_CONFENABLED" = 1 ]; then
        # Starting from Jessie and Apache 2.4, /etc/apache2/conf.d/
        # must be replaced by conf-available/ and config files symlinked
        # to conf-enabled/
        if is_debian_jessie || is_debian_stretch; then
            if [ -f /etc/apache2/apache2.conf ]; then
                test -d /etc/apache2/conf.d/ && failed "IS_APACHE_CONFENABLED"
                grep -q 'Include conf.d' /etc/apache2/apache2.conf && failed "IS_APACHE_CONFENABLED"
            fi
        fi
    fi

    if [ "$IS_MELTDOWN_SPECTRE" = 1 ]; then
        # For Stretch, detection is easy as the kernel use
        # /sys/devices/system/cpu/vulnerabilities/
        if is_debian_stretch; then
            for vuln in meltdown spectre_v1 spectre_v2; do
                test -f /sys/devices/system/cpu/vulnerabilities/$vuln \
                    || failed "IS_MELTDOWN_SPECTRE"
            done
        # For Jessie this is quite complicated to verify and we need to use kernel config file
        elif is_debian_jessie; then
            if grep -q "BOOT_IMAGE=" /proc/cmdline; then
                kernelPath=$(grep -Eo 'BOOT_IMAGE=[^ ]+' /proc/cmdline | cut -d= -f2)
                kernelVer=${kernelPath##*/vmlinuz-}
                kernelConfig="config-${kernelVer}"
                # Sometimes autodetection of kernel config file fail, so we test if the file really exists.
                if [ -f /boot/$kernelConfig ]; then
                    grep -Eq '^CONFIG_PAGE_TABLE_ISOLATION=y' /boot/$kernelConfig \
                        || failed "IS_MELTDOWN_SPECTRE"
                    grep -Eq '^CONFIG_RETPOLINE=y' /boot/$kernelConfig \
                        || failed "IS_MELTDOWN_SPECTRE"
                fi
            fi
        fi
    fi

    if [ "$IS_OLD_HOME_DIR" = 1 ]; then
        for dir in /home/*; do
            statResult=$(stat -c "%n has owner %u resolved as %U" "$dir" \
                | grep -Eve '.bak' -e '\.[0-9]{2}-[0-9]{2}-[0-9]{4}' \
                | grep "UNKNOWN")
            # There is at least one dir matching
            if [[ -n "$statResult" ]]; then
                failed "IS_OLD_HOME_DIR"
                if [[ "$VERBOSE" == 1 ]]; then
                    echo "$statResult"
                else
                    break
                fi
            fi
        done
    fi
fi


if is_openbsd; then

    if [ "$IS_SOFTDEP" = 1 ]; then
        grep -q "softdep" /etc/fstab || failed "IS_SOFTDEP"
    fi

    if [ "$IS_WHEEL" = 1 ]; then
        grep -qE "^%wheel.*$" /etc/sudoers || failed "IS_WHEEL"
    fi

    if [ "$IS_SUDOADMIN" = 1 ]; then
        grep -qE "^User_Alias ADMIN=.*$" /etc/sudoers || failed "IS_SUDOADMIN"
    fi

    if [ "$IS_PKGMIRROR" = 1 ]; then
        grep -qE "^export PKG_PATH=http://ftp\.fr\.openbsd\.org/pub/OpenBSD/[0-9.]+/packages/[a-z0-9]+/$" /root/.profile \
            || failed "IS_PKGMIRROR"
    fi

    if [ "$IS_HISTORY" = 1 ]; then
        f=/root/.profile
        grep -q "^HISTFILE=\$HOME/.histfile" $f \
            && grep -q "^export HISTFILE" $f \
            && grep -q "^HISTSIZE=1000" $f \
            && grep -q "^export HISTSIZE" $f \
            || failed "IS_HISTORY"
    fi

    if [ "$IS_VIM" = 1 ]; then
        command -v vim > /dev/null 2>&1 || failed "IS_VIM"
    fi

    if [ "$IS_TTYC0SECURE" = 1 ]; then
        grep -Eqv "^ttyC0.*secure$" /etc/ttys || failed "IS_TTYC0SECURE"
    fi

    if [ "$IS_CUSTOMSYSLOG" = 1 ]; then
        grep -q "Evolix" /etc/newsyslog.conf || failed "IS_CUSTOMSYSLOG"
    fi

    if [ "$IS_NOINETD" = 1 ]; then
        grep -q "inetd=NO" /etc/rc.conf.local 2>/dev/null || failed "IS_NOINETD"
    fi

    if [ "$IS_SUDOMAINT" = 1 ]; then
        f=/etc/sudoers
        grep -q "Cmnd_Alias MAINT = /usr/share/scripts/evomaintenance.sh" $f \
            && grep -q "ADMIN ALL=NOPASSWD: MAINT" $f \
            || failed "IS_SUDOMAINT"
    fi

    if [ "$IS_POSTGRESQL" = 1 ]; then
        pkg info | grep -q postgresql-client || failed "IS_POSTGRESQL"
    fi

    if [ "$IS_NRPE" = 1 ]; then
        ( pkg info | grep -qE "nagios-plugins-[0-9.]" \
            && pkg info | grep -q nagios-plugins-ntp \
            && pkg info | grep -q nrpe ) || failed "IS_NRPE"
    fi

# if [ "$IS_NRPEDISKS" = 1 ]; then
#     NRPEDISKS=$(grep command.check_disk /etc/nrpe.cfg 2>/dev/null | grep "^command.check_disk[0-9]" | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
#     DFDISKS=$(df -Pl | grep -E -v "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)" | wc -l)
#     [ "$NRPEDISKS" = "$DFDISKS" ] || failed "IS_NRPEDISKS"
# fi

# Verification du check_mailq dans nrpe.cfg (celui-ci doit avoir l'option "-M postfix" si le MTA est Postfix)
#
# if [ "$IS_NRPEPOSTFIX" = 1 ]; then
#     pkg info | grep -q postfix && ( grep -q "^command.*check_mailq -M postfix" /etc/nrpe.cfg 2>/dev/null || failed "IS_NRPEPOSTFIX" )
# fi

    if [ "$IS_NRPEDAEMON" = 1 ]; then
        grep -q "echo -n ' nrpe';        /usr/local/sbin/nrpe -d" /etc/rc.local \
            || failed "IS_NREPEDAEMON"
    fi

    if [ "$IS_ALERTBOOT" = 1 ]; then
        grep -qE "^date \| mail -sboot/reboot .*evolix.fr$" /etc/rc.local \
            || failed "IS_ALERTBOOT"
    fi

    if [ "$IS_RSYNC" = 1 ]; then
        pkg info | grep -q rsync || failed "IS_RSYNC"
    fi

    if [ "$IS_CRONPATH" = 1 ]; then
        grep -q "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin" /var/cron/tabs/root \
            || failed "IS_CRONPATH"
    fi

    #TODO
    # - Check en profondeur de postfix
    # - NRPEDISK et NRPEPOSTFIX
fi

if [ "$IS_TMP_1777" = 1 ]; then
    actual=$(stat --format "%A" /tmp)
    expected="drwxrwxrwt"
    test "$expected" = "$actual" || failed "IS_TMP_1777"
fi

if [ "$IS_ROOT_0700" = 1 ]; then
    actual=$(stat --format "%A" /root)
    expected="drwx------"
    test "$expected" = "$actual" || failed "IS_ROOT_0700"
fi

if [ "$IS_USRSHARESCRIPTS" = 1 ]; then
    actual=$(stat --format "%A" /usr/share/scripts)
    expected="drwx------"
    test "$expected" = "$actual" || failed "IS_USRSHARESCRIPTS"
fi

if [ "$IS_SSHPERMITROOTNO" = 1 ]; then
    if is_debian_stretch; then
        grep -q "^PermitRoot" /etc/ssh/sshd_config && grep -E -qi "PermitRoot.*no" /etc/ssh/sshd_config \
            || failed "IS_SSHPERMITROOTNO"
    else
        grep -E -qi "PermitRoot.*no" /etc/ssh/sshd_config || failed "IS_SSHPERMITROOTNO"
    fi
fi

if [ "$IS_EVOMAINTENANCEUSERS" = 1 ]; then
    # Can be changed in evocheck.cf
    homeDir=${homeDir:-/home}
    if is_debian_stretch; then
        for i in $(getent group evolinux-sudo | cut -d':' -f4 | tr ',' ' '); do
            grep -qs "^trap.*sudo.*evomaintenance.sh" ${homeDir}/$i/.*profile
            if [ $? != 0 ]; then
                failed "IS_EVOMAINTENANCEUSERS"
                if [ "$VERBOSE" = 1 ]; then
                    echo "$i doesn't have evomaintenance trap!"
                else
                    break
                fi
            fi
        done
    else
        if [ -f /etc/sudoers.d/evolinux ]; then
            sudoers="/etc/sudoers.d/evolinux"
        else
            sudoers="/etc/sudoers"
        fi
        users=$( (grep "^User_Alias *ADMIN" $sudoers | cut -d= -f2 | tr -d " "; grep "^sudo" /etc/group | cut -d: -f 4) | tr "," "\n" | sort -u)
        for i in $users; do
            grep -qs "^trap.*sudo.*evomaintenance.sh" ${homeDir}/${i}/.*profile
            if [ $? != 0 ]; then
                failed "IS_EVOMAINTENANCEUSERS"
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
    perms=$(stat -c "%a" $f)
    ( test -e $f \
        && test "$perms" = "600" \
        && grep "^export PGPASSWORD" $f | grep -qv "your-passwd" \
        && grep "^PGDB" $f | grep -qv "your-db" \
        && grep "^PGTABLE" $f | grep -qv "your-table" \
        && grep "^PGHOST" $f | grep -qv "your-pg-host" \
        && grep "^FROM" $f | grep -qv "jdoe@example.com" \
        && grep "^FULLFROM" $f | grep -qv "John Doe <jdoe@example.com>" \
        && grep "^URGENCYFROM" $f | grep -qv "mama.doe@example.com" \
        && grep "^URGENCYTEL" $f | grep -qv "06.00.00.00.00" \
        && grep "^REALM" $f | grep -qv "example.com" ) \
        || failed "IS_EVOMAINTENANCECONF"
fi

if [ "$IS_PRIVKEYWOLRDREADABLE" = 1 ]; then
    for f in /etc/ssl/private/*; do
        perms=$(stat -L -c "%a" $f)
        if [ "${perms: -1}" != "0" ]; then
            failed "IS_PRIVKEYWOLRDREADABLE"
            break
        fi
    done
fi
