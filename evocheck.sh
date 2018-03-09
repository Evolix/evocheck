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

# Source configuration file
test -f /etc/evocheck.cf && . /etc/evocheck.cf

# If --cron is passed, ignore some checks.
if [ "$1" = "--cron" ]; then
    IS_KERNELUPTODATE=0
    IS_UPTIME=0
fi

# Functions
is_pack_web(){
    test -e /usr/share/scripts/web-add.sh || test -e /usr/share/scripts/evoadmin/web-add.sh
}

is_pack_samba(){
    test -e /usr/share/scripts/add.pl
}

is_installed(){
    for pkg in $*; do
            dpkg -l $pkg 2>/dev/null |grep -q ^ii || return 1
    done
}

is_debianversion(){
    [ $(lsb_release -c -s) = $1 ] && return 0
}

#-----------------------------------------------------------
#Vérifie si c'est une debian et fait les tests appropriés.
#-----------------------------------------------------------

if [ -e /etc/debian_version ]; then

    if [ "$IS_DPKGWARNING" = 1 ]; then
        is_debianversion squeeze && ( [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ] ) && ( \
            egrep -i "(Pre-Invoke ..echo Are you sure to have rw on|Post-Invoke ..echo Dont forget to mount -o remount)" \
            /etc/apt/apt.conf | wc -l | grep -q ^2$ || echo 'IS_DPKGWARNING FAILED!' )
        is_debianversion wheezy && ( ( [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ] ) && \
            ( test -e /etc/apt/apt.conf.d/80evolinux || echo 'IS_DPKGWARNING FAILED!' )
            test -e /etc/apt/apt.conf && echo 'IS_DPKGWARNING FAILED!' )
        is_debianversion stretch && (test -e /etc/apt/apt.conf.d/z-evolinux.conf || echo 'IS_DPKGWARNING FAILED!')
    fi

    if [ "$IS_UMASKSUDOERS" = 1 ]; then
        is_debianversion squeeze && ( grep -q ^Defaults.*umask=0077 /etc/sudoers || echo 'IS_UMASKSUDOERS FAILED!' )
    fi

    # Verifying check_mailq in Nagios NRPE config file. (Option "-M postfix" need to be set if the MTA is Postfix)
    if [ "$IS_NRPEPOSTFIX" = 1 ]; then
        is_debianversion squeeze && is_installed postfix && ( grep -q "^command.*check_mailq -M postfix" /etc/nagios/nrpe.cfg || echo 'IS_NRPEPOSTFIX FAILED!' )
        is_debianversion squeeze || ( is_installed postfix && ( test -e /etc/nagios/nrpe.cfg && grep -qr "^command.*check_mailq -M postfix" /etc/nagios/nrpe.* || echo 'IS_NRPEPOSTFIX FAILED!' ) )
    fi

    # Check if mod-security config file is present
    if [ "$IS_MODSECURITY" = 1 ]; then
        is_debianversion squeeze && is_installed libapache-mod-security && \
            (test -e /etc/apache2/conf.d/mod-security2.conf || echo 'IS_MODSECURITY FAILED!')
        is_debianversion wheezy && is_installed libapache2-modsecurity && \
            (test -e /etc/apache2/conf.d/mod-security2.conf || echo 'IS_MODSECURITY FAILED!')
    fi

    if [ "$IS_CUSTOMSUDOERS" = 1 ]; then
        egrep -qr "umask=0077" /etc/sudoers* || echo 'IS_CUSTOMSUDOERS FAILED!'
    fi

    if [ "$IS_VARTMPFS" = 1 ]; then
        df /var/tmp | grep -q tmpfs || echo 'IS_VARTMPFS FAILED!'
    fi
    
    if [ "$IS_SERVEURBASE" = 1 ]; then
        is_installed serveur-base || echo 'IS_SERVEURBASE FAILED!'
    fi
    
    if [ "$IS_LOGROTATECONF" = 1 ]; then
        test -e /etc/logrotate.d/zsyslog || echo 'IS_LOGROTATECONF FAILED!'
    fi
    
    if [ "$IS_SYSLOGCONF" = 1 ]; then
        grep -q "^# Syslog for Pack Evolix serveur" /etc/*syslog.conf || echo 'IS_SYSLOGCONF FAILED!'
    fi
    
    if [ "$IS_DEBIANSECURITY" = 1 ]; then
        grep -q "^deb.*security" /etc/apt/sources.list || echo 'IS_DEBIANSECURITY FAILED!'
    fi
    
    if [ "$IS_APTITUDEONLY" = 1 ]; then
        is_debianversion squeeze && test -e /usr/bin/apt-get && echo 'IS_APTITUDEONLY FAILED!'
        is_debianversion wheezy && test -e /usr/bin/apt-get && echo 'IS_APTITUDEONLY FAILED!'
    fi

    if [ "$IS_APTITUDE" = 1 ]; then
        is_debianversion jessie && test -e /usr/bin/aptitude && echo 'IS_APTITUDE FAILED!'
        is_debianversion stretch && test -e /usr/bin/aptitude && echo 'IS_APTITUDE FAILED!'
    fi

    if [ "$IS_APTGETBAK" = 1 ]; then
        is_debianversion jessie && test -e /usr/bin/apt-get.bak && echo 'IS_APTGETBAK FAILED!'
        is_debianversion stretch && test -e /usr/bin/apt-get.bak && echo 'IS_APTGETBAK FAILED!'
    fi

    if [ "$IS_APTICRON" = 1 ]; then
        status="OK"
        test -e /etc/cron.d/apticron || status="fail"
        test -e /etc/cron.daily/apticron && status="fail"
        test "$status" = "fail" || test -e /usr/bin/apt-get.bak || status="fail"
        ( is_debianversion squeeze || is_debianversion wheezy ) && test "$status" = "fail" && echo 'IS_APTICRON FAILED!'
    fi
    
    if [ "$IS_USRRO" = 1 ]; then
        grep /usr /etc/fstab | grep -q ro || echo 'IS_USRRO FAILED!'
    fi
    
    if [ "$IS_TMPNOEXEC" = 1 ]; then
        mount | grep "on /tmp" | grep -q noexec || echo 'IS_TMPNOEXEC FAILED!'
    fi
    
    if [ "$IS_MOUNT_FSTAB" = 1 ]; then
        # Test if lsblk available, if not skip this test...
        if test -x "$(command -v lsblk)"; then
            for mountPoint in $(lsblk -o MOUNTPOINT -l -n | grep '/'); do
                grep -Eq "$mountPoint\W" /etc/fstab || echo 'IS_MOUNT_FSTAB FAILED!'
            done
        fi
    fi

    if [ "$IS_LISTCHANGESCONF" = 1 ]; then
        if is_debianversion stretch; then
            is_installed apt-listchanges && echo 'IS_LISTCHANGESCONF FAILED!'
        else
            test -e /etc/apt/listchanges.conf && egrep "(which=both|confirm=1)" /etc/apt/listchanges.conf | wc -l | grep -q ^2$ || echo 'IS_LISTCHANGESCONF FAILED!'
        fi
    fi
    
    if [ "$IS_CUSTOMCRONTAB" = 1 ]; then
        egrep "^(17 \*|25 6|47 6|52 6)" /etc/crontab | wc -l | grep -q ^4$ && echo 'IS_CUSTOMCRONTAB FAILED!'
    fi
    
    if [ "$IS_SSHALLOWUSERS" = 1 ]; then
        egrep -qi "AllowUsers" /etc/ssh/sshd_config || echo 'IS_SSHALLOWUSERS FAILED!'
    fi
    
    if [ "$IS_DISKPERF" = 1 ]; then
        test -e /root/disk-perf.txt || echo 'IS_DISKPERF FAILED!'
    fi
    
    if [ "$IS_TMOUTPROFILE" = 1 ]; then
        grep -q TMOUT= /etc/profile /etc/profile.d/evolinux.sh || echo 'IS_TMOUTPROFILE FAILED!'
    fi
    
    if [ "$IS_ALERT5BOOT" = 1 ]; then
        grep -q ^date /etc/rc2.d/S*alert5 || echo 'IS_ALERT5BOOT FAILED!'
    fi
    
    if [ "$IS_ALERT5MINIFW" = 1 ]; then
        grep -q ^/etc/init.d/minifirewall /etc/rc2.d/S*alert5 || echo 'IS_ALERT5MINIFW FAILED!'
    fi

    if [ "$IS_ALERT5MINIFW" = 1 ] && [ "$IS_MINIFW" = 1 ]; then
        /sbin/iptables -L -n | grep -q -E "^ACCEPT\s*all\s*--\s*31\.170\.8\.4\s*0\.0\.0\.0/0\s*$" || echo 'IS_MINIFW FAILED!'
    fi
    
    if [ "$IS_NRPEPERMS" = 1 ]; then
        test -d /etc/nagios && ls -ld /etc/nagios | grep -q drwxr-x--- || echo 'IS_NRPEPERMS FAILED!'
    fi
    
    if [ "$IS_MINIFWPERMS" = 1 ]; then
        is_debianversion squeeze && ( ls -l /etc/firewall.rc | grep -q -- -rw------- || echo 'IS_MINIFWPERMS FAILED!' )
        is_debianversion wheezy && ( ls -l /etc/firewall.rc | grep -q -- -rw------- || echo 'IS_MINIFWPERMS FAILED!' )
        is_debianversion jessie && ( ls -l /etc/default/minifirewall | grep -q -- -rw------- || echo 'IS_MINIFWPERMS FAILED!' )
        is_debianversion stretch && ( ls -l /etc/default/minifirewall | grep -q -- -rw------- || echo 'IS_MINIFWPERMS FAILED!' )
    fi
    
    if [ "$IS_NRPEDISKS" = 1 ]; then
        NRPEDISKS=$(grep command.check_disk /etc/nagios/nrpe.cfg | grep ^command.check_disk[0-9] | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
        DFDISKS=$(df -Pl | egrep -v "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)" | wc -l)
        [ "$NRPEDISKS" = "$DFDISKS" ] || echo 'IS_NRPEDISKS FAILED!'
    fi

    if [ "$IS_NRPEPID" = 1 ]; then
        is_debianversion squeeze || (test -e /etc/nagios/nrpe.cfg && grep -q "^pid_file=/var/run/nagios/nrpe.pid" /etc/nagios/nrpe.cfg || echo 'IS_NRPEPID FAILED!')
    fi
    
    if [ "$IS_GRSECPROCS" = 1 ]; then
        uname -a | grep -q grsec && ( grep -q ^command.check_total_procs..sudo /etc/nagios/nrpe.cfg && grep -A1 "^\[processes\]" /etc/munin/plugin-conf.d/munin-node | grep -q "^user root" || echo 'IS_GRSECPROCS FAILED!' )
    fi
    
    if [ "$IS_APACHEMUNIN" = 1 ]; then
        test -e /etc/apache2/apache2.conf && ( is_debianversion stretch || ( egrep -q "^env.url.*/server-status-[[:alnum:]]{4}" /etc/munin/plugin-conf.d/munin-node && egrep -q "/server-status-[[:alnum:]]{4}" /etc/apache2/apache2.conf || egrep -q "/server-status-[[:alnum:]]{4}" /etc/apache2/apache2.conf /etc/apache2/mods-enabled/status.conf 2>/dev/null || echo 'IS_APACHEMUNIN FAILED!' ) )
        test -e /etc/apache2/apache2.conf && ( is_debianversion stretch && ( test -h /etc/apache2/mods-enabled/status.load && test -h /etc/munin/plugins/apache_accesses && test -h /etc/munin/plugins/apache_processes && test -h /etc/munin/plugins/apache_accesses || echo 'IS_APACHEMUNIN FAILED!' ) )
    fi
    
    # Verification mytop + Munin si MySQL
    if [ "$IS_MYSQLUTILS" = 1 ]; then
        is_installed mysql-server && ( grep -q mysqladmin /root/.my.cnf && test -x /usr/bin/mytop && grep -q debian-sys-maint /root/.mytop || echo 'IS_MYSQLUTILS FAILED!' )
    fi
    
    # Verification de la configuration du raid soft (mdadm)
    if [ "$IS_RAIDSOFT" = 1 ]; then
        test -e /proc/mdstat && grep -q md /proc/mdstat && \
            ( grep -q "^AUTOCHECK=true" /etc/default/mdadm \
        && grep -q "^START_DAEMON=true" /etc/default/mdadm \
        && grep -qv "^MAILADDR ___MAIL___" /etc/mdadm/mdadm.conf || echo 'IS_RAIDSOFT FAILED!')
    fi
    
    # Verification du LogFormat de AWStats
    if [ "$IS_AWSTATSLOGFORMAT" = 1 ]; then
        is_installed apache2.2-common && ( grep -qE '^LogFormat=1' /etc/awstats/awstats.conf.local || echo 'IS_AWSTATSLOGFORMAT FAILED!' )
    fi
    
    # Verification de la présence de la config logrotate pour Munin
    if [ "$IS_MUNINLOGROTATE" = 1 ]; then
        ( test -e /etc/logrotate.d/munin-node && test -e /etc/logrotate.d/munin ) || echo 'IS_MUNINLOGROTATE FAILED!'
    fi

    # Verification de la présence de metche
    #if [ "$IS_METCHE" = 1 ]; then
    #	is_installed metche || echo 'IS_METCHE FAILED!'
    #fi
        
    # Verification de l'activation de Squid dans le cas d'un pack mail
    if [ "$IS_SQUID" = 1 ]; then
        squidconffile=/etc/squid*/squid.conf
        is_debianversion squeeze && f=/etc/firewall.rc
        is_debianversion wheezy && f=/etc/firewall.rc
        is_debianversion jessie && f=/etc/default/minifirewall
        is_debianversion stretch && f=/etc/default/minifirewall && squidconffile=/etc/squid/evolinux-custom.conf
        is_pack_web && ( is_installed squid || is_installed squid3 \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT" $f \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d `hostname -i` -j ACCEPT" $f \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d 127.0.0.(1|0/8) -j ACCEPT" $f \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port.* `grep http_port $squidconffile | cut -f 2 -d " "`" $f || echo 'IS_SQUID FAILED!' )
    fi
    
    # Verification de la conf et de l'activation de mod-deflate
    if [ "$IS_MODDEFLATE" = 1 ]; then
        f=/etc/apache2/mods-enabled/deflate.conf
        is_installed apache2.2 && (test -e $f && grep -q "AddOutputFilterByType DEFLATE text/html text/plain text/xml" $f \
        && grep -q "AddOutputFilterByType DEFLATE text/css" $f \
        && grep -q "AddOutputFilterByType DEFLATE application/x-javascript application/javascript" $f || echo 'IS_MODDEFLATE FAILED!')
    fi
    
    # Verification de la conf log2mail
    if [ "$IS_LOG2MAILRUNNING" = 1 ]; then
        is_pack_web && (is_installed log2mail && pgrep log2mail >/dev/null || echo 'IS_LOG2MAILRUNNING')
    fi
    if [ "$IS_LOG2MAILAPACHE" = 1 ]; then
        if is_debianversion stretch; then
            conf=/etc/log2mail/config/apache
        else
            conf=/etc/log2mail/config/default
        fi
        is_pack_web && ( is_installed log2mail && grep -q "^file = /var/log/apache2/error.log" $conf 2>/dev/null || echo 'IS_LOG2MAILAPACHE FAILED!' )
    fi
    if [ "$IS_LOG2MAILMYSQL" = 1 ]; then
        is_pack_web && ( is_installed log2mail && grep -q "^file = /var/log/syslog" /etc/log2mail/config/{default,mysql,mysql.conf} 2>/dev/null || echo 'IS_LOG2MAILMYSQL FAILED!' )
    fi
    if [ "$IS_LOG2MAILSQUID" = 1 ]; then
        is_pack_web && ( is_installed log2mail && grep -q "^file = /var/log/squid.*/access.log" \
            /etc/log2mail/config/* 2>/dev/null || echo 'IS_LOG2MAILSQUID FAILED!' )
    fi
    
    # Verification si bind est chroote
    if [ "$IS_BINDCHROOT" = 1 ]; then
        if is_installed bind9 && $(netstat -utpln |grep "/named" |grep :53 |grep -qvE "(127.0.0.1|::1)"); then
            if grep -q '^OPTIONS=".*-t' /etc/default/bind9 && grep -q '^OPTIONS=".*-u' /etc/default/bind9; then
                if [ "$(md5sum /usr/sbin/named |cut -f 1 -d ' ')" != "$(md5sum /var/chroot-bind/usr/sbin/named |cut -f 1 -d ' ')" ]; then
                    echo 'IS_BINDCHROOT FAILED!'
                fi
            else
                echo 'IS_BINDCHROOT FAILED!'
            fi
        fi
    fi
    
    # Verification de la présence du depot volatile
    if [ "$IS_REPVOLATILE" = 1 ]; then
        test `cat /etc/debian_version |cut -d "." -f 1` -eq 5 && (grep -qE "^deb http://volatile.debian.org/debian-volatile" /etc/apt/sources.list || echo 'IS_REPVOLATILE FAILED!')
            test `cat /etc/debian_version |cut -d "." -f 1` -eq 6 && (grep -qE "^deb.*squeeze-updates" /etc/apt/sources.list || echo 'IS_REPVOLATILE FAILED!')
    fi
    
    # /etc/network/interfaces should be present, we don't manage systemd-network yet
    if [ "$IS_NETWORK_INTERFACES" = 1 ]; then
        if ! test -f /etc/network/interfaces; then
            echo "IS_NETWORK_INTERFACES FAILED!"
            IS_AUTOIF=0
            IS_INTERFACESGW=0
        fi
    fi

    # Verify if all if are in auto
    if [ "$IS_AUTOIF" = 1 ]; then
        is_debianversion stretch || for interface in `/sbin/ifconfig -s |tail -n +2 |egrep -v "^(lo|vnet|docker|veth|tun|tap|macvtap)" |cut -d " " -f 1 |tr "\n" " "`; do
                    grep -q "^auto $interface" /etc/network/interfaces || (echo 'IS_AUTOIF FAILED!' && break)
            done
        is_debianversion stretch && for interface in `/sbin/ip address show up | grep ^[0-9]*: |egrep -v "(lo|vnet|docker|veth|tun|tap|macvtap)" | cut -d " " -f 2 |tr -d : |cut -d@ -f1 |tr "\n" " "`; do
                    grep -q "^auto $interface" /etc/network/interfaces || (echo 'IS_AUTOIF FAILED!' && break)
            done
    fi
    
    # Network conf verification
    if [ "$IS_INTERFACESGW" = 1 ]; then
        number=$(grep -Ec "^[^#]*gateway [0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}" /etc/network/interfaces)
        test $number -gt 1 && echo 'IS_INTERFACESGW FAILED!'
        number=$(grep -Ec "^[^#]*gateway [0-9a-fA-F]+:" /etc/network/interfaces)
        test $number -gt 1 && echo 'IS_INTERFACESGW FAILED!'
    fi

    # Verification de la mise en place d'evobackup
    if [ "$IS_EVOBACKUP" = 1 ]; then
        ls /etc/cron* |grep -q "evobackup" || echo 'IS_EVOBACKUP FAILED!'
    fi
    
    # Verification de la presence du userlogrotate
    if [ "$IS_USERLOGROTATE" = 1 ]; then
        is_pack_web && (test -x /etc/cron.weekly/userlogrotate || echo 'IS_USERLOGROTATE FAILED!')
    fi
    
    
    # Verification de la syntaxe de la conf d'Apache
    if [ "$IS_APACHECTL" = 1 ]; then
        is_installed apache2.2-common && (/usr/sbin/apache2ctl configtest 2>&1 |grep -q "^Syntax OK$" || echo 'IS_APACHECTL FAILED!')
    fi

    # Check if there is regular files in Apache sites-enabled.
    if [ "$IS_APACHESYMLINK" = 1 ]; then
        is_installed apache2.2-common && \
            (stat -c %F /etc/apache2/sites-enabled/* | grep -q regular && echo 'IS_APACHESYMLINK FAILED!')
    fi

    # Check if there is real IP addresses in Allow/Deny directives (no trailing space, inline comments or so).
    if [ "$IS_APACHEIPINALLOW" = 1 ]; then
        # Note: Replace "exit 1" by "print" in Perl code to debug it.
        is_installed apache2.2-common && \
            (grep -IrE "^[^#] *(Allow|Deny) from" /etc/apache2/ |grep -iv "from all" |grep -iv "env=" |perl -ne 'exit 1 unless (/from( [\da-f:.\/]+)+$/i)' || echo 'IS_APACHEIPINALLOW FAILED!')
    fi

    # Check if default Apache configuration file for munin is absent (or empty or commented).
    if [ "$IS_MUNINAPACHECONF" = 1 ]; then
        if is_debianversion squeeze || is_debianversion wheezy; then
            muninconf="/etc/apache2/conf.d/munin"
        else
            muninconf="/etc/apache2/conf-available/munin.conf"
        fi
        is_installed apache2.2-common && ([ -e $muninconf ] && grep -vEq "^( |\t)*#" $muninconf && echo 'IS_MUNINAPACHECONF FAILED!')
    fi
    
    # Verification de la priorité du package samba si les backports sont utilisés
    if [ "$IS_SAMBAPINPRIORITY" = 1 ]; then
        is_pack_samba && grep -qrE "^[^#].*backport" /etc/apt/sources.list{,.d} && ( priority=`grep -E -A2 "^Package:.*samba" /etc/apt/preferences |grep -A1 "^Pin: release a=lenny-backports" |grep "^Pin-Priority:" |cut -f2 -d" "` && test $priority -gt 500 || echo 'IS_SAMBAPINPRIORITY FAILED!' )
    fi
    
    # Verification si le système doit redémarrer suite màj kernel.
    if [ "$IS_KERNELUPTODATE" = 1 ]; then
        if is_installed linux-image* && [ $(date -d $(ls --full-time -lcrt /boot | tail -n1 | tr -s " " | cut -d " " -f 6) +%s) -gt $(($(date +%s) - $(cut -f1 -d '.' /proc/uptime))) ]; then
            echo 'IS_KERNELUPTODATE FAILED!'
        fi
    fi
    
    # Check if the server is running for more than a year.
    if [ "$IS_UPTIME" = 1 ]; then
        if is_installed linux-image* && [ $(date -d "now - 2 year" +%s) -gt $(($(date +%s) - $(cut -f1 -d '.' /proc/uptime))) ]; then
            echo 'IS_UPTIME FAILED!'
        fi
    fi

    # Check if munin-node running and RRD files are up to date.
    if [ "$IS_MUNINRUNNING" = 1 ]; then
        pgrep munin-node >/dev/null || echo 'IS_MUNINRUNNING FAILED!'
        [ "$(stat -c "%Y" /var/lib/munin/*/*load-g.rrd |sort |tail -1)" -lt $(date +"%s" -d "now - 10 minutes") ] && echo 'IS_MUNINRUNNING FAILED!'
        grep -q "^graph_strategy cron" /etc/munin/munin.conf && ([ "$(stat -c "%Y" /var/cache/munin/www/*/*/load-day.png |sort |tail -1)" -lt $(date +"%s" -d "now - 10 minutes") ]) && echo 'IS_MUNINRUNNING FAILED!'
    fi

    # Check if files in /home/backup/ are up-to-date
    if [ "$IS_BACKUPUPTODATE" = 1 ]; then
        [ -d /home/backup/ ] && for file in /home/backup/*; do
            if [ -f $file ] && [ $(stat -c "%Y" $file) -lt $(date +"%s" -d "now - 2 day") ]; then
                echo 'IS_BACKUPUPTODATE FAILED!'
                break;
            fi
        done
    fi

    # Check if /etc/.git/ has read/write permissions for root only.
    if [ "$IS_GITPERMS" = 1 ]; then
        test -d /etc/.git && [ "$(stat -c "%a" /etc/.git/)" = "700" ] || echo 'IS_GITPERMS FAILED!'
    fi

    # Check if no package has been upgraded since $limit.
    if [ "$IS_NOTUPGRADED" = 1 ]; then
        last_upgrade=$(date +%s -d $(zgrep -h upgrade /var/log/dpkg.log* |sort -n |tail -1 |cut -f1 -d ' '))
        limit=$(date +%s -d "now - 90 days")
        if [ -f /var/log/evolinux/00_prepare_system.log ]; then
            install_date=$(stat -c %Z /var/log/evolinux/00_prepare_system.log)
        else
            install_date=0
        fi
        [ $install_date -lt $limit ] && [ $last_upgrade -lt $limit ] && echo 'IS_NOTUPGRADED FAILED!'
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
                echo 'IS_TUNE2FS_M5 FAILED!'
                # Set debug to 1, to displays which partitions has less than 5%
                debug=0
                if [ "$debug" -eq 1 ]; then
                    echo "Partition $part has less than 5% reserved blocks!"
                fi
            fi
        done
    fi

    if [ "$IS_EVOLINUXSUDOGROUP" = 1 ]; then
        if is_debianversion stretch; then
            (grep -q ^evolinux-sudo: /etc/group \
                && grep -q '^%evolinux-sudo  ALL=(ALL:ALL) ALL' /etc/sudoers.d/evolinux) || echo 'IS_EVOLINUXSUDOGROUP FAILED!'
        fi
    fi

    if [ "$IS_USERINADMGROUP" = 1 ]; then
        if is_debianversion stretch; then
            for user in $(grep ^evolinux-sudo: /etc/group |awk -F: '{print $4}' |tr ',' ' '); do
                groups $user |grep -q adm || echo 'IS_USERINADMGROUP FAILED!'
            done
        fi
    fi

    if [ "$IS_APACHE2EVOLINUXCONF" = 1 ]; then
        if (test -d /etc/apache2 && is_debianversion stretch); then
            (test -L /etc/apache2/conf-enabled/z-evolinux-defaults.conf \
                && test -L /etc/apache2/conf-enabled/zzz-evolinux-custom.conf \
                && test -f /etc/apache2/ipaddr_whitelist.conf) || echo 'IS_APACHE2EVOLINUXCONF FAILED!'
        fi
    fi

    if [ "$IS_BACKPORTSCONF" = 1 ]; then
        if is_debianversion stretch; then
            grep -q backports /etc/apt/sources.list && echo 'IS_BACKPORTSCONF FAILED!'
            grep -q backports /etc/apt/sources.list.d/*.list 2>/dev/null && (grep -q backports /etc/apt/preferences.d/* || echo 'IS_BACKPORTSCONF FAILED!')
        fi
    fi

    if [ "$IS_BIND9MUNIN" = 1 ]; then
        if is_debianversion stretch && is_installed bind9; then
            (test -L /etc/munin/plugins/bind9 && test -e /etc/munin/plugin-conf.d/bind9) || echo 'IS_BIND9MUNIN FAILED!'
        fi
    fi

    if [ "$IS_BIND9LOGROTATE" = 1 ]; then
        if is_debianversion stretch && is_installed bind9; then
            test -e /etc/logrotate.d/bind9 || echo 'IS_BIND9LOGROTATE FAILED!'
        fi
    fi

    if [ "$IS_BROADCOMFIRMWARE" = 1 ]; then
        if lspci | grep -q 'NetXtreme II'; then
            (is_installed firmware-bnx2 && grep -q "^deb http://mirror.evolix.org/debian.* non-free" /etc/apt/sources.list) || echo 'IS_BROADCOMFIRMWARE FAILED!'
        fi
    fi

    if [ "$IS_HARDWARERAIDTOOL" = 1 ]; then
        lspci |grep -q 'MegaRAID SAS' && (is_installed megacli && (is_installed megaclisas-status || is_installed megaraidsas-status) || echo 'IS_HARDWARERAIDTOOL FAILED!')
        lspci |grep -q 'Hewlett-Packard Company Smart Array' && (is_installed cciss-vol-status || echo 'IS_HARDWARERAIDTOOL FAILED!')
    fi

    if [ "$IS_LOG2MAILSYSTEMDUNIT" = 1 ]; then
        if is_debianversion stretch; then
            (systemctl -q is-active log2mail.service && test -f /etc/systemd/system/log2mail.service && ! test -f /etc/init.d/log2mail) || echo 'IS_LOG2MAILSYSTEMDUNIT FAILED!'
        fi
    fi

    if [ "$IS_LISTUPGRADE" = 1 ]; then
        (test -f /etc/cron.d/listupgrade && test -x /usr/share/scripts/listupgrade.sh) || echo 'IS_LISTUPGRADE FAILED!'
    fi

    if [ "$IS_MARIADBEVOLINUXCONF" = 1 ]; then
        if is_debianversion stretch && is_installed mariadb-server; then
            (test -f /etc/mysql/mariadb.conf.d/z-evolinux-defaults.cnf \
                && test -f /etc/mysql/mariadb.conf.d/zzz-evolinux-custom.cnf) || echo 'IS_MARIADBEVOLINUXCONF FAILED!'
        fi
    fi

    if [ "$IS_SQL_BACKUP" = 1 ]; then
        if (is_installed "mysql-server" || is_installed "mariadb-server"); then
            # You could change the default path in /etc/evocheck.cf
            SQL_BACKUP_PATH=${SQL_BACKUP_PATH:-"/home/backup/mysql.bak.gz"}
            test -f "$SQL_BACKUP_PATH" || echo 'IS_SQL_BACKUP FAILED!'
        fi
    fi

    if [ "$IS_POSTGRES_BACKUP" = 1 ]; then
        if is_installed "postgresql-9*"; then
            # If you use something like barman, you should deactivate this check
            # You could change the default path in /etc/evocheck.cf
            POSTGRES_BACKUP_PATH=${POSTGRES_BACKUP_PATH:-"/home/backup/pg.dump.bak"}
            test -f "$POSTGRES_BACKUP_PATH" || echo 'IS_POSTGRES_BACKUP FAILED!'
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
                        if [ -f $file ] && [ $(stat -c "%Y" $file) -lt $(date +"%s" -d "now - 2 day") ]; then
                            echo 'IS_MONGO_BACKUP FAILED!'
                        fi
                    fi
                done
            else
                echo 'IS_MONGO_BACKUP FAILED!'
            fi
        fi
    fi

    if [ "$IS_LDAP_BACKUP" = 1 ]; then
        if is_installed slapd; then
            # You could change the default path in /etc/evocheck.cf
            LDAP_BACKUP_PATH=${LDAP_BACKUP_PATH:-"/home/backup/ldap.bak"}
            test -f "$LDAP_BACKUP_PATH" || echo 'IS_LDAP_BACKUP FAILED!'
        fi
    fi

    if [ "$IS_REDIS_BACKUP" = 1 ]; then
        if is_installed redis-server; then
            # You could change the default path in /etc/evocheck.cf
            REDIS_BACKUP_PATH=${REDIS_BACKUP_PATH:-"/home/backup/dump.rdb"}
            test -f "$REDIS_BACKUP_PATH" || echo 'IS_REDIS_BACKUP FAILED!'
        fi
    fi

    if [ "$IS_ELASTIC_BACKUP" = 1 ]; then
        if is_installed elasticsearch; then
            # You could change the default path in /etc/evocheck.cf
            ELASTIC_BACKUP_PATH=${ELASTIC_BACKUP_PATH:-"/home/backup/elasticsearch"}
            test -d "$ELASTIC_BACKUP_PATH" || echo 'IS_ELASTIC_BACKUP FAILED!'
        fi
    fi

    if [ "$IS_MARIADBSYSTEMDUNIT" = 1 ]; then
        if is_debianversion stretch && is_installed mariadb-server; then
            (systemctl -q is-active mariadb.service && test -f /etc/systemd/system/mariadb.service.d/evolinux.conf) || echo 'IS_MARIADBSYSTEMDUNIT FAILED!'
        fi
    fi

    if [ "$IS_MYSQLMUNIN" = 1 ]; then
        if is_debianversion stretch && is_installed mariadb-server; then
            for file in mysql_bytes mysql_queries mysql_slowqueries \
            mysql_threads mysql_connections mysql_files_tables \
            mysql_innodb_bpool mysql_innodb_bpool_act mysql_innodb_io \
            mysql_innodb_log mysql_innodb_rows mysql_innodb_semaphores \
            mysql_myisam_indexes mysql_qcache mysql_qcache_mem \
            mysql_sorts mysql_tmp_tables; do

                if [[ ! -L /etc/munin/plugins/$file ]]; then
                    echo 'IS_MYSQLMUNIN FAILED!'
                    break
                fi
            done
        fi
    fi

    if [ "$IS_MYSQLNRPE" = 1 ]; then
        if is_debianversion stretch && is_installed mariadb-server; then
            (test -f ~nagios/.my.cnf \
                && [ $(stat -c %U ~nagios/.my.cnf) = "nagios" ] \
                && [ $(stat -c %a ~nagios/.my.cnf) = "600" ] \
                && grep -q -F "command[check_mysql]=/usr/lib/nagios/plugins/check_mysql -H localhost  -f ~nagios/.my.cnf") || echo 'IS_MYSQLNRPE FAILED!'
        fi
    fi

    if [ "$IS_PHPEVOLINUXCONF" = 1 ]; then
        if is_debianversion stretch && is_installed php; then
            (test -f /etc/php/7.0/cli/conf.d/z-evolinux-defaults.ini \
                && test -f /etc/php/7.0/cli/conf.d/zzz-evolinux-custom.ini) || echo 'IS_PHPEVOLINUXCONF FAILED!'
        fi
    fi

    if [ "$IS_SQUIDLOGROTATE" = 1 ]; then
        if is_debianversion stretch && is_installed squid; then
            grep -q monthly /etc/logrotate.d/squid || echo 'IS_SQUIDLOGROTATE FAILED!'
        fi
    fi

    if [ "$IS_SQUIDEVOLINUXCONF" = 1 ]; then
        if is_debianversion stretch && is_installed squid; then
            (grep -q "^CONFIG=/etc/squid/evolinux-defaults.conf$" /etc/default/squid \
                && test -f /etc/squid/evolinux-defaults.conf \
                && test -f /etc/squid/evolinux-whitelist-defaults.conf \
                && test -f /etc/squid/evolinux-whitelist-custom.conf \
                && test -f /etc/squid/evolinux-acl.conf \
                && test -f /etc/squid/evolinux-httpaccess.conf \
                && test -f /etc/squid/evolinux-custom.conf) || echo 'IS_SQUIDEVOLINUXCONF FAILED!'
        fi
    fi

    if [ "IS_DUPLICATE_FS_LABEL" = 1 ]; then
        # Only on systems that have lsblk
        if [ -x "$(which lsblk)" ]; then
            tmpFile=$(mktemp -p /tmp)
            for part in $(lsblk -n -o LABEL); do
                echo $part >> $tmpFile
            done
            sort < $tmpFile | uniq -d
        fi
    fi
fi


if [ `uname -s` == "OpenBSD" ]; then

    if [ "$IS_SOFTDEP" = 1 ]; then
        grep -q "softdep" /etc/fstab || echo 'IS_SOFTDEP FAILED!'
    fi
    
    if [ "$IS_WHEEL" = 1 ]; then
        grep -qE "^%wheel.*$" /etc/sudoers || echo 'IS_WHEEL FAILED!'
    fi
    
    if [ "$IS_SUDOADMIN" = 1 ]; then
    grep -qE "^User_Alias ADMIN=.*$" /etc/sudoers || echo 'IS_SUDOADMIN FAILED!'
    fi
    
    if [ "$IS_PKGMIRROR" = 1 ]; then
        grep -qE "^export PKG_PATH=http://ftp\.fr\.openbsd\.org/pub/OpenBSD/[0-9.]+/packages/[a-z0-9]+/$" /root/.profile || echo 'IS_PKGMIRROR FAILED!'
    fi
    
    if [ "$IS_HISTORY" = 1 ]; then
        f=/root/.profile
        grep -q "^HISTFILE=\$HOME/.histfile" $f \
        && grep -q "^export HISTFILE" $f \
        && grep -q "^HISTSIZE=1000" $f \
        && grep -q "^export HISTSIZE" $f \
        || echo 'IS_HISTORY FAILED!'
    fi
    
    if [ "$IS_VIM" = 1 ]; then
        which vim 2>1 >> /dev/null || echo 'IS_VIM FAILED!'
    fi
    
    if [ "$IS_TTYC0SECURE" = 1 ]; then
        grep -Eqv "^ttyC0.*secure$" /etc/ttys || echo 'IS_TTYC0SECURE FAILED!'
    fi
    
    if [ "$IS_CUSTOMSYSLOG" = 1 ]; then
        grep -q Evolix /etc/newsyslog.conf || echo 'IS_CUSTOMSYSLOG FAILED!'
    fi
    
    if [ "$IS_NOINETD" = 1 ]; then
        grep -q inetd=NO /etc/rc.conf.local 2>/dev/null || echo 'IS_NOINETD FAILED!'
    fi
    
    if [ "$IS_SUDOMAINT" = 1 ]; then
        f=/etc/sudoers
        grep -q "Cmnd_Alias MAINT = /usr/share/scripts/evomaintenance.sh" $f \
        && grep -q "ADMIN ALL=NOPASSWD: MAINT" $f \
        || echo 'IS_SUDOMAINT FAILED!'
    fi
    
    if [ "$IS_POSTGRESQL" = 1 ]; then
        pkg info | grep -q postgresql-client || echo 'IS_POSTGRESQL FAILED!'
    fi
    
    if [ "$IS_NRPE" = 1 ]; then
        ( pkg info | grep -qE "nagios-plugins-[0-9.]" \
        && pkg info | grep -q nagios-plugins-ntp \
        && pkg info | grep -q nrpe ) || echo 'IS_NRPE FAILED!'
    fi
    
# if [ "$IS_NRPEDISKS" = 1 ]; then
#     NRPEDISKS=$(grep command.check_disk /etc/nrpe.cfg 2>/dev/null | grep ^command.check_disk[0-9] | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
#     DFDISKS=$(df -Pl | egrep -v "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)" | wc -l)
#     [ "$NRPEDISKS" = "$DFDISKS" ] || echo 'IS_NRPEDISKS FAILED!'
# fi
    
# Verification du check_mailq dans nrpe.cfg (celui-ci doit avoir l'option "-M postfix" si le MTA est Postfix)
# 
# if [ "$IS_NRPEPOSTFIX" = 1 ]; then
#     pkg info | grep -q postfix && ( grep -q "^command.*check_mailq -M postfix" /etc/nrpe.cfg 2>/dev/null || echo 'IS_NRPEPOSTFIX FAILED!' )
# fi
    
    if [ "$IS_NRPEDAEMON" = 1 ]; then
        grep -q "echo -n ' nrpe';        /usr/local/sbin/nrpe -d" /etc/rc.local || echo 'IS_NREPEDAEMON FAILED!'
    fi
    
    if [ "$IS_ALERTBOOT" = 1 ]; then
        grep -qE "^date \| mail -sboot/reboot .*evolix.fr$" /etc/rc.local || echo 'IS_ALERTBOOT FAILED!'
    fi
    
    if [ "$IS_RSYNC" = 1 ]; then
        pkg info | grep -q rsync || echo 'IS_RSYNC FAILED!'
    fi
    
    if [ "$IS_CRONPATH" = 1 ]; then
        grep -q "PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin" /var/cron/tabs/root || echo 'IS_CRONPATH FAILED!'
    fi
    
    #TODO
    # - Check en profondeur de postfix
    # - NRPEDISK et NRPEPOSTFIX
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
    is_debianversion stretch || ( egrep -qi "PermitRoot.*no" /etc/ssh/sshd_config || echo 'IS_SSHPERMITROOTNO FAILED!' )
    is_debianversion stretch && grep -q ^PermitRoot /etc/ssh/sshd_config && ( egrep -qi "PermitRoot.*no" /etc/ssh/sshd_config || echo 'IS_SSHPERMITROOTNO FAILED!' )
fi

if [ "$IS_EVOMAINTENANCEUSERS" = 1 ]; then
    if ! is_debianversion stretch; then
        if [ -f /etc/sudoers.d/evolinux ]; then
            sudoers="/etc/sudoers.d/evolinux"
        else
            sudoers="/etc/sudoers"
        fi
        for i in $( (grep "^User_Alias *ADMIN" $sudoers | cut -d= -f2 | tr -d " "; grep ^sudo /etc/group |cut -d: -f 4) | tr "," "\n" |sort -u); do
            grep -q "^trap.*sudo.*evomaintenance.sh" /home/$i/.*profile || echo 'IS_EVOMAINTENANCEUSERS FAILED!'
        done
    else
        for i in $(getent group evolinux-sudo | cut -d':' -f4 | tr ',' ' '); do 
            grep -q "^trap.*sudo.*evomaintenance.sh" /home/$i/.*profile || echo 'IS_EVOMAINTENANCEUSERS FAILED!'
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

if [ "$IS_PRIVKEYWOLRDREADABLE" = 1 ]; then
    for f in /etc/ssl/private/*; do
        perms=$(stat -c "%a" $f)
        if [ ${perms: -1} != "0" ]; then
            echo 'IS_PRIVKEYWOLRDREADABLE FAILED!'
        fi
    done
fi
