#!/bin/bash

# EvoCheck script

# version 0.3.3-beta
# Copyright 2011 Gregory Colpart <reg@evolix.fr>, Evolix <info@evolix.fr>
# Last revision : 29 Juin 2011

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
IS_APTICRON=1
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
IS_SAMBAPINPRIORITY=1
IS_KERNELUPTODATE=1

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

# Functions
is_pack_web(){

    test -e /usr/share/scripts/web-add.sh

}

is_pack_samba(){

    test -e /usr/share/scripts/add.pl

}

is_installed(){

    for pkg in $*; do
            dpkg -l $pkg 2>/dev/null |grep -q ^ii || return 1
    done

}

#-----------------------------------------------------------
#Vérifie si c'est une debian et fait les tests appropriés.
#-----------------------------------------------------------

if [ -e /etc/debian_version ]; then

     # Proper to Squeeze or Wheezy version.
    if [ $(lsb_release -c -s) = "squeeze" ]; then
        if [ "$IS_DPKGWARNING" = 1 ] && ( [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ] ); then
            egrep -i "(Pre-Invoke ..echo Are you sure to have rw on|Post-Invoke ..echo Dont forget to mount -o remount)" \
                /etc/apt/apt.conf | wc -l | grep -q ^2$ || \
                echo 'IS_DPKGWARNING FAILED!'
        fi

        if [ "$IS_UMASKSUDOERS" = 1 ]; then
            grep -q ^Defaults.*umask=0077 /etc/sudoers || echo 'IS_UMASKSUDOERS FAILED!'
        fi

        # Verifying check_mailq in Nagios NRPE config file. (Option "-M postfix" need to be set if the MTA is Postfix)
        if [ "$IS_NRPEPOSTFIX" = 1 ]; then
            is_installed postfix && ( grep -q "^command.*check_mailq -M postfix" /etc/nagios/nrpe.cfg || echo 'IS_NRPEPOSTFIX FAILED!' )
        fi

        # Check if mod-security config file is present.
        if [ "$IS_MODSECURITY" = 1 ]; then
           is_installed libapache-mod-security && \
                (test -e /etc/apache2/conf.d/mod-security2.conf || echo 'IS_MODSECURITY FAILED!')
        fi
    fi

    if [ $(lsb_release -c -s) = "wheezy" ]; then
        if [ "$IS_DPKGWARNING" = 1 ] && ( [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ] ); then
            test -e /etc/apt/apt.conf && echo 'IS_DPKGWARNING FAILED!'
            test -e /etc/apt/apt.conf.d/80evolinux || echo 'IS_DPKGWARNING FAILED!'
        fi
    
        # Check if mod-security config file is present.
        if [ "$IS_MODSECURITY" = 1 ]; then
           is_installed libapache2-modsecurity && \
                (test -e /etc/apache2/conf.d/mod-security2.conf || echo 'IS_MODSECURITY FAILED!')
        fi
    fi

    # Compatible Squeeze & Wheezy.
    if [ "$IS_CUSTOMSUDOERS" = 1 ]; then
        egrep -qr "umask=0077" /etc/sudoers* || echo 'IS_CUSTOMSUDOERS FAILED!'
    fi

    # Verifying check_mailq in Nagios NRPE config file. (Option "-M postfix" need to be set if the MTA is Postfix)
    if [ "$IS_NRPEPOSTFIX" = 1 ]; then
        is_installed postfix && ( grep -qr "^command.*check_mailq -M postfix" /etc/nagios/nrpe.* || echo 'IS_NRPEPOSTFIX FAILED!' )
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
        test -e /usr/bin/apt-get && echo 'IS_APTITUDEONLY FAILED!'
    fi

    if [ "$IS_APTICRON" = 1 ]; then
        status="OK"
        test -e /etc/cron.d/apticron && status="fail"
        test -e /etc/cron.daily/apticron || status="fail"
        test "$status" = "fail" || test -e /usr/bin/apt-get.bak || status="fail"
        test "$status" = "fail" || /usr/bin/apt-get.bak -qq update || status="fail"
        test "$status" = "fail" && echo 'IS_APTICRON FAILED!'
    fi
    
    if [ "$IS_USRRO" = 1 ]; then
        grep /usr /etc/fstab | grep -q ro || echo 'IS_USRRO FAILED!'
    fi
    
    if [ "$IS_TMPNOEXEC" = 1 ]; then
        mount | grep "on /tmp" | grep -q noexec || echo 'IS_TMPNOEXEC FAILED!'
    fi
    
    if [ "$IS_LISTCHANGESCONF" = 1 ]; then
        egrep "(which=both|confirm=1)" /etc/apt/listchanges.conf | wc -l | grep -q ^2$ || echo 'IS_LISTCHANGESCONF FAILED!'
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
        grep -q TMOUT= /etc/profile || echo 'IS_TMOUTPROFILE FAILED!'
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
        ls -ld /etc/nagios | grep -q drwxr-x--- || echo 'IS_NRPEPERMS FAILED!'
    fi
    
    if [ "$IS_MINIFWPERMS" = 1 ]; then
        ls -l /etc/firewall.rc | grep -q -- -rw------- || echo 'IS_MINIFWPERMS FAILED!'
    fi
    
    if [ "$IS_NRPEDISKS" = 1 ]; then
        NRPEDISKS=$(grep command.check_disk /etc/nagios/nrpe.cfg | grep ^command.check_disk[0-9] | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
        DFDISKS=$(df -Pl | egrep -v "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)" | wc -l)
        [ "$NRPEDISKS" = "$DFDISKS" ] || echo 'IS_NRPEDISKS FAILED!'
    fi
    
    if [ "$IS_GRSECPROCS" = 1 ]; then
        uname -a | grep -q grsec && ( grep -q ^command.check_total_procs..sudo /etc/nagios/nrpe.cfg && grep -A1 "^\[processes\]" /etc/munin/plugin-conf.d/munin-node | grep -q "^user root" || echo 'IS_GRSECPROCS FAILED!' )
    fi
    
    if [ "$IS_APACHEMUNIN" = 1 ]; then
        test -e /etc/apache2/apache2.conf && ( egrep -q "^env.url.*/server-status-[[:alnum:]]{4}" /etc/munin/plugin-conf.d/munin-node && egrep -q "/server-status-[[:alnum:]]{4}" /etc/apache2/apache2.conf || egrep -q "/server-status-[[:alnum:]]{4}" /etc/apache2/apache2.conf /etc/apache2/mods-enabled/status.conf 2>/dev/null || echo 'IS_APACHEMUNIN FAILED!' )
    fi
    
    # Verification mytop + Munin si MySQL
    if [ "$IS_MYSQLUTILS" = 1 ]; then
        is_installed mysql-server && ( grep -q mysqladmin /root/.my.cnf && is_installed mytop && grep -q debian-sys-maint /root/.mytop || echo 'IS_MYSQLUTILS FAILED!' )
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
        f=/etc/firewall.rc
        is_pack_web && ( is_installed squid || is_installed squid3 \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT" $f \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d `hostname -i` -j ACCEPT" $f \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d 127.0.0.1 -j ACCEPT" $f \
        && grep -qE "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port.* `grep http_port /etc/squid*/squid.conf |cut -f 2 -d " "`" $f || echo 'IS_SQUID FAILED!' )
    fi
    
    # Verification de la conf et de l'activation de mod-deflate
    if [ "$IS_MODDEFLATE" = 1 ]; then
        f=/etc/apache2/mods-enabled/deflate.conf
        is_installed apache2.2 && ((test -e $f && grep -q "AddOutputFilterByType DEFLATE text/html text/plain text/xml" $f \
        && grep -q "AddOutputFilterByType DEFLATE text/css" $f\
        && grep -q "AddOutputFilterByType DEFLATE application/x-javascript application/javascript" $f) || echo 'IS_MODDEFLATE FAILED!')
    fi
    
    # Verification de la conf log2mail
    if [ "$IS_LOG2MAILAPACHE" = 1 ]; then
        is_pack_web && ( is_installed log2mail && grep -q "^file = /var/log/apache2/error.log" /etc/log2mail/config/default 2>/dev/null || echo 'IS_LOG2MAILAPACHE FAILED!' )
    fi
    if [ "$IS_LOG2MAILMYSQL" = 1 ]; then
        is_pack_web && ( is_installed log2mail && grep -q "^file = /var/log/syslog" /etc/log2mail/config/default 2>/dev/null || echo 'IS_LOG2MAILMYSQL FAILED!' )
    fi
    if [ "$IS_LOG2MAILSQUID" = 1 ]; then
        is_pack_web && ( is_installed log2mail && grep -q "^file = /var/log/squid.*/access.log" /etc/log2mail/config/default 2>/dev/null || echo 'IS_LOG2MAILSQUID FAILED!' )
    fi
    
    # Verification si bind est chroote
    if [ "$IS_BINDCHROOT" = 1 ]; then
        is_installed bind && ( grep -qE '^OPTIONS=".*-t"' /etc/default/bind9 && grep -qE '^OPTIONS=".*-u"' /etc/default/bind9 || echo 'IS_BINDCHROOT FAILED!' )
    fi
    
    # Verification de la présence du depot volatile
    if [ "$IS_REPVOLATILE" = 1 ]; then
        test `cat /etc/debian_version |cut -d "." -f 1` -eq 5 && (grep -qE "^deb http://volatile.debian.org/debian-volatile" /etc/apt/sources.list || echo 'IS_REPVOLATILE FAILED!')
            test `cat /etc/debian_version |cut -d "." -f 1` -eq 6 && (grep -qE "^deb.*squeeze-updates" /etc/apt/sources.list || echo 'IS_REPVOLATILE FAILED!')
    fi
    
    # Verification interface en auto
    if [ "$IS_AUTOIF" = 1 ]; then
        for interface in `/sbin/ifconfig -s |tail -n +2 |egrep -v "^(lo|vnet)" |cut -d " " -f 1 |tr "\n" " "`; do
                    grep -q "^auto $interface" /etc/network/interfaces || (echo 'IS_AUTOIF FAILED!' && break)
            done
    fi
    
    # Verification interface en auto
    if [ "$IS_INTERFACESGW" = 1 ]; then
        number=$(grep -Ec [^#]gateway /etc/network/interfaces)
        test $number -gt 1 && echo 'IS_INTERFACESGW FAILED!'
    fi
    # Verification du nombre de debian-sys-maint
    if [ "$IS_TOOMUCHDEBIANSYSMAINT" = 1 ]; then
        is_installed mysql-server && (test `echo "SELECT user FROM mysql.user WHERE user='debian-sys-maint';" |mysql --skip-column-names |wc -l` -eq 1 || echo 'IS_TOOMUCHDEBIANSYSMAINT FAILED!')
    fi

    # Verification de la mise en place d'evobackup
    if [ "$IS_EVOBACKUP" = 1 ]; then
        ls /etc/cron* |grep -q "zz.backup$" || echo 'IS_EVOBACKUP FAILED!'
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
    if [ "IS_APACHESYMLINK" = 1 ]; then
        is_installed apache2.2-common && \
            (stat -c %F /etc/apache2/sites-enabled/* | grep -q regular && echo 'IS_APACHESYMLINK FAILED!')
    fi
    
    # Verification de la priorité du package samba si les backports sont utilisés
    if [ "$IS_SAMBAPINPRIORITY" = 1 ]; then
        is_pack_samba && grep -qrE "^[^#].*backport" /etc/apt/sources.list{,.d} && ( priority=`grep -E -A2 "^Package:.*samba" /etc/apt/preferences |grep -A1 "^Pin: release a=lenny-backports" |grep "^Pin-Priority:" |cut -f2 -d" "` && test $priority -gt 500 || echo 'IS_SAMBAPINPRIORITY FAILED!' )
    fi
    
    # Verification si le système doit redémarrer suite màj kernel.
    if [ "$IS_KERNELUPTODATE" = 1 ]; then
        if is_installed linux-image* && [ $(date -d $(ls --full-time -lcrt /boot | tail -n1 | tr -s " " | cut -d " " -f 6) +%s) -gt $(date -d $(LANG=en_US.UTF8 LANGUAGE=C who -b | tr -s " " | cut -d " " -f 4) +%s) ]; then
            echo 'IS_KERNELUPTODATE FAILED!'
        fi
    fi
fi

#-----------------------------------------------------------
#Vérifie si c'est une OpenBSD et fait les tests appropriés.
#-----------------------------------------------------------

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

#---------------
# Tests communs
#---------------

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
    egrep -qi "PermitRoot.*no" /etc/ssh/sshd_config || echo 'IS_SSHPERMITROOTNO FAILED!'
fi

if [ "$IS_EVOMAINTENANCEUSERS" = 1 ]; then
    for i in $(grep "^User_Alias ADMIN" /etc/sudoers | cut -d= -f2 | tr -d " " | tr "," "\n"); do
        grep -q "^trap.*sudo.*evomaintenance.sh" /home/$i/.*profile || echo 'IS_EVOMAINTENANCEUSERS FAILED!'
    done
fi

# Verification de la configuration d'evomaintenance
if [ "$IS_EVOMAINTENANCECONF" = 1 ]; then
    f=/etc/evomaintenance.cf
    ( grep "^export PGPASSWORD" $f |grep -qv "your-passwd" \
    && grep "^PGDB" $f |grep -qv "your-db" \
    && grep "^PGTABLE" $f |grep -qv "your-table" \
    && grep "^PGHOST" $f |grep -qv "your-pg-host" \
    && grep "^FROM" $f |grep -qv "jdoe@example.com" \
    && grep "^FULLFROM" $f |grep -qv "John Doe <jdoe@example.com>" \
    && grep "^URGENCYFROM" $f |grep -qv "mama.doe@example.com" \
    && grep "^URGENCYTEL" $f |grep -qv "06.00.00.00.00" \
    && grep "^REALM" $f |grep -qv "example.com" ) || echo 'IS_EVOMAINTENANCECONF FAILED!'
fi
