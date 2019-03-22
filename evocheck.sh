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

# Verbose function
verbose() {
    msg="${1:-$(cat /dev/stdin)}"
    [ "${VERBOSE}" -eq 1 ] && [ -n "${msg}" ] && echo "${msg}"
}

# Source configuration file
test -f /etc/evocheck.cf && . /etc/evocheck.cf

VERBOSE="${VERBOSE:-0}"

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

# Check if the server is running for more than a year.
if [ "$IS_UPTIME" = 1 ]; then
        echo 'IS_UPTIME FAILED!'
    fi
fi

# Check if files in /home/backup/ are up-to-date

# Check if /etc/.git/ has read/write permissions for root only.
if [ "$IS_GITPERMS" = 1 ]; then
    fi
fi


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
    f=/root/.profile
    grep -q "^HISTFILE=\$HOME/.histfile" $f \
    && grep -q "^export HISTFILE" $f \
    && grep -q "^HISTSIZE=1000" $f \
    && grep -q "^export HISTSIZE" $f \
    || echo 'IS_HISTORY FAILED!'
fi

if [ "$IS_VIM" = 1 ]; then
    command -v vim 2>1 >> /dev/null || echo 'IS_VIM FAILED!'
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
    is_debianversion stretch || ( grep -E -qi "PermitRoot.*no" /etc/ssh/sshd_config || echo 'IS_SSHPERMITROOTNO FAILED!' )
    is_debianversion stretch && grep -q ^PermitRoot /etc/ssh/sshd_config && ( grep -E -qi "PermitRoot.*no" /etc/ssh/sshd_config || echo 'IS_SSHPERMITROOTNO FAILED!' )
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

if [ "$IS_PRIVKEYWOLRDREADABLE" = 1 ]; then
    for f in /etc/ssl/private/*; do
        perms=$(stat -L -c "%a" $f)
        if [ ${perms: -1} != "0" ]; then
            echo 'IS_PRIVKEYWOLRDREADABLE FAILED!'
            break
        fi
    done
fi
