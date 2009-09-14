#!/bin/sh

# EvoCheck script

# version 0.3.2-beta
# Copyright 2009 Gregory Colpart <reg@evolix.fr>, Evolix <info@evolix.fr>

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
IS_NRPEPERMS=1
IS_MINIFWPERMS=1
IS_NRPEDISKS=1
IS_NRPEPOSTFIX=1
IS_GRSECPROCS=1
IS_UMASKSUDOERS=1
IS_EVOMAINTENANCEUSERS=1
IS_APACHEMUNIN=1
IS_MYSQLUTILS=1

# Source configuration file
test -f /etc/evocheck.cf && . /etc/evocheck.cf

if [ "$IS_TMP_1777" = 1 ]; then
    ls -ld /tmp | grep drwxrwxrwt > /dev/null || echo 'IS_TMP_1777 FAILED!'
fi

if [ "$IS_ROOT_0700" = 1 ]; then
    ls -ld /root | grep drwx------ > /dev/null || echo 'IS_ROOT_0700 FAILED!'
fi

if [ "$IS_VARTMPFS" = 1 ]; then
    df /var/tmp | grep tmpfs > /dev/null || echo 'IS_VARTMPFS FAILED!'
fi

if [ "$IS_USRSHARESCRIPTS" = 1 ]; then
    ls -ld /usr/share/scripts | grep drwx------ > /dev/null || echo 'IS_USRSHARESCRIPTS FAILED!'
fi

if [ "$IS_SERVEURBASE" = 1 ]; then
    dpkg -l serveur-base | grep ^ii > /dev/null || echo 'IS_SERVEURBASE FAILED!'
fi

if [ "$IS_LOGROTATECONF" = 1 ]; then
    test -e /etc/logrotate.d/zsyslog || echo 'IS_LOGROTATECONF FAILED!'
fi

if [ "$IS_SYSLOGCONF" = 1 ]; then
    grep "^# Syslog for Pack Evolix serveur$" /etc/*syslog.conf > /dev/null || echo 'IS_SYSLOGCONF FAILED!'
fi

if [ "$IS_DEBIANSECURITY" = 1 ]; then
    grep "^deb.*security" /etc/apt/sources.list  > /dev/null || echo 'IS_DEBIANSECURITY FAILED!'
fi

if [ "$IS_APTITUDEONLY" = 1 ]; then
    test -e /usr/bin/apt-get && echo 'IS_APTITUDEONLY FAILED!'
fi

if [ "$IS_USRRO" = 1 ]; then
    grep /usr /etc/fstab | grep ro > /dev/null || echo 'IS_USRRO FAILED!'
fi

if [ "$IS_TMPNOEXEC" = 1 ]; then
    mount | grep "on /tmp" | grep noexec > /dev/null || echo 'IS_TMPNOEXEC FAILED!'
fi

if [ "$IS_LISTCHANGESCONF" = 1 ]; then
    egrep "(which=both|confirm=1)" /etc/apt/listchanges.conf | wc -l | grep ^2$ > /dev/null || echo 'IS_LISTCHANGESCONF FAILED!'
fi

if [ "$IS_DPKGWARNING" = 1 ] && ( [ "$IS_USRRO" = 1 ] || [ "$IS_TMPNOEXEC" = 1 ] ); then
    egrep -i "(Pre-Invoke ..echo Are you sure to have rw on|Post-Invoke ..echo Dont forget to mount -o remount)" /etc/apt/apt.conf | wc -l | grep ^2$ > /dev/null || echo 'IS_DPKGWARNING FAILED!'
fi

if [ "$IS_CUSTOMCRONTAB" = 1 ]; then
    egrep "^(17 \*|25 6|47 6|52 6)" /etc/crontab | wc -l | grep ^4$ > /dev/null && echo 'IS_CUSTOMCRONTAB FAILED!'
fi

if [ "$IS_CUSTOMSUDOERS" = 1 ]; then
    egrep "env_reset,.*umask=0077" /etc/sudoers > /dev/null || echo 'IS_CUSTOMSUDOERS FAILED!'
fi

if [ "$IS_SSHPERMITROOTNO" = 1 ]; then
    egrep -i "PermitRoot.*no" /etc/ssh/sshd_config > /dev/null || echo 'IS_SSHPERMITROOTNO FAILED!'
fi

if [ "$IS_SSHALLOWUSERS" = 1 ]; then
    egrep -i "AllowUsers" /etc/ssh/sshd_config > /dev/null || echo 'IS_SSHALLOWUSERS FAILED!'
fi

if [ "$IS_DISKPERF" = 1 ]; then
    test -e /root/disk-perf.txt || echo 'IS_DISKPERF FAILED!'
fi

if [ "$IS_TMOUTPROFILE" = 1 ]; then
    grep TMOUT= /etc/profile > /dev/null || echo 'IS_TMOUTPROFILE FAILED!'
fi

if [ "$IS_ALERT5BOOT" = 1 ]; then
    grep ^date /etc/rc2.d/S99alert5 > /dev/null || echo 'IS_ALERT5BOOT FAILED!'
fi

if [ "$IS_ALERT5MINIFW" = 1 ]; then
    grep ^/etc/init.d/minifirewall /etc/rc2.d/S99alert5 > /dev/null || echo 'IS_ALERT5MINIFW FAILED!'
fi

if [ "$IS_NRPEPERMS" = 1 ]; then
    ls -ld /etc/nagios | grep drwxr-x--- > /dev/null || echo 'IS_NRPEPERMS FAILED!'
fi

if [ "$IS_MINIFWPERMS" = 1 ]; then
    ls -l /etc/firewall.rc | grep -- -rw------- > /dev/null || echo 'IS_MINIFWPERMS FAILED!'
fi

if [ "$IS_NRPEDISKS" = 1 ]; then
    NRPEDISKS=$(grep command.check_disk /etc/nagios/nrpe.cfg | grep ^command.check_disk[0-9] | sed -e "s/^command.check_disk\([0-9]\+\).*/\1/" | sort -n | tail -1)
    DFDISKS=$(df -Pl | egrep -v "(^Filesystem|/lib/init/rw|/dev/shm|udev)" | wc -l)
    [ "$NRPEDISKS" = "$DFDISKS" ] || echo 'IS_NRPEDISKS FAILED!'
fi

# Verification du check_mailq dans nrpe.cfg (celui-ci doit avoir l'option "-M postfix" si le MTA est Postfix)

if [ "$IS_NRPEPOSTFIX" = 1 ]; then
    dpkg -l postfix | grep ^ii >/dev/null && ( grep "^command.*check_mailq -M postfix" /etc/nagios/nrpe.cfg > /dev/null || echo 'IS_NRPEPOSTFIX FAILED!' )
fi

if [ "$IS_GRSECPROCS" = 1 ]; then
    uname -a | grep grsec >/dev/null && ( grep ^command.check_total_procs..sudo /etc/nagios/nrpe.cfg >/dev/null && grep -A1 "^\[processes\]" /etc/munin/plugin-conf.d/munin-node | grep "^user root" >/dev/null || echo 'IS_GRSECPROCS FAILED!' )
fi

if [ "$IS_UMASKSUDOERS" = 1 ]; then
    grep ^Defaults.*umask=0077 /etc/sudoers >/dev/null || echo 'IS_UMASKSUDOERS FAILED!'
fi

if [ "$IS_EVOMAINTENANCEUSERS" = 1 ]; then
    for i in $(grep "^User_Alias ADMIN" /etc/sudoers | cut -d= -f2 | tr -d " " | tr "," "\n"); do
        grep "^trap.*sudo.*evomaintenance.sh" /home/$i/.*profile >/dev/null || echo 'IS_EVOMAINTENANCEUSERS FAILED!'
    done
fi

if [ "$IS_APACHEMUNIN" = 1 ]; then
    test -e /etc/apache2/apache2.conf && ( egrep "^env.url.*/server-status-[0-9]{4}" /etc/munin/plugin-conf.d/munin-node >/dev/null && egrep "/server-status-[0-9]{4}" /etc/apache2/apache2.conf >/dev/null || egrep "/server-status-[0-9]{4}" /etc/apache2/apache2.conf /etc/apache2/mods-enabled/status.conf >/dev/null 2>/dev/null || echo 'IS_APACHEMUNIN FAILED!' )
fi

# Verification mytop + Munin si MySQL
if [ "$IS_MYSQLUTILS" = 1 ]; then
    dpkg -l mysql-server | grep ^ii >/dev/null && ( grep mysqladmin /root/.my.cnf >/dev/null && dpkg -l mytop 2> /dev/null | grep ^ii >/dev/null && grep debian-sys-maint /root/.mytop >/dev/null || echo 'IS_MYSQLUTILS FAILED!' )
fi

