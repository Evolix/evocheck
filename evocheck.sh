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
IS_RAIDSOFT=1
IS_AWSTATSLOGFORMAT=1
IS_MUNINLOGROTATE=1
IS_EVOMAINTENANCECONF=1
IS_METCHE=1
IS_SQUID=1
IS_MODDEFLATE=1
IS_LOG2MAILAPACHE=1
IS_LOG2MAILMYSQL=1
IS_LOG2MAILSQUID=1
IS_BINDCHROOT=1
IS_REPVOLATILE=1
IS_AUTOIF=1

# Source configuration file
test -f /etc/evocheck.cf && . /etc/evocheck.cf

# Functions
function is_pack_web {
	test -e /usr/share/scripts/web-add.sh
}

function is_pack_samba {
	test -e /usr/share/scripts/add.pl
}

function is_installed {
	for pkg in $*; do
		dpkg -l $pkg 2>/dev/null |grep ^ii >/dev/null || return 1
	done
}

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
    is_installed server-base || echo 'IS_SERVEURBASE FAILED!'
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
    DFDISKS=$(df -Pl | egrep -v "(^Filesystem|/lib/init/rw|/dev/shm|udev|rpc_pipefs)" | wc -l)
    [ "$NRPEDISKS" = "$DFDISKS" ] || echo 'IS_NRPEDISKS FAILED!'
fi

# Verification du check_mailq dans nrpe.cfg (celui-ci doit avoir l'option "-M postfix" si le MTA est Postfix)

if [ "$IS_NRPEPOSTFIX" = 1 ]; then
    is_installed postfix && ( grep "^command.*check_mailq -M postfix" /etc/nagios/nrpe.cfg > /dev/null || echo 'IS_NRPEPOSTFIX FAILED!' )
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
    is_installed mysql-server && ( grep mysqladmin /root/.my.cnf >/dev/null && is_installed mytop && grep debian-sys-maint /root/.mytop >/dev/null || echo 'IS_MYSQLUTILS FAILED!' )
fi

# Verification de la configuration du raid soft (mdadm)
if [ "$IS_RAIDSOFT" = 1 ]; then
	test -e /proc/mdstat && \
	 ( grep "^AUTOCHECK=true" /etc/default/mdadm >/dev/null \
	&& grep "^START_DAEMON=true" /etc/default/mdadm >/dev/null \
	&& grep -E "^MAILADDR (root|alert3@evolix.fr)" /etc/mdadm/mdadm.conf || echo 'IS_RAIDSOFT FAILED!')
fi

# Verification du LogFormat de AWStats
if [ "$IS_AWSTATSLOGFORMAT" = 1 ]; then
	is_installed apache2.2-common && ( grep -E '^LogFormat=1' /etc/awstats/awstats.conf.local >/dev/null || echo 'IS_AWSTATSLOGFORMAT FAILED!' )
fi

# Verification de la présence de la config logrotate pour Munin
if [ "$IS_MUNINLOGROTATE" = 1 ]; then
	( test -e /etc/logrotate.d/munin-node && test -e /etc/logrotate.d/munin ) || echo 'IS_MUNINLOGROTATE FAILED!'
fi

# Verification de la configuration d'evomaintenance
if [ "$IS_EVOMAINTENANCECONF" = 1 ]; then
	f=/etc/evomaintenance.cf
	 ( grep "^HOSTNAME=`hostname`$" $f >/dev/null \
	&& grep "^export PGPASSWORD" $f |grep -v "your-passwd" >/dev/null \
	&& grep "^EVOMAINTMAIL" $f |grep -v "evomaintenance-your-host@example.com" >/dev/null \
	&& grep "^PGDB" $f |grep -v "your-db" >/dev/null \
	&& grep "^PGTABLE" $f |grep -v "your-table" >/dev/null \
	&& grep "^PGHOST" $f |grep -v "your-pg-host" >/dev/null \
	&& grep "^FROM" $f |grep -v "jdoe@example.com" >/dev/null \
	&& grep "^FULLFROM" $f |grep -v "John Doe <jdoe@example.com>" > /dev/null \
	&& grep "^URGENCYFROM" $f |grep -v "mama.doe@example.com" >/dev/null \
	&& grep "^URGENCYTEL" $f |grep -v "06.00.00.00.00" >/dev/null \
	&& grep "^REALM" $f |grep -v "example.com" >/dev/null ) || echo 'IS_EVOMAINTENANCECONF FAILED!'
fi

# Verification de la présence de metche
if [ "$IS_METCHE" = 1 ]; then
	is_installed metche || echo 'IS_METCHE FAILED!'
fi

# Verification de l'activation de Squid dans le cas d'un pack mail
if [ "$IS_SQUID" = 1 ]; then
	f=/etc/firewall.rc
	is_pack_web && ( is_installed squid \
	&& grep -E "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -m owner --uid-owner proxy -j ACCEPT" $f >/dev/null \
	&& grep -E "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d `hostname -i` -j ACCEPT" $f >/dev/null \
	&& grep -E "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -d 127.0.0.1 -j ACCEPT" $f >/dev/null \
	&& grep -E "^[^#]*iptables -t nat -A OUTPUT -p tcp --dport 80 -j REDIRECT --to-port `grep http_port /etc/squid/squid.conf |cut -f 2 -d " "`" $f >/dev/null || echo 'IS_SQUID FAILED!' )
fi

# Verification de la conf et de l'activation de mod-deflate
if [ "$IS_MODDEFLATE" = 1 ]; then
	f=/etc/apache2/mods-enabled/deflate.conf
	test -e $f && grep "AddOutputFilterByType DEFLATE text/html text/plain text/xml text/css application/javascript$" $f >/dev/null || echo 'IS_MODDEFLATE FAILED!'
fi

# Verification de la conf log2mail
if [ "$IS_LOG2MAILAPACHE" = 1 ]; then
	is_pack_web && ( is_installed log2mail && grep "^file = /var/log/apache2/error.log" /etc/log2mail/config/default 2>/dev/null >/dev/null || echo 'IS_LOG2MAILAPACHE FAILED!' )
fi
if [ "$IS_LOG2MAILMYSQL" = 1 ]; then
	is_pack_web && ( is_installed log2mail && grep "^file = /var/log/syslog" /etc/log2mail/config/default 2>/dev/null >/dev/null || echo 'IS_LOG2MAILMYSQL FAILED!' )
fi
if [ "$IS_LOG2MAILSQUID" = 1 ]; then
	is_pack_web && ( is_installed log2mail && grep "^file = /var/log/squid/access.log" /etc/log2mail/config/default 2>/dev/null >/dev/null || echo 'IS_LOG2MAILSQUID FAILED!' )
fi

# Verification si bind est chroote
if [ "$IS_BINDCHROOT" = 1 ]; then
	is_installed bind && ( grep -E '^OPTIONS=".*-t"' /etc/default/bind9 >/dev/null && grep -E '^OPTIONS=".*-u"' /etc/default/bind9 >/dev/null || echo 'IS_BINDCHROOT FAILED!' )
fi

# Verification de la présence du depot volatile
if [ "$IS_REPVOLATILE" = 1 ]; then
	test `cat /etc/debian_version |cut -d "." -f 1` -ge 5 && (grep -E "^deb http://volatile.debian.org/debian-volatile" /etc/apt/sources.list >/dev/null || echo 'IS_REPVOLATILE FAILED!')
fi

# Verification interface en auto
if [ "$IS_AUTOIF" = 1 ]; then
	for interface in `/sbin/ifconfig -s |tail -n +2 |grep -v "^lo" |cut -d " " -f 1 |tr "\n" " "`; do
		grep "^auto $interface" /etc/network/interfaces >/dev/null || (echo 'IS_AUTOIF FAILED!' && break)
	done
fi

