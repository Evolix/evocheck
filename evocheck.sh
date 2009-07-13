#!/bin/sh

# EvoCheck script

# version 0.2
# Copyright 2009 Gregory Colpart <reg@evolix.fr>, Evolix <info@evolix.fr>

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

