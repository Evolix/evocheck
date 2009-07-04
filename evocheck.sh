#!/bin/sh

# EvoCheck script

# version 0.1
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
