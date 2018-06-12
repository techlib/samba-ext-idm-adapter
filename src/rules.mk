#!/usr/bin/make -f

sbin += samba-ext-idm-adapter

samba-ext-idm-adapter = samba.c main.c -lldb -ltevent -ltalloc

# EOF
