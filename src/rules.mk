#!/usr/bin/make -f

sbin += samba-ext-idm-adapter

samba-ext-idm-adapter = main.c -lldb -ltalloc

# EOF
