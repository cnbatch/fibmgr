# fibmgr
Simple Managerment tool of FreeBSD's FIB

```
fibmgr: usage:
	fibmgr [-4] [-6] copy fibnum to fibnum1,fibnum2 fibnum3
	fibmgr [-4] [-6] reset fibnum fibnum1,fibnum2 fibnum3
Examples:
	fibmgr copy 0 to 1,2
	fibmgr copy 0 to 1 2 3
	fibmgr copy 0 to 1,2 3
	fibmgr copy 0 to all
	fibmgr -4 copy 0 to all
	fibmgr reset 1,2
	fibmgr reset 1 2 3
	fibmgr reset 1,2 3
	fibmgr reset all
	fibmgr -6 reset all
```

'-4' means IPv4 only, '-6' means IPv6 only.

Note: This tool can only works on FreeBSD version ≥ 14.2

[Jail](https://man.freebsd.org/cgi/man.cgi?jail) is not supported yet.