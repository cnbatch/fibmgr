# fibmgr
Simple Managerment tool of FreeBSD's FIB

```
fibmgr: usage:
	fibmgr copy fibnum to fibnum1,fibnum2 fibnum3
	fibmgr reset fibnum fibnum1,fibnum2 fibnum3
Examples:
	fibmgr copy 0 to 1,2
	fibmgr copy 0 to 1 2 3
	fibmgr copy 0 to 1,2 3
	fibmgr copy 0 to all
	fibmgr reset 1,2
	fibmgr reset 1 2 3
	fibmgr reset 1,2 3
	fibmgr reset all
```

Note: This tool can only works on FreeBSD version ≥ 14.2