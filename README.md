laf
===

A python script that scans for admin/login panels on a given host or list of hosts.

Scan a single host:
```
./laf.py -d google.de
```

Scan a list of host:
```
./laf.py -l hostlist.txt
```

Scan a list of hosts from stdin:
```
cat hostlist.txt | ./laf.py -l -
```
