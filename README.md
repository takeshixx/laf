laf
===

A python script that scans for admin/login panels on a given host or list of hosts.

```
usage: laf.py [-h] [-d host] [-l hostfile|-] [-sys system] [-c cookie]
              [-u user] [-da] [-p pass] [-ic] [-k] [-v]

Find admin/login panel for a single host (-d) or a list of hosts (-l).

optional arguments:
  -h, --help     show this help message and exit
  -d host        host to scan
  -l hostfile|-  list of hosts, one per line (- instead of a file to read from
                 stdin)
  -sys system    comma seperated list of dirs|php|cfm|asp|pl|html|pma
                 (default: dirs)
  -c cookie      cookie
  -u user        http authentication username
  -da            use digest auth instead of basic
  -p pass        http authentication password
  -ic            ignore invalid tls certificate
  -k             halt on first valid path
  -v             enable verbosity

```

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
