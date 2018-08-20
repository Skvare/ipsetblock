# Usage

ipsetblock allows easy creation of ipsets from block list such as [spamhaus](https://www.spamhaus.org), and [stopforumspam](https://www.stopforumspam.com). 

```
usage: ipsetblock.py [-h] [-v] [-c CONFIGFILE] [-d DATAFILE] [-l LOGFILE]

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose
  -c CONFIGFILE, --configfile CONFIGFILE
  -d DATAFILE, --datafile DATAFILE
  -l LOGFILE, --logfile LOGFILE
```

## Config

The configuration should be in `config.json`. An example config is provided.

The following keys are accepted in the `config.json`:

```yaml
ipsets:
  Type: Array of ipset objects
  Keys:
  - Key: name
    Type: string
  - Key: family
    Type: string
    Accepted Values: ipset family, one of { inet | inet6 }
  - Key: method
    Type: string
    Accepted Values: ipset method
  - Key: datatype
    Type: string
    Accepted Values: ipset method
  - Key: saveto
    Type: string
    Accepted Values: filename
  - Key: blocklists
    Type: Array of blocklist objects
    Keys:
    - Key: name
      Type: string
    - Key: data_type
      Type: string
      Accepted Values: "{ text | zip }"
    - Key: comment
      Type: string
    - Key: update
      Type: string
      Accepted Values: "{ always | daily | hourly | minute }"
    - Key: url or file
      Type: string
    - Key: ips
      Type: Ip object
      Keys:
      - Key: blacklisted
        Type: Array of ip strings to add to ip set
      - Key: whitelisted
        Type: Array of ip strings to never add to ip set
```
