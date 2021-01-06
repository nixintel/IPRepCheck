#### IPRepCheck

IPRepCheck is a simple Python tool that allows single or bulk queries of the AbuseIPDB API.
IPv4 addresses can be queried as a list or as single IPs. Results are returned as a CSV file.

By default only results from the past 180 days are queried. AbuseIPDB's upper limit is 365 days.

##### Requirements

AbuseIPDB API key  (free tier permits 1000 lookups per day).

Python 3 (tested on Python 3.8)

##### Installation

Clone the repository and install the requirements

```
git clone https://github.com/nixintel/IPRepCheck

pip install -r requirements.txt
```

Be sure to rename ``.env.example`` to ``.env`` and insert your own API key.

##### Usage

###### Single IP query

``$ python main.py -i x.x.x.x -o results.csv``

Add ``-d`` flag to change the number of days' worth of history (default is 180 days):

``$ python main.py -i x.x.x.x -d 30 -o results.csv``

CIDR notation is also supported:

`` $ python main.py -i x.x.x.x/27 -o results.csv``

####### Multiple IP queries

Specific IP addresses and CIDR format can be submitted as a list for a bulk query. Use the ``-l`` 
flag and ensure each entry is on a new line e.g.

```
x.x.x.x
y.y.y.y/29
z.z.z.z
```
Example query:

```
$ python main.py -l iplist.txt -o results.csv
```





