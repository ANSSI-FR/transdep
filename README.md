# Transdep

Transdep is a utility to discover single points of failure (SPOF) in DNS dependency graphs leading to unability to 
resolve domain names.
 
DNS dependency graph is a notion that was introduced by Venugopalan Ramasubramanian and Emin Gün Sirer in 
[Perils of Transitive Trust in the Domain Name System][1].

Current types of single points of failure that are detected are :
- domain names (which can be availability SPOF if DNSSEC is incorrectly configured);
- IP addresses of name servers;
- Longest network prefixes that may generally be announced over the Internet (/24 over IPv4 and /48 over IPv6);
- ASN of the AS announcing the IP addresses of name servers.

The ``transdep`` utility is the CLI version of the tool. The ``webserver`` utility spawns a REST/JSON webservice. 
Endpoints are described below.

[1]: https://www.cs.cornell.edu/people/egs/papers/dnssurvey.pdf

## Licence

Transdep is licenced under the 2-clause BSD licence.

## Installation

Transdep uses the following external libraries:
- https://github.com/miekg/dns
- https://github.com/awalterschulze/gographviz
- https://github.com/hashicorp/golang-lru
- https://github.com/deckarep/golang-set
- https://github.com/hashicorp/go-immutable-radix

You may install them using the go get command or whichever other method you prefer:

```bash
$ go get github.com/miekg/dns
$ go get github.com/awalterschulze/gographviz
$ go get github.com/hashicorp/golang-lru
$ go get github.com/deckarep/golang-set
$ go get github.com/hashicorp/go-immutable-radix
```

You may then use the Makefile to compile the Transdep tools:

```bash
$ make all
```

## Usage

### CLI

The ``transdep`` utility can be used to analyze the dependencies of a single domain name, of multiple names, or a saved 
dependency graph.

#### Analysis Target Types
To analyze a single name, the ``-domain`` option is to be used:

```bash
./transdep -domain www.example.net
```

To analyze multiple domain names, you must provide a list stored in a file with one domain name per line, with the 
option ``-file``:

```bash
./transdep -file <(echo -ne "example.com\nexample.net")

./transdep -file /tmp/list_of_domain_names
```

If you saved a dependency graph into a file (that was generated using the ``-graph`` option ), you may analyze it by 
loading the graph with the ``-load`` option:

```bash
./transdep -domain example.net -graph > /tmp/example_net_graph.json

./transdep -load /tmp/example_net_graph.json
```

#### Analysis Nature

Transdep can analyze a domain based on multiple criteria.

All analysis types consider that IP addresses and announcing network prefixes may be SPOF. 
 
By default, SPOF discovery is conducted while considering that all names may break, including non-DNSSEC protected 
domain names. This is used to analyze SPOF in the event of misconfigurations, zone truncation and all other types of 
zone corruptions that may render a zone impossible to resolve.

If the analysis must be constrained to only consider that DNSSEC protected names may break, the ``-dnssec`` option must 
be added to the command line:

```bash
./transdep -domain www.example.com -dnssec
```   

By default, the SPOF discovery considers that resolvers are connected to both IPv4 and IPv6 networks. This means that if 
an IPv4 address is unavailable, this unavailibility may be covered for by a server available over IPv6.

In some scenarii, this is unacceptable, because the IPv4 resolvers and the IPv6 resolvers are separate servers. Also, 
one of these two networks might be unavailable (temporarily or permanently). To represent these situations, the 
``-break4`` (resp. ``-break6``) options simulates that all IPv4 (resp. IPv6) addresses are always considered unavailable 
when analyzing the SPOF potential of an IP address in the other network type:

```bash
./transdep -domain www.x-cli.eu -break4
www.x-cli.eu:this domain name requires some IPv4 addresses to be resolved properly


./transdep -domain www.example.com -break4
www.example.com.:Name:example.com.
www.example.com.:IP:2001:500:8d::53
www.example.com.:Name:iana-servers.net.
www.example.com.:Name:.
www.example.com.:Name:net.
www.example.com.:Name:com.
```

In the previous example, `www.x-cli.eu.` cannot be resolved by IPv6-only resolvers (because some names or delegations do 
not have IPv6 addresses).
For `www.example.com`, the result shows that during that run, `Transdep` detected that when using a resolver that 
has only access to the IPv6 network at the time of resolution, the name `www.example.com` might not be possible to 
resolve if the IP address ``2001:500:8d::53`` is unavailable.

The ``-all`` option indicates to `Transdep` to analyze the requested domain name(s), using all possible compositions of 
the previous options: with and without ``-dnssec``, and with and without ``-break4`` or with and without ``-break6``.

```bash
./transdep -domain www.x-cli.eu -all
AllNames:www.x-cli.eu.:Name:x-cli.eu.
AllNames:www.x-cli.eu.:Name:.
AllNames:www.x-cli.eu.:Name:eu.
DNSSEC:www.x-cli.eu.:Name:.
DNSSEC:www.x-cli.eu.:Name:eu.
AllNamesNo4:www.x-cli.eu.:this domain name requires some IPv4 addresses to be resolved properly
DNSSECNo4:www.x-cli.eu.:this domain name requires some IPv4 addresses to be resolved properly
AllNamesNo6:www.x-cli.eu.:Name:eu.
AllNamesNo6:www.x-cli.eu.:Name:x-cli.eu.
AllNamesNo6:www.x-cli.eu.:Name:.
DNSSECNo6:www.x-cli.eu.:Name:.
DNSSECNo6:www.x-cli.eu.:Name:eu.
```

`Transdep` may also consider an analysis criterion based on the ASN of the AS announcing the network prefixes covering 
the IP addresses of the name servers. The association between the ASN and the IP address is done by using a file whose 
format is as follows:
- one association per line;
- each line contains an ASN and an announced network prefix.

Here is an example of such a file:
```
64501 192.0.2.0/24
64501 198.51.100.0/24
64502 203.0.113.0/24
64502 2001:db8::/32
```

Such a file can be generated from a MRT dump file (bviews) such as the ones made available by the [RIS project][2], 
using ANSSI's [`mabo`][3] tool with the sub-command ``prefixes``.

The ASN-prefix file is provided to `Transdep` using the ``-mabo`` option:

```bash
./mabo prefixes bview.20171013.0800.gz > prefixes-20171013.txt
./transdep -domain www.example.com -mabo prefixes-20171013.txt
```
  
[2]: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris
[3]: https://github.com/ANSSI-FR/mabo

#### Output Types

`Transdep` can generate several types of documents. By default, it generates a CSV containing the discovered SPOF for 
the requested analysis.

If the ``-all`` option is provided, the format is ``AnalysisType:DomainName:TypeOfSPOF:SPOFReference``, where 
``AnalysisType`` indicates one of the following combinations:
* ``AllNames``: default options (no ``-dnssec``, no ``-break4``, no ``-break6``);
* ``AllNamesNo4``: default options except that ``-break4`` is specified;
* ``AllNamesNo6``: default options except that ``-break6`` is specified;
* ``DNSSEC``: default options except that ``-dnssec`` is specified;
* ``DNSSECNo4``: ``-dnssec`` and ``-break4`` options are specified;
* ``DNSSECNo6``: ``-dnssec`` and ``-break6`` options are specified.

If the ``-all`` option is not specified, the format is ``DomainName:TypeOfSPOF:SPOFRerefence``.

In both formats, ``DomainName`` indicates the domain name that is analyzed.

``TypeOfSPOF`` can value:
* ``Name``: the next field specifies a domain name that must be resolvable for ``DomainName`` to be resolvable.
* ``IP``: the next field specifies an IP address that must be available and not hijacked for ``DomainName`` to be 
resolvable.
* ``Prefix:``: the next field specifies a network prefix that must be available and not hijacked for ``DomainName`` to 
be resolvable.
* ``ASN:``: the next field specifies an AS number whose whole network must not be totally broken for ``DomainName`` to 
be resolvable. 

TypeOfSPOF may also value a special value: ``Cycle``. ``Cycle`` indicates that there is a circular dependency in the 
graph somewhere, or an overly long CNAME chain (for some definition of "overly long"). 
Having ``Cycle`` as dependency means that the name cannot be resolved at all using a RFC-compliant resolver at the time 
of resolution. 

The ``-graph`` output option generates an output that can be later loaded for analysis using the 
``-load`` option, described above.

The ``-dot`` output option generates a DOT file output. This output may be passed to any Graphviz interpret for graph 
drawing. The generated DOT file will highlight domain name and IP addresses that are SPOF by coloring the nodes in red.  

```bash
./transdep -domain www.x-cli.eu | dot -T pdf -o /tmp/graph_x-cli.eu.pdf
```

#### Caches

`Transdep` maintains several caches in order to limit the number of requests to name servers during the discovery of the 
dependency graph. There are in-memory caches, using LRU lists and go routines, and on-disk caches for long term cache 
and to store value overflowing from the in-memory LRU lists.

In-memory cache sizes are controlled with the ``-nrlrusize``, ``-zcflrusize`` and ``-dflrusize`` options. The first two 
options are associated with lists that contain data that is cached on disk when the LRU lists are overflowing. 
The on-disk cache is leverage whenever possible and the entry is reinstated in the LRU list upon usage. Thus, an entry 
is either in-memory or on-disk and is never lost unless the cache directoy is flushed manually. The third option is 
associated with a LRU list whose entries may be very large. These entries are synthetized from the entries of the other 
caches, and thus are not stored on disk when the list is overflowing.

If your computer swaps or consumes too much memory while running `Transdep`, you should try to lower these values, 
trying to lower ``-dflrusize`` value first. If your computer spends too much time in "disk I/O wait" and you have 
some RAM capacity available, you may try to increase the two first options. 

On-disk caches consist of a lot very small JSON files. Please monitor the number of remaining inodes and adapt your 
inode table accordingly.

On-disk caches are stored in the directory designated by the `TMPDIR` environment variable, the `-cachedir` command line 
option. The default value is ``/tmp``.

`Transdep` caches never expire, with the current implementation. If you need to flush the cache, you may change the 
cache directory to keep the previous one and yet start fresh. You may also delete the `nameresolver` and `zonecut` 
directories that are present in the designated cache directory.

#### Root Zone Hint File

You may specify a root zone hint file with the `-hints` option. If left unspecified, a hard-coded list of root-servers 
will be used by `Transdep`, when querying the root zone for delegations. 

#### DNS Violations

Using a RFC-compliant implementation prevents you from resolving many domain names. Thus, some degree of DNS violation 
tolerance was implemented in `Transdep`, with much grumble.
By default, `Transdep` will consider `rcode 3` status on non-terminal nodes equivalent to `rcode 0` answers with 
`ancount=0`. You may reinstate RFC8020 compliance with the `-rfc8020` option.

Some devices are also unable to answer to non-A/AAAA queries and always return `rcode 2` answers for any other qtype, 
including NS or DS. By default, `Transdep` considers this servers as broken, but you may use the `-servfail` option to 
indicate `Transdep` to treat these answers as `rcode 0` answers with `ancount=0`. This may lead `Transdep` to return 
incorrect results in some instances. 

#### Script Friendliness

If you don't care about the nature of errors that may arise during the analysis of a domain name or if you want to have 
a output that is easily parsable, you may use the `-script` option to return errors as the constant ``-ERROR-``.

`Transdep` will return an error if any name that is part of the dependency graph cannot be resolved at the time of 
dependency graph discovery. Doing otherwise might have led to incorrect results from partial dependency graph discovery.   

#### Concurrency

You may adapt the number of domain names whose dependency graphs are discovered simultaneously with the `-jobs` option. 
The higher this option value, the more you will harass the name servers. You will want to keep this value relatively low, 
to prevent blacklisting of your IP and false measurements.

### Web Service

The webservice uses the ``webserver`` binary. 

The ``-bind`` and ``-port`` can be used to specify, respectively, on which address and port the web server should listen 
on. By default, the service is available on `http://127.0.0.1:5000`.

The ``-nrlrusize``, ``-zcflrusize``, ``-dflrusize``, ``-jobs``, ``-hints`` and ``-cachedir`` options have the same usage
as for the `Transdep` CLI utility.

The web server exposes several endpoints:
* ``/allnames`` is the endpoint corresponding to the default behaviour of the `transdep` CLI utility.
* ``/dnssec`` is the endpoint corresponding to the ``-dnssec`` option of the `transdep` CLI utility.
* ``/break4`` is the endpoint corresponding to the ``-break4`` option of the `transdep` CLI utility.
* ``/break6`` is the endpoint corresponding to the ``-break6`` option of the `transdep` CLI utility.

Combination of ``-dnssec`` and ``-break4`` or ``-break6`` is not possible with the web server.

Each endpoint takes a ``domain`` parameter as part of the query string, to specify which domain name is to be analyzed.

Endpoints may also receive ``rfc8020`` and ``servfail`` query string parameters to indicate which DNS violations are 
tolerated for this analysis. If these options are not specified, `rcode 3` answers on non-terminal nodes are treated as 
`rcode 0` answers with `ancount=0` and `rcode 2` answers are considered as broken name servers. 

When launched from a console, the `webserver` utility outputs a URL to query to gracefully stop the service. Gracefully 
shutting down the service is strongly advised to prevent on-disk cache corruption or incompleteness.

```bash
$ ./webserver &
[1] 7416
To stop the server, send a query to http://127.0.0.1:5000/stop?secret=5942985ebdc9102663130752c1d21f23
$ curl http://127.0.0.1:5000/stop?secret=5942985ebdc9102663130752c1d21f23
Stopping.
Stopping the finder: OK
$
```
