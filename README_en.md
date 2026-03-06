gostc - C-based GOST simple Tunnel
======
 
### A C-based simple security tunnel compatibility gost

Features
------
* Listening on multiple ports
* Multi-level forward proxy - proxy chain
* Standard TCP(S)/UDP(S) proxy protocols support
* Probing resistance support for web proxy
* TLS encryption via negotiation support for SOCKS5 proxy
* TCP/UDP Transparent proxy
* Local/remote TCP/UDP port forwarding
* Permission control]
* Load balancing]
* Routing control
* DNS resolver and proxy
* TUN/TAP device
Build
------

#### From source

```bash
git clone https://github.com/chxaitz/gostc.git
cd gostc/
make
```

Getting started
------
#### Forward proxy

```bash
gostc -L=:8080 -F=192.168.1.1:8081
```

* Forward proxy authentication

```bash
gostc -L=:8080 -F=tcp://admin:123456@192.168.1.1:8081
```

#### Remote TCP port forwarding

```bash
gost -L=rtcp://:2222/192.168.1.1:22 -F forward+ssh://:2222
```

#### Remote UDP port forwarding

```bash
gost -L=rudp://:5353/192.168.1.1:53?ttl=60 [-F=... -F=socks5://172.24.10.1:1080]
```

The data on 172.24.10.1:5353 is forwarded to 192.168.1.1:53 (through the proxy chain).
Each forwarding channel has a timeout period. When this time is exceeded and there is no data interaction during this time period, the channel will be closed. The timeout value can be set by the `ttl` parameter. The default value is 60 seconds.

**NOTE:** When forwarding UDP data, if there is a proxy chain, the end of the chain (the last -F parameter) must be gost SOCKS5 proxy, gost will use UDP-over-TCP to forward data.

#### TLS
There is built-in TLS certificate in gost, if you need to use other TLS certificate, there are two ways:

* Place two files cert.pem (public key) and key.pem (private key) in the current working directory, gost will automatically load them.

* Use the parameter to specify the path to the certificate file:

```bash
gost -L="tcp://:443?cert=/path/to/my/cert/file&key=/path/to/my/key/file"
```

Client can specify `secure` parameter to perform server's certificate chain and host name verification:

```bash
gost -L=:8080 -F="tcp://server_domain_name:443?secure=true"
```

Client can specify a CA certificate to allow for [Certificate Pinning](https://en.wikipedia.org/wiki/Transport_Layer_Security#Certificate_pinning):

```bash
gost -L=:8080 -F="tcp://:443?ca=ca.pem"
```
