# iptables-tracer
[![CI](https://github.com/dhrm1k/iptables-tracer/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/dhrm1k/iptables-tracer/actions/workflows/ci.yml)
[![Go Report Card](https://goreportcard.com/badge/github.com/dhrm1k/iptables-tracer)](https://goreportcard.com/report/github.com/dhrm1k/iptables-tracer)

Insert trace-points into the running configuration to observe the path of packets through the iptables chains.

## Usage

Trace packets in both directions for a host:

```
$ iptables-tracer --host 10.1.50.11 -t 30s
```

Combine `--host` with `-f` to narrow both directions further:

```
$ iptables-tracer --host 10.1.50.11 -f "-p icmp" -t 30s
```

When `--host` is used without `-f`, all protocols to or from that IP address are traced. Without `--host`, the default filter remains UDP port 53.

An explicit iptables filter can also be used directly:

```
$ iptables-tracer -f "-s 192.0.2.1 -p tcp --dport 443" -t 30s
14:42:00.284882 raw    PREROUTING   0x00000000 IP 192.0.2.1.36028 > 203.0.113.41.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:]
14:42:00.287255 mangle PREROUTING   0x00008000 IP 192.0.2.1.36028 > 203.0.113.41.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:]
14:42:00.288966 nat    PREROUTING   0x00008000 IP 192.0.2.1.36028 > 203.0.113.41.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:]
14:42:00.290545 mangle FORWARD      0x00008000 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:eth1]
14:42:00.292123 filter FORWARD      0x00008002 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In:eth0 Out:eth1]
14:42:00.293164 mangle POSTROUTING  0x00008002 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In: Out:eth1]
14:42:00.293780 nat    POSTROUTING  0x00008002 IP 192.0.2.1.36028 > 198.51.100.8.443: Flags [S], seq 3964691400, win 29200, length 0  [In: Out:eth1]
```
