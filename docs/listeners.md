---
date: 2025-09-16T06:00:00Z
title: "Pingoo listeners"
type: "page"
url: "/docs/listeners"
---

# Listeners

Listeners are the addresses, ports and protcols that Pingoo listen to.

**pingoo.yml**
```yml
listeners:
  http:
    address: http://0.0.0.0:8080
  https:
    address: http://0.0.0.0:8080
    services: ["api"]
```

Valid protocols:
- `http`
- `https`
- `tcp`
- `tcp+tls`

## Trusted proxies

If Pingoo runs behind a load balancer, a CDN or a reverse proxy, you can configure the `trusted_proxies` option with the IP ranges (CIDR) of your proxies. Pingoo will then resolve the real client address from the `X-Forwarded-For` header and use this single determination everywhere: GeoIP lookups, rules, the captcha, logs and proxying.

**pingoo.yml**
```yml
listeners:
  https:
    address: https://0.0.0.0:443
    trusted_proxies: ["10.0.0.0/8", "192.168.1.10"]
```

The resolution fails closed: `X-Forwarded-For` headers coming from untrusted peers, malformed entries and chains composed only of trusted proxies are ignored, and the direct peer address is used instead. When proxying, only the verified entries of the chain are forwarded upstream, so forged entries sent by direct clients are dropped.

## Graceful shutdown

When receiving a `Ctrl+C` / `terminate` signal, listeners initiate the graceful shutdown process. They first stop accepting new connections / requests and then wait up to 20 seconds (this may change in the future) for in-flight connections / request to finish.

## Zero-downtime upgrades

Pingoo uses the `SO_REUSEPORT` option on sockets to enable zero-downtime upgrades.

If you are using docker you will need to use the `--network host` CLI argument to use zero-downtime upgrades with `SO_REUSEPORT`.

```bash
$ docker run -d --network host pingooio/pingoo
```
