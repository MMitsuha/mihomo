<h1 align="center">
  <img src="Meta.png" alt="Meta Kennel" width="200">
  <br>Meta Kernel<br>
</h1>

<h3 align="center">Another Mihomo Kernel.</h3>

<p align="center">
  <a href="https://goreportcard.com/report/github.com/MetaCubeX/mihomo">
    <img src="https://goreportcard.com/badge/github.com/MetaCubeX/mihomo?style=flat-square">
  </a>
  <img src="https://img.shields.io/github/go-mod/go-version/MetaCubeX/mihomo/Alpha?style=flat-square">
  <a href="https://github.com/MetaCubeX/mihomo/releases">
    <img src="https://img.shields.io/github/release/MetaCubeX/mihomo/all.svg?style=flat-square">
  </a>
  <a href="https://github.com/MetaCubeX/mihomo">
    <img src="https://img.shields.io/badge/release-Meta-00b4f0?style=flat-square">
  </a>
</p>

## Features

- Local HTTP/HTTPS/SOCKS server with authentication support
- VMess, VLESS, Shadowsocks, Trojan, Snell, TUIC, Hysteria protocol support
- Built-in DNS server that aims to minimize DNS pollution attack impact, supports DoH/DoT upstream and fake IP.
- Rules based off domains, GEOIP, IPCIDR or Process to forward packets to different nodes
- Remote groups allow users to implement powerful rules. Supports automatic fallback, load balancing or auto select node
  based off latency
- Remote providers, allowing users to get node lists remotely instead of hard-coding in config
- Netfilter TCP redirecting. Deploy Mihomo on your Internet gateway with `iptables`.
- Transparent in-tunnel MITM with on-the-fly TLS interception and a regex-based
  rewrite engine (reject / redirect / header / body rewrite for HTTP and HTTPS).
- Comprehensive HTTP RESTful API controller

## Dashboard

A web dashboard with first-class support for this project has been created; it can be checked out at [metacubexd](https://github.com/MetaCubeX/metacubexd).

## Configration example

Configuration example is located at [/docs/config.yaml](https://github.com/MetaCubeX/mihomo/blob/Alpha/docs/config.yaml).

## Docs

Documentation can be found in [mihomo Docs](https://wiki.metacubex.one/).

## For development

Requirements:
[Go 1.20 or newer](https://go.dev/dl/)

Build mihomo:

```shell
git clone https://github.com/MetaCubeX/mihomo.git
cd mihomo && go mod download
go build
```

Set go proxy if a connection to GitHub is not possible:

```shell
go env -w GOPROXY=https://goproxy.io,direct
```

Build with gvisor tun stack:

```shell
go build -tags with_gvisor
```

### IPTABLES configuration

Work on Linux OS which supported `iptables`

```yaml
# Enable the TPROXY listener
tproxy-port: 9898

iptables:
  enable: true # default is false
  inbound-interface: eth0 # detect the inbound interface, default is 'lo'
```

### MITM

MITM doesn't listen on its own port — it's a transparent layer inside the
tunnel. Whatever traffic any inbound (mixed/http/socks/tun/redir/tproxy)
dispatches to a port listed under `mitm.ports` is intercepted: TLS is
terminated with a CA generated on first boot, and the request/response is
run through `mitm.rules`. Connections to a host that no rule targets pass
through verbatim — the engine never terminates TLS or parses HTTP for
those, so wire bytes survive untouched. (Once a host is targeted, every
exchange to it is parsed and re-emitted, which can rewrite hop-by-hop
headers and the Connection header even for requests no URL rule matches.)

```yaml
mitm:
  enable: true
  ports: [80, 443, 8443]
  rules:
    # block ad requests with 404
    - url: '^https?://ads\.example\.com/.*'
      action: reject
    # rewrite URL with capture-group back-reference
    - url: '^https?://api\.example\.com/v1/(.*)'
      action: '302'
      new: 'https://api.example.com/v2/$1'
    # rewrite request header
    - url: '^https?://example\.com/.*'
      action: request-header
      old: 'User-Agent: .*'
      new: 'User-Agent: mihomo-mitm'
    # rewrite response body (known Content-Length, text-like Content-Type)
    - url: '^https?://example\.com/score'
      action: response-body
      old: '"score":\d+'
      new: '"score":999'
```

Available `action` values: `reject`, `reject-200`, `reject-img`, `reject-dict`,
`reject-array`, `302`, `307`, `request-header`, `request-body`,
`response-header`, `response-body`. Body-rewrite rules only apply to
text-like content types (`text/*`, JSON, XML, form-urlencoded).

The CA certificate is written to `mitm.crt` / `mitm.key` under the mihomo
home directory on first use. Install `mitm.crt` as a trusted root on the
client device, or fetch it from the running engine via the REST API:

```sh
curl -OJ http://<external-controller>/mitm/ca.crt
```

## Debugging

Check [wiki](https://wiki.metacubex.one/api/#debug) to get an instruction on using debug
API.

## Credits

- [Dreamacro/clash](https://github.com/Dreamacro/clash)
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box)
- [riobard/go-shadowsocks2](https://github.com/riobard/go-shadowsocks2)
- [v2ray/v2ray-core](https://github.com/v2ray/v2ray-core)
- [WireGuard/wireguard-go](https://github.com/WireGuard/wireguard-go)
- [yaling888/clash-plus-pro](https://github.com/yaling888/clash)

## License

This software is released under the GPL-3.0 license.

**In addition, any downstream projects not affiliated with `MetaCubeX` shall not contain the word `mihomo` in their names.**