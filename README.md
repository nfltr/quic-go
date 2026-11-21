<div align="center" style="margin-bottom: 15px;">
  <img src="./assets/quic-go-logo.png" width="700" height="auto">
</div>

# A QUIC implementation in pure Go

> **This is nfltr's fork** (module `github.com/nfltr/quic-go`), for
> `github.com/nfltr/link/peerlink/quiclink`. Branch `nfltr` is upstream
> `4b404ee15e68` plus fixes, each its own commit with its test, to be
> offered upstream: the send stream's reliable size is fixed once its
> write side is reset, so aborting a stream after the peer's STOP_SENDING
> no longer panics (`numOutStandingFrames negative`); HyStart leaves slow
> start only while the sender is congestion window limited; a late ACK
> restores the congestion window also after a reordered burst of more than
> 64 packets; a send that fails because the path is briefly gone
> (ENETUNREACH, EHOSTUNREACH, EADDRNOTAVAIL, ENETDOWN: a NAT rebinding, a
> host changing networks) or a local firewall drops it (EPERM, once the
> socket has sent its first packet) is a lost packet, not a closed
> connection, so the connection migrates or resumes once the path is
> back; only ack-eliciting packets are paced (RFC 9002 7.7), so a receiver
> that ACKs every packet of a reordering path still sends its
> MAX_STREAM_DATA. Three additions: `Config.CongestionControl` selects
> BBR (v1, Chromium QUICHE's BbrSender as ported by Hysteria, MIT,
> `internal/congestion/bbr`) instead of NewReno, the default: on a long
> path with random loss NewReno's window falls to a few packets and grows
> one packet per RTT (300 Mbit/s, 260 ms RTT, 0.05 % loss: 3 Mbit/s;
> BBR: 190 Mbit/s, medians of 6);
> `Stream.SetSendWindowCallback` reports each increase of a stream's send
> window (the peer's MAX_STREAM_DATA), so a writer sees its bytes still
> being consumed after its last Write returned; `ConnectionStats`'
> `IdleTimeoutStart` is when the idle timer started (the first
> ack-eliciting packet sent after the last one received), so a liveness
> check sees a keep-alive the process sent late. Three CPU cuts for hosts
> without UDP offloads (macOS, where every packet is a syscall): past the
> first 100 1-RTT packets, with an RTT known, the receiver acknowledges
> every 10th ack-eliciting packet or after a quarter of the min RTT (as
> Chromium; receiver-only); on darwin a packet is written inline, in one
> non-blocking sendmsg, when nothing waits in the send queue, instead of
> waking the queue's goroutine; and on darwin a connection that has sent 64
packets sends on a socket of its own, bound to the shared socket's port
(SO_REUSEPORT) and connected to the peer, whose received packets are
handed to the transport as if read on the shared socket: macOS looks up
the route and policy on every send of an unconnected UDP socket to a
non-loopback address, about 6 times the cost of a connected send. On
Linux it uses the UDP offloads further: a GSO batch holds up to 44
full-size packets (was 20 KiB, 14), and receive turns on UDP GRO, the
kernel's coalesced buffer split back into its packets in order before
the connection sees them (`QUIC_GO_DISABLE_GRO` turns it off, as
`QUIC_GO_DISABLE_GSO` does GSO), and a connection queues up to 4096
received packets not yet processed (256 upstream), eight such reads, so a
receiver busy for one read no longer drops the rest of it (a peer's
datagram over 1452 bytes is cut to that, as without GRO, so the queue holds
at most 4096 x 1452 bytes, ~5.7 MiB); `SocketBuffers` reports the socket
buffers the host gave (asked: `SocketBufferWanted`, 7 MiB), so a program
can tell its user to raise `net.core.rmem_max`/`wmem_max`.
`master` mirrors upstream.


[![Documentation](https://img.shields.io/badge/docs-quic--go.net-red?style=flat)](https://quic-go.net/docs/)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/quic-go/quic-go)](https://pkg.go.dev/github.com/quic-go/quic-go)
[![Code Coverage](https://img.shields.io/codecov/c/github/quic-go/quic-go/master.svg?style=flat-square)](https://codecov.io/gh/quic-go/quic-go/)
[![Fuzzing Status](https://oss-fuzz-build-logs.storage.googleapis.com/badges/quic-go.svg)](https://introspector.oss-fuzz.com/project-profile?project=quic-go)

quic-go is an implementation of the QUIC protocol ([RFC 9000](https://datatracker.ietf.org/doc/html/rfc9000), [RFC 9001](https://datatracker.ietf.org/doc/html/rfc9001), [RFC 9002](https://datatracker.ietf.org/doc/html/rfc9002)) in Go.

Other QUIC specifications:

* Unreliable Datagram Extension ([RFC 9221](https://datatracker.ietf.org/doc/html/rfc9221))
* Datagram Packetization Layer Path MTU Discovery (DPLPMTUD, [RFC 8899](https://datatracker.ietf.org/doc/html/rfc8899))
* QUIC Version 2 ([RFC 9369](https://datatracker.ietf.org/doc/html/rfc9369))
* QUIC Event Logging using qlog ([draft-ietf-quic-qlog-main-schema](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-main-schema/) and [draft-ietf-quic-qlog-quic-events](https://datatracker.ietf.org/doc/draft-ietf-quic-qlog-quic-events/))
* QUIC Stream Resets with Partial Delivery ([draft-ietf-quic-reliable-stream-reset-07](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-07) and [draft-ietf-quic-reliable-stream-reset-09](https://datatracker.ietf.org/doc/html/draft-ietf-quic-reliable-stream-reset-09))

quic-go also supports HTTP/3 ([RFC 9114](https://datatracker.ietf.org/doc/html/rfc9114)).

Other HTTP/3 specifications:

* QPACK: Field Compression for HTTP/3 ([RFC 9204](https://datatracker.ietf.org/doc/html/rfc9204))
* Extensible Prioritization Scheme for HTTP ([RFC 9218](https://datatracker.ietf.org/doc/html/rfc9218))
* HTTP Datagrams and the Capsule Protocol ([RFC 9297](https://datatracker.ietf.org/doc/html/rfc9297))

Related projects:

* [webtransport-go](https://github.com/quic-go/webtransport-go) implements WebTransport over HTTP/3 ([draft-ietf-webtrans-http3](https://datatracker.ietf.org/doc/draft-ietf-webtrans-http3/)).
* [masque-go](https://github.com/quic-go/masque-go) implements CONNECT-UDP ([RFC 9298](https://datatracker.ietf.org/doc/html/rfc9298)).
* [connect-ip-go](https://github.com/quic-go/connect-ip-go) implements CONNECT-IP ([RFC 9484](https://datatracker.ietf.org/doc/html/rfc9484)).

Detailed documentation can be found on [quic-go.net](https://quic-go.net/docs/).

## FIPS 140-3

Starting with v0.60, quic-go supports use in FIPS 140-3 environments when built with Go 1.26 or newer, using Go standard library cryptography for the QUIC code paths relevant in FIPS mode; see [FIPS140.md](FIPS140.md) for details.

## Projects using quic-go

| Project                                                   | Description                                                                                                                                                       | Stars                                                                                               |
| ---------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| [AdGuardHome](https://github.com/AdguardTeam/AdGuardHome) | Free and open source, powerful network-wide ads & trackers blocking DNS server.                                                                                   | ![GitHub Repo stars](https://img.shields.io/github/stars/AdguardTeam/AdGuardHome?style=flat-square) |
| [algernon](https://github.com/xyproto/algernon)           | Small self-contained pure-Go web server with Lua, Markdown, HTTP/2, QUIC, Redis and PostgreSQL support                                                            | ![GitHub Repo stars](https://img.shields.io/github/stars/xyproto/algernon?style=flat-square)        |
| [caddy](https://github.com/caddyserver/caddy/)            | Fast, multi-platform web server with automatic HTTPS                                                                                                              | ![GitHub Repo stars](https://img.shields.io/github/stars/caddyserver/caddy?style=flat-square)       |
| [cloudflared](https://github.com/cloudflare/cloudflared)  | A tunneling daemon that proxies traffic from the Cloudflare network to your origins                                                                               | ![GitHub Repo stars](https://img.shields.io/github/stars/cloudflare/cloudflared?style=flat-square)  |
| [frp](https://github.com/fatedier/frp)                    | A fast reverse proxy to help you expose a local server behind a NAT or firewall to the internet                                                                   | ![GitHub Repo stars](https://img.shields.io/github/stars/fatedier/frp?style=flat-square)            |
| [go-libp2p](https://github.com/libp2p/go-libp2p)          | libp2p implementation in Go, powering [Kubo](https://github.com/ipfs/kubo) (IPFS) and [Lotus](https://github.com/filecoin-project/lotus) (Filecoin), among others | ![GitHub Repo stars](https://img.shields.io/github/stars/libp2p/go-libp2p?style=flat-square)     |
| [gost](https://github.com/go-gost/gost)                   | A simple security tunnel written in Go                                                                                                                        | ![GitHub Repo stars](https://img.shields.io/github/stars/go-gost/gost?style=flat-square)            |
| [Hysteria](https://github.com/apernet/hysteria)           | A powerful, lightning fast and censorship resistant proxy                                                                                                         | ![GitHub Repo stars](https://img.shields.io/github/stars/apernet/hysteria?style=flat-square)        |
| [Mercure](https://github.com/dunglas/mercure)             | An open, easy, fast, reliable and battery-efficient solution for real-time communications                                                                         | ![GitHub Repo stars](https://img.shields.io/github/stars/dunglas/mercure?style=flat-square)         |
| [nodepass](https://github.com/NodePassProject/nodepass) | A secure, efficient TCP/UDP tunneling solution that delivers fast, reliable access across network restrictions using pre-established TCP/QUIC/WebSocket or HTTP/2 connections. | ![GitHub Repo stars](https://img.shields.io/github/stars/NodePassProject/nodepass?style=flat-square)  |
| [OONI Probe](https://github.com/ooni/probe-cli)           | Next generation OONI Probe. Library and CLI tool.                                                                                                                 | ![GitHub Repo stars](https://img.shields.io/github/stars/ooni/probe-cli?style=flat-square)          |
| [reverst](https://github.com/flipt-io/reverst)            | Reverse Tunnels in Go over HTTP/3 and QUIC                                                                                                                        | ![GitHub Repo stars](https://img.shields.io/github/stars/flipt-io/reverst?style=flat-square) |
| [RoadRunner](https://github.com/roadrunner-server/roadrunner) | High-performance PHP application server, process manager written in Go and powered with plugins | ![GitHub Repo stars](https://img.shields.io/github/stars/roadrunner-server/roadrunner?style=flat-square) |
| [syncthing](https://github.com/syncthing/syncthing/)      | Open Source Continuous File Synchronization                                                                                                                       | ![GitHub Repo stars](https://img.shields.io/github/stars/syncthing/syncthing?style=flat-square)     |
| [traefik](https://github.com/traefik/traefik)             | The Cloud Native Application Proxy                                                                                                                                | ![GitHub Repo stars](https://img.shields.io/github/stars/traefik/traefik?style=flat-square)         |
| [v2ray-core](https://github.com/v2fly/v2ray-core)         | A platform for building proxies to bypass network restrictions                                                                                                    | ![GitHub Repo stars](https://img.shields.io/github/stars/v2fly/v2ray-core?style=flat-square)        |
| [YoMo](https://github.com/yomorun/yomo)                   | Streaming Serverless Framework for Geo-distributed System                                                                                                         | ![GitHub Repo stars](https://img.shields.io/github/stars/yomorun/yomo?style=flat-square)            |

If you'd like to see your project added to this list, please send us a PR.

## Release Policy

quic-go always aims to support the latest two Go releases.

## Contributing

We are always happy to welcome new contributors! We have a number of self-contained issues that are suitable for first-time contributors, they are tagged with [help wanted](https://github.com/quic-go/quic-go/issues?q=is%3Aissue+is%3Aopen+label%3A%22help+wanted%22). If you have any questions, please feel free to reach out by opening an issue or leaving a comment.

## License

The code is licensed under the MIT license. The logo and brand assets are excluded from the MIT license. See [assets/LICENSE.md](https://github.com/quic-go/quic-go/tree/master/assets/LICENSE.md) for the full usage policy and details.
