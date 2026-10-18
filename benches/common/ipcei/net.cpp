// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// net.cpp — the emulated Ethernet of net.hpp.
//
// Processes: the bench (the end zones' lwIP stack and the central node's OS sockets) and
// two peers forked before any library starts threads: an lwIP peer, joined to the bench's
// lwIP interface by two shared-memory frame rings (one per direction), and an OS socket
// peer on loopback. lwIP keeps its state in globals, so each process has its own stack.
// The bench drives the peers through pipes (one command byte, one reply byte) and a shared
// buffer holding the message of the current transfer.
#include "ipcei/net.hpp"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <new>
#include <thread>

#include "lwip/etharp.h"
#include "lwip/init.h"
#include "lwip/ip4_addr.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/priv/tcp_priv.h"  // tcp_ack_now
#include "lwip/tcp.h"
#include "lwip/timeouts.h"
#include "netif/ethernet.h"

extern "C" u32_t sys_now(void) {
	static const auto t0 = std::chrono::steady_clock::now();
	return (u32_t)std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - t0).count();
}

namespace ipcei {
namespace net {

namespace {

constexpr size_t kHeader = 12;
constexpr size_t kFrameMax = 1536;
constexpr uint32_t kSlots = 512;
constexpr size_t kMaxMessage = 8u << 20;
constexpr int kConns = 4;  // 0..2: the uplinks of the three end zones, 3: the downlink
constexpr int kDownlink = 3;
constexpr u16_t kPortBase = 7000;
constexpr int kMss = 1460;

[[noreturn]] void Die(const char* what) {
	std::perror(what);
	std::fprintf(stderr, "net: %s failed\n", what);
	std::exit(1);
}

void PutLe32(uint8_t* p, uint32_t v) {
	for (int i = 0; i < 4; ++i) p[i] = (uint8_t)(v >> (8 * i));
}
uint32_t GetLe32(const uint8_t* p) {
	return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}

// ---------------------------------------------------------------- shared memory

/// Single-producer single-consumer ring of Ethernet frames: the emulated MAC's DMA buffers.
struct Ring {
	std::atomic<uint32_t> head{0}, tail{0};
	struct Slot {
		uint32_t len;
		uint8_t data[kFrameMax];
	} slot[kSlots];

	uint8_t* Reserve() {  // never full in practice: TCP keeps a window's worth in flight
		const uint32_t h = head.load(std::memory_order_relaxed);
		while (h - tail.load(std::memory_order_acquire) == kSlots) std::this_thread::yield();
		return slot[h % kSlots].data;
	}
	void Commit(uint32_t len) {
		const uint32_t h = head.load(std::memory_order_relaxed);
		slot[h % kSlots].len = len;
		head.store(h + 1, std::memory_order_release);
	}
	const Slot* Front() const {
		const uint32_t t = tail.load(std::memory_order_relaxed);
		return t == head.load(std::memory_order_acquire) ? nullptr : &slot[t % kSlots];
	}
	void Pop() { tail.store(tail.load(std::memory_order_relaxed) + 1, std::memory_order_release); }
};

struct Shared {
	Ring to_peer, to_node;  // lwIP link: bench -> lwIP peer, lwIP peer -> bench
	uint32_t len = 0;       // the message of the current transfer
	int zone = 0;
	uint8_t data[kMaxMessage];
};

// ---------------------------------------------------------------- lwIP (one stack per process)

struct Conn {
	tcp_pcb* pcb = nullptr;
	bool up = false;
	Bytes rx;
	size_t expect = 0;
};

struct LwipState {
	netif nif;
	Ring* in = nullptr;
	uint8_t mac[6] = {0x02, 0, 0, 0, 0, 0};
	Conn conn[kConns];
	u32_t last_tick = 0;
} g;

err_t LinkOutput(netif* n, pbuf* p) {
	Ring* r = static_cast<Ring*>(n->state);
	uint8_t* d = r->Reserve();
	pbuf_copy_partial(p, d, p->tot_len, 0);
	r->Commit(p->tot_len);
	return ERR_OK;
}

err_t IfInit(netif* n) {
	n->name[0] = 'e';
	n->name[1] = 't';
	n->output = etharp_output;
	n->linkoutput = LinkOutput;
	n->mtu = 1500;
	n->hwaddr_len = 6;
	std::memcpy(n->hwaddr, g.mac, 6);
	n->flags = NETIF_FLAG_BROADCAST | NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET | NETIF_FLAG_LINK_UP;
	return ERR_OK;
}

void LwipUp(Ring* out, Ring* in, uint8_t self, uint8_t peer, bool offload) {
	lwip_init();
	g.mac[5] = self;
	ip4_addr_t ip, mask, gw, peer_ip;
	IP4_ADDR(&ip, 10, 0, 0, self);
	IP4_ADDR(&mask, 255, 255, 255, 0);
	IP4_ADDR(&gw, 0, 0, 0, 0);
	IP4_ADDR(&peer_ip, 10, 0, 0, peer);
	if (!netif_add(&g.nif, &ip, &mask, &gw, out, IfInit, ethernet_input)) Die("netif_add");
	netif_set_default(&g.nif);
	netif_set_up(&g.nif);
	netif_set_link_up(&g.nif);
	if (offload) NETIF_SET_CHECKSUM_CTRL(&g.nif, NETIF_CHECKSUM_DISABLE_ALL);
	eth_addr peer_mac = {{0x02, 0, 0, 0, 0, peer}};
	etharp_add_static_entry(&peer_ip, &peer_mac);
	g.in = in;
	g.last_tick = sys_now();
}

/// Feeds every frame waiting in the receive ring to lwIP; returns the time spent in it.
double PollInput() {
	double ms = 0;
	while (const Ring::Slot* s = g.in->Front()) {
		const auto t0 = Clock::now();
		pbuf* p = pbuf_alloc(PBUF_RAW, (u16_t)s->len, PBUF_POOL);
		if (p) {
			pbuf_take(p, s->data, (u16_t)s->len);
			if (g.nif.input(p, &g.nif) != ERR_OK) pbuf_free(p);
		}
		g.in->Pop();
		ms += MsSince(t0);
	}
	return ms;
}

/// lwIP's timers, once per millisecond tick (the idle polling between ticks is not timed).
double Timers() {
	const u32_t now = sys_now();
	if (now == g.last_tick) return 0;
	g.last_tick = now;
	const auto t0 = Clock::now();
	sys_check_timeouts();
	return MsSince(t0);
}

err_t OnRecv(void* arg, tcp_pcb* pcb, pbuf* p, err_t) {
	Conn* c = static_cast<Conn*>(arg);
	if (!p) return ERR_OK;
	const size_t off = c->rx.size();
	c->rx.resize(off + p->tot_len);
	pbuf_copy_partial(p, c->rx.data() + off, p->tot_len, 0);
	tcp_recved(pcb, p->tot_len);
	pbuf_free(p);
	if (c->expect && c->rx.size() >= c->expect) {  // the whole message: acknowledge it now
		tcp_ack_now(pcb);
		tcp_output(pcb);
	}
	return ERR_OK;
}

/// Writes n bytes and waits until the peer acknowledged them; returns the time in lwIP.
double SendAll(Conn& c, const uint8_t* d, size_t n) {
	double ms = 0;
	size_t off = 0;
	for (;;) {
		if (off < n) {
			const size_t room = tcp_sndbuf(c.pcb);
			if (room >= std::min<size_t>(n - off, kMss) && tcp_sndqueuelen(c.pcb) + 64 < TCP_SND_QUEUELEN) {
				const size_t chunk = std::min(n - off, room);
				const auto t0 = Clock::now();
				if (tcp_write(c.pcb, d + off, (u16_t)chunk, TCP_WRITE_FLAG_COPY) == ERR_OK) off += chunk;
				tcp_output(c.pcb);
				ms += MsSince(t0);
			}
		}
		ms += PollInput();
		ms += Timers();
		if (off == n && !c.pcb->unsent && !c.pcb->unacked) return ms;
	}
}

/// Receives the n-byte message the peer is sending on c; returns the time in lwIP.
double RecvAll(Conn& c, size_t n) {
	double ms = 0;
	while (c.rx.size() < n) {
		ms += PollInput();
		ms += Timers();
	}
	c.expect = 0;
	return ms;
}

err_t OnConnected(void* arg, tcp_pcb*, err_t) {
	static_cast<Conn*>(arg)->up = true;
	return ERR_OK;
}

err_t OnAccept(void*, tcp_pcb* pcb, err_t err) {
	if (err != ERR_OK || !pcb) return ERR_VAL;
	Conn& c = g.conn[pcb->local_port - kPortBase];
	c.pcb = pcb;
	c.up = true;
	tcp_arg(pcb, &c);
	tcp_recv(pcb, OnRecv);
	tcp_nagle_disable(pcb);
	return ERR_OK;
}

bool AllUp() {
	for (const Conn& c : g.conn)
		if (!c.up) return false;
	return true;
}

void Reply(int fd, char c) {
	if (write(fd, &c, 1) != 1) _exit(1);
}

/// The lwIP peer: the other end of the end zones' connections.
[[noreturn]] void LwipPeer(Shared* sh, int cmd, int done, bool offload) {
	LwipUp(&sh->to_node, &sh->to_peer, 1, 2, offload);
	for (int i = 0; i < kConns; ++i) {
		tcp_pcb* pcb = tcp_new();
		if (!pcb || tcp_bind(pcb, IP4_ADDR_ANY, (u16_t)(kPortBase + i)) != ERR_OK) _exit(1);
		tcp_pcb* l = tcp_listen(pcb);
		if (!l) _exit(1);
		tcp_accept(l, OnAccept);
	}
	Reply(done, 'R');
	for (;;) {
		char c;
		if (read(cmd, &c, 1) != 1) _exit(0);  // the bench exited
		if (c == 'C') {
			while (!AllUp()) {
				PollInput();
				Timers();
			}
			Reply(done, 'K');
		} else if (c == 'U') {
			Conn& k = g.conn[sh->zone];
			k.rx.clear();
			k.rx.reserve(sh->len);
			k.expect = sh->len;
			RecvAll(k, sh->len);
			Reply(done, k.rx.size() == sh->len && std::memcmp(k.rx.data(), sh->data, sh->len) == 0 ? 'K' : 'X');
		} else if (c == 'D') {
			SendAll(g.conn[kDownlink], sh->data, sh->len);
			Reply(done, 'K');
		} else {
			_exit(0);
		}
	}
}

// ---------------------------------------------------------------- OS sockets

double ThreadCpuMs() {
	timespec ts;
	clock_gettime(CLOCK_THREAD_CPUTIME_ID, &ts);
	return ts.tv_sec * 1e3 + ts.tv_nsec * 1e-6;
}

void SetTcp(int fd) {
	int one = 1, mss = kMss;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);
	setsockopt(fd, IPPROTO_TCP, TCP_MAXSEG, &mss, sizeof mss);  // as on a 1500-byte MTU link
}

bool WriteFull(int fd, const uint8_t* p, size_t n) {
	while (n) {
		const ssize_t k = write(fd, p, n);
		if (k <= 0) return false;
		p += k;
		n -= (size_t)k;
	}
	return true;
}
bool ReadFull(int fd, uint8_t* p, size_t n) {
	while (n) {
		const ssize_t k = read(fd, p, n);
		if (k <= 0) return false;
		p += k;
		n -= (size_t)k;
	}
	return true;
}

/// The socket peer: the other end of the central node's connections.
[[noreturn]] void SocketPeer(Shared* sh, uint16_t port, int cmd, int done) {
	int sock[kConns];
	for (int i = 0; i < kConns; ++i) {
		sock[i] = socket(AF_INET, SOCK_STREAM, 0);
		SetTcp(sock[i]);
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port = htons(port);
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		if (connect(sock[i], (sockaddr*)&a, sizeof a) != 0) _exit(1);
		const uint8_t id = (uint8_t)i;
		if (!WriteFull(sock[i], &id, 1)) _exit(1);
	}
	Reply(done, 'R');
	Bytes buf;
	for (;;) {
		char c;
		if (read(cmd, &c, 1) != 1) _exit(0);
		if (c == 'U') {
			Reply(done, WriteFull(sock[sh->zone], sh->data, sh->len) ? 'K' : 'X');
		} else if (c == 'D') {
			buf.resize(sh->len);
			const bool ok = ReadFull(sock[kDownlink], buf.data(), sh->len) && std::memcmp(buf.data(), sh->data, sh->len) == 0;
			Reply(done, ok ? 'K' : 'X');
		} else {
			_exit(0);
		}
	}
}

struct Peer {
	pid_t pid = -1;
	int cmd = -1, done = -1;
	void Send(char c) const {
		if (write(cmd, &c, 1) != 1) Die("peer command");
	}
	char Wait() const {
		char c = 0;
		if (read(done, &c, 1) != 1) Die("peer reply");
		return c;
	}
};

/// Forks a peer running body(cmd_read_fd, done_write_fd).
template <class F>
Peer Spawn(F body) {
	int to[2], from[2];
	if (pipe(to) != 0 || pipe(from) != 0) Die("pipe");
	Peer p;
	p.pid = fork();
	if (p.pid < 0) Die("fork");
	if (p.pid == 0) {
		close(to[1]);
		close(from[0]);
		body(to[0], from[1]);
	}
	close(to[0]);
	close(from[1]);
	p.cmd = to[1];
	p.done = from[0];
	return p;
}

}  // namespace

// ---------------------------------------------------------------- messages

Bytes Pack(const Bytes& payload, const Bytes& signature, size_t proof_bytes) {
	const size_t total = kHeader + payload.size() + signature.size() + proof_bytes;
	Bytes m(total);
	PutLe32(m.data(), (uint32_t)total);
	PutLe32(m.data() + 4, (uint32_t)payload.size());
	PutLe32(m.data() + 8, (uint32_t)signature.size());
	uint8_t* p = m.data() + kHeader;
	if (!payload.empty()) std::memcpy(p, payload.data(), payload.size());
	p += payload.size();
	if (!signature.empty()) std::memcpy(p, signature.data(), signature.size());
	p += signature.size();
	uint32_t x = 0x9E3779B9u ^ (uint32_t)total;  // stand-in bytes of the ADSC proof
	for (size_t i = 0; i < proof_bytes; ++i) {
		x = x * 1664525u + 1013904223u;
		p[i] = (uint8_t)(x >> 24);
	}
	return m;
}

bool Unpack(const Bytes& m, Bytes& payload, Bytes& signature) {
	if (m.size() < kHeader || GetLe32(m.data()) != m.size()) return false;
	const size_t np = GetLe32(m.data() + 4), ns = GetLe32(m.data() + 8);
	if (kHeader + np + ns > m.size()) return false;
	payload.assign(m.begin() + kHeader, m.begin() + kHeader + np);
	signature.assign(m.begin() + kHeader + np, m.begin() + kHeader + np + ns);
	return true;
}

// ---------------------------------------------------------------- Network

struct Network::Impl {
	Shared* sh = nullptr;
	Peer lwip, sockets;
	int sock[kConns] = {-1, -1, -1, -1};

	explicit Impl(bool offload) {
		signal(SIGPIPE, SIG_IGN);
		void* m = mmap(nullptr, sizeof(Shared), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANON, -1, 0);
		if (m == MAP_FAILED) Die("mmap");
		sh = new (m) Shared();

		// the central node's listening socket, before the socket peer is forked
		const int ls = socket(AF_INET, SOCK_STREAM, 0);
		int one = 1;
		setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
		SetTcp(ls);
		sockaddr_in a{};
		a.sin_family = AF_INET;
		a.sin_port = 0;
		a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		socklen_t al = sizeof a;
		if (bind(ls, (sockaddr*)&a, sizeof a) != 0 || listen(ls, kConns) != 0 || getsockname(ls, (sockaddr*)&a, &al) != 0)
			Die("listen");
		const uint16_t port = ntohs(a.sin_port);

		Shared* s = sh;
		lwip = Spawn([s, ls, offload](int cmd, int done) {
			close(ls);
			LwipPeer(s, cmd, done, offload);
		});
		sockets = Spawn([s, ls, port](int cmd, int done) {
			close(ls);
			SocketPeer(s, port, cmd, done);
		});

		for (int i = 0; i < kConns; ++i) {
			const int fd = accept(ls, nullptr, nullptr);
			uint8_t id = 0;
			if (fd < 0 || !ReadFull(fd, &id, 1) || id >= kConns) Die("accept");
			SetTcp(fd);
			sock[id] = fd;
		}
		close(ls);
		if (sockets.Wait() != 'R') Die("socket peer start");

		// the end zones' lwIP stack, after the forks: the peer has its own
		LwipUp(&sh->to_peer, &sh->to_node, 2, 1, offload);
		if (lwip.Wait() != 'R') Die("lwIP peer start");
		lwip.Send('C');
		ip4_addr_t peer_ip;
		IP4_ADDR(&peer_ip, 10, 0, 0, 1);
		for (int i = 0; i < kConns; ++i) {
			Conn& c = g.conn[i];
			c.pcb = tcp_new();
			tcp_arg(c.pcb, &c);
			tcp_recv(c.pcb, OnRecv);
			tcp_nagle_disable(c.pcb);
			if (tcp_connect(c.pcb, &peer_ip, (u16_t)(kPortBase + i), OnConnected) != ERR_OK) Die("tcp_connect");
		}
		while (!AllUp()) {
			PollInput();
			Timers();
		}
		if (lwip.Wait() != 'K') Die("lwIP connections");
	}

	~Impl() {
		for (Peer* p : {&lwip, &sockets}) {
			p->Send('Q');
			waitpid(p->pid, nullptr, 0);
			close(p->cmd);
			close(p->done);
		}
		for (int fd : sock) close(fd);
		munmap(sh, sizeof(Shared));
	}

	void Stage(const Bytes& m, int zone) {
		if (m.size() > kMaxMessage) {
			std::fprintf(stderr, "net: message of %zu bytes exceeds %zu\n", m.size(), kMaxMessage);
			std::exit(1);
		}
		std::memcpy(sh->data, m.data(), m.size());
		sh->len = (uint32_t)m.size();
		sh->zone = zone;
	}

	bool Uplink(Recorder& rec, Zone z, const Bytes& m, Bytes& got) {
		const int zi = z == Zone::Passenger ? 0 : z == Zone::Driver ? 1 : 2;
		Stage(m, zi);
		lwip.Send('U');
		rec.Add(z, "send_uplink", SendAll(g.conn[zi], m.data(), m.size()));
		const bool sent = lwip.Wait() == 'K';

		sockets.Send('U');
		const double t0 = ThreadCpuMs();
		uint8_t hdr[4];
		bool ok = ReadFull(sock[zi], hdr, 4);
		const uint32_t total = ok ? GetLe32(hdr) : 0;
		ok = ok && total >= kHeader && total <= kMaxMessage;
		if (ok) {
			got.resize(total);
			std::memcpy(got.data(), hdr, 4);
			ok = ReadFull(sock[zi], got.data() + 4, total - 4);
		}
		rec.Add(Zone::Central, "recv_uplink", ThreadCpuMs() - t0);
		return sockets.Wait() == 'K' && sent && ok;
	}

	bool Downlink(Recorder& rec, const Bytes& m, Bytes& got) {
		Stage(m, kDownlink);
		sockets.Send('D');
		const double t0 = ThreadCpuMs();
		const bool sent = WriteFull(sock[kDownlink], m.data(), m.size());
		rec.Add(Zone::Central, "send_downlink", ThreadCpuMs() - t0);
		const bool peer_ok = sockets.Wait() == 'K';

		Conn& c = g.conn[kDownlink];
		c.rx.clear();
		c.rx.reserve(m.size());
		c.expect = m.size();
		lwip.Send('D');
		rec.Add(Zone::Passenger, "recv_downlink", RecvAll(c, m.size()));
		got = c.rx;
		return lwip.Wait() == 'K' && sent && peer_ok;
	}
};

Network::Network(const Options& opts) : offload_(opts.eth_offload) {
	if (opts.net) impl_ = std::make_unique<Impl>(opts.eth_offload);
}

void Network::Describe(Recorder& rec) const {
	rec.Param("network", !impl_ ? std::string("off (--no-net): no transfers, wire time modelled only")
			: std::string("emulated Ethernet, TCP/IPv4, MSS 1460: end zones lwIP " LWIP_VERSION_STRING
					" (NO_SYS, raw API, checksums ") + (offload_ ? "offloaded to the MAC" : "in software") +
			"), central node OS TCP stack (loopback)");
}

Network::~Network() = default;

bool Network::Uplink(Recorder& rec, Zone z, Bytes& payload, Bytes& signature, size_t proof_bytes) {
	const Bytes m = Pack(payload, signature, proof_bytes);
	rec.Link(std::string("uplink ") + ZoneName(z), m.size());
	if (!impl_) return true;
	Bytes got;
	return impl_->Uplink(rec, z, m, got) && got == m && Unpack(got, payload, signature);
}

bool Network::Downlink(Recorder& rec, Bytes& payload, Bytes& signature) {
	const Bytes m = Pack(payload, signature, 0);
	rec.Link("downlink", m.size());
	if (!impl_) return true;
	Bytes got;
	return impl_->Downlink(rec, m, got) && got == m && Unpack(got, payload, signature);
}

}  // namespace net
}  // namespace ipcei
