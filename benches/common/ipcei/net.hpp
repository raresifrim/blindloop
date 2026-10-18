// Copyright (c) 2026 Rares Ifrim, National University of Science and Technology POLITEHNICA Bucharest.
// All rights reserved.
//
// net.hpp — emulated automotive Ethernet between the end zones and the central node.
//
// Every uplink and the downlink cross a real TCP connection, and each node pays the CPU
// cost of the stack it would run in the vehicle:
//
//   end zones     lwIP (third_party/lwip), the stack of an MCU-class node: no OS
//                 (NO_SYS=1), raw TCP API, an Ethernet interface whose "driver" copies each
//                 frame into a shared-memory ring in place of the MAC's DMA buffers.
//                 Steps <zone>.send_uplink and passenger.recv_downlink: the time spent in
//                 lwIP (writing, segmenting, framing, processing the ACKs or the incoming
//                 frames), not the time spent waiting for the peer.
//   central node  the operating system's TCP stack (loopback, MSS 1460 as on a
//                 1500-byte MTU link). Steps central.recv_uplink and central.send_downlink:
//                 the thread's CPU time (user + system) in the socket calls.
//
// The other end of each connection is a peer process, untimed: an lwIP stack facing the
// end zones, an OS socket client facing the central node. Both carry the same bytes, so
// one message is sent by the end zone's stack and received by the central node's stack.
// The time on the wire is not emulated but modelled (harness.hpp, EthernetWire).
//
// A message is a header (12 bytes: total, payload and signature lengths), the payload,
// the signature and a block the size of the ADSC proof (the proof object itself is passed
// in memory: its serialization is not part of the measurement). The central node and the
// End Node continue with the bytes they received.
#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "ipcei/harness.hpp"

namespace ipcei {
namespace net {

using Bytes = std::vector<uint8_t>;

Bytes Pack(const Bytes& payload, const Bytes& signature, size_t proof_bytes);
bool Unpack(const Bytes& message, Bytes& payload, Bytes& signature);

class Network {
public:
	/// Starts the two peer processes and opens the connections when opts.net (call it
	/// early in main, before any library starts threads: it forks).
	explicit Network(const Options& opts);
	~Network();
	Network(const Network&) = delete;
	Network& operator=(const Network&) = delete;

	bool enabled() const { return impl_ != nullptr; }
	/// Records the network configuration as a bench parameter.
	void Describe(Recorder& rec) const;

	/// Zone z's uplink: sent by the zone over lwIP, received by the central node over OS
	/// TCP. Records the link size always and, when enabled, <z>.send_uplink and
	/// central.recv_uplink; payload and signature become the received bytes. False when
	/// the transfer corrupted the message.
	bool Uplink(Recorder& rec, Zone z, Bytes& payload, Bytes& signature, size_t proof_bytes);

	/// The downlink: sent by the central node over OS TCP, received by the End Node
	/// (passenger) over lwIP. Records central.send_downlink and passenger.recv_downlink.
	bool Downlink(Recorder& rec, Bytes& payload, Bytes& signature);

	struct Impl;

private:
	std::unique_ptr<Impl> impl_;
	bool offload_ = false;
};

}  // namespace net
}  // namespace ipcei
