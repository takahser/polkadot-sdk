// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! libp2p-related discovery code for litep2p backend.

use crate::{
	config::{NetworkConfiguration, ProtocolId},
	litep2p::peerstore::PeerstoreHandle,
	Litep2pNetworkBackend, Multiaddr,
};

use array_bytes::bytes2hex;
use futures::{pin_mut, Future, FutureExt, Stream};
use futures_timer::Delay;
use litep2p::{
	protocol::{
		libp2p::{
			identify::{Config as IdentifyConfig, IdentifyEvent},
			kademlia::{
				Config as KademliaConfig, ConfigBuilder as KademliaConfigBuilder, KademliaEvent,
				KademliaHandle,
			},
			ping::{Config as PingConfig, PingEvent},
		},
		mdns::{Config as MdnsConfig, MdnsEvent},
	},
	PeerId, ProtocolName,
};

use sp_runtime::traits::Block;

use std::{
	collections::{HashMap, HashSet},
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

// TODO: remove LOG_TARGET and export from `crate`
// TODO: when the node starts, start kad query for own peer id

/// Logging target for the file.
const LOG_TARGET: &str = "sub-libp2p";

/// Kademlia query interval.
const KADEMLIA_QUERY_INTERVAL: Duration = Duration::from_secs(30);

/// mDNS query interval.
const MDNS_QUERY_INTERVAL: Duration = Duration::from_secs(30);

/// Discovery events.
#[derive(Debug)]
pub enum DiscoveryEvent {
	/// Ping RTT measured for peer.
	Ping {
		/// Remote peer ID.
		peer: PeerId,

		/// Ping round-trip time.
		rtt: Duration,
	},

	/// Peer identified over `/ipfs/identify/1.0.0` protocol.
	Identified {
		/// Peer ID.
		peer: PeerId,

		/// Supported protocols.
		supported_protocols: HashSet<String>,
	},

	/// One or more addresses discovered.
	Discovered {
		/// Discovered addresses.
		addresses: Vec<Multiaddr>,
	},
}

pub struct Discovery {
	/// Ping event stream.
	ping_event_stream: Box<dyn Stream<Item = PingEvent> + Send + Unpin>,

	/// Identify event stream.
	identify_event_stream: Box<dyn Stream<Item = IdentifyEvent> + Send + Unpin>,

	/// mDNS event stream, if enabled.
	mdns_event_stream: Option<Box<dyn Stream<Item = MdnsEvent> + Send + Unpin>>,

	/// Kademlia handle.
	kademlia_handle: KademliaHandle,

	/// `Peerstore` handle.
	peerstore_handle: PeerstoreHandle,

	/// Next Kademlia query for a random peer ID.
	///
	/// If `None`, there is currently a query pending.
	next_kad_query: Option<Delay>,
}

/// Legacy (fallback) Kademlia protocol name based on `protocol_id`.
fn legacy_kademlia_protocol_name(id: &ProtocolId) -> ProtocolName {
	ProtocolName::from(format!("/{}/kad", id.as_ref()))
}

/// Kademlia protocol name based on `genesis_hash` and `fork_id`.
fn kademlia_protocol_name<Hash: AsRef<[u8]>>(
	genesis_hash: Hash,
	fork_id: Option<&str>,
) -> ProtocolName {
	let genesis_hash_hex = bytes2hex("", genesis_hash.as_ref());
	let protocol = if let Some(fork_id) = fork_id {
		format!("/{}/{}/kad", genesis_hash_hex, fork_id)
	} else {
		format!("/{}/kad", genesis_hash_hex)
	};

	ProtocolName::from(protocol)
}

impl Discovery {
	/// Create new [`Discovery`].
	///
	/// Enables `/ipfs/ping/1.0.0` and `/ipfs/identify/1.0.0` by default and starts
	/// the mDNS peer discovery if it was enabled.
	pub fn new<Hash: AsRef<[u8]>>(
		config: &NetworkConfiguration,
		genesis_hash: Hash,
		fork_id: Option<&str>,
		protocol_id: &ProtocolId,
		known_peers: HashMap<PeerId, Vec<Multiaddr>>,
		peerstore_handle: PeerstoreHandle,
	) -> (Self, PingConfig, IdentifyConfig, KademliaConfig, Option<MdnsConfig>) {
		let (ping_config, ping_event_stream) = PingConfig::default();
		let (identify_config, identify_event_stream) = IdentifyConfig::new();

		let (mdns_config, mdns_event_stream) = match config.transport {
			crate::config::TransportConfig::Normal { enable_mdns, .. } => match enable_mdns {
				true => {
					let (mdns_config, mdns_event_stream) = MdnsConfig::new(MDNS_QUERY_INTERVAL);
					(Some(mdns_config), Some(mdns_event_stream))
				},
				false => (None, None),
			},
			_ => panic!("memory transport not supported"),
		};

		let (kademlia_config, kademlia_handle) = {
			let protocol_names = vec![
				kademlia_protocol_name(genesis_hash, fork_id),
				legacy_kademlia_protocol_name(protocol_id),
			];

			KademliaConfigBuilder::new()
				.with_known_peers(known_peers)
				.with_protocol_names(protocol_names)
				.build()
		};

		(
			Self {
				ping_event_stream,
				identify_event_stream,
				mdns_event_stream,
				kademlia_handle,
				peerstore_handle,
				next_kad_query: Some(Delay::new(KADEMLIA_QUERY_INTERVAL)),
			},
			ping_config,
			identify_config,
			kademlia_config,
			mdns_config,
		)
	}

	// Add known peer to DHT.
	pub async fn add_known_peer(&mut self, peer: PeerId, addresses: Vec<Multiaddr>) {
		self.kademlia_handle.add_known_peer(peer, addresses).await;
	}
}

impl Stream for Discovery {
	type Item = DiscoveryEvent;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = Pin::into_inner(self);

		if let Some(mut delay) = this.next_kad_query.take() {
			match delay.poll_unpin(cx) {
				Poll::Pending => {
					this.next_kad_query = Some(delay);
				},
				Poll::Ready(()) => {
					log::error!(target: LOG_TARGET, "start next kademlia query");

					let future = this.kademlia_handle.find_node(PeerId::random());
					pin_mut!(future);

					match future.poll(cx) {
						Poll::Pending => {
							this.next_kad_query = Some(Delay::new(KADEMLIA_QUERY_INTERVAL));
						},
						Poll::Ready(_) => {},
					}
				},
			}
		}

		match Pin::new(&mut this.ping_event_stream).poll_next(cx) {
			Poll::Ready(None) => return Poll::Ready(None),
			Poll::Ready(Some(PingEvent::Ping { peer, ping })) =>
				return Poll::Ready(Some(DiscoveryEvent::Ping { peer, rtt: ping })),
			_ => {},
		}

		match Pin::new(&mut this.identify_event_stream).poll_next(cx) {
			Poll::Ready(None) => return Poll::Ready(None),
			Poll::Ready(Some(IdentifyEvent::PeerIdentified { peer, supported_protocols })) =>
				return Poll::Ready(Some(DiscoveryEvent::Identified { peer, supported_protocols })),
			_ => {},
		}

		match Pin::new(&mut this.kademlia_handle).poll_next(cx) {
			Poll::Ready(None) => return Poll::Ready(None),
			Poll::Ready(Some(KademliaEvent::FindNodeResult { peers, .. })) => {
				// the addresses are already inserted into the DHT and in `TransportManager` so
				// there is no need to add them again. The found peers must be registered to
				// `Peerstore` so other protocols are aware of them through `Peerset`.
				log::error!(target: LOG_TARGET, "DHT random walk yielded {} peers", peers.len());

				for (peer, _) in peers {
					this.peerstore_handle.add_known_peer(peer.into());
				}
				this.next_kad_query = Some(Delay::new(KADEMLIA_QUERY_INTERVAL));
			},
			Poll::Ready(Some(KademliaEvent::RoutingTableUpdate { peers })) => {
				log::error!(target: LOG_TARGET, "routing table update, num peers {} {}", peers.len(), this.peerstore_handle.peer_count());

				for peer in peers {
					this.peerstore_handle.add_known_peer(peer.into());
				}
			},
			Poll::Ready(Some(KademliaEvent::GetRecordResult { .. })) => {
				todo!("should not get getrecordresult");
			},
			_ => {},
		}

		if let Some(ref mut mdns_event_stream) = &mut this.mdns_event_stream {
			match Pin::new(mdns_event_stream).poll_next(cx) {
				Poll::Ready(None) => return Poll::Ready(None),
				Poll::Ready(Some(MdnsEvent::Discovered(addresses))) =>
					return Poll::Ready(Some(DiscoveryEvent::Discovered { addresses })),
				_ => {},
			}
		}

		Poll::Pending
	}
}
