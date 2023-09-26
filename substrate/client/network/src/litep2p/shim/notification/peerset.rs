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

//! `Peerset` implementation for `litep2p`.

use crate::{litep2p::peerstore::PeerstoreHandle, service::traits::Direction, ProtocolName};

use futures::{future::BoxFuture, stream::FuturesUnordered, Stream, StreamExt};
use futures_timer::Delay;

use litep2p::protocol::notification::{NotificationError, ValidationResult};
use sc_network_types::PeerId;
use sc_utils::mpsc::{tracing_unbounded, TracingUnboundedReceiver, TracingUnboundedSender};

use std::{
	collections::{hash_map::Entry, HashMap, HashSet},
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

/// Logging target for the file.
const LOG_TARGET: &str = "sub-libp2p::peerset";

/// Default backoff for connection re-attempts.
const DEFAULT_BACKOFF: Duration = Duration::from_secs(30);

/// Reputation adjustment when a peer gets disconnected.
///
/// Lessens the likelyhood of the peer getting selected for an outbound connection soon.
const DISCONNECT_ADJUSTMENT: i32 = -256;

/// Reputation adjustment when a substream fails to open.
///
/// Lessens the likelyhood of the peer getting selected for an outbound connection soon.
const OPEN_FAILURE_ADJUSTMENT: i32 = -256;

/// Commands emitted by other subsystems of the blockchain to [`Peerset`].
#[derive(Debug)]
pub enum PeersetCommand {
	/// Set current reserved peer set.
	///
	/// This command removes all reserved peers that are not in `peers`.
	SetReservedPeers {
		/// New seserved peer set.
		peers: HashSet<PeerId>,
	},

	/// Add one or more reserved peers.
	///
	/// This command doesn't remove any reserved peers but only add new peers.
	AddReservePeers {
		/// Reserved peers to add.
		peers: HashSet<PeerId>,
	},

	/// Remove reserved peers.
	RemoveReservedPeers {
		/// Reserved peers to remove.
		peers: HashSet<PeerId>,
	},

	/// Set reserved-only mode to true/false.
	SetReservedOnly {
		/// Should the protocol only accept/establish connections to reserved peers.
		reserved_only: bool,
	},

	/// Disconnect peer.
	DisconnectPeer {
		/// Peer ID.
		peer: PeerId,
	},
}

/// Commands emitted by [`Peerset`] to the notification protocol.
#[derive(Debug)]
pub enum PeersetNotificationCommand {
	/// Open substream to peer.
	OpenSubstream {
		/// Peer Id.
		peer: PeerId,
	},

	/// Close substream to peer.
	CloseSubstream {
		/// Peer ID.
		peer: PeerId,
	},
}

// TODO: introduce backoff
#[derive(Debug)]
enum PeerState {
	/// No active connection to peer.
	NotConnected,

	/// Connection to peer is pending.
	Opening,

	/// Substream to peer was recently closed and the peer is currently backed off.
	///
	/// Backoff only applies to outbound substreams. Inbound substream will not experience any sort
	/// of "banning" even if the peer is backed off and an inbound substream for the peer is
	/// received.
	Backoff,

	// Connected to peer.
	Connected {
		/// Is the peer inbound or outbound.
		direction: Direction,
	},

	/// Connection to peer is closing.
	///
	/// State implies that the substream was asked to be closed by the local node and litep2p is
	/// closing the substream. No command modifying the connection state is accepted until the
	/// state has been set to [`PeerState::NotConnected`].
	Closing {
		/// Is the peer inbound or outbound.
		direction: Direction,
	},
}

/// Peer context.
#[derive(Debug)]
struct PeerContext {
	/// Is the peer a reserved peer.
	is_reserved: bool,

	/// Peer state.
	state: PeerState,
}

/// `Peerset` implementation.
///
/// `Peerset` allows other subsystems of the blockchain to modify the connection state
/// of the notification protocol by adding and removing reserved peers.
///
/// `Peerset` is also responsible for maintaining the desired amount of peers the protocol is
/// connected to by establishing outbound connections and accepting/rejecting inbound connections.
#[derive(Debug)]
pub struct Peerset {
	/// Protocol name.
	protocol: ProtocolName,

	/// RX channel for receiving commands.
	cmd_rx: TracingUnboundedReceiver<PeersetCommand>,

	/// Maximum number of outbound peers.
	max_out: usize,

	/// Current number of outbound peers.
	num_out: usize,

	/// Maximum number of inbound peers.
	max_in: usize,

	/// Current number of inbound peers.
	num_in: usize,

	/// Accept connections from non-reserved peers.
	accept_non_reserved_peers: bool,

	/// Current reserved peer set.
	reserved_peers: HashSet<PeerId>,

	/// Handle to `Peerstore`.
	peerstore_handle: PeerstoreHandle,

	/// Peers.
	peers: HashMap<PeerId, PeerState>,

	/// Pending backoffs for peers who recently disconnected.
	pending_backoffs: FuturesUnordered<BoxFuture<'static, PeerId>>,
}

impl Peerset {
	/// Create new [`Peerset`].
	pub fn new(
		protocol: ProtocolName,
		max_out: usize,
		max_in: usize,
		accept_non_reserved_peers: bool,
		reserved_peers: HashSet<PeerId>,
		mut peerstore_handle: PeerstoreHandle,
	) -> (Self, TracingUnboundedSender<PeersetCommand>) {
		let (cmd_tx, cmd_rx) = tracing_unbounded("mpsc-peerset-protocol", 100_000);
		let peers = reserved_peers
			.iter()
			.map(|peer| (*peer, PeerState::NotConnected))
			.collect::<HashMap<_, _>>();

		// register protocol's commad channel to `Peerstore` so it can issue disconnect commands
		// if some connected peer gets banned.
		peerstore_handle.register_protocol(cmd_tx.clone());

		(
			Self {
				protocol,
				max_out,
				num_out: 0usize,
				max_in,
				num_in: 0usize,
				reserved_peers,
				cmd_rx,
				peerstore_handle,
				accept_non_reserved_peers,
				peers,
				pending_backoffs: FuturesUnordered::new(),
			},
			cmd_tx,
		)
	}

	/// Report to [`Peerset`] that a substream was opened.
	pub fn report_substream_opened(&mut self, peer: PeerId, direction: Direction) {
		log::debug!(
			target: LOG_TARGET,
			"substream opened to {peer:?}, direction {direction:?}, reserved peer {}",
			self.reserved_peers.contains(&peer)
		);

		self.peers.insert(peer, PeerState::Connected { direction });

		match (self.reserved_peers.contains(&peer), direction) {
			(false, Direction::Inbound) => {
				self.num_in += 1;
			},
			(false, Direction::Outbound) => {
				self.num_out += 1;
			},
			_ => {},
		}
	}

	/// Report to [`Peerset`] that a substream was closed.
	pub fn report_substream_closed(&mut self, peer: PeerId) {
		log::debug!(
			target: LOG_TARGET,
			"substream closed to {peer:?}, reserved peer {}",
			self.reserved_peers.contains(&peer)
		);

		let Some(state) = self.peers.get_mut(&peer) else {
			log::debug!(target: LOG_TARGET, "substream closed for unknown peer {peer:?}");
			return
		};

		match (self.reserved_peers.contains(&peer), &state) {
			(
				false,
				PeerState::Closing { direction: Direction::Inbound } |
				PeerState::Connected { direction: Direction::Inbound },
			) => {
				self.num_in -= 1;
			},
			(
				false,
				PeerState::Closing { direction: Direction::Outbound } |
				PeerState::Connected { direction: Direction::Outbound },
			) => {
				self.num_out -= 1;
			},
			(true, PeerState::Closing { .. }) => {
				log::debug!(target: LOG_TARGET, "reserved peer {peer:?} disconnected");
			},
			(_, state) => {
				log::warn!(target: LOG_TARGET, "invalid state for disconnected peer: {state:?} ");
			},
		}
		*state = PeerState::Backoff;

		self.peerstore_handle.report_peer(peer, DISCONNECT_ADJUSTMENT);
		self.pending_backoffs.push(Box::pin(async move {
			Delay::new(DEFAULT_BACKOFF).await;
			peer
		}));
	}

	/// Report to [`Peerset`] that an inbound substream was opened and that it should validate it.
	pub fn report_inbound_substream(&mut self, peer: PeerId) -> ValidationResult {
		log::trace!(target: LOG_TARGET, "inbound substream from {peer:?}");

		match self.peers.entry(peer) {
			Entry::Vacant(entry) => {
				todo!();
			},
			Entry::Occupied(entry) => {
				todo!();
			},
		}

		if self.reserved_peers.contains(&peer) {
			return ValidationResult::Accept
		}

		// if self.num_in < self.max_in {
		// 	self.num_in += 1;
		return ValidationResult::Accept
		// }
	}

	/// Report to [`Peerset`] that an inbound substream was opened and that it should validate it.
	pub fn report_substream_open_failure(&mut self, peer: PeerId, error: NotificationError) {
		log::trace!(target: LOG_TARGET, "failed to open substream to peer {peer:?}: {error:?}");

		self.peers.insert(peer, PeerState::Backoff);
		self.peerstore_handle.report_peer(peer, OPEN_FAILURE_ADJUSTMENT);
		self.pending_backoffs.push(Box::pin(async move {
			Delay::new(DEFAULT_BACKOFF).await;
			peer
		}));
	}

	/// Try to get next reserved peer which is not currently connected.
	fn try_get_reserved_peer(&self) -> Option<PeerId> {
		self.peers
			.iter()
			.find(|(peer, state)| {
				self.reserved_peers.contains(peer) && std::matches!(state, PeerState::NotConnected)
			})
			.map(|info| *info.0)
	}
}

impl Stream for Peerset {
	type Item = PeersetNotificationCommand;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		// check if any pending backoffs have expired
		while let Poll::Ready(Some(peer)) = self.pending_backoffs.poll_next_unpin(cx) {
			log::trace!(target: LOG_TARGET, "backoff expired for {peer:?}");
			self.peers.insert(peer, PeerState::NotConnected);
		}

		if let Poll::Ready(Some(action)) = Pin::new(&mut self.cmd_rx).poll_next(cx) {
			// TODO: ugly
			match action {
				PeersetCommand::DisconnectPeer { peer } => match self.peers.remove(&peer) {
					Some(PeerState::Connected { direction }) => {
						log::trace!(target: LOG_TARGET, "close connection to {peer:?}, direction {direction:?}");

						self.peers.insert(peer, PeerState::Closing { direction });
						return Poll::Ready(Some(PeersetNotificationCommand::CloseSubstream {
							peer,
						}))
					},
					Some(PeerState::Opening { .. }) => {
						todo!("queue pending close for the stream and once it opens, close the stream");
					},
					Some(state) => {
						log::warn!(target: LOG_TARGET, "cannot disconnect peer, invalid state: {state:?}");
						self.peers.insert(peer, state);
					},
					None => log::error!(target: LOG_TARGET, "peer doens't exist"),
				},
				_ => todo!("unhandled command"),
			}
		}

		// try to establish connection any reserved peer who is not currently connected
		if let Some(peer) = self.try_get_reserved_peer() {
			log::trace!(target: LOG_TARGET, "open connection to reserved peer {peer:?}");

			self.peers.insert(peer, PeerState::Opening);
			return Poll::Ready(Some(PeersetNotificationCommand::OpenSubstream { peer }))
		}

		// if the number of outbound peers is lower than the desired amount of oubound peers,
		// query `PeerStore` and try to get a new outbound candidated.
		if self.num_out < self.max_out {
			let ignore = self
				.peers
				.iter()
				.filter_map(|(peer, state)| {
					std::matches!(
						state,
						PeerState::Closing { .. } |
							PeerState::Backoff | PeerState::Opening |
							PeerState::Connected { .. }
					)
					.then_some(peer)
				})
				.collect();

			match self.peerstore_handle.next_outbound_peer(&ignore) {
				Some(peer) => {
					log::trace!(target: LOG_TARGET, "start connecting to peer {peer:?}");

					self.peers.insert(peer, PeerState::Opening);
					self.num_out += 1;
					return Poll::Ready(Some(PeersetNotificationCommand::OpenSubstream { peer }))
				},
				None => {
					log::trace!(target: LOG_TARGET, "no peer available for an outbound connection");
				},
			}
		}

		Poll::Pending
	}
}
