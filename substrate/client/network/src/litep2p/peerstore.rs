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

//! `Peerstore` implementation for `litep2p`.
//!
//! `Peerstore` is responsible for storing information about remote peers
//! such as their addresses, reputations, supported protocols etc.

use crate::litep2p::shim::notification::peerset::PeersetCommand;

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use sc_network_types::PeerId;
use sc_utils::mpsc::TracingUnboundedSender;

use std::{
	collections::{HashMap, HashSet},
	sync::Arc,
};

/// Logging target for the file.
const LOG_TARGET: &str = "sub-libp2p::peerstore";

#[derive(Debug, Default)]
pub struct PeerstoreHandleInner {
	peers: HashMap<PeerId, i32>,
	protocols: Vec<TracingUnboundedSender<PeersetCommand>>,
}

#[derive(Debug, Clone, Default)]
pub struct PeerstoreHandle(Arc<Mutex<PeerstoreHandleInner>>);

impl PeerstoreHandle {
	/// Register protocol to `PeerstoreHandle`.
	///
	/// This channel is only used to disconnect banned peers and may be replaced
	/// with something else in the future.
	pub fn register_protocol(&mut self, sender: TracingUnboundedSender<PeersetCommand>) {
		self.0.lock().protocols.push(sender);
	}

	/// Add known peer to [`Peerstore`].
	pub fn add_known_peer(&mut self, peer: PeerId) {
		self.0.lock().peers.insert(peer, 0i32);
	}

	/// Adjust peer reputation.
	pub fn report_peer(&mut self, peer: PeerId, reputation_change: i32) {
		*self.0.lock().peers.entry(peer).or_default() += reputation_change;
	}

	/// Get next outbound peer for connection attempt, ignoring all peers in `ignore`.
	///
	/// Returns `None` if there are no peers available.
	pub fn next_outbound_peer(&self, ignore: &HashSet<&PeerId>) -> Option<PeerId> {
		let handle = self.0.lock();

		for peer in handle.peers.keys() {
			if !ignore.contains(peer) {
				return Some(*peer)
			}
		}

		None
	}

	pub fn peer_count(&self) -> usize {
		self.0.lock().peers.len()
	}
}

// TODO: documentation
static PEERSET_HANDLE: Lazy<PeerstoreHandle> =
	Lazy::new(|| PeerstoreHandle(Arc::new(Mutex::new(Default::default()))));

/// Get handle to `Peerstore`.
pub fn peerstore_handle() -> PeerstoreHandle {
	Lazy::force(&PEERSET_HANDLE).clone()
}

/// Peerstore implementation.
pub struct Peerstore {
	/// Handle to `Peerstore`.
	peerstore_handle: PeerstoreHandle,
}

impl Peerstore {
	/// Create new [`Peerstore`].
	pub fn new() -> Self {
		Self { peerstore_handle: peerstore_handle() }
	}

	/// Add known peer to [`Peerstore`].
	pub fn add_known_peer(&mut self, peer: PeerId) {
		self.peerstore_handle.0.lock().peers.insert(peer, 0i32);
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use sc_utils::mpsc::tracing_unbounded;

	#[test]
	fn acquire_mutual_handle() {
		// acquire first handle to peer store and register protocol
		let mut handle1 = peerstore_handle();
		let (tx1, _) = tracing_unbounded("mpsc-peerset-protocol", 100_000);
		handle1.register_protocol(tx1);

		// acquire second handle to peerstore and verify both handles have the registered protocol
		let mut handle2 = peerstore_handle();
		assert_eq!(handle1.0.lock().protocols.len(), 1);
		assert_eq!(handle2.0.lock().protocols.len(), 1);

		// register another protocol using the second handle and verify both handles have the
		// protocol
		let (tx2, _) = tracing_unbounded("mpsc-peerset-protocol", 100_000);
		handle1.register_protocol(tx2);
		assert_eq!(handle1.0.lock().protocols.len(), 2);
		assert_eq!(handle2.0.lock().protocols.len(), 2);
	}
}
