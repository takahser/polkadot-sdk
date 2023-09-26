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

//! `litep2p` notification protocol configuration.

use crate::{
	config::{MultiaddrWithPeerId, NonReservedPeerMode, NotificationHandshake, SetConfig},
	litep2p::{
		peerstore::{peerstore_handle, PeerstoreHandle},
		shim::notification::{
			peerset::{Peerset, PeersetCommand},
			NotificationProtocol,
		},
	},
	service::traits::NotificationConfig,
	NotificationService, ProtocolName,
};

use once_cell::sync::Lazy;
use parking_lot::Mutex;

use sc_network_types::PeerId;
use sc_utils::mpsc::TracingUnboundedSender;

use std::{collections::HashMap, sync::Arc};

/// Configuration for the notification protocol.
#[derive(Debug)]
pub struct NotificationProtocolConfig {
	/// Name of the notifications protocols of this set. A substream on this set will be
	/// considered established once this protocol is open.
	pub protocol_name: ProtocolName,

	/// Maximum allowed size of single notifications.
	max_notification_size: usize,

	/// Base configuration.
	set_config: SetConfig,

	/// `litep2p` notification config.
	pub config: litep2p::protocol::notification::Config,

	/// TX channel for sending commands to `Peerset` the notification protocol.
	pub peerset_tx: TracingUnboundedSender<PeersetCommand>,
}

impl NotificationProtocolConfig {
	// Create new [`NotificationProtocolConfig`].
	pub fn new(
		protocol_name: ProtocolName,
		fallback_names: Vec<ProtocolName>,
		max_notification_size: usize,
		handshake: Option<NotificationHandshake>,
		set_config: SetConfig,
	) -> (Self, Box<dyn NotificationService>) {
		// create `Peerset`/`Peerstore` handle for the protocol
		let (peerset, peerset_tx) = Peerset::new(
			protocol_name.clone(),
			set_config.out_peers as usize,
			set_config.in_peers as usize,
			set_config.non_reserved_mode == NonReservedPeerMode::Accept,
			set_config.reserved_nodes.iter().map(|address| address.peer_id).collect(),
			peerstore_handle(),
		);

		// create `litep2p` notification protocol configuration for the protocol
		// TODO: fix handshake
		let (config, handle) =
			litep2p::protocol::notification::ConfigBuilder::new(protocol_name.clone().into())
				.with_handshake(handshake.map_or(vec![1], |handshake| (*handshake).to_vec()))
				.with_max_size(max_notification_size as usize)
				.with_auto_accept_inbound(true)
				.with_fallback_names(fallback_names.into_iter().map(From::from).collect())
				.build();

		// initialize the actual object implementing `NotificationService` and combine the
		// `litep2p::NotificationHandle` with `Peerset` to implement a full and independent
		// notification protocol runner
		let protocol = NotificationProtocol::new(protocol_name.clone(), handle, peerset);

		(
			Self { protocol_name, max_notification_size, set_config, config, peerset_tx },
			Box::new(protocol),
		)
	}

	/// Get reference to protocol name.
	pub fn protocol_name(&self) -> &ProtocolName {
		&self.protocol_name
	}

	/// Get reference to `SetConfig`.
	pub fn set_config(&self) -> &SetConfig {
		&self.set_config
	}

	/// Modifies the configuration to allow non-reserved nodes.
	pub fn allow_non_reserved(&mut self, in_peers: u32, out_peers: u32) {
		self.set_config.in_peers = in_peers;
		self.set_config.out_peers = out_peers;
		self.set_config.non_reserved_mode = NonReservedPeerMode::Accept;
	}

	/// Add a node to the list of reserved nodes.
	pub fn add_reserved(&mut self, peer: MultiaddrWithPeerId) {
		self.set_config.reserved_nodes.push(peer);
	}

	/// Get maximum notification size.
	pub fn max_notification_size(&self) -> usize {
		self.max_notification_size
	}
}

impl NotificationConfig for NotificationProtocolConfig {
	fn set_config(&self) -> &SetConfig {
		&self.set_config
	}

	// TODO: this won't work
	fn allow_non_reserved(&mut self, in_peers: u32, out_peers: u32) {
		self.set_config.in_peers = in_peers;
		self.set_config.out_peers = out_peers;
		self.set_config.non_reserved_mode = NonReservedPeerMode::Accept;
	}

	/// Get reference to protocol name.
	fn protocol_name(&self) -> &ProtocolName {
		&self.protocol_name
	}
}
