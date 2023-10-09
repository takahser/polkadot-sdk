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

//! Shim for litep2p's request-response implementation to make it work with `sc_network`'s
//! request-response API.

use crate::{
	config::{IncomingRequest, OutgoingResponse},
	service::traits::RequestResponseConfig as RequestResponseConfigT,
	IfDisconnected, ProtocolName, RequestFailure,
};

use futures::{
	channel::oneshot, future::BoxFuture, pin_mut, stream::FuturesUnordered, Future, Stream,
	StreamExt,
};
use litep2p::{
	protocol::request_response::{
		DialOptions, RequestResponseError, RequestResponseEvent, RequestResponseHandle,
	},
	types::RequestId,
};
use sc_network_types::PeerId;

use std::{
	collections::{HashMap, VecDeque},
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};

// TODO: add tests
// TODO: get rid of the hideous `can_send()` contraption
// TODO: get rid of the hideous `pending_actions` contraption

/// Logging target for the file.
const LOG_TARGET: &str = "sub-libp2p";

/// Request-response protocol configuration.
///
/// See [`RequestResponseConfiguration`](crate::request_response::ProtocolConfig) for more details.
#[derive(Debug)]
pub struct RequestResponseConfig {
	/// Name of the protocol on the wire. Should be something like `/foo/bar`.
	pub protocol_name: ProtocolName,

	/// Fallback on the wire protocol names to support.
	pub fallback_names: Vec<ProtocolName>,

	/// Maximum allowed size, in bytes, of a request.
	pub max_request_size: u64,

	/// Maximum allowed size, in bytes, of a response.
	pub max_response_size: u64,

	/// Duration after which emitted requests are considered timed out.
	pub request_timeout: Duration,

	/// Channel on which the networking service will send incoming requests.
	pub inbound_queue: Option<async_channel::Sender<IncomingRequest>>,
}

// TODO: create litep2p request-response config here already?
impl RequestResponseConfig {
	/// Create new [`RequestResponseConfig`].
	pub(crate) fn new(
		protocol_name: ProtocolName,
		fallback_names: Vec<ProtocolName>,
		max_request_size: u64,
		max_response_size: u64,
		request_timeout: Duration,
		inbound_queue: Option<async_channel::Sender<IncomingRequest>>,
	) -> Self {
		Self {
			protocol_name,
			fallback_names,
			max_request_size,
			max_response_size,
			request_timeout,
			inbound_queue,
		}
	}
}

impl RequestResponseConfigT for RequestResponseConfig {
	fn protocol_name(&self) -> &ProtocolName {
		&self.protocol_name
	}
}

enum Action {
	/// Send response.
	SendResponse {
		/// Request ID.
		request_id: RequestId,

		/// Response.
		response: Vec<u8>,
	},

	/// Reject request.
	RejectRequest {
		/// Request ID.
		request_id: RequestId,
	},
}

/// Request-response protocol.
///
/// TODO: explain in more detail
pub struct RequestResponseProtocol {
	/// Protocol name.
	protocol: ProtocolName,

	/// Handle to request-response protocol.
	handle: RequestResponseHandle,

	/// Inbound queue for sending received requests to protocol implementation in Polkadot SDK.
	inbound_queue: async_channel::Sender<IncomingRequest>,

	/// Pending responses.
	pending_inbound_responses: HashMap<RequestId, oneshot::Sender<Result<Vec<u8>, RequestFailure>>>,

	/// Pending outbound responses.
	pending_outbound_responses:
		FuturesUnordered<BoxFuture<'static, (RequestId, Result<OutgoingResponse, ()>)>>,

	/// Pending actions.
	pending_actions: VecDeque<Action>,
}

impl RequestResponseProtocol {
	/// Create new [`RequestResponseProtocol`].
	pub fn new(
		protocol: ProtocolName,
		handle: RequestResponseHandle,
		inbound_queue: async_channel::Sender<IncomingRequest>,
	) -> Self {
		Self {
			protocol,
			handle,
			inbound_queue,
			pending_actions: VecDeque::new(),
			pending_inbound_responses: HashMap::new(),
			pending_outbound_responses: FuturesUnordered::new(),
		}
	}

	/// Send `request` to `peer`.
	pub async fn send_request(
		&mut self,
		peer: PeerId,
		request: Vec<u8>,
		tx: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,
		connect: IfDisconnected,
	) -> Result<(), ()> {
		let dial_options = match connect {
			IfDisconnected::TryConnect => DialOptions::Dial,
			IfDisconnected::ImmediateError => DialOptions::Reject,
		};

		// sending the request only fails if the protocol has exited
		let request_id = self
			.handle
			.send_request(peer.into(), request, dial_options)
			.await
			.map_err(|_| ())?;
		self.pending_inbound_responses.insert(request_id, tx);

		Ok(())
	}
}

impl Stream for RequestResponseProtocol {
	type Item = void::Void;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		let this = Pin::into_inner(self);

		// handle pending actions which were queued in a previous iteration
		loop {
			let Some(action) = this.pending_actions.pop_front() else { break };

			if !this.handle.can_send() {
				this.pending_actions.push_front(action);
				break
			}

			// TODO: this is so ugly
			match action {
				Action::SendResponse { request_id, response } => {
					let future = this.handle.send_response(request_id, response);
					pin_mut!(future);

					match future.poll(cx) {
						Poll::Pending =>
							log::error!(target: LOG_TARGET, "channel has capacity but couldn't send"),
						Poll::Ready(Err(_)) => return Poll::Ready(None),
						Poll::Ready(Ok(())) => {},
					}
				},
				Action::RejectRequest { request_id } => {
					let future = this.handle.reject_request(request_id);
					pin_mut!(future);

					match future.poll(cx) {
						Poll::Pending =>
							log::error!(target: LOG_TARGET, "channel has capacity but couldn't send"),
						Poll::Ready(()) => {},
					}
				},
			}
		}

		// handle event's from litep2p's `RequestResponseHandle`.
		while let Poll::Ready(event) = Pin::new(&mut this.handle).poll_next(cx) {
			match event {
				None => return Poll::Ready(None),
				Some(event) => match event {
					RequestResponseEvent::RequestReceived {
						peer,
						fallback,
						request_id,
						request,
					} => {
						log::trace!(
							target: LOG_TARGET, "{:?}: request received for {:?}, (peer {:?}), request size {:?}",
							this.protocol,
							request_id,
							peer,
							request.len(),
						);
						let (tx, rx) = oneshot::channel();

						match this.inbound_queue.try_send(IncomingRequest {
							peer: peer.into(),
							payload: request,
							pending_response: tx,
						}) {
							Ok(_) => {
								this.pending_outbound_responses.push(Box::pin(async move {
									(request_id, rx.await.map(|response| response).map_err(|_| ()))
								}));
							},
							Err(_) => {
								log::trace!(
									target: LOG_TARGET, "{:?}: dropping request, inbound queue full",
									this.protocol,
								);

								match this.handle.can_send() {
									true => {
										let future = this.handle.reject_request(request_id);
										pin_mut!(future);

										match future.poll(cx) {
											Poll::Pending =>
												log::error!(target: LOG_TARGET, "channel has capacity but couldn't send"),
											Poll::Ready(()) => {},
										}
									},
									false => {
										this.pending_actions
											.push_back(Action::RejectRequest { request_id });
									},
								}
							},
						}
					},
					RequestResponseEvent::ResponseReceived { peer, request_id, response } =>
						match this.pending_inbound_responses.remove(&request_id) {
							None => log::warn!(
								target: LOG_TARGET,
								"{:?}: pending request for {request_id:?} (peer {peer:?}) doesn't exist",
								this.protocol,
							),
							Some(tx) => {
								// log::error!(
								// 	target: LOG_TARGET, "{:?}: response received for {:?}, (peer
								// {:?}), response size {:?}", 	this.protocol,
								// 	request_id,
								// 	peer,
								// 	response.len(),
								// );
								let _ = tx.send(Ok(response));
							},
						},
					RequestResponseEvent::RequestFailed { peer, request_id, error } => {
						// log::error!(target: LOG_TARGET, "request failed error: {error:?},
						// {request_id:?} {peer:?}");

						match this.pending_inbound_responses.remove(&request_id) {
							None => log::warn!(
								target: LOG_TARGET,
								"{:?}: pending failed request for {request_id:?} (peer {peer:?}) doesn't exist",
								this.protocol,
							),
							Some(tx) => {
								let error = match error {
									RequestResponseError::NotConnected =>
										RequestFailure::NotConnected,
									RequestResponseError::Rejected => RequestFailure::Refused,
									RequestResponseError::Timeout => RequestFailure::Refused,
									error => {
										log::error!(target: LOG_TARGET, "unknown error: {error:?}");
										todo!();
									},
								};
								let _ = tx.send(Err(error));
							},
						}
					},
				},
			}
		}

		// handle pending outbound responses
		while let Poll::Ready(Some((request_id, event))) =
			this.pending_outbound_responses.poll_next_unpin(cx)
		{
			match event {
				Err(_) => {
					log::error!(target: LOG_TARGET, "reject request");
					// todo!();
				},
				Ok(_) => {
					log::error!(target: LOG_TARGET, "send respones");
					// todo!();
				},
			}
		}

		Poll::Pending
	}
}

/// Request-response protocol set.
///
/// Only used to provide access to the actual protocol implementations and also responsible
/// for polling the protocols for events.
pub struct RequestResponseProtocolSet {
	/// Registered protocols.
	protocols: HashMap<ProtocolName, RequestResponseProtocol>,
}

impl RequestResponseProtocolSet {
	/// Create new [`RequestResponseProtocolSet`].
	pub fn new() -> Self {
		Self { protocols: HashMap::new() }
	}

	/// Register new request-response protocol.
	pub fn register_protocol(
		&mut self,
		protocol_name: ProtocolName,
		protocol: RequestResponseProtocol,
	) {
		self.protocols.insert(protocol_name, protocol);
	}

	/// Send `request` to `peer` over `protocol`.
	pub async fn send_request(
		&mut self,
		peer: PeerId,
		protocol: ProtocolName,
		request: Vec<u8>,
		tx: oneshot::Sender<Result<Vec<u8>, RequestFailure>>,
		connect: IfDisconnected,
	) -> Result<(), ()> {
		match self.protocols.get_mut(&protocol) {
			None => {
				log::warn!(target: LOG_TARGET, "tried to send request to {peer:?} over unregisted protocol {protocol:?}");
				return Err(())
			},
			Some(context) => {
				log::trace!(target: LOG_TARGET, "send request to {peer:?} over {protocol:?}, request size {}", request.len());
				context.send_request(peer, request, tx, connect).await
			},
		}
	}
}

impl Stream for RequestResponseProtocolSet {
	type Item = void::Void;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
		for protocol in self.protocols.values_mut() {
			match Pin::new(protocol).poll_next(cx) {
				Poll::Ready(Some(event)) => match event {},
				Poll::Ready(None) => return Poll::Ready(None),
				Poll::Pending => {},
			}
		}

		Poll::Pending
	}
}
