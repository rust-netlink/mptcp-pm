// SPDX-License-Identifier: MIT

use std::io;

use futures::channel::mpsc::UnboundedReceiver;
use genetlink::message::RawGenlMessage;
use netlink_packet_core::NetlinkMessage;
use netlink_proto::Connection;
use netlink_sys::{AsyncSocket, SocketAddr};

use crate::MptcpPathManagerHandle;

#[cfg(feature = "tokio_socket")]
#[allow(clippy::type_complexity)]
pub fn new_connection() -> io::Result<(
    Connection<RawGenlMessage>,
    MptcpPathManagerHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)> {
    new_connection_with_socket()
}

#[allow(clippy::type_complexity)]
pub fn new_connection_with_socket<S>() -> io::Result<(
    Connection<RawGenlMessage, S>,
    MptcpPathManagerHandle,
    UnboundedReceiver<(NetlinkMessage<RawGenlMessage>, SocketAddr)>,
)>
where
    S: AsyncSocket,
{
    let (conn, handle, messages) = genetlink::new_connection_with_socket()?;
    Ok((conn, MptcpPathManagerHandle::new(handle), messages))
}
