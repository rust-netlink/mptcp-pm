// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, append_u32, parse_u32, DecodeError, DefaultNla, EncodeError,
    ErrorContext, Nla, NlaBuffer, Parseable,
};

const MPTCP_PM_ATTR_RCV_ADD_ADDRS: u16 = 2;
const MPTCP_PM_ATTR_SUBFLOWS: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MptcpPathManagerLimitsAttr {
    RcvAddAddrs(u32),
    Subflows(u32),
    Other(DefaultNla),
}

impl Nla for MptcpPathManagerLimitsAttr {
    fn kind(&self) -> u16 {
        match self {
            Self::RcvAddAddrs(_) => MPTCP_PM_ATTR_RCV_ADD_ADDRS,
            Self::Subflows(_) => MPTCP_PM_ATTR_SUBFLOWS,
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::RcvAddAddrs(d) | Self::Subflows(d) => append_u32(out, *d),
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }
}

impl<'a> Parseable<NlaBuffer<'a>> for MptcpPathManagerLimitsAttr {
    fn parse(buf: &NlaBuffer<'a>) -> Result<Self, DecodeError> {
        let payload = buf.value();
        Ok(match buf.kind() {
            MPTCP_PM_ATTR_RCV_ADD_ADDRS => Self::RcvAddAddrs(
                parse_u32(payload)
                    .context("Invalid MPTCP_PM_ATTR_RCV_ADD_ADDRS value")?,
            ),
            MPTCP_PM_ATTR_SUBFLOWS => Self::Subflows(
                parse_u32(payload)
                    .context("Invalid MPTCP_PM_ATTR_SUBFLOWS value")?,
            ),
            _ => Self::Other(
                DefaultNla::parse(buf).context("invalid NLA (unknown kind)")?,
            ),
        })
    }
}
