// SPDX-License-Identifier: MIT

use netlink_packet_core::{
    append_bytes, DecodeError, DefaultNla, Emitable, EncodeError, ErrorContext,
    Nla, NlasIterator, Parseable, ParseableParametrized,
};
use netlink_packet_generic::{GenlFamily, GenlHeader};

use crate::{
    address::MptcpPathManagerAddressAttr, limits::MptcpPathManagerLimitsAttr,
};

const MPTCP_PM_CMD_GET_ADDR: u8 = 3;
const MPTCP_PM_CMD_GET_LIMITS: u8 = 6;

const MPTCP_PM_ATTR_ADDR: u16 = 1;
const MPTCP_PM_ATTR_RCV_ADD_ADDRS: u16 = 2;
const MPTCP_PM_ATTR_SUBFLOWS: u16 = 3;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum MptcpPathManagerCmd {
    AddressGet,
    LimitsGet,
}

impl From<MptcpPathManagerCmd> for u8 {
    fn from(cmd: MptcpPathManagerCmd) -> Self {
        match cmd {
            MptcpPathManagerCmd::AddressGet => MPTCP_PM_CMD_GET_ADDR,
            MptcpPathManagerCmd::LimitsGet => MPTCP_PM_CMD_GET_LIMITS,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MptcpPathManagerAttr {
    Address(MptcpPathManagerAddressAttr),
    Limits(MptcpPathManagerLimitsAttr),
    Other(DefaultNla),
}

impl Nla for MptcpPathManagerAttr {
    fn kind(&self) -> u16 {
        match self {
            Self::Address(attr) => attr.kind(),
            Self::Limits(attr) => attr.kind(),
            Self::Other(attr) => attr.kind(),
        }
    }

    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        match self {
            Self::Address(attr) => attr.emit_value(out)?,
            Self::Limits(attr) => attr.emit_value(out)?,
            Self::Other(attr) => append_bytes(out, attr.value()),
        }
        Ok(())
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct MptcpPathManagerMessage {
    pub cmd: MptcpPathManagerCmd,
    pub nlas: Vec<MptcpPathManagerAttr>,
}

impl GenlFamily for MptcpPathManagerMessage {
    fn family_name() -> &'static str {
        "mptcp_pm"
    }

    fn version(&self) -> u8 {
        1
    }

    fn command(&self) -> u8 {
        self.cmd.into()
    }
}

impl MptcpPathManagerMessage {
    pub fn new_address_get() -> Self {
        MptcpPathManagerMessage {
            cmd: MptcpPathManagerCmd::AddressGet,
            nlas: vec![],
        }
    }

    pub fn new_limits_get() -> Self {
        MptcpPathManagerMessage {
            cmd: MptcpPathManagerCmd::LimitsGet,
            nlas: vec![],
        }
    }
}

impl Emitable for MptcpPathManagerMessage {
    fn emit_value(&self, out: &mut Vec<u8>) -> Result<(), EncodeError> {
        self.nlas.as_slice().emit(out)
    }
}

fn parse_nlas(buffer: &[u8]) -> Result<Vec<MptcpPathManagerAttr>, DecodeError> {
    let mut nlas = Vec::new();
    for nla in NlasIterator::new(buffer)? {
        match nla.kind() {
            MPTCP_PM_ATTR_ADDR => {
                for addr_nla in NlasIterator::new(nla.value())? {
                    nlas.push(MptcpPathManagerAttr::Address(
                        MptcpPathManagerAddressAttr::parse(&addr_nla)
                            .context("Failed to parse MPTCP_PM_ATTR_ADDR")?,
                    ))
                }
            }
            MPTCP_PM_ATTR_RCV_ADD_ADDRS => {
                nlas.push(MptcpPathManagerAttr::Limits(
                    MptcpPathManagerLimitsAttr::parse(&nla).context(
                        "Failed to parse MPTCP_PM_ATTR_RCV_ADD_ADDRS",
                    )?,
                ))
            }
            MPTCP_PM_ATTR_SUBFLOWS => nlas.push(MptcpPathManagerAttr::Limits(
                MptcpPathManagerLimitsAttr::parse(&nla)
                    .context("Failed to parse MPTCP_PM_ATTR_RCV_ADD_ADDRS")?,
            )),
            _ => nlas.push(MptcpPathManagerAttr::Other(
                DefaultNla::parse(&nla)
                    .context("invalid NLA (unknown kind)")?,
            )),
        }
    }
    Ok(nlas)
}

impl ParseableParametrized<[u8], GenlHeader> for MptcpPathManagerMessage {
    fn parse_with_param(
        buffer: &[u8],
        header: GenlHeader,
    ) -> Result<Self, DecodeError> {
        Ok(match header.cmd {
            MPTCP_PM_CMD_GET_ADDR => Self {
                cmd: MptcpPathManagerCmd::AddressGet,
                nlas: parse_nlas(buffer)?,
            },
            MPTCP_PM_CMD_GET_LIMITS => Self {
                cmd: MptcpPathManagerCmd::LimitsGet,
                nlas: parse_nlas(buffer)?,
            },
            cmd => {
                return Err(DecodeError::from(format!(
                    "Unsupported mptcp reply command: {cmd}"
                )))
            }
        })
    }
}
