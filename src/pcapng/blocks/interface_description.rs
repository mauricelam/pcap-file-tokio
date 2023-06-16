#![allow(clippy::cast_lossless)]

//! Interface Description Block (IDB).

use std::borrow::Cow;
use std::io::Result as IoResult;

use byteorder::ByteOrder;
use derive_into_owned::IntoOwned;
use tokio::io::AsyncWrite;
use tokio_byteorder::{AsyncReadBytesExt, AsyncWriteBytesExt};

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CustomBinaryOption, CustomUtf8Option, PcapNgOption, UnknownOption, WriteOptTo};
use crate::errors::PcapError;
use crate::DataLink;


/// An Interface Description Block (IDB) is the container for information describing an interface
/// on which packet data is captured.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct InterfaceDescriptionBlock<'a> {
    /// A value that defines the link layer type of this interface.
    /// 
    /// The list of Standardized Link Layer Type codes is available in the
    /// [tcpdump.org link-layer header types registry.](http://www.tcpdump.org/linktypes.html).
    pub linktype: DataLink,

    /// Maximum number of octets captured from each packet.
    /// 
    /// The portion of each packet that exceeds this value will not be stored in the file.
    /// A value of zero indicates no limit.
    pub snaplen: u32,

    /// Options
    pub options: Vec<InterfaceDescriptionOption<'a>>,
}

#[async_trait::async_trait]
impl<'a> PcapNgBlock<'a> for InterfaceDescriptionBlock<'a> {
    async fn from_slice<B: ByteOrder + Send>(mut slice: &'a [u8]) -> Result<(&'a [u8], Self), PcapError> {
        if slice.len() < 8 {
            return Err(PcapError::InvalidField("InterfaceDescriptionBlock: block length < 8"));
        }

        let linktype = (slice.read_u16::<B>().await.unwrap() as u32).into();

        let reserved = slice.read_u16::<B>().await.unwrap();
        if reserved != 0 {
            return Err(PcapError::InvalidField("InterfaceDescriptionBlock: reserved != 0"));
        }

        let snaplen = slice.read_u32::<B>().await.unwrap();
        let (slice, options) = InterfaceDescriptionOption::opts_from_slice::<B>(slice).await?;

        let block = InterfaceDescriptionBlock { linktype, snaplen, options };

        Ok((slice, block))
    }

    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(u32::from(self.linktype) as u16).await?;
        writer.write_u16::<B>(0).await?;
        writer.write_u32::<B>(self.snaplen).await?;

        let opt_len = InterfaceDescriptionOption::write_opts_to::<B, W>(&self.options, writer).await?;
        Ok(8 + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::InterfaceDescription(self)
    }
}

impl InterfaceDescriptionBlock<'static> {
    /// Creates a new [`InterfaceDescriptionBlock`]
    pub fn new(linktype: DataLink, snaplen: u32) -> Self {
        Self { linktype, snaplen, options: vec![] }
    }
}

/// The Interface Description Block (IDB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum InterfaceDescriptionOption<'a> {
    /// The opt_comment option is a UTF-8 string containing human-readable comment text
    /// that is associated to the current block.
    Comment(Cow<'a, str>),

    /// The if_name option is a UTF-8 string containing the name of the device used to capture data.
    IfName(Cow<'a, str>),

    /// The if_description option is a UTF-8 string containing the description of the device used to capture data.
    IfDescription(Cow<'a, str>),

    /// The if_IPv4addr option is an IPv4 network address and corresponding netmask for the interface.
    IfIpv4Addr(Cow<'a, [u8]>),

    /// The if_IPv6addr option is an IPv6 network address and corresponding prefix length for the interface.
    IfIpv6Addr(Cow<'a, [u8]>),

    /// The if_MACaddr option is the Interface Hardware MAC address (48 bits), if available.
    IfMacAddr(Cow<'a, [u8]>),

    /// The if_EUIaddr option is the Interface Hardware EUI address (64 bits), if available.
    IfEuIAddr(u64),

    /// The if_speed option is a 64-bit number for the Interface speed (in bits per second).
    IfSpeed(u64),

    /// The if_tsresol option identifies the resolution of timestamps.
    IfTsResol(u8),

    /// The if_tzone option identifies the time zone for GMT support.
    IfTzone(u32),

    /// The if_filter option identifies the filter (e.g. "capture only TCP traffic") used to capture traffic.
    IfFilter(Cow<'a, [u8]>),

    /// The if_os option is a UTF-8 string containing the name of the operating system
    /// of the machine in which this interface is installed.
    IfOs(Cow<'a, str>),

    /// The if_fcslen option is an 8-bit unsigned integer value that specifies
    /// the length of the Frame Check Sequence (in bits) for this interface.
    IfFcsLen(u8),

    /// The if_tsoffset option is a 64-bit integer value that specifies an offset (in seconds)
    /// that must be added to the timestamp of each packet to obtain the absolute timestamp of a packet.
    IfTsOffset(u64),

    /// The if_hardware option is a UTF-8 string containing the description of the interface hardware.
    IfHardware(Cow<'a, str>),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

#[async_trait::async_trait]
impl<'a> PcapNgOption<'a> for InterfaceDescriptionOption<'a> {
    async fn from_slice<B: ByteOrder + Send>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => InterfaceDescriptionOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => InterfaceDescriptionOption::IfName(Cow::Borrowed(std::str::from_utf8(slice)?)),
            3 => InterfaceDescriptionOption::IfDescription(Cow::Borrowed(std::str::from_utf8(slice)?)),
            4 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfIpv4Addr length != 8"));
                }
                InterfaceDescriptionOption::IfIpv4Addr(Cow::Borrowed(slice))
            },
            5 => {
                if slice.len() != 17 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfIpv6Addr length != 17"));
                }
                InterfaceDescriptionOption::IfIpv6Addr(Cow::Borrowed(slice))
            },
            6 => {
                if slice.len() != 6 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfMacAddr length != 6"));
                }
                InterfaceDescriptionOption::IfMacAddr(Cow::Borrowed(slice))
            },
            7 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfEuIAddr length != 8"));
                }
                InterfaceDescriptionOption::IfEuIAddr(slice.read_u64::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            8 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfSpeed length != 8"));
                }
                InterfaceDescriptionOption::IfSpeed(slice.read_u64::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            9 => {
                if slice.len() != 1 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfTsResol length != 1"));
                }
                InterfaceDescriptionOption::IfTsResol(slice.read_u8().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            10 => {
                if slice.len() != 1 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfTzone length != 1"));
                }
                InterfaceDescriptionOption::IfTzone(slice.read_u32::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            11 => {
                if slice.is_empty() {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfFilter is empty"));
                }
                InterfaceDescriptionOption::IfFilter(Cow::Borrowed(slice))
            },
            12 => InterfaceDescriptionOption::IfOs(Cow::Borrowed(std::str::from_utf8(slice)?)),
            13 => {
                if slice.len() != 1 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfFcsLen length != 1"));
                }
                InterfaceDescriptionOption::IfFcsLen(slice.read_u8().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            14 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("InterfaceDescriptionOption: IfTsOffset length != 8"));
                }
                InterfaceDescriptionOption::IfTsOffset(slice.read_u64::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            15 => InterfaceDescriptionOption::IfHardware(Cow::Borrowed(std::str::from_utf8(slice)?)),

            2988 | 19372 => InterfaceDescriptionOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice).await?),
            2989 | 19373 => InterfaceDescriptionOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice).await?),

            _ => InterfaceDescriptionOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            InterfaceDescriptionOption::Comment(a) => a.write_opt_to::<B, W>(1, writer).await,
            InterfaceDescriptionOption::IfName(a) => a.write_opt_to::<B, W>(2, writer).await,
            InterfaceDescriptionOption::IfDescription(a) => a.write_opt_to::<B, W>(3, writer).await,
            InterfaceDescriptionOption::IfIpv4Addr(a) => a.write_opt_to::<B, W>(4, writer).await,
            InterfaceDescriptionOption::IfIpv6Addr(a) => a.write_opt_to::<B, W>(5, writer).await,
            InterfaceDescriptionOption::IfMacAddr(a) => a.write_opt_to::<B, W>(6, writer).await,
            InterfaceDescriptionOption::IfEuIAddr(a) => a.write_opt_to::<B, W>(7, writer).await,
            InterfaceDescriptionOption::IfSpeed(a) => a.write_opt_to::<B, W>(8, writer).await,
            InterfaceDescriptionOption::IfTsResol(a) => a.write_opt_to::<B, W>(9, writer).await,
            InterfaceDescriptionOption::IfTzone(a) => a.write_opt_to::<B, W>(10, writer).await,
            InterfaceDescriptionOption::IfFilter(a) => a.write_opt_to::<B, W>(11, writer).await,
            InterfaceDescriptionOption::IfOs(a) => a.write_opt_to::<B, W>(12, writer).await,
            InterfaceDescriptionOption::IfFcsLen(a) => a.write_opt_to::<B, W>(13, writer).await,
            InterfaceDescriptionOption::IfTsOffset(a) => a.write_opt_to::<B, W>(14, writer).await,
            InterfaceDescriptionOption::IfHardware(a) => a.write_opt_to::<B, W>(15, writer).await,
            InterfaceDescriptionOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer).await,
            InterfaceDescriptionOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer).await,
            InterfaceDescriptionOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer).await,
        }
    }
}
