//! Enhanced Packet Block (EPB).

use std::borrow::Cow;
use std::io::Result as IoResult;
use std::time::Duration;

use byteorder::ByteOrder;
use derive_into_owned::IntoOwned;
use tokio::io::AsyncWrite;
use tokio_byteorder::{AsyncWriteBytesExt, AsyncReadBytesExt};

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CustomBinaryOption, CustomUtf8Option, PcapNgOption, UnknownOption, WriteOptTo};
use crate::errors::PcapError;


/// An Enhanced Packet Block (EPB) is the standard container for storing the packets coming from the network.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct EnhancedPacketBlock<'a> {
    /// It specifies the interface this packet comes from.
    /// 
    /// The correct interface will be the one whose Interface Description Block
    /// (within the current Section of the file) is identified by the same number of this field.
    pub interface_id: u32,

    /// Number of units of time that have elapsed since 1970-01-01 00:00:00 UTC.
    pub timestamp: Duration,

    /// Actual length of the packet when it was transmitted on the network.
    pub original_len: u32,

    /// The data coming from the network, including link-layer headers.
    pub data: Cow<'a, [u8]>,

/// Options
    pub options: Vec<EnhancedPacketOption<'a>>,
}

#[async_trait::async_trait]
impl<'a> PcapNgBlock<'a> for EnhancedPacketBlock<'a> {
    async fn from_slice<B: ByteOrder + Send>(mut slice: &'a [u8]) -> Result<(&'a [u8], EnhancedPacketBlock<'a>), PcapError> {
        if slice.len() < 20 {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: block length length < 20"));
        }

        let interface_id = slice.read_u32::<B>().await.unwrap();
        let timestamp_high = slice.read_u32::<B>().await.unwrap() as u64;
        let timestamp_low = slice.read_u32::<B>().await.unwrap() as u64;
        let timestamp = (timestamp_high << 32) + timestamp_low;
        let captured_len = slice.read_u32::<B>().await.unwrap();
        let original_len = slice.read_u32::<B>().await.unwrap();

        let pad_len = (4 - (captured_len as usize % 4)) % 4;
        let tot_len = captured_len as usize + pad_len;

        if slice.len() < tot_len {
            return Err(PcapError::InvalidField("EnhancedPacketBlock: captured_len + padding > block length"));
        }

        let data = &slice[..captured_len as usize];
        slice = &slice[tot_len..];

        let (slice, options) = EnhancedPacketOption::opts_from_slice::<B>(slice).await?;
        let block = EnhancedPacketBlock {
            interface_id,
            timestamp: Duration::from_nanos(timestamp),
            original_len,
            data: Cow::Borrowed(data),
            options,
        };

        Ok((slice, block))
    }

    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        let pad_len = (4 - (&self.data.len() % 4)) % 4;

        writer.write_u32::<B>(self.interface_id).await?;

        let timestamp = self.timestamp.as_nanos();
        let timestamp_high = (timestamp >> 32) as u32;
        writer.write_u32::<B>(timestamp_high).await?;
        let timestamp_low = (timestamp & 0xFFFFFFFF) as u32;
        writer.write_u32::<B>(timestamp_low).await?;

        writer.write_u32::<B>(self.data.len() as u32).await?;
        writer.write_u32::<B>(self.original_len).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &self.data).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        let opt_len = EnhancedPacketOption::write_opts_to::<B, W>(&self.options, writer).await?;

        Ok(20 + &self.data.len() + pad_len + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::EnhancedPacket(self)
    }
}

/// The Enhanced Packet Block (EPB) options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum EnhancedPacketOption<'a> {
    /// Comment associated with the current block
    Comment(Cow<'a, str>),

    /// 32-bit flags word containing link-layer information.
    Flags(u32),

    /// Contains a hash of the packet.
    Hash(Cow<'a, [u8]>),

    /// 64-bit integer value specifying the number of packets lost
    /// (by the interface and the operating system) between this packet and the preceding one for
    /// the same interface or, for the first packet for an interface, between this packet
    /// and the start of the capture process.
    DropCount(u64),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

#[async_trait::async_trait]
impl<'a> PcapNgOption<'a> for EnhancedPacketOption<'a> {
    async fn from_slice<B: ByteOrder + Send>(code: u16, length: u16, mut slice: &'a [u8]) -> Result<Self, PcapError> {
        let opt = match code {
            1 => EnhancedPacketOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => {
                if slice.len() != 4 {
                    return Err(PcapError::InvalidField("EnhancedPacketOption: Flags length != 4"));
                }
                EnhancedPacketOption::Flags(slice.read_u32::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },
            3 => EnhancedPacketOption::Hash(Cow::Borrowed(slice)),
            4 => {
                if slice.len() != 8 {
                    return Err(PcapError::InvalidField("EnhancedPacketOption: DropCount length != 8"));
                }
                EnhancedPacketOption::DropCount(slice.read_u64::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?)
            },

            2988 | 19372 => EnhancedPacketOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice).await?),
            2989 | 19373 => EnhancedPacketOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice).await?),

            _ => EnhancedPacketOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            EnhancedPacketOption::Comment(a) => a.write_opt_to::<B, W>(1, writer).await,
            EnhancedPacketOption::Flags(a) => a.write_opt_to::<B, W>(2, writer).await,
            EnhancedPacketOption::Hash(a) => a.write_opt_to::<B, W>(3, writer).await,
            EnhancedPacketOption::DropCount(a) => a.write_opt_to::<B, W>(4, writer).await,
            EnhancedPacketOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer).await,
            EnhancedPacketOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer).await,
            EnhancedPacketOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer).await,
        }
    }
}
