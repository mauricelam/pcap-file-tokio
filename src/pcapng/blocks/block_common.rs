//! Common block types.

use std::borrow::Cow;
use std::io::{Result as IoResult};

use byteorder::{ByteOrder, BigEndian, LittleEndian};
use derive_into_owned::IntoOwned;
use tokio::io::AsyncWrite;
use tokio_byteorder::{AsyncReadBytesExt, AsyncWriteBytesExt};

use super::enhanced_packet::EnhancedPacketBlock;
use super::interface_description::InterfaceDescriptionBlock;
use super::interface_statistics::InterfaceStatisticsBlock;
use super::name_resolution::NameResolutionBlock;
use super::packet::PacketBlock;
use super::section_header::SectionHeaderBlock;
use super::simple_packet::SimplePacketBlock;
use super::systemd_journal_export::SystemdJournalExportBlock;
use super::unknown::UnknownBlock;
use crate::errors::PcapError;
use crate::PcapResult;


/// Section header block type
pub const SECTION_HEADER_BLOCK: u32 = 0x0A0D0D0A;
/// Interface description block type
pub const INTERFACE_DESCRIPTION_BLOCK: u32 = 0x00000001;
/// Packet block type
pub const PACKET_BLOCK: u32 = 0x00000002;
/// Simple packet block type
pub const SIMPLE_PACKET_BLOCK: u32 = 0x00000003;
/// Name resolution block type
pub const NAME_RESOLUTION_BLOCK: u32 = 0x00000004;
/// Interface statistic block type
pub const INTERFACE_STATISTIC_BLOCK: u32 = 0x00000005;
/// Enhanced packet block type
pub const ENHANCED_PACKET_BLOCK: u32 = 0x00000006;
/// Systemd journal export block type
pub const SYSTEMD_JOURNAL_EXPORT_BLOCK: u32 = 0x00000009;

//   0               1               2               3
//   0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7 0 1 2 3 4 5 6 7
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                          Block Type                           |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Block Total Length                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  /                          Block Body                           /
//  /          /* variable length, aligned to 32 bits */            /
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//  |                      Block Total Length                       |
//  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
/// PcapNg Block
#[derive(Clone, Debug)]
pub struct RawBlock<'a> {
    /// Type field
    pub type_: u32,
    /// Initial length field
    pub initial_len: u32,
    /// Body of the block
    pub body: Cow<'a, [u8]>,
    /// Trailer length field
    pub trailer_len: u32,
}

impl<'a> RawBlock<'a> {
    /// Parses a borrowed [`RawBlock`] from a slice.
    pub async fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapError> {
        if slice.len() < 12 {
            return Err(PcapError::IncompleteBuffer);
        }

        let type_ = slice.read_u32::<B>().await.unwrap();

        // Special case for the section header because we don't know the endianness yet
        if type_ == SECTION_HEADER_BLOCK {
            let initial_len = slice.read_u32::<BigEndian>().await.unwrap();

            // Check the first field of the Section header to find the endianness
            let mut tmp_slice = slice;
            let magic = tmp_slice.read_u32::<BigEndian>().await.unwrap();
            let res = match magic {
                0x1A2B3C4D => inner_parse::<BigEndian>(slice, type_, initial_len).await,
                0x4D3C2B1A => inner_parse::<LittleEndian>(slice, type_, initial_len.swap_bytes()).await,
                _ => Err(PcapError::InvalidField("SectionHeaderBlock: invalid magic number")),
            };

            return res;
        }
        else {
            let initial_len = slice.read_u32::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?;
            return inner_parse::<B>(slice, type_, initial_len).await;
        };

        // Section Header parsing
        async fn inner_parse<B: ByteOrder>(slice: &[u8], type_: u32, initial_len: u32) -> Result<(&[u8], RawBlock<'_>), PcapError> {
            if (initial_len % 4) != 0 {
                return Err(PcapError::InvalidField("Block: (initial_len % 4) != 0"));
            }

            if initial_len < 12 {
                return Err(PcapError::InvalidField("Block: initial_len < 12"));
            }

            // Check if there is enough data for the body and the trailer_len
            if slice.len() < initial_len as usize - 8 {
                return Err(PcapError::IncompleteBuffer);
            }

            let body_len = initial_len - 12;
            let body = &slice[..body_len as usize];

            let mut rem = &slice[body_len as usize..];

            let trailer_len = rem.read_u32::<B>().await.unwrap();

            if initial_len != trailer_len {
                return Err(PcapError::InvalidField("Block: initial_length != trailer_length"));
            }

            let block = RawBlock { type_, initial_len, body: Cow::Borrowed(body), trailer_len };

            Ok((rem, block))
        }
    }

    /// Writes a [`RawBlock`] to a writer.
    ///
    /// Uses the endianness of the header.
    pub async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin>(&self, writer: &mut W) -> IoResult<usize> {
        writer.write_u32::<B>(self.type_).await?;
        writer.write_u32::<B>(self.initial_len).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &self.body[..]).await?;
        writer.write_u32::<B>(self.trailer_len).await?;

        Ok(self.body.len() + 6)
    }

    /// Tries to convert a [`RawBlock`] into a [`Block`]
    pub async fn try_into_block<B: ByteOrder + Send>(self) -> PcapResult<Block<'a>> {
        Block::try_from_raw_block::<B>(self).await
    }
}

/// PcapNg parsed blocks
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum Block<'a> {
    /// Section Header block
    SectionHeader(SectionHeaderBlock<'a>),
    /// Interface Description block
    InterfaceDescription(InterfaceDescriptionBlock<'a>),
    /// Packet block
    Packet(PacketBlock<'a>),
    /// Simple packet block
    SimplePacket(SimplePacketBlock<'a>),
    /// Name Resolution block
    NameResolution(NameResolutionBlock<'a>),
    /// Interface statistics block
    InterfaceStatistics(InterfaceStatisticsBlock<'a>),
    /// Enhanced packet block
    EnhancedPacket(EnhancedPacketBlock<'a>),
    /// Systemd Journal Export block
    SystemdJournalExport(SystemdJournalExportBlock<'a>),
    /// Unknown block
    Unknown(UnknownBlock<'a>),
}

impl<'a> Block<'a> {
    /// Parses a [`Block`] from a slice
    pub async fn from_slice<B: ByteOrder + Send>(slice: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapError> {
        let (rem, raw_block) = RawBlock::from_slice::<B>(slice).await?;
        let block = Self::try_from_raw_block::<B>(raw_block).await?;

        Ok((rem, block))
    }

    /// Writes a [`Block`] to a writer.
    pub async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        return match self {
            Self::SectionHeader(b) => inner_write_to::<B, _, W>(b, SECTION_HEADER_BLOCK, writer).await,
            Self::InterfaceDescription(b) => inner_write_to::<B, _, W>(b, INTERFACE_DESCRIPTION_BLOCK, writer).await,
            Self::Packet(b) => inner_write_to::<B, _, W>(b, PACKET_BLOCK, writer).await,
            Self::SimplePacket(b) => inner_write_to::<B, _, W>(b, SIMPLE_PACKET_BLOCK, writer).await,
            Self::NameResolution(b) => inner_write_to::<B, _, W>(b, NAME_RESOLUTION_BLOCK, writer).await,
            Self::InterfaceStatistics(b) => inner_write_to::<B, _, W>(b, INTERFACE_STATISTIC_BLOCK, writer).await,
            Self::EnhancedPacket(b) => inner_write_to::<B, _, W>(b, ENHANCED_PACKET_BLOCK, writer).await,
            Self::SystemdJournalExport(b) => inner_write_to::<B, _, W>(b, SYSTEMD_JOURNAL_EXPORT_BLOCK, writer).await,
            Self::Unknown(b) => inner_write_to::<B, _, W>(b, b.type_, writer).await,
        };

        async fn inner_write_to<'a, B: ByteOrder, BL: PcapNgBlock<'a>, W: AsyncWrite + Unpin + Send>(block: &BL, block_code: u32, writer: &mut W) -> IoResult<usize> {
            // Fake write to compute the data length
            let data_len = block.write_to::<B, _>(&mut tokio::io::sink()).await.unwrap();
            let pad_len = (4 - (data_len % 4)) % 4;

            let block_len = data_len + pad_len + 12;

            writer.write_u32::<B>(block_code).await?;
            writer.write_u32::<B>(block_len as u32).await?;
            block.write_to::<B, _>(writer).await?;
            tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;
            writer.write_u32::<B>(block_len as u32).await?;

            Ok(block_len)
        }
    }

    /// Tries to create a [`Block`] from a [`RawBlock`].
    ///
    /// The RawBlock must be Borrowed.
    pub async fn try_from_raw_block<B: ByteOrder + Send>(raw_block: RawBlock<'a>) -> Result<Block<'a>, PcapError> {
        let body = match raw_block.body {
            Cow::Borrowed(b) => b,
            _ => panic!("The raw block is not borrowed"),
        };

        match raw_block.type_ {
            SECTION_HEADER_BLOCK => {
                let (_, block) = SectionHeaderBlock::from_slice::<BigEndian>(body).await?;
                Ok(Block::SectionHeader(block))
            },
            INTERFACE_DESCRIPTION_BLOCK => {
                let (_, block) = InterfaceDescriptionBlock::from_slice::<B>(body).await?;
                Ok(Block::InterfaceDescription(block))
            },
            PACKET_BLOCK => {
                let (_, block) = PacketBlock::from_slice::<B>(body).await?;
                Ok(Block::Packet(block))
            },
            SIMPLE_PACKET_BLOCK => {
                let (_, block) = SimplePacketBlock::from_slice::<B>(body).await?;
                Ok(Block::SimplePacket(block))
            },
            NAME_RESOLUTION_BLOCK => {
                let (_, block) = NameResolutionBlock::from_slice::<B>(body).await?;
                Ok(Block::NameResolution(block))
            },
            INTERFACE_STATISTIC_BLOCK => {
                let (_, block) = InterfaceStatisticsBlock::from_slice::<B>(body).await?;
                Ok(Block::InterfaceStatistics(block))
            },
            ENHANCED_PACKET_BLOCK => {
                let (_, block) = EnhancedPacketBlock::from_slice::<B>(body).await?;
                Ok(Block::EnhancedPacket(block))
            },
            SYSTEMD_JOURNAL_EXPORT_BLOCK => {
                let (_, block) = SystemdJournalExportBlock::from_slice::<B>(body).await?;
                Ok(Block::SystemdJournalExport(block))
            },
            type_ => Ok(Block::Unknown(UnknownBlock::new(type_, raw_block.initial_len, body))),
        }
    }

    /// Tries to downcasts the current block into an [`EnhancedPacketBlock`]
    pub fn into_enhanced_packet(self) -> Option<EnhancedPacketBlock<'a>> {
        match self {
            Block::EnhancedPacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block into an [`InterfaceDescriptionBlock`]
    pub fn into_interface_description(self) -> Option<InterfaceDescriptionBlock<'a>> {
        match self {
            Block::InterfaceDescription(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcasts the current block into an [`InterfaceStatisticsBlock`]
    pub fn into_interface_statistics(self) -> Option<InterfaceStatisticsBlock<'a>> {
        match self {
            Block::InterfaceStatistics(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`NameResolutionBlock`], if possible
    pub fn into_name_resolution(self) -> Option<NameResolutionBlock<'a>> {
        match self {
            Block::NameResolution(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`PacketBlock`], if possible
    pub fn into_packet(self) -> Option<PacketBlock<'a>> {
        match self {
            Block::Packet(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`SectionHeaderBlock`], if possible
    pub fn into_section_header(self) -> Option<SectionHeaderBlock<'a>> {
        match self {
            Block::SectionHeader(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`SimplePacketBlock`], if possible
    pub fn into_simple_packet(self) -> Option<SimplePacketBlock<'a>> {
        match self {
            Block::SimplePacket(a) => Some(a),
            _ => None,
        }
    }

    /// Tries to downcast the current block into an [`SystemdJournalExportBlock`], if possible
    pub fn into_systemd_journal_export(self) -> Option<SystemdJournalExportBlock<'a>> {
        match self {
            Block::SystemdJournalExport(a) => Some(a),
            _ => None,
        }
    }
}


/// Common interface for the PcapNg blocks
#[async_trait::async_trait]
pub trait PcapNgBlock<'a> {
    /// Parse a new block from a slice
    async fn from_slice<B: ByteOrder + Send>(slice: &'a [u8]) -> Result<(&[u8], Self), PcapError>
    where
        Self: std::marker::Sized;

    /// Write the content of a block into a writer
    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize>;

    /// Convert a block into the [`Block`] enumeration
    fn into_block(self) -> Block<'a>;
}
