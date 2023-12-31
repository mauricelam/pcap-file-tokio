use byteorder::{BigEndian, LittleEndian, ByteOrder};

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::blocks::{INTERFACE_DESCRIPTION_BLOCK, SECTION_HEADER_BLOCK};
use crate::errors::PcapError;
use crate::Endianness;


/// Parses a PcapNg from a slice of bytes.
///
/// You can match on [`PcapError::IncompleteBuffer`] to know if the parser need more data.
///
/// # Example
/// ```rust,no_run
/// # tokio_test::block_on(async {
/// use tokio::fs::File;
///
/// use pcap_file_tokio::pcapng::PcapNgParser;
/// use pcap_file_tokio::PcapError;
///
/// let pcap = tokio::fs::read("test.pcapng").await.expect("Error reading file");
/// let mut src = &pcap[..];
///
/// let (rem, mut pcapng_parser) = PcapNgParser::new(src).await.unwrap();
/// src = rem;
///
/// loop {
///     match pcapng_parser.next_block(src).await {
///         Ok((rem, block)) => {
///             // Do something
///
///             // Don't forget to update src
///             src = rem;
///         },
///         Err(PcapError::IncompleteBuffer) => {
///             // Load more data into src
///         },
///         Err(_) => {
///             // Handle parsing error
///         },
///     }
/// }
/// # });
/// ```
pub struct PcapNgParser {
    section: SectionHeaderBlock<'static>,
    interfaces: Vec<InterfaceDescriptionBlock<'static>>,
}

impl PcapNgParser {
    /// Creates a new [`PcapNgParser`].
    ///
    /// Parses the first block which must be a valid SectionHeaderBlock.
    pub async fn new(src: &[u8]) -> Result<(&[u8], Self), PcapError> {
        // Always use BigEndian here because we can't know the SectionHeaderBlock endianness
        let (rem, section) = Block::from_slice::<BigEndian>(src).await?;
        let section = match section {
            Block::SectionHeader(section) => section.into_owned(),
            _ => return Err(PcapError::InvalidField("PcapNg: SectionHeader invalid or missing")),
        };

        let parser = PcapNgParser { section, interfaces: vec![] };

        Ok((rem, parser))
    }

    /// Returns the remainder and the next [`Block`].
    pub async fn next_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], Block<'a>), PcapError> {
        // Read next Block
        match self.section.endianness {
            Endianness::Big => {
                let (rem, raw_block) = self.next_raw_block_inner::<BigEndian>(src).await?;
                let block = raw_block.try_into_block::<BigEndian>().await?;
                Ok((rem, block))
            },
            Endianness::Little => {
                let (rem, raw_block) = self.next_raw_block_inner::<LittleEndian>(src).await?;
                let block = raw_block.try_into_block::<LittleEndian>().await?;
                Ok((rem, block))
            },
        }
    }

    /// Returns the remainder and the next [`RawBlock`].
    pub async fn next_raw_block<'a>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapError> {
        // Read next Block
        match self.section.endianness {
            Endianness::Big => self.next_raw_block_inner::<BigEndian>(src).await,
            Endianness::Little => self.next_raw_block_inner::<LittleEndian>(src).await,
        }
    }

    /// Inner function to parse the next raw block.
    async fn next_raw_block_inner<'a, B: ByteOrder + Send>(&mut self, src: &'a [u8]) -> Result<(&'a [u8], RawBlock<'a>), PcapError> {
        let (rem, raw_block) = RawBlock::from_slice::<B>(src).await?;

        match raw_block.type_ {
            SECTION_HEADER_BLOCK => {
                self.section = raw_block.clone().try_into_block::<B>().await?.into_owned().into_section_header().unwrap();
                self.interfaces.clear();
            },
            INTERFACE_DESCRIPTION_BLOCK => {
                let interface = raw_block.clone().try_into_block::<B>().await?.into_owned().into_interface_description().unwrap();
                self.interfaces.push(interface);
            },
            _ => {},
        }

        Ok((rem, raw_block))
    }

    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        &self.section
    }

    /// Returns all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        &self.interfaces[..]
    }

    /// Returns the [`InterfaceDescriptionBlock`] corresponding to the given packet.
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces.get(packet.interface_id as usize)
    }
}
