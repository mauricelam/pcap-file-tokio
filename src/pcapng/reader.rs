use tokio::io::AsyncRead;

use super::blocks::block_common::{Block, RawBlock};
use super::blocks::enhanced_packet::EnhancedPacketBlock;
use super::blocks::interface_description::InterfaceDescriptionBlock;
use super::blocks::section_header::SectionHeaderBlock;
use super::PcapNgParser;
use crate::errors::PcapError;
use crate::read_buffer::ReadBuffer;

/// Reads a PcapNg from a reader.
///
/// # Example
/// ```rust,no_run
/// # tokio_test::block_on(async {
/// use tokio::fs::File;
///
/// use pcap_file_tokio::pcapng::PcapNgReader;
///
/// let file_in = File::open("test.pcapng").await.expect("Error opening file");
/// let mut pcapng_reader = PcapNgReader::new(file_in).await.unwrap();
///
/// // Read test.pcapng
/// while let Some(block) = pcapng_reader.next_block().await {
///     //Check if there is no error
///     let block = block.unwrap();
///
///     //Do something
/// }
/// # });
/// ```
pub struct PcapNgReader<R: AsyncRead + Unpin> {
    parser: PcapNgParser,
    reader: ReadBuffer<R>,
}

impl<R: AsyncRead + Unpin> PcapNgReader<R> {
    /// Creates a new [`PcapNgReader`] from a reader.
    ///
    /// Parses the first block which must be a valid SectionHeaderBlock.
    pub async fn new(reader: R) -> Result<PcapNgReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapNgParser::new).await?;
        Ok(Self { parser, reader })
    }

    /// Returns the next [`Block`].
    pub async fn next_block(&mut self) -> Option<Result<Block, PcapError>> {
        match self.reader.has_data_left().await {
            Ok(has_data) => {
                if has_data {
                    Some(
                        self.reader
                            .parse_with_context(&mut self.parser, |parser, src| async { (parser.next_block(src).await, parser) })
                            .await,
                    )
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the next [`RawBlock`].
    pub async fn next_raw_block(&mut self) -> Option<Result<RawBlock, PcapError>> {
        match self.reader.has_data_left().await {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with_context(&mut self.parser, |parser, src| async { (parser.next_raw_block(src).await, parser) }).await)
                } else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the current [`SectionHeaderBlock`].
    pub fn section(&self) -> &SectionHeaderBlock<'static> {
        self.parser.section()
    }

    /// Returns all the current [`InterfaceDescriptionBlock`].
    pub fn interfaces(&self) -> &[InterfaceDescriptionBlock<'static>] {
        self.parser.interfaces()
    }

    /// Returns the [`InterfaceDescriptionBlock`] corresponding to the given packet
    pub fn packet_interface(&self, packet: &EnhancedPacketBlock) -> Option<&InterfaceDescriptionBlock> {
        self.interfaces().get(packet.interface_id as usize)
    }

    /// Consumes the [`Self`], returning the wrapped reader.
    pub fn into_inner(self) -> R {
        self.reader.into_inner()
    }

    /// Gets a reference to the wrapped reader.
    pub fn get_ref(&self) -> &R {
        self.reader.get_ref()
    }
}
