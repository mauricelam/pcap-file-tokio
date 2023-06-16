use tokio::io::AsyncRead;

use super::{PcapParser, RawPcapPacket};
use crate::errors::*;
use crate::pcap::{PcapHeader, PcapPacket};
use crate::read_buffer::ReadBuffer;


/// Reads a pcap from a reader.
///
/// # Example
///
/// ```rust,no_run
/// # tokio_test::block_on(async {
/// use tokio::fs::File;
///
/// use pcap_file_tokio::pcap::PcapReader;
///
/// let file_in = File::open("test.pcap").await.expect("Error opening file");
/// let mut pcap_reader = PcapReader::new(file_in).await.unwrap();
///
/// // Read test.pcap
/// while let Some(pkt) = pcap_reader.next_packet().await {
///     //Check if there is no error
///     let pkt = pkt.unwrap();
///
///     //Do something
/// }
/// # });
/// ```
#[derive(Debug)]
pub struct PcapReader<R: AsyncRead + Unpin> {
    parser: PcapParser,
    reader: ReadBuffer<R>,
}

impl<R: AsyncRead + Unpin> PcapReader<R> {
    /// Creates a new [`PcapReader`] from an existing reader.
    ///
    /// This function reads the global pcap header of the file to verify its integrity.
    ///
    /// The underlying reader must point to a valid pcap file/stream.
    ///
    /// # Errors
    /// The data stream is not in a valid pcap file format.
    ///
    /// The underlying data are not readable.
    pub async fn new(reader: R) -> Result<PcapReader<R>, PcapError> {
        let mut reader = ReadBuffer::new(reader);
        let parser = reader.parse_with(PcapParser::new).await?;

        Ok(PcapReader { parser, reader })
    }

    /// Consumes [`Self`], returning the wrapped reader.
    pub fn into_reader(self) -> R {
        self.reader.into_inner()
    }

    /// Returns the next [`PcapPacket`].
    pub async fn next_packet(&mut self) -> Option<Result<PcapPacket, PcapError>> {
        match self.reader.has_data_left().await {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with(|src|  self.parser.next_packet(src)).await)
                }
                else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the next [`RawPcapPacket`].
    pub async fn next_raw_packet(&mut self) -> Option<Result<RawPcapPacket, PcapError>> {
        match self.reader.has_data_left().await {
            Ok(has_data) => {
                if has_data {
                    Some(self.reader.parse_with(|src| self.parser.next_raw_packet(src)).await)
                }
                else {
                    None
                }
            },
            Err(e) => Some(Err(PcapError::IoError(e))),
        }
    }

    /// Returns the global header of the pcap.
    pub fn header(&self) -> PcapHeader {
        self.parser.header()
    }
}
