use tokio::io::AsyncWrite;

use byteorder::{BigEndian, LittleEndian};

use super::RawPcapPacket;
use crate::errors::*;
use crate::pcap::{PcapHeader, PcapPacket};
use crate::{Endianness, TsResolution};


/// Writes a pcap to a writer.
///
/// # Example
/// ```rust,no_run
/// # tokio_test::block_on(async {
/// use tokio::fs::File;
///
/// use pcap_file_tokio::pcap::{PcapReader, PcapWriter};
///
/// let file_in = File::open("test.pcap").await.expect("Error opening file");
/// let mut pcap_reader = PcapReader::new(file_in).await.unwrap();
///
/// let file_out = File::create("out.pcap").await.expect("Error creating file out");
/// let mut pcap_writer = PcapWriter::new(file_out).await.expect("Error writing file");
///
/// // Read test.pcap
/// while let Some(pkt) = pcap_reader.next_packet().await {
///     //Check if there is no error
///     let pkt = pkt.unwrap();
///
///     //Write each packet of test.pcap in out.pcap
///     pcap_writer.write_packet(&pkt).await.unwrap();
/// }
/// # });
/// ```
#[derive(Debug)]
pub struct PcapWriter<W: AsyncWrite> {
    endianness: Endianness,
    snaplen: u32,
    ts_resolution: TsResolution,
    writer: W,
}

impl<W: AsyncWrite + Unpin> PcapWriter<W> {
    /// Creates a new [`PcapWriter`] from an existing writer.
    ///
    /// Defaults to the native endianness of the CPU.
    ///
    /// Writes this default global pcap header to the file:
    /// ```rust, ignore
    /// PcapHeader {
    ///     version_major: 2,
    ///     version_minor: 4,
    ///     ts_correction: 0,
    ///     ts_accuracy: 0,
    ///     snaplen: 65535,
    ///     datalink: DataLink::ETHERNET,
    ///     ts_resolution: TsResolution::MicroSecond,
    ///     endianness: Endianness::Native
    /// };
    /// ```
    ///
    /// # Errors
    /// The writer can't be written to.
    pub async fn new(writer: W) -> PcapResult<PcapWriter<W>> {
        let header = PcapHeader { endianness: Endianness::native(), ..Default::default() };

        PcapWriter::with_header(writer, header).await
    }

    /// Creates a new [`PcapWriter`] from an existing writer with a user defined [`PcapHeader`].
    ///
    /// It also writes the pcap header to the file.
    ///
    /// # Errors
    /// The writer can't be written to.
    pub async fn with_header(mut writer: W, header: PcapHeader) -> PcapResult<PcapWriter<W>> {
        header.write_to(&mut writer).await?;

        Ok(PcapWriter {
            endianness: header.endianness,
            snaplen: header.snaplen,
            ts_resolution: header.ts_resolution,
            writer,
        })
    }

    /// Consumes [`Self`], returning the wrapped writer.
    pub fn into_writer(self) -> W {
        self.writer
    }

    /// Writes a [`PcapPacket`].
    pub async fn write_packet(&mut self, packet: &PcapPacket<'_>) -> PcapResult<usize> {
        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer, self.ts_resolution, self.snaplen).await,
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer, self.ts_resolution, self.snaplen).await,
        }
    }

    /// Writes a [`RawPcapPacket`].
    pub async fn write_raw_packet(&mut self, packet: &RawPcapPacket<'_>) -> PcapResult<usize> {
        match self.endianness {
            Endianness::Big => packet.write_to::<_, BigEndian>(&mut self.writer).await,
            Endianness::Little => packet.write_to::<_, LittleEndian>(&mut self.writer).await,
        }
    }

    /// Returns the endianess used by the writer.
    pub fn endianness(&self) -> Endianness {
        self.endianness
    }

    /// Returns the snaplen used by the writer, i.e. an unsigned value indicating the maximum number of octets captured
    /// from each packet.
    pub fn snaplen(&self) -> u32 {
        self.snaplen
    }

    /// Returns the timestamp resolution of the writer.
    pub fn ts_resolution(&self) -> TsResolution {
        self.ts_resolution
    }
}
