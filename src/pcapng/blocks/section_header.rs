//! Section Header Block.

use std::borrow::Cow;
use std::io::Result as IoResult;

use byteorder::{ByteOrder, BigEndian, LittleEndian};
use derive_into_owned::IntoOwned;
use tokio::io::AsyncWrite;
use tokio_byteorder::{AsyncReadBytesExt, AsyncWriteBytesExt};

use super::block_common::{Block, PcapNgBlock};
use super::opt_common::{CustomBinaryOption, CustomUtf8Option, PcapNgOption, UnknownOption, WriteOptTo};
use crate::errors::PcapError;
use crate::Endianness;


/// Section Header Block: it defines the most important characteristics of the capture file.
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct SectionHeaderBlock<'a> {
    /// Endianness of the section.
    pub endianness: Endianness,

    /// Major version of the format.
    /// Current value is 1.
    pub major_version: u16,

    /// Minor version of the format.
    /// Current value is 0.
    pub minor_version: u16,

    /// Length in bytes of the following section excluding this block.
    ///
    /// This block can be used to skip the section for faster navigation in
    /// large files. Length of -1i64 means that the length is unspecified.
    pub section_length: i64,

    /// Options
    pub options: Vec<SectionHeaderOption<'a>>,
}

#[async_trait::async_trait]
impl<'a> PcapNgBlock<'a> for SectionHeaderBlock<'a> {
    async fn from_slice<B: ByteOrder>(mut slice: &'a [u8]) -> Result<(&'a [u8], SectionHeaderBlock<'a>), PcapError> {
        if slice.len() < 16 {
            return Err(PcapError::InvalidField("SectionHeaderBlock: block length < 16"));
        }

        let magic = slice.read_u32::<BigEndian>().await.unwrap();
        let endianness = match magic {
            0x1A2B3C4D => Endianness::Big,
            0x4D3C2B1A => Endianness::Little,
            _ => return Err(PcapError::InvalidField("SectionHeaderBlock: invalid magic number")),
        };

        let (rem, major_version, minor_version, section_length, options) = match endianness {
            Endianness::Big => parse_inner::<BigEndian>(slice).await?,
            Endianness::Little => parse_inner::<LittleEndian>(slice).await?,
        };

        let block = SectionHeaderBlock { endianness, major_version, minor_version, section_length, options };

        return Ok((rem, block));

        #[allow(clippy::type_complexity)]
        async fn parse_inner<B: ByteOrder + Send>(mut slice: &[u8]) -> Result<(&[u8], u16, u16, i64, Vec<SectionHeaderOption>), PcapError> {
            let maj_ver = slice.read_u16::<B>().await.unwrap();
            let min_ver = slice.read_u16::<B>().await.unwrap();
            let sec_len = slice.read_i64::<B>().await.unwrap();
            let (rem, opts) = SectionHeaderOption::opts_from_slice::<B>(slice).await?;

            Ok((rem, maj_ver, min_ver, sec_len, opts))
        }
    }

    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        match self.endianness {
            Endianness::Big => writer.write_u32::<BigEndian>(0x1A2B3C4D).await?,
            Endianness::Little => writer.write_u32::<LittleEndian>(0x1A2B3C4D).await?,
        };

        writer.write_u16::<B>(self.major_version).await?;
        writer.write_u16::<B>(self.minor_version).await?;
        writer.write_i64::<B>(self.section_length).await?;

        let opt_len = SectionHeaderOption::write_opts_to::<B, W>(&self.options, writer).await?;

        Ok(16 + opt_len)
    }

    fn into_block(self) -> Block<'a> {
        Block::SectionHeader(self)
    }
}

impl Default for SectionHeaderBlock<'static> {
    fn default() -> Self {
        Self {
            endianness: Endianness::Big,
            major_version: 1,
            minor_version: 0,
            section_length: -1,
            options: vec![],
        }
    }
}


/// Section Header Block options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub enum SectionHeaderOption<'a> {
    /// Comment associated with the current block
    Comment(Cow<'a, str>),

    /// Description of the hardware used to create this section
    Hardware(Cow<'a, str>),

    /// Name of the operating system used to create this section
    OS(Cow<'a, str>),

    /// Name of the application used to create this section
    UserApplication(Cow<'a, str>),

    /// Custom option containing binary octets in the Custom Data portion
    CustomBinary(CustomBinaryOption<'a>),

    /// Custom option containing a UTF-8 string in the Custom Data portion
    CustomUtf8(CustomUtf8Option<'a>),

    /// Unknown option
    Unknown(UnknownOption<'a>),
}

#[async_trait::async_trait]
impl<'a> PcapNgOption<'a> for SectionHeaderOption<'a> {
    async fn from_slice<B: ByteOrder + Send>(code: u16, length: u16, slice: &'a [u8]) -> Result<SectionHeaderOption<'a>, PcapError> {
        let opt = match code {
            1 => SectionHeaderOption::Comment(Cow::Borrowed(std::str::from_utf8(slice)?)),
            2 => SectionHeaderOption::Hardware(Cow::Borrowed(std::str::from_utf8(slice)?)),
            3 => SectionHeaderOption::OS(Cow::Borrowed(std::str::from_utf8(slice)?)),
            4 => SectionHeaderOption::UserApplication(Cow::Borrowed(std::str::from_utf8(slice)?)),

            2988 | 19372 => SectionHeaderOption::CustomUtf8(CustomUtf8Option::from_slice::<B>(code, slice).await?),
            2989 | 19373 => SectionHeaderOption::CustomBinary(CustomBinaryOption::from_slice::<B>(code, slice).await?),

            _ => SectionHeaderOption::Unknown(UnknownOption::new(code, length, slice)),
        };

        Ok(opt)
    }

    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        match self {
            SectionHeaderOption::Comment(a) => a.write_opt_to::<B, W>(1, writer).await,
            SectionHeaderOption::Hardware(a) => a.write_opt_to::<B, W>(2, writer).await,
            SectionHeaderOption::OS(a) => a.write_opt_to::<B, W>(3, writer).await,
            SectionHeaderOption::UserApplication(a) => a.write_opt_to::<B, W>(4, writer).await,
            SectionHeaderOption::CustomBinary(a) => a.write_opt_to::<B, W>(a.code, writer).await,
            SectionHeaderOption::CustomUtf8(a) => a.write_opt_to::<B, W>(a.code, writer).await,
            SectionHeaderOption::Unknown(a) => a.write_opt_to::<B, W>(a.code, writer).await,
        }
    }
}
