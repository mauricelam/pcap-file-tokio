use std::borrow::Cow;
use std::io::Result as IoResult;

use byteorder::ByteOrder;
use derive_into_owned::IntoOwned;
use tokio::io::AsyncWrite;
use tokio_byteorder::{AsyncWriteBytesExt, AsyncReadBytesExt};

use crate::errors::PcapError;


/// Common fonctions of the PcapNg options
#[async_trait::async_trait]
pub(crate) trait PcapNgOption<'a> {
    /// Parse an option from a slice
    async fn from_slice<B: ByteOrder + Send>(code: u16, length: u16, slice: &'a [u8]) -> Result<Self, PcapError>
    where
        Self: std::marker::Sized;

    /// Parse all options in a block
    async fn opts_from_slice<B: ByteOrder + Send>(mut slice: &'a [u8]) -> Result<(&'a [u8], Vec<Self>), PcapError>
    where
        Self: std::marker::Sized,
    {
        let mut options = vec![];

        // If there is nothing left in the slice, it means that there is no option
        if slice.is_empty() {
            return Ok((slice, options));
        }

        while !slice.is_empty() {
            if slice.len() < 4 {
                return Err(PcapError::InvalidField("Option: slice.len() < 4"));
            }

            let code = slice.read_u16::<B>().await.unwrap();
            let length = slice.read_u16::<B>().await.unwrap() as usize;
            let pad_len = (4 - (length % 4)) % 4;

            if code == 0 {
                return Ok((slice, options));
            }

            if slice.len() < length + pad_len {
                return Err(PcapError::InvalidField("Option: length + pad.len() > slice.len()"));
            }

            let tmp_slice = &slice[..length];
            let opt = Self::from_slice::<B>(code, length as u16, tmp_slice).await?;

            // Jump over the padding
            slice = &slice[length + pad_len..];

            options.push(opt);
        }

        Err(PcapError::InvalidField("Invalid option"))
    }

    /// Write the option to a writer
    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize>;

    /// Write all options in a block
    async fn write_opts_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(opts: &[Self], writer: &mut W) -> IoResult<usize>
    where
        Self: std::marker::Sized + Sync,
    {
        let mut have_opt = false;
        let mut written = 0;
        for opt in opts {
            written += opt.write_to::<B, W>(writer).await?;
            have_opt = true;
        }

        if have_opt {
            writer.write_u16::<B>(0).await?;
            writer.write_u16::<B>(0).await?;
            written += 4;
        }

        Ok(written)
    }
}

/// Unknown options
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownOption<'a> {
    /// Option code
    pub code: u16,
    /// Option length
    pub length: u16,
    /// Option value
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownOption<'a> {
    /// Creates a new [`UnknownOption`]
    pub fn new(code: u16, length: u16, value: &'a [u8]) -> Self {
        UnknownOption { code, length, value: Cow::Borrowed(value) }
    }
}

/// Custom binary option
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct CustomBinaryOption<'a> {
    /// Option code
    pub code: u16,
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, [u8]>,
}

impl<'a> CustomBinaryOption<'a> {
    /// Parse an [`CustomBinaryOption`] from a slice
    pub async fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<CustomBinaryOption<'a>, PcapError> {
        let pen = src.read_u32::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?;
        let opt = CustomBinaryOption { code, pen, value: Cow::Borrowed(src) };
        Ok(opt)
    }
}

/// Custom string (UTF-8) option
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct CustomUtf8Option<'a> {
    /// Option code
    pub code: u16,
    /// Option PEN identifier
    pub pen: u32,
    /// Option value
    pub value: Cow<'a, str>,
}

impl<'a> CustomUtf8Option<'a> {
    /// Parse a [`CustomUtf8Option`] from a slice
    pub async fn from_slice<B: ByteOrder>(code: u16, mut src: &'a [u8]) -> Result<CustomUtf8Option<'a>, PcapError> {
        let pen = src.read_u32::<B>().await.map_err(|_| PcapError::IncompleteBuffer)?;
        let opt = CustomUtf8Option { code, pen, value: Cow::Borrowed(std::str::from_utf8(src)?) };
        Ok(opt)
    }
}

#[async_trait::async_trait]
pub(crate) trait WriteOptTo {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize>;
}

#[async_trait::async_trait]
impl<'a> WriteOptTo for Cow<'a, [u8]> {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = self.len();
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(len as u16).await?;
        tokio::io::AsyncWriteExt::write_all(writer, self).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        Ok(len + pad_len + 4)
    }
}

#[async_trait::async_trait]
impl<'a> WriteOptTo for Cow<'a, str> {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = self.as_bytes().len();
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(len as u16).await?;
        tokio::io::AsyncWriteExt::write_all(writer, self.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        Ok(len + pad_len + 4)
    }
}

#[async_trait::async_trait]
impl WriteOptTo for u8 {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(1).await?;
        writer.write_u8(*self).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3]).await?;

        Ok(8)
    }
}

#[async_trait::async_trait]
impl WriteOptTo for u16 {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(2).await?;
        writer.write_u16::<B>(*self).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 2]).await?;

        Ok(8)
    }
}

#[async_trait::async_trait]
impl WriteOptTo for u32 {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(4).await?;
        writer.write_u32::<B>(*self).await?;

        Ok(8)
    }
}

#[async_trait::async_trait]
impl WriteOptTo for u64 {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(8).await?;
        writer.write_u64::<B>(*self).await?;

        Ok(12)
    }
}

#[async_trait::async_trait]
impl<'a> WriteOptTo for CustomBinaryOption<'a> {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = &self.value.len() + 4;
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(len as u16).await?;
        writer.write_u32::<B>(self.pen).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &self.value).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        Ok(len + pad_len + 4)
    }
}

#[async_trait::async_trait]
impl<'a> WriteOptTo for CustomUtf8Option<'a> {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = &self.value.len() + 4;
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(len as u16).await?;
        writer.write_u32::<B>(self.pen).await?;
        tokio::io::AsyncWriteExt::write_all(writer, self.value.as_bytes()).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        Ok(len + pad_len + 4)
    }
}

#[async_trait::async_trait]
impl<'a> WriteOptTo for UnknownOption<'a> {
    async fn write_opt_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, code: u16, writer: &mut W) -> IoResult<usize> {
        let len = self.value.len();
        let pad_len = (4 - len % 4) % 4;

        writer.write_u16::<B>(code).await?;
        writer.write_u16::<B>(len as u16).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &self.value).await?;
        tokio::io::AsyncWriteExt::write_all(writer, &[0_u8; 3][..pad_len]).await?;

        Ok(len + pad_len + 4)
    }
}
