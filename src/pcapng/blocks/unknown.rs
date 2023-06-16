//! Unknown Block.

use std::borrow::Cow;
use std::io::Result as IoResult;

use byteorder::ByteOrder;
use derive_into_owned::IntoOwned;
use tokio::io::AsyncWrite;

use super::block_common::{Block, PcapNgBlock};
use crate::PcapError;


/// Unknown block
#[derive(Clone, Debug, IntoOwned, Eq, PartialEq)]
pub struct UnknownBlock<'a> {
    /// Block type
    pub type_: u32,
    /// Block length
    pub length: u32,
    /// Block value
    pub value: Cow<'a, [u8]>,
}

impl<'a> UnknownBlock<'a> {
    /// Creates a new [`UnknownBlock`]
    pub fn new(type_: u32, length: u32, value: &'a [u8]) -> Self {
        UnknownBlock { type_, length, value: Cow::Borrowed(value) }
    }
}

#[async_trait::async_trait]
impl<'a> PcapNgBlock<'a> for UnknownBlock<'a> {
    async fn from_slice<B: ByteOrder>(_slice: &'a [u8]) -> Result<(&[u8], UnknownBlock<'a>), PcapError>
    where
        Self: Sized,
    {
        unimplemented!("UnkknownBlock::<as PcapNgBlock>::From_slice shouldn't be called")
    }

    async fn write_to<B: ByteOrder, W: AsyncWrite + Unpin + Send>(&self, writer: &mut W) -> IoResult<usize> {
        tokio::io::AsyncWriteExt::write_all(writer, &self.value).await?;
        Ok(self.value.len())
    }

    fn into_block(self) -> Block<'a> {
        Block::Unknown(self)
    }
}
