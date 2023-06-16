use byteorder::{ByteOrder, BigEndian, LittleEndian};

/// Timestamp resolution of the pcap
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum TsResolution {
    /// Microsecond resolution
    MicroSecond,
    /// Nanosecond resolution
    NanoSecond,
}

/// Endianness of the pcap
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Endianness {
    /// Big endian
    Big,
    /// Little endian
    Little,
}

impl Endianness {
    /// True if LitlleEndian
    pub fn is_little(self) -> bool {
        match self {
            Endianness::Big => false,
            Endianness::Little => true,
        }
    }

    /// True if BigEndian
    pub fn is_big(self) -> bool {
        match self {
            Endianness::Big => true,
            Endianness::Little => false,
        }
    }

    /// Return the endianness of the given ByteOrder
    pub fn from_byteorder<B: ByteOrder>() -> Self {
        if B::read_u32(&[0, 0, 0, 1]) == 1 {
            Endianness::Big
        }
        else {
            Endianness::Little
        }
    }

    /// Return the native endianness of the system
    pub fn native() -> Self {
        #[cfg(target_endian = "big")]
        return Endianness::Big;

        #[cfg(target_endian = "little")]
        return Endianness::Little;
    }
}

pub(crate) trait RuntimeByteorder: ByteOrder {
    fn endianness() -> Endianness;
}

impl RuntimeByteorder for BigEndian {
    fn endianness() -> Endianness {
        Endianness::Big
    }
}

impl RuntimeByteorder for LittleEndian {
    fn endianness() -> Endianness {
        Endianness::Little
    }
}

pub use pcap_file::DataLink;
