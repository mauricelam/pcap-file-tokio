#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file_tokio::pcap::PcapReader;

fuzz_target!(|data: &[u8]| {
    tokio_test::block_on(async {
        if let Ok(mut pcap_reader) = PcapReader::new(data).await {
            while let Some(_packet) = pcap_reader.next_packet().await {}
        }
    });
});
