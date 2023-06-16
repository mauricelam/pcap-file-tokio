#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file_tokio::pcapng::PcapNgReader;

fuzz_target!(|data: &[u8]| {
    tokio_test::block_on(async {
        if let Ok(mut pcapng_reader) = PcapNgReader::new(data).await {
            while let Some(_block) = pcapng_reader.next_block().await {}
        }
    });
});
