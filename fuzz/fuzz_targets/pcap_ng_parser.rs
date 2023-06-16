#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file_tokio::pcapng::PcapNgParser;

fuzz_target!(|data: &[u8]| {
    tokio_test::block_on(async {
        if let Ok((rem, mut pcapng_parser)) = PcapNgParser::new(data).await {
            let mut src = rem;
    
            while !src.is_empty() {
                let _ = pcapng_parser.next_block(src).await;
                src = &src[1..];
            }
        }
    });
});
