#![no_main]
use libfuzzer_sys::fuzz_target;
use pcap_file_tokio::pcap::PcapParser;

fuzz_target!(|data: &[u8]| {
    tokio_test::block_on(async {
        if let Ok((rem, pcap_parser)) = PcapParser::new(data).await {
            let mut src = rem;

            while !src.is_empty() {
                let _ = pcap_parser.next_packet(src).await;
                src = &src[1..];
            }
        }
    });
});
