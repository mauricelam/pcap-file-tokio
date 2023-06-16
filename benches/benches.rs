use criterion::{criterion_group, criterion_main, Criterion};
use pcap_file_tokio::pcap::{PcapParser, PcapReader};
use pcap_file_tokio::pcapng::{PcapNgParser, PcapNgReader};
use pcap_file_tokio::PcapError;
use tokio::runtime::Runtime;

/// Bench and compare Pcap readers and parsers
pub fn pcap(c: &mut Criterion) {
    let pcap = tokio_test::block_on(tokio::fs::read("benches/bench.pcap")).unwrap();

    let mut group = c.benchmark_group("Pcap");
    group.throughput(criterion::Throughput::Bytes(pcap.len() as u64));

    group.bench_function("Parser", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let (mut src, parser) = PcapParser::new(&pcap).await.unwrap();
            loop {
                match parser.next_packet(src).await {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("ParserRaw", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let (mut src, parser) = PcapParser::new(&pcap).await.unwrap();
            loop {
                match parser.next_raw_packet(src).await {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("Reader", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let mut src = &pcap[..];
            let mut reader = PcapReader::new(&mut src).await.unwrap();
            while let Some(pkt) = reader.next_packet().await {
                pkt.unwrap();
            }
        })
    });

    group.bench_function("ReaderRaw", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let mut src = &pcap[..];
            let mut reader = PcapReader::new(&mut src).await.unwrap();
            while let Some(pkt) = reader.next_raw_packet().await {
                pkt.unwrap();
            }
        })
    });
}

/// Bench and compare PcapNg readers and parsers
pub fn pcapng(c: &mut Criterion) {
    let pcapng = tokio_test::block_on(tokio::fs::read("benches/bench.pcapng")).unwrap();

    let mut group = c.benchmark_group("PcapNg");
    group.throughput(criterion::Throughput::Bytes(pcapng.len() as u64));

    group.bench_function("Parser", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let (mut src, mut parser) = PcapNgParser::new(&pcapng).await.unwrap();
            loop {
                match parser.next_block(src).await {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("ParserRaw", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let (mut src, mut parser) = PcapNgParser::new(&pcapng).await.unwrap();
            loop {
                match parser.next_raw_block(src).await {
                    Ok((rem, _)) => src = rem,
                    Err(PcapError::IncompleteBuffer) => break,
                    Err(_) => panic!(),
                }
            }
        })
    });

    group.bench_function("Reader", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let mut src = &pcapng[..];
            let mut reader = PcapNgReader::new(&mut src).await.unwrap();
            while let Some(pkt) = reader.next_block().await {
                pkt.unwrap();
            }
        })
    });

    group.bench_function("ReaderRaw", |b| {
        let rt = Runtime::new().unwrap();
        b.to_async(rt).iter(|| async {
            let mut src = &pcapng[..];
            let mut reader = PcapNgReader::new(&mut src).await.unwrap();
            while let Some(pkt) = reader.next_raw_block().await {
                pkt.unwrap();
            }
        })
    });
}

criterion_group!(benches, pcap, pcapng);
criterion_main!(benches);
