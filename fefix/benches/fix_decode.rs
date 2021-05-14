use criterion::{black_box, criterion_group, criterion_main, Criterion};
use fefix::tagvalue::{Config, Decoder};
use fefix::Dictionary;

const FIX_MESSAGE: &[u8] = b"8=FIX.4.4\x019=289\x0135=8\x0134=1090\x0149=TESTSELL1\x0152=20180920-18:23:53.671\x0156=TESTBUY1\x016=113.35\x0111=636730640278898634\x0114=3500.0000000000\x0115=USD\x0117=20636730646335310000\x0121=2\x0131=113.35\x0132=3500\x0137=20636730646335310000\x0138=7000\x0139=1\x0140=1\x0154=1\x0155=MSFT\x0160=20180920-18:23:53.531\x01150=F\x01151=3500\x01453=1\x01448=BRK2\x01447=D\x01452=1\x0110=151\x01";

fn decode_fix_message(fix_decoder: &mut Decoder<Config>, msg: &[u8]) {
    fix_decoder.decode(msg).expect("Invalid FIX message");
}

fn criterion_benchmark(c: &mut Criterion) {
    let fix_dictionary = Dictionary::fix44();
    let fix_decoder = &mut Decoder::<Config>::new(fix_dictionary);
    fix_decoder.config_mut().set_separator(b'\x01');
    fix_decoder.config_mut().set_verify_checksum(false);
    fix_decoder.config_mut().set_decode_assoc(true);
    fix_decoder.config_mut().set_decode_seq(false);
    c.bench_function("FIX tag-value decoding", |b| {
        b.iter(|| decode_fix_message(black_box(fix_decoder), black_box(FIX_MESSAGE)))
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
