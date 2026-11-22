//! Synthetic, redistributable specimens built entirely in-process (no copyrighted data).

use romux::{JobContext, MemorySource, SharedSource};
use std::sync::Arc;

pub fn mem(v: Vec<u8>) -> SharedSource {
    Arc::new(MemorySource::new(v))
}

pub fn iso(files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut b = romux::disc::testkit::IsoBuilder::new("FIXTURE");
    for (p, d) in files {
        b.add_file(p, mem(d.to_vec())).unwrap();
    }
    let mut out = Vec::new();
    b.write(&mut out, &JobContext::default()).unwrap();
    out
}

pub fn psp_iso() -> Vec<u8> {
    let mut psf = romux::ps4::sfo::Psf::default();
    psf.entries.insert("TITLE".into(), romux::ps4::sfo::PsfValue::Text("Fixture".into()));
    psf.entries.insert("DISC_ID".into(), romux::ps4::sfo::PsfValue::Text("ULUS00000".into()));
    iso(&[("UMD_DATA.BIN", b"ULUS-00000|0|0001|G"), ("PSP_GAME/PARAM.SFO", &psf.to_bytes())])
}

pub fn chd_dvd(data: &[u8]) -> Vec<u8> {
    let mut c = std::io::Cursor::new(Vec::new());
    romux::disc::testkit::write_chd(
        &romux::disc::testkit::ChdInput::Dvd(mem(data.to_vec())),
        &Default::default(),
        &mut c,
        &JobContext::default(),
    )
    .unwrap();
    c.into_inner()
}

pub fn pfs0(files: &[(&str, Vec<u8>)]) -> Vec<u8> {
    romux::switch::testkit::pfs0_image(files)
}

pub fn cso(data: &[u8]) -> Vec<u8> {
    let mut c = Vec::new();
    romux::psp::testkit::cso_compress(&MemorySource::new(data.to_vec()), &mut c, 6, &JobContext::default()).unwrap();
    c
}

pub fn ps4_pkg() -> Vec<u8> {
    let mut psf = romux::ps4::sfo::Psf::default();
    psf.entries.insert("TITLE".into(), romux::ps4::sfo::PsfValue::Text("Fixture".into()));
    psf.entries.insert("CONTENT_ID".into(), romux::ps4::sfo::PsfValue::Text("UP0000-CUSA00001_00-FIXTURE000000000".into()));
    romux::ps4::testkit::build("UP0000-CUSA00001_00-FIXTURE000000000", &[(0x1000, psf.to_bytes(), false), (0x1200, vec![1; 64], false)])
}

pub fn xiso() -> Vec<u8> {
    let mut b = romux::xbox::testkit::XisoBuilder::new();
    b.add_file("default.xbe", mem(romux::xbox::testkit::xbe(0x41430001, "Fixture"))).unwrap();
    b.add_file("media/a.bin", mem(vec![3; 5000])).unwrap();
    let mut c = std::io::Cursor::new(Vec::new());
    b.write(&mut c, &JobContext::default()).unwrap();
    c.into_inner()
}

pub fn gc_disc() -> Vec<u8> {
    romux::wii::testkit::gc_disc("GFIX", "Fixture", &[("a.bin", vec![9u8; 4000])])
}

pub fn rvz() -> Vec<u8> {
    let mut c = std::io::Cursor::new(Vec::new());
    romux::wii::testkit::write_rvz_gc(&MemorySource::new(gc_disc()), &mut c, 3, 0x20000, &JobContext::default()).unwrap();
    c.into_inner()
}

pub fn u8arc() -> Vec<u8> {
    let mut b = romux::wii::testkit::U8Builder::new();
    b.add_file("a/b.bin", mem(vec![1; 10])).unwrap();
    let mut o = Vec::new();
    b.write(&mut o, &JobContext::default()).unwrap();
    o
}

pub fn cci() -> Vec<u8> {
    let n = romux::n3ds::testkit::ncch(0x0004_0000_0000_1000, "CTR-P-FIXT", &[(".code", vec![1u8; 0x200])]);
    romux::n3ds::testkit::cci(0x0004_0000_0000_1000, &[n])
}

pub fn vpk() -> Vec<u8> {
    let mut psf = romux::ps4::sfo::Psf::default();
    psf.entries.insert("TITLE_ID".into(), romux::ps4::sfo::PsfValue::Text("FIXT00001".into()));
    psf.entries.insert("PSP2_SYSTEM_VER".into(), romux::ps4::sfo::PsfValue::Int(0));
    let mut c = std::io::Cursor::new(Vec::new());
    {
        let mut z = romux::vita::testkit::ZipWriter::new(&mut c);
        z.add("sce_sys/param.sfo", &MemorySource::new(psf.to_bytes()), false, 6).unwrap();
        z.add("eboot.bin", &MemorySource::new(vec![7u8; 4096]), true, 6).unwrap();
        z.finish().unwrap();
    }
    c.into_inner()
}

pub fn wux() -> Vec<u8> {
    let mut img = vec![0u8; 0x8000 * 4];
    img[..10].copy_from_slice(b"WUP-P-FIXT");
    let mut c = Vec::new();
    romux::wiiu::testkit::wux_compress(&MemorySource::new(img), &mut c, 0x8000, &JobContext::default()).unwrap();
    c
}

/// (name, expected format id, bytes) for every fixture.
pub fn all() -> Vec<(&'static str, &'static str, Vec<u8>)> {
    vec![
        ("iso", "disc.iso9660", iso(&[("A.TXT", b"hello"), ("D/B.BIN", &[2u8; 3000])])),
        ("psp", "psp.iso", psp_iso()),
        ("chd", "disc.chd", chd_dvd(&iso(&[("X", b"x")]))),
        ("pfs0", "switch.pfs0", pfs0(&[("main", vec![1; 100]), ("main.npdm", vec![2; 50])])),
        ("cso", "psp.cso", cso(&psp_iso())),
        ("ps4", "ps4.pkg", ps4_pkg()),
        ("xiso", "xbox.xiso", xiso()),
        ("gc", "gamecube.iso", gc_disc()),
        ("rvz", "wii.rvz", rvz()),
        ("u8", "wii.u8", u8arc()),
        ("cci", "3ds.cci", cci()),
        ("vpk", "vita.vpk", vpk()),
        ("wux", "wiiu.wux", wux()),
    ]
}
