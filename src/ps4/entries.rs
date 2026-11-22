//! Well-known PS4 PKG entry identifiers.

pub const ENTRY_NAMES: u32 = 0x0200;
pub const PARAM_SFO: u32 = 0x1000;

/// Conventional file name of an entry ID (falls back to `entry_0xNNNN.bin`).
pub fn name(id: u32) -> String {
    let n = match id {
        0x0001 => "digests",
        0x0010 => "entry_keys",
        0x0020 => "image_key",
        0x0080 => "general_digests",
        0x0100 => "metas",
        0x0200 => "entry_names",
        0x0400 => "license.dat",
        0x0401 => "license.info",
        0x0402 => "nptitle.dat",
        0x0403 => "npbind.dat",
        0x0404 => "selfinfo.dat",
        0x0406 => "imageinfo.dat",
        0x0407 => "target-deltainfo.dat",
        0x0408 => "origin-deltainfo.dat",
        0x0409 => "psreserved.dat",
        0x1000 => "param.sfo",
        0x1001 => "playgo-chunk.dat",
        0x1002 => "playgo-chunk.sha",
        0x1003 => "playgo-manifest.xml",
        0x1004 => "pronunciation.xml",
        0x1005 => "pronunciation.sig",
        0x1006 => "pic1.png",
        0x1007 => "pubtoolinfo.dat",
        0x1008 => "app/playgo-chunk.dat",
        0x1009 => "app/playgo-chunk.sha",
        0x100A => "app/playgo-manifest.xml",
        0x100B => "shareparam.json",
        0x100C => "shareoverlayimage.png",
        0x100D => "save_data.png",
        0x100E => "shareprivacyguardimage.png",
        0x1200 => "icon0.png",
        0x1220 => "pic0.png",
        0x1240 => "snd0.at9",
        0x1260 => "changeinfo/changeinfo.xml",
        0x1280 => "icon0.dds",
        0x12A0 => "pic0.dds",
        0x12C0 => "pic1.dds",
        0x1400 => "trophy/trophy00.trp",
        _ => {
            if (0x1201..0x1220).contains(&id) {
                return format!("icon0_{:02}.png", id - 0x1201);
            }
            if (0x1241..0x1260).contains(&id) {
                return format!("pic1_{:02}.png", id - 0x1241);
            }
            if (0x1261..0x1280).contains(&id) {
                return format!("changeinfo/changeinfo_{:02}.xml", id - 0x1261);
            }
            if (0x1401..0x1500).contains(&id) {
                return format!("trophy/trophy{:02}.trp", id - 0x1400);
            }
            return format!("entry_0x{id:04x}.bin");
        }
    };
    n.to_string()
}
