//! Shared pixel artwork for the terminal mascot and the WASM visual fixtures.

pub const SIZE: u16 = 24;

// Honey face, crooked antennae, sidelong eyes, and a lopsided grin.
pub const REST: [&str; SIZE as usize] = [
    "........................",
    ".......KK........KK.....",
    ".......K........K.......",
    "........K......K........",
    ".........K.....K........",
    ".........KKKKKK.........",
    ".......KKHHHHHHYYKK.....",
    "......KHHHHHHHHHYYYYK...",
    "..BB.KHHHHHHHHHHYYYYKB..",
    ".BWWBKHHKKKHHHHHKKHYKWB.",
    "BWWWBKHHWWWKHHHWWWKYKWWB",
    "BWWWWKHHWWKKHHHWWKKYKWWB",
    ".BWWWKHHRHHHHHHHHHRYKWB.",
    "..BBBBKHHHHKHHHHKHYYKB..",
    ".......KYHHHHKKKKHYYK...",
    "........KKYYYYYYYYKK....",
    "......K.KYYYYYYYYK.K....",
    ".....K..KKKKKKKKK..K....",
    "........KYYYYYYYYYYK....",
    ".........KYYYYYYYYK.....",
    "..........KKKKKKKK......",
    "..........K....K........",
    ".........KK....KK.......",
    "........................",
];

pub fn pixel(c: u8) -> Option<(u8, u8, u8)> {
    match c {
        b'K' => Some((0x42, 0x30, 0x29)),
        b'H' => Some((0xFF, 0xD7, 0x66)),
        b'Y' => Some((0xEF, 0xAD, 0x32)),
        b'W' => Some((0xEF, 0xFA, 0xF7)),
        b'B' => Some((0x91, 0xC8, 0xCC)),
        b'R' => Some((0xE5, 0x84, 0x50)),
        _ => None,
    }
}
