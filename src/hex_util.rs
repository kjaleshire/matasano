pub fn hex_decode_string(hex_string: &[u8]) -> Vec<u8> {
    if hex_string.len() % 2 == 1 {
        panic!("Must be even-length byte array. Last value `{}`", hex_string.last().unwrap());
    }
    hex_string.iter().enumerate().filter(|&(index, _)| {
        index % 2 == 0
    }).zip(hex_string.iter().enumerate().filter(|&(index, _)| {
        index % 2 == 1
    })).map(|((_, &left_char), (_, &right_char))| {
        hex_decode_char(right_char) | hex_decode_char(left_char) << 0x04
    }).collect()
}

pub fn hex_encode_bytes_to_string(values_slice: &[u8]) -> Vec<u8> {
    values_slice.iter().flat_map(|&value_char| {
        (vec![hex_encode_as_char(value_char >> 0x04), hex_encode_as_char(value_char & 0x0F)]).into_iter()
    }).collect()
}

fn hex_decode_char(hex_char: u8) -> u8 {
    match hex_char {
        x if x >= b'0' && x <= b'9' => x - b'0',
        x if x >= b'a' && x <= b'f' => x - b'a' + 10,
        x => x
    }
}

fn hex_encode_as_char(value: u8) -> u8 {
    match value {
        x if x <= 9 => x + b'0',
        x if x >= 10 && x <= 15 => x + b'a' - 10,
        x => x
    }
}
