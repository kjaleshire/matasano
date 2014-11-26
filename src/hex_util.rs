pub fn hex_chars_to_values(hex_string: &[u8]) -> Vec<u8> {
    if hex_string.len() % 2 == 1 {
        panic!("Must be even-length byte array. Last value `{}`", hex_string.last().unwrap());
    }
    hex_string.iter().enumerate().filter(|&(index, _)| {
        index % 2 == 0
    }).zip(hex_string.iter().enumerate().filter(|&(index, _)| {
        index % 2 == 1
    })).map(|((_, &left_char), (_, &right_char))| {
        hex_char_to_value(right_char) | hex_char_to_value(left_char) << 4
    }).collect()
}

pub fn values_to_hex_chars(values_slice: &[u8]) -> Vec<u8> {
    values_slice.iter().flat_map(|&value_char| {
        (vec![value_to_hex_char(value_char >> 4), value_to_hex_char(value_char & 0xF)]).into_iter()
    }).collect()
}

fn hex_char_to_value(hex_char: u8) -> u8 {
    match hex_char {
        x if x >= b'0' && x <= b'9' => x - b'0',
        x if x >= b'a' && x <= b'f' => x - b'a' + 10,
        x => x
    }
}

fn value_to_hex_char(hex_char: u8) -> u8 {
    match hex_char {
        x if x <= 9 => x + b'0',
        x if x >= 10 && x <= 15 => x + b'a' - 10,
        x => x
    }
}
