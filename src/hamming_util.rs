pub fn bit_distance(bytes1: &[u8], bytes2: &[u8]) -> usize {
    bytes1.iter().zip(bytes2.iter()).map(|(&byte1, &byte2)| {
        (0..8).map(|bit_index| ((byte1 ^ byte2) >> bit_index) & 1 ).filter(|&x| x == 1).count()
    }).fold(0, |accumulator, score| accumulator + score )
}
