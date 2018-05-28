pub fn bit_distance(byte_slice_1: &[u8], byte_slice_2: &[u8]) -> usize {
    byte_slice_1
        .iter()
        .zip(byte_slice_2)
        .map(|(&byte_1, &byte_2)| (byte_1 ^ byte_2).count_ones() as usize)
        .fold(0, |a, s| a + s)
}
