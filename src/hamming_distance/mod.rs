pub fn bit_distance(string1: &str, string2: &str) -> usize {
    let string1_iter = string1.as_bytes().iter();
    let string2_iter = string2.as_bytes().iter();

    string1_iter.zip(string2_iter).map(|(&byte1, &byte2)| {
        (0..8).map(|bit_index| ((byte1 ^ byte2) >> bit_index) & 1 ).filter(|&x| x == 1).count()
    }).fold(0, |accumulator, score| accumulator + score )
}
