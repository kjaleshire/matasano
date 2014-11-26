use std::collections::bitv;

pub fn bit_distance(string1: &str, string2: &str) -> uint {
    let (string1_iter, string2_iter) = (string1.as_bytes().iter(), string2.as_bytes().iter());

    string1_iter.zip(string2_iter).map(|(&byte1, &byte2)| {
        bitv::from_bytes(([byte1 ^ byte2])[]).iter().filter(|x| *x).count()
    }).fold(0u, |acc, score| acc + score )
}
