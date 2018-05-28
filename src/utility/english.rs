pub fn string_score(s: &str) -> f32 {
    score_chars(s) + score_digraphs(s)
}

fn score_chars(text_string: &str) -> f32 {
    text_string
        .chars()
        .map(|score_char| match score_char.to_ascii_uppercase() {
            'E' => 12.02,
            'T' => 9.10,
            'A' => 8.12,
            'O' => 7.68,
            'I' => 7.31,
            'N' => 6.95,
            'S' => 6.28,
            'R' => 6.02,
            'H' => 5.92,
            'D' => 4.32,
            'L' => 3.98,
            'U' => 2.88,
            'C' => 2.71,
            'M' => 2.61,
            'F' => 2.30,
            'Y' => 2.11,
            'W' => 2.09,
            'G' => 2.03,
            'P' => 1.82,
            'B' => 1.49,
            'V' => 1.11,
            'K' => 0.69,
            'X' => 0.17,
            'Q' => 0.11,
            'J' => 0.10,
            'Z' => 0.07,
            ' ' => 10.0,
            '-' | '\'' | '\n' | '/' | ',' | '.' | '?' | '!' => 0.1,
            _ => 0.0,
        })
        .fold(0.0, |a, s| a + s)
}

fn score_digraphs(text_string: &str) -> f32 {
    (0..text_string.len() - 1)
        .map(
            |index| match &text_string.as_bytes()[index..index + 2].to_ascii_uppercase()[..] {
                b"TH" => 3.88 * 4.0,
                b"HE" => 3.68 * 4.0,
                b"IN" => 2.28 * 4.0,
                b"ER" => 2.17 * 4.0,
                b"AN" => 2.14 * 4.0,
                b"RE" => 1.74 * 4.0,
                b"ND" => 1.57 * 4.0,
                b"ON" => 1.41 * 4.0,
                b"EN" => 1.38 * 4.0,
                b"AT" => 1.33 * 4.0,
                b"OU" => 1.28 * 4.0,
                b"ED" => 1.27 * 4.0,
                b"HA" => 1.27 * 4.0,
                b"TO" => 1.16 * 4.0,
                b"OR" => 1.15 * 4.0,
                b"IT" => 1.13 * 4.0,
                b"IS" => 1.10 * 4.0,
                b"HI" => 1.09 * 4.0,
                b"ES" => 1.09 * 4.0,
                b"NG" => 1.05 * 4.0,
                _ => 0.0,
            },
        )
        .fold(0.0, |a, s| a + s)
}
