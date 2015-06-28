// Quite hacky, but will do as a weekend solution. Something like Markov chains would be a better
// solution. Ragel state machines anyone?
pub fn character_score(text_string: &str) -> usize {
    text_string.chars().map(|score_char| {
        match score_char {
            x if x >= 'A' && x <= 'Z' => 1,
            x if x >= 'a' && x <= 'z' => 1,
            x if x >= '0' && x <= '9' => 1,
            ' ' => 1,
            '-' => 1,
            '\'' => 1,
            '\n' => 1,
            '/' => 1,
            ',' => 1,
            '.' => 1,
            '?' => 1,
            '!' => 1,
            _ => 0
        }
    }).fold(0, |accumulator, score| accumulator + score )
}
