// Quite hacky, but will do as a weekend solution. Something like Markov chains would be a better
// solution. Ragel state machines anyone?
pub fn character_score(text_string: &str) -> uint {
    text_string.chars().filter_map(|score_char| {
        match score_char {
            x if x >= 'A' && x <= 'Z' => Some(1u),
            x if x >= 'a' && x <= 'z' => Some(1u),
            x if x >= '0' && x <= '9' => Some(1u),
            ' ' =>                       Some(1u),
            '-' =>                       Some(1u),
            '\'' =>                      Some(1u),
            '\n' =>                      Some(1u),
            '/' =>                       Some(1u),
            ',' =>                       Some(1u),
            '.' =>                       Some(1u),
            '?' =>                       Some(1u),
            '!' =>                       Some(1u),
            _ =>                         None
        }
    }).count()
}
