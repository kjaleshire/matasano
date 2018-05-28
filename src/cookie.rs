use url::form_urlencoded;

use std::collections::HashMap;

pub fn parse<'a>(encoded_cookie: &'a str) -> HashMap<String, String> {
    let mut map = HashMap::new();

    for (key, value) in form_urlencoded::parse(encoded_cookie.as_bytes()).into_owned() {
        map.insert(key, value);
    }

    map
}

pub fn profile_for<'a>(email: &'a str) -> String {
    format!(
        "email={}&uid=10&role=user",
        email.replace("=", "").replace("&", "")
    )
}
