//! Public RFC 8032 fixtures for secretless host builds.
//!
//! Release Android builds receive the same roles from explicit CI inputs.

pub const AGENT_CATALOG: [u8; 32] =
    hex32("278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e");
pub const NATIVE_EXECUTABLE: [u8; 32] =
    hex32("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c");
pub const RESTORE: [u8; 32] =
    hex32("fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025");
pub const RELEASE_CATALOG: [u8; 32] =
    hex32("0b513ad9b4924015ca0902ed079044d3ac5dbec2306f06948c10da8eb6e39f2d");

pub fn assert_distinct() {
    let keys = [AGENT_CATALOG, NATIVE_EXECUTABLE, RESTORE, RELEASE_CATALOG];
    for left in 0..keys.len() {
        for right in left + 1..keys.len() {
            assert_ne!(keys[left], keys[right], "host role fixtures must differ");
        }
    }
}

const fn hex32(value: &str) -> [u8; 32] {
    let bytes = value.as_bytes();
    assert!(bytes.len() == 64, "fixture public key must be 32 bytes");
    let mut output = [0u8; 32];
    let mut index = 0;
    while index < output.len() {
        output[index] = (nibble(bytes[index * 2]) << 4) | nibble(bytes[index * 2 + 1]);
        index += 1;
    }
    output
}

const fn nibble(value: u8) -> u8 {
    match value {
        b'0'..=b'9' => value - b'0',
        b'a'..=b'f' => value - b'a' + 10,
        _ => panic!("invalid fixture hex"),
    }
}
