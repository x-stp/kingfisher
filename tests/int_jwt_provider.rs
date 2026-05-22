use jsonwebtoken::DecodingKey;
use kingfisher_scanner::validation::jwt::{ValidateOptions, validate_jwt_with};

const RS256_TOKEN: &str = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrLXN1YmplY3QiLCJuYmYiOjAsImV4cCI6NDEwMjQ0NDgwMH0.T87uqt_EI9ISXFmfn2hVTJa-sDTF2xWjNl0Fo6ZClM3_bvdyEB5BWzkIjDmQGbXjP1iVGHv59esuoHjeRYR_S7cBBIM-J2ZWuR_FfVSwjI-jxDlQGw8BFBN6qqpX2dBQfe0NmJ4GzBmQmyPX9GVNlw6zZvW0SGnaX5GcD7HOCqoZQhkiI4W1zTCQ_J4OjJnMwdNg6XkquwBj_yV-VKx_9NYXXTCjl6JtFBF9ZP2X3I58sLSOTzbkTSwSHfLpWLxWfzEYItwHALsK_fBAYMlSZwRvHpRBc48Tqg_2hjOi8j2qQiMbPDTNJJDnt1jEz0JeYahH8N7aJzIPEmd2HXFdKw";

const RSA_PUBLIC_KEY_PEM: &str = r#"-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA2OcytZklidtKr63saWAt
CnwQmMS8W7OEpbnrP746SSR/gkkrNYBkW3POX3T9dcaf4Ozn50QuFGUqBdCAvHUS
9ZFjubPXsqaxOY9R1eiQt8V+0mf1yI7Q9KCygbqZvilyJ6//kvWTKWA5N9A48J69
wkkxuDXnhmSK0zwuNOetphuQNtVuCvePrvrI9OkcYp8EC2qtJi6oxy+0dI9lCN5+
qQyxWDAJVtPw1I/xSZFzMdFrpZWA65VcqKVqjCEB4bHAc15S7UCuLEgBFlqQEndk
6qTKCy0cVm7LqMOLuNJzbhzNU5caXbEYu6uzzU4vLgIdWpIr09dpNxFl+oA0zbMa
vQIDAQAB
-----END PUBLIC KEY-----"#;

#[tokio::test]
async fn validate_jwt_with_fallback_key_handles_rs256_without_panicking() {
    let opts = ValidateOptions {
        allow_alg_none: false,
        fallback_decoding_key: Some(
            DecodingKey::from_rsa_pem(RSA_PUBLIC_KEY_PEM.as_bytes()).expect("valid RSA key"),
        ),
    };

    let (ok, message) = validate_jwt_with(RS256_TOKEN, &opts, false, false)
        .await
        .expect("RS256 validation should not panic or error");

    assert!(ok, "expected JWT signature verification to succeed: {message}");
    assert!(
        message.contains("JWT valid via fallback key"),
        "unexpected validation message: {message}"
    );
}
