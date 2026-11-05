// Public fixed seeds are for interoperability testing only.

///|
fn main {
  let seed = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  try {
    let facts = [
      @biscuit.parse_fact("item(12)"),
      @biscuit.parse_fact("caption(12, \"value, <-\")"),
    ]
    let rule = @biscuit.parse_rule(
      "eligible($n) <- item($n), caption($n, \"value, <-\"), $n >= 10",
    )
    let query = @biscuit.parse_query_body("eligible($n), $n >= 10")
    let check = @biscuit.Check::{ mode: @biscuit.Any, queries: [query], }
    let token = @biscuit.issue(
      facts,
      [rule],
      [check],
      6,
      seed,
      Bytes::make(32, b'\x42'),
    )
    let extended = @biscuit.attenuate(
      token,
      root,
      [check],
      6,
      Bytes::make(32, b'\x43'),
    )
    println(@biscuit.token_to_base64url(extended))
  } catch {
    _ => println("Issuance failed")
  }
}
