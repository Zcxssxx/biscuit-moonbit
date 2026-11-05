// This is a disposable interoperability example. The fixed seed is public.

///|
fn main {
  let root_seed : Bytes = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key : Bytes = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  try {
    let token = @biscuit.issue(
      [@biscuit.parse_fact("right(\"file1\", \"read\")")],
      [],
      [],
      3,
      root_seed,
      Bytes::make(32, b'\x43'),
    )
    let blocks = @biscuit.verify_block_facts(token, root_key)
    let query = @biscuit.parse_query("right(\"file1\", \"read\")")
    let matches = @biscuit.match_query(query, blocks[0].facts)
    println("Verified blocks: " + blocks.length().to_string())
    println("Authority facts: " + blocks[0].facts.length().to_string())
    println("right(file1, read) matches: " + matches.length().to_string())
    println("Inspection only. This program made no authorization decision.")
  } catch {
    _ => println("Token verification or fact inspection failed.")
  }
}
