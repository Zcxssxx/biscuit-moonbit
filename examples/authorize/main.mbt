// This is a disposable test token. Its fixed signing seed is public.

///|
fn main {
  let root_seed : Bytes = b"\x9d\x61\xb1\x9d\xef\xfd\x5a\x60\xba\x84\x4a\xf4\x92\xec\x2c\xc4\x44\x49\xc5\x69\x7b\x32\x69\x19\x70\x3b\xac\x03\x1c\xae\x7f\x60"
  let root_key : Bytes = b"\xd7\x5a\x98\x01\x82\xb1\x0a\xb7\xd5\x4b\xfe\xd3\xc9\x64\x07\x3a\x0e\xe1\x72\xf3\xda\xa6\x23\x25\xaf\x02\x1a\x68\xf7\x07\x51\x1a"
  let authority : Bytes = b"\x0a\x05file1\x0a\x01r\x18\x06\x22\x0d\x0a\x0b\x08\x04\x12\x03\x18\x80\x08\x12\x02\x18\x00\x32\x24\x0a\x22\x0a\x02\x08\x04\x12\x07\x08\x02\x12\x03\x08\x81\x08\x12\x06\x08\x03\x12\x02\x18\x00\x12\x0b\x08\x04\x12\x03\x08\x81\x08\x12\x02\x18\x00"
  try {
    let token = @biscuit.issue_raw(
      authority,
      root_seed,
      Bytes::make(32, b'\x51'),
    )
    let policy = @biscuit.Policy::{
      kind: @biscuit.Allow,
      queries: [@biscuit.parse_query_body("right(\"file1\", \"read\")")],
    }
    let read_request = [
      @biscuit.parse_fact("resource(\"file1\")"),
      @biscuit.parse_fact("operation(\"read\")"),
    ]
    @biscuit.authorize_token(
      token,
      root_key,
      read_request,
      [],
      [policy],
      100,
      20,
    )
    println("read file1: allowed")

    let write_request = [
      @biscuit.parse_fact("resource(\"file1\")"),
      @biscuit.parse_fact("operation(\"write\")"),
    ]
    try {
      @biscuit.authorize_token(
        token,
        root_key,
        write_request,
        [],
        [policy],
        100,
        20,
      )
      println("write file1: unexpectedly allowed")
    } catch {
      @biscuit.FailedCheck(_) => println("write file1: denied by token check")
      _ => println("write file1: denied")
    }
    println("The example uses the restricted subset described in README.md.")
  } catch {
    _ => println("Token construction or authorization failed.")
  }
}
