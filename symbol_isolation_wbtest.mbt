///|
test "third-party symbols are isolated and later blocks ignore them" {
  let blocks = [
    encode_block([parse_fact("record(\"shared\")")], [], [], 6),
    encode_block([parse_fact("approval(\"shared\")")], [], [], 6),
    encode_block_with_symbols([parse_fact("next(\"shared\")")], [], [], 6, [
      "record", "shared",
    ]),
  ]
  let signed : Array[SignedBlock] = []
  let encoded : Array[EncodedFactBlock] = []
  for i = 0; i < blocks.length(); i = i + 1 {
    signed.push({
      data: blocks[i],
      next_key: b"",
      signature: b"",
      version: 1,
      external_signature: if i == 1 {
        Some({ public_key: b"", signature: b"", encoded: b"", })
      } else {
        None
      },
    })
    encoded.push(parse_encoded_fact_block(blocks[i]))
  }
  let tables = verified_symbol_tables(signed, encoded)
  assert_true(
    parse_proto_fact(encoded[0].facts[0], tables[0], 6) ==
    parse_fact("record(\"shared\")"),
  )
  assert_true(
    parse_proto_fact(encoded[1].facts[0], tables[1], 6) ==
    parse_fact("approval(\"shared\")"),
  )
  assert_true(
    parse_proto_fact(encoded[2].facts[0], tables[2], 6) ==
    parse_fact("next(\"shared\")"),
  )
  assert_false(tables[0].contains("next"))
  assert_false(tables[2].contains("approval"))
}
