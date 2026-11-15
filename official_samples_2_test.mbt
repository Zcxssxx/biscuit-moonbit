///|
test "official test011_authorizer_authority_caveats default" {
  let actual = run_official_sample(
    "EoIBChgKBWZpbGUxGAMiDQoLCAQSAxiACBICGAASJAgAEiAQVcdQsaFQWTevFTfGJroyY5lcM6ZHWKqvsSdbAxLihBpAqAyYXd74lVGMIW9kxl3NUKXZfQEqlEU9eRWa7SmBZUsf6XSMaGxWZ2BAJqlPuNuKHQLedH32Hpn6mmP_KHitACIiCiCZ6HsOkVhTHu61A_8VJm4rI8KiUHsTjJ0bHyq0WN8tYQ",
    "resource(\"file2\");\noperation(\"read\");\n\ncheck if right($0, $1), resource($0), operation($1);\n\nallow if true;\n",
    false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test012_authority_caveats file1" {
  let actual = run_official_sample(
    "EoQBChoKBWZpbGUxGAMyDwoNCgIIGxIHCAISAxiACBIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkBqj5Da1nrirBiEYEY5FK5zJv2kMcgHhXVfTtzBXxpTkR9zZuYGrYDLvrqUZy5CcT6IYyqTISjx15bOm6fXoLgKIiIKIJnoew6RWFMe7rUD_xUmbisjwqJQexOMnRsfKrRY3y1h",
    "resource(\"file1\");\noperation(\"read\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test012_authority_caveats file2" {
  let actual = run_official_sample(
    "EoQBChoKBWZpbGUxGAMyDwoNCgIIGxIHCAISAxiACBIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkBqj5Da1nrirBiEYEY5FK5zJv2kMcgHhXVfTtzBXxpTkR9zZuYGrYDLvrqUZy5CcT6IYyqTISjx15bOm6fXoLgKIiIKIJnoew6RWFMe7rUD_xUmbisjwqJQexOMnRsfKrRY3y1h",
    "resource(\"file2\");\noperation(\"read\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test013_block_rules file1" {
  let actual = run_official_sample(
    "EpgBCi4KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQMRtBx_z8zQ0IjyDBf2tUp9iv3i7XZy_wqNF1LymvzFAFIQOGLo1P4b9uQc9WLErjIcqwfjlk8LpBkuQ9sLt4AYaqAIKvQEKCnZhbGlkX2RhdGUKATAKATEYAyo1CggIgggSAxiACBIHCAUSAwiDCBIHCAISAxiACBoXCgUKAwiDCAoICgYgz-LxlQcKBBoCCAIqVQoICIIIEgMIhAgSBwgFEgMIgwgSBwgCEgMIhAgaFwoFCgMIgwgKCAoGIM_RssMDCgQaAggCGh4KCQoHOgUKAxiACAoFCgMIhAgKBBoCCAUKBBICCAAyGQoXCgIIGxIICIIIEgMIgwgSBwgCEgMIgwgSJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpAoMTBY6CzykBt9Ozj0TcTVhkN8EII7M73L3fode0FMbXTfiQ9bziLGWd3al39Fu8ijxnFvdbSgg8UXF7Tw9zcACIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX618Q",
    "resource(\"file1\");\ntime(2020-12-21T09:23:12Z);\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test013_block_rules file2" {
  let actual = run_official_sample(
    "EpgBCi4KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQMRtBx_z8zQ0IjyDBf2tUp9iv3i7XZy_wqNF1LymvzFAFIQOGLo1P4b9uQc9WLErjIcqwfjlk8LpBkuQ9sLt4AYaqAIKvQEKCnZhbGlkX2RhdGUKATAKATEYAyo1CggIgggSAxiACBIHCAUSAwiDCBIHCAISAxiACBoXCgUKAwiDCAoICgYgz-LxlQcKBBoCCAIqVQoICIIIEgMIhAgSBwgFEgMIgwgSBwgCEgMIhAgaFwoFCgMIgwgKCAoGIM_RssMDCgQaAggCGh4KCQoHOgUKAxiACAoFCgMIhAgKBBoCCAUKBBICCAAyGQoXCgIIGxIICIIIEgMIgwgSBwgCEgMIgwgSJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpAoMTBY6CzykBt9Ozj0TcTVhkN8EII7M73L3fode0FMbXTfiQ9bziLGWd3al39Fu8ijxnFvdbSgg8UXF7Tw9zcACIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX618Q",
    "resource(\"file2\");\ntime(2020-12-21T09:23:12Z);\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test014_regex_constraint file1" {
  let actual = run_official_sample(
    "EqYBCjwKATAKDmZpbGVbMC05XSsudHh0GAMyJQojCgIIGxIHCAISAwiACBoUCgUKAwiACAoFCgMYgQgKBBoCCAgSJAgAEiAQVcdQsaFQWTevFTfGJroyY5lcM6ZHWKqvsSdbAxLihBpA2kJxitJjHBLTpEt3ENzHbGx4Cca8Oi1-sDeMQVTq4Q4IhKjVSizSXKPf4BCR2Bbru50kYie696NZp4fLI0StByIiCiCZ6HsOkVhTHu61A_8VJm4rI8KiUHsTjJ0bHyq0WN8tYQ",
    "resource(\"file1\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test014_regex_constraint file123" {
  let actual = run_official_sample(
    "EqYBCjwKATAKDmZpbGVbMC05XSsudHh0GAMyJQojCgIIGxIHCAISAwiACBoUCgUKAwiACAoFCgMYgQgKBBoCCAgSJAgAEiAQVcdQsaFQWTevFTfGJroyY5lcM6ZHWKqvsSdbAxLihBpA2kJxitJjHBLTpEt3ENzHbGx4Cca8Oi1-sDeMQVTq4Q4IhKjVSizSXKPf4BCR2Bbru50kYie696NZp4fLI0StByIiCiCZ6HsOkVhTHu61A_8VJm4rI8KiUHsTjJ0bHyq0WN8tYQ",
    "resource(\"file123.txt\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test015_multi_queries_caveats default" {
  let actual = run_official_sample(
    "EpABCiYKD211c3RfYmVfcHJlc2VudAoFaGVsbG8YAyIKCggIgAgSAxiBCBIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkCw1GbTHgFfqFoHX6h19-HJAX7dUD_un2Kl8DPh_PqBEHS2453-WvL0UgQ9uXo_mGUFkqNw9WhbYsXWq_ndELYDIiIKIJnoew6RWFMe7rUD_xUmbisjwqJQexOMnRsfKrRY3y1h",
    "check if must_be_present($0) or must_be_present($0);\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test016_caveat_head_name default" {
  let actual = run_official_sample(
    "EoQBChoKBWhlbGxvGAMyDwoNCgIIGxIHCAISAxiACBIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkDOb4BPQ5Dmk6iFPZpKEL1PPJS4a3xtZxmTpuGTRrxNILu1LMlF5dDQLk51-l2iyqmXZAUBkDU1ZKCgtLJ2gJQCGn0KEwoEdGVzdBgDIgkKBwgbEgMYgQgSJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpAkW1WbMck4HcwRvxSZunQ2AQxFDW41pVbMy-COrKWvpp43-oZBEdzKsn2IXI0z1cmvs-I9lFpxt5Wp2avVUUbDyIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX618Q",
    "allow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test017_expressions default" {
  let actual = run_official_sample(
    "EpINCqcMCgtoZWxsbyB3b3JsZAoFaGVsbG8KBXdvcmxkCgZhYWFiZGUKBmEqYz8uZQoDYWJkCgNhYWEKAWIKAmRlCgZhYmNEMTIKAsOpCgNhYmMKA2RlZhgDMg4KDAoCCBsaBgoECgIwATIUChIKAggbGgwKBAoCMAAKBBICCAAyGgoYCgIIGxoSCgQKAjABCgQKAjABCgQaAggEMhoKGAoCCBsaEgoECgIwAAoECgIwAAoEGgIIBDIaChgKAggbGhIKBAoCEAEKBAoCEAIKBBoCCAAyGgoYCgIIGxoSCgQKAhACCgQKAhABCgQaAggBMhoKGAoCCBsaEgoECgIQAQoECgIQAgoEGgIIAjIaChgKAggbGhIKBAoCEAEKBAoCEAEKBBoCCAIyGgoYCgIIGxoSCgQKAhACCgQKAhABCgQaAggDMhoKGAoCCBsaEgoECgIQAgoECgIQAgoEGgIIAzIaChgKAggbGhIKBAoCEAMKBAoCEAMKBBoCCAQySgpICgIIGxpCCgQKAhABCgQKAhACCgQKAhADCgQaAggLCgQaAggJCgQKAhAECgQKAhACCgQaAggMCgQaAggKCgQKAhAFCgQaAggEMjIKMAoCCBsaFAoFCgMYgAgKBQoDGIEICgQaAggGGhQKBQoDGIAICgUKAxiCCAoEGgIIBzIcChoKAggbGhQKBQoDGIMICgUKAxiECAoEGgIICDIcChoKAggbGhQKBQoDGIMICgUKAxiFCAoEGgIIBTI2CjQKAggbGi4KBQoDGIMICgUKAxiGCAoFCgMYhwgKBBoCCAkKBQoDGIgICgQaAggJCgQaAggEMhwKGgoCCBsaFAoFCgMYiQgKBQoDGIkICgQaAggEMiEKHwoCCBsaGQoFCgMYiQgKBBICCAIKBAoCEAYKBBoCCAQyIQofCgIIGxoZCgUKAxiKCAoEEgIIAgoECgIQAgoEGgIIBDIiCiAKAggbGhoKCAoGIIGBnu8FCggKBiCBi6j-BQoEGgIIADIiCiAKAggbGhoKCAoGIIGLqP4FCggKBiCBgZ7vBQoEGgIIATIiCiAKAggbGhoKCAoGIIGBnu8FCggKBiCBi6j-BQoEGgIIAjIiCiAKAggbGhoKCAoGIIGLqP4FCggKBiCBi6j-BQoEGgIIAzIiCiAKAggbGhoKCAoGIIGLqP4FCggKBiCBgZ7vBQoEGgIIAzIiCiAKAggbGhoKCAoGIIGLqP4FCggKBiCBi6j-BQoEGgIIAzIiCiAKAggbGhoKCAoGIIGLqP4FCggKBiCBi6j-BQoEGgIIBDIeChwKAggbGhYKBgoEKgISqwoGCgQqAhKrCgQaAggEMiIKIAoCCBsaGgoMCgo6CAoCEAEKAhACCgQKAhACCgQaAggFMi4KLAoCCBsaJgoUChI6EAoGIIGBnu8FCgYggYuo_gUKCAoGIIGLqP4FCgQaAggFMiIKIAoCCBsaGgoMCgo6CAoCMAAKAjABCgQKAjABCgQaAggFMiUKIwoCCBsaHQoOCgw6CgoDGIsICgMYjAgKBQoDGIsICgQaAggFMigKJgoCCBsaIAoQCg46DAoEKgISqwoEKgI03goGCgQqAjTeCgQaAggFMiYKJAoCCBsaHgoMCgo6CAoCEAEKAhACCggKBjoECgIQAgoEGgIIBTIqCigKAggbGiIKDAoKOggKAhABCgIQAgoMCgo6CAoCEAEKAhACCgQaAggEMjoKOAoCCBsaMgoMCgo6CAoCEAEKAhACCgwKCjoICgIQAgoCEAMKBBoCCA8KCAoGOgQKAhACCgQaAggEMkIKQAoCCBsaOgoMCgo6CAoCEAEKAhACCgwKCjoICgIQAgoCEAMKBBoCCBAKEAoOOgwKAhABCgIQAgoCEAMKBBoCCAQyOgo4CgIIGxoyChAKDjoMCgIQAQoCEAIKAhADCgwKCjoICgIQAQoCEAIKBBoCCA8KBAoCEAEKBBoCCAUyQAo-CgIIGxo4ChAKDjoMCgIQAQoCEAIKAhADCgwKCjoICgIQAQoCEAIKBBoCCA8KBBICCAIKBAoCEAIKBBoCCAQyIAoeCgIIGxoYCgQKAjoACgQSAggCCgQKAhAACgQaAggEEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQPo1jk476olkFbGFnmzTR-ZOGRj7huMa4_4ghigyFXakf3oml2A1fikcgn7Jy-MiB09oYKVGIHpk4TPIOiFLtQUiIgogmeh7DpFYUx7utQP_FSZuKyPColB7E4ydGx8qtFjfLWE",
    "allow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test018_unbound_variables_in_rule default" {
  let actual = run_official_sample(
    "EnwKEhgDMg4KDAoCCBsSBggDEgIYABIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkCkQhDGoB5V6t78fYVAwubv-Aq27u3eR1Hec0-deAQ1eAaA0_Qtgmt-Dw3PSlujA_1MEWmEuzCXiBPUbthnkkMHGp4BCjQKB3VuYm91bmQKBGFueTEKBGFueTIYAyobCgsIAxIDCIAIEgIYABIMCAMSAwiBCBIDCIIIEiQIABIg1EJNHhKRM6FHl-NM3F-p2qdMKxtnqv5PtdGzPr3aWtEaQLCjPj9M0JlMB2bBlsTRHBXloPm_unmjorNd3QTduJAoKnxjM2raXGgLn5yUDB-nEn0mmXVMvHfCHhothcXvcAwiIgogykHasIWQ7aRCMbb89LsRDIUrJPAwv5lqifAszMV-tfE",
    "", false,
  )
  assert_eq(actual, "invalid_token")
}

///|
test "official test019_generating_ambient_from_variables default" {
  let actual = run_official_sample(
    "EnwKEhgDMg4KDAoCCBsSBggDEgIYABIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkCkQhDGoB5V6t78fYVAwubv-Aq27u3eR1Hec0-deAQ1eAaA0_Qtgmt-Dw3PSlujA_1MEWmEuzCXiBPUbthnkkMHGoQBChoKA2FueRgDKhEKBggDEgIYABIHCAMSAwiACBIkCAASINRCTR4SkTOhR5fjTNxfqdqnTCsbZ6r-T7XRsz692lrRGkDT-IIqm5vA7jkzKDxJPKnnEb5d2DObX-Lrod44BarU6E0-L7Sv-0p0PxKJkVwWdYK5QlNDY15FtwVz6h7noeoDIiIKIMpB2rCFkO2kQjG2_PS7EQyFKyTwML-ZaonwLMzFfrXx",
    "operation(\"write\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test020_sealed default" {
  let actual = run_official_sample(
    "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHWVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMalQEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIYABILCAQSAwiCCBICGAASJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpARfTBT52ej6BE1ovnouyM3bg19XXHuRPsWb1jbHCsrpqQ25BkugswhCkO0MQiu7cXAJKohPXgICsx6SNbvMFlDSJCEkCfIpa5yKK-ahepkwhc6RvDyntWIW_VMsGtUkqV47nLtsU8Y7kjVdFJBJGfc-ijQ23RAEcD5tGR54nVtqdgbpYE",
    "resource(\"file1\");\noperation(\"read\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}
