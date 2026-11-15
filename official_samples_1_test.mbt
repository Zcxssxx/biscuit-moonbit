///|
test "official test001_basic default" {
  let actual = run_official_sample(
    "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHWVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMalQEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIYABILCAQSAwiCCBICGAASJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpARfTBT52ej6BE1ovnouyM3bg19XXHuRPsWb1jbHCsrpqQ25BkugswhCkO0MQiu7cXAJKohPXgICsx6SNbvMFlDSIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX618Q",
    "resource(\"file1\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test002_different_root_key default" {
  let actual = run_official_sample(
    "EoIBChgKBWZpbGUxGAMiDQoLCAQSAxiACBICGAASJAgAEiA8b_aenR_tJpC-YgiZTdPabDqsaPmTs6_oIzhwDLt-DxpAsAm7GjYvmwhNXRaNW7cp9yCrJDWHSD_XDll906TiP_bm9aEkaoFGe8ku618lgbL1NQ4vObnAzGkVdyaLm001BRqVAQorCgEwGAMyJAoiCgIIGxIHCAISAwiBCBIGCAMSAhgAEgsIBBIDCIEIEgIYABIkCAASIJTeCBeyvWuHNJ9Uv_VEIyC2CAVUeRD9iZnw1lhoidDjGkBOSpfHBywXfnf55qeX732VhHWIHAHuc5Y7lvHv8lx6PwudeGE39mfuCjSZpG1y79s4oLGpfiQQ_EJ6Xbg2YaQBIiIKIKnizwCMlIIJXTUNcEavQ-HdabYohs11zRwKMlUvcvN1",
    "", false,
  )
  assert_eq(actual, "bad_signature")
}

///|
test "official test003_invalid_signature_format default" {
  let actual = run_official_sample(
    "EncKPQoFZmlsZTEKBWZpbGUyGAMiDQoLCAQSAxiACBICGAAiDQoLCAQSAxiBCBICGAAiDQoLCAQSAxiACBICGAESJAgAEiAQVcdQsaFQWTevFTfGJroyY5lcM6ZHWKqvsSdbAxLihBoQdZWhEqHrW4Gm45iFLmEYtxqVAQorCgEwGAMyJAoiCgIIGxIHCAISAwiCCBIGCAMSAhgAEgsIBBIDCIIIEgIYABIkCAASINRCTR4SkTOhR5fjTNxfqdqnTCsbZ6r-T7XRsz692lrRGkBF9MFPnZ6PoETWi-ei7IzduDX1dce5E-xZvWNscKyumpDbkGS6CzCEKQ7QxCK7txcAkqiE9eAgKzHpI1u8wWUNIiIKIMpB2rCFkO2kQjG2_PS7EQyFKyTwML-ZaonwLMzFfrXx",
    "", false,
  )
  assert_eq(actual, "invalid_token")
}

///|
test "official test004_random_block default" {
  let actual = run_official_sample(
    "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHWVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMaigEKIBOPl08C7zD-nuPmK1DySlbZBCtLwCUfIySNkpkECK-kEiQIABIg1EJNHhKRM6FHl-NM3F-p2qdMKxtnqv5PtdGzPr3aWtEaQEX0wU-dno-gRNaL56LsjN24NfV1x7kT7Fm9Y2xwrK6akNuQZLoLMIQpDtDEIru3FwCSqIT14CArMekjW7zBZQ0iIgogykHasIWQ7aRCMbb89LsRDIUrJPAwv5lqifAszMV-tfE",
    "", false,
  )
  assert_eq(actual, "bad_signature")
}

///|
test "official test005_invalid_signature default" {
  let actual = run_official_sample(
    "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHaVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMalQEKKwoBMBgDMiQKIgoCCBsSBwgCEgMIgggSBggDEgIYABILCAQSAwiCCBICGAASJAgAEiDUQk0eEpEzoUeX40zcX6nap0wrG2eq_k-10bM-vdpa0RpARfTBT52ej6BE1ovnouyM3bg19XXHuRPsWb1jbHCsrpqQ25BkugswhCkO0MQiu7cXAJKohPXgICsx6SNbvMFlDSIiCiDKQdqwhZDtpEIxtvz0uxEMhSsk8DC_mWqJ8CzMxX618Q",
    "", false,
  )
  assert_eq(actual, "bad_signature")
}

///|
test "official test006_reordered_blocks default" {
  let actual = run_official_sample(
    "EqcBCj0KBWZpbGUxCgVmaWxlMhgDIg0KCwgEEgMYgAgSAhgAIg0KCwgEEgMYgQgSAhgAIg0KCwgEEgMYgAgSAhgBEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHWVoRKh61uBpuOYhS5hGLf1uMu_9FJ3jmVRAOX7T6qNOir1L-LE-VJIeWBWdfriatvEeD4Mr8Q1IvqCOF85bAMafQoTGAMyDwoNCgIIGxIHCAISAxiACBIkCAASIDbD7WPvhhCFSWbU8EIHjXj968cFpQKtK5Dz_GT3vruXGkBdF7IQW7p4cNwuZCyVLmWvMTwPvxu4Cg1oqbYCF3YYfOsUQVPiSj2K6hDyEfEMGMCFpr_J1Ykh5i-1L7ZW37kLGpUBCisKATAYAzIkCiIKAggbEgcIAhIDCIIIEgYIAxICGAASCwgEEgMIgggSAhgAEiQIABIg1EJNHhKRM6FHl-NM3F-p2qdMKxtnqv5PtdGzPr3aWtEaQEX0wU-dno-gRNaL56LsjN24NfV1x7kT7Fm9Y2xwrK6akNuQZLoLMIQpDtDEIru3FwCSqIT14CArMekjW7zBZQ0iIgogE2rE5I8ZBdaX-BnfT6KkEgJ-WaDv6E-3MFpA5_6dK1c",
    "", false,
  )
  assert_eq(actual, "bad_signature")
}

///|
test "official test007_scoped_rules default" {
  let actual = run_official_sample(
    "Ep8BCjUKB3VzZXJfaWQKBWFsaWNlCgVmaWxlMRgDIgoKCAiACBIDGIEIIg4KDAgHEgMYgQgSAxiCCBIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkBNhsmvgI3C4Fg_Rygub13z4J3CZNUjHsNgtFGeFd2u7GCyWpu8si6NGS9NNqDaP5JDcR4wU1sA7lXFPLE5XyMKGsgBCl4KATAKATEYAyouCgsIBBIDCIMIEgIYABIHCAISAwiDCBIICIAIEgMIhAgSDAgHEgMIhAgSAwiDCDIkCiIKAggbEgcIAhIDCIMIEgYIAxICGAASCwgEEgMIgwgSAhgAEiQIABIg1EJNHhKRM6FHl-NM3F-p2qdMKxtnqv5PtdGzPr3aWtEaQGMgjGaMZvO6aScUC6N1M1k7JeA0WUR4BdSyqLda3u9FeUw9ckmv5Qbtd8zuJ2Fgu0BSpACTAr00hxpEDwcLRQkagwEKGQoFZmlsZTIYAyIOCgwIBxIDGIEIEgMYhQgSJAgAEiA2w-1j74YQhUlm1PBCB414_evHBaUCrSuQ8_xk9767lxpA2NqYKIjq6MA45IlKjAb8V9jl8GrS6XK5z0veSa1ggEVYoNGTgZJZbHAtjk9_EuwZIB18M9DNd3dKDYeaM4gNAiIiCiATasTkjxkF1pf4Gd9PoqQSAn5ZoO_oT7cwWkDn_p0rVw",
    "resource(\"file2\");\noperation(\"read\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test008_scoped_checks default" {
  let actual = run_official_sample(
    "EoIBChgKBWZpbGUxGAMiDQoLCAQSAxiACBICGAASJAgAEiAQVcdQsaFQWTevFTfGJroyY5lcM6ZHWKqvsSdbAxLihBpAqAyYXd74lVGMIW9kxl3NUKXZfQEqlEU9eRWa7SmBZUsf6XSMaGxWZ2BAJqlPuNuKHQLedH32Hpn6mmP_KHitABqVAQorCgEwGAMyJAoiCgIIGxIHCAISAwiBCBIGCAMSAhgAEgsIBBIDCIEIEgIYABIkCAASINRCTR4SkTOhR5fjTNxfqdqnTCsbZ6r-T7XRsz692lrRGkB330VEK-hqQWqgL9nZjW1HA8Y0qeOx0pO0H13JeEmvvn-u7IwiohBXSIiswAj7ZP5pHsno0mVVhvlw2aa2V3AAGoIBChgKBWZpbGUyGAMiDQoLCAQSAxiCCBICGAASJAgAEiA2w-1j74YQhUlm1PBCB414_evHBaUCrSuQ8_xk9767lxpAsxOYrv6X09tB68RFdg8hb7Oqe_dDmtz8OgdIm_zBY5cK8_TiD1RgqiTPhBEBpasRTSGswO6NRCuud5OxIShJACIiCiATasTkjxkF1pf4Gd9PoqQSAn5ZoO_oT7cwWkDn_p0rVw",
    "resource(\"file2\");\noperation(\"read\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test009_expired_token default" {
  let actual = run_official_sample(
    "EmwKAhgDEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQMJIkHu25fQzu7Xt9jZ7OZ6-_KDTIdCy6p_Gf2bcEGTOkmrbDAXZDD6KKDMyizV495xOG8pDWD2bz7K6bDcwPQAarAEKQgoFZmlsZTEYAzIPCg0KAggbEgcIAhIDGIAIMiYKJAoCCBsSBggFEgIIBRoWCgQKAggFCggKBiCAt-vgBQoEGgIIAhIkCAASINRCTR4SkTOhR5fjTNxfqdqnTCsbZ6r-T7XRsz692lrRGkCk7feq6oZYu5rhmz_-KtzHfMnxbCSa6wqFpYS1Ni-J8n98Z6wK8W1xcGc9bR-xVj0ZNLJexaRh9sAfpJgFzV4HIiIKIMpB2rCFkO2kQjG2_PS7EQyFKyTwML-ZaonwLMzFfrXx",
    "resource(\"file1\");\noperation(\"read\");\ntime(2020-12-21T09:23:12Z);\n\nallow if true;\n",
    false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test010_authorizer_scope default" {
  let actual = run_official_sample(
    "EoIBChgKBWZpbGUxGAMiDQoLCAQSAxiACBICGAASJAgAEiAQVcdQsaFQWTevFTfGJroyY5lcM6ZHWKqvsSdbAxLihBpAqAyYXd74lVGMIW9kxl3NUKXZfQEqlEU9eRWa7SmBZUsf6XSMaGxWZ2BAJqlPuNuKHQLedH32Hpn6mmP_KHitABqCAQoYCgVmaWxlMhgDIg0KCwgEEgMYgQgSAhgAEiQIABIg1EJNHhKRM6FHl-NM3F-p2qdMKxtnqv5PtdGzPr3aWtEaQJZuzrKqk3xBslNogIurbgaYwCpAON5mnQB8nD1DYCY4pkAINVjRV2rIDPPrKsanWFUn4PbBplQC8JNc9_TfgAUiIgogykHasIWQ7aRCMbb89LsRDIUrJPAwv5lqifAszMV-tfE",
    "resource(\"file2\");\noperation(\"read\");\n\ncheck if right($0, $1), resource($0), operation($1);\n\nallow if true;\n",
    false,
  )
  assert_eq(actual, "denied")
}
