///|
test "official test021_parsing default" {
  let actual = run_official_sample(
    "EpUBCisKDG5zOjpmYWN0XzEyMwoNaGVsbG8gw6kJ8J-YgRgDIgoKCAiACBIDGIEIEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQNSy9Be26QZDT99QWK_Kv8uY02KPgU8cndfmQlDZvuxEZa_1G9DLLoXQ5n3J9hPCpCr2FYxni8b4tGhM06LQ0wIiIgogmeh7DpFYUx7utQP_FSZuKyPColB7E4ydGx8qtFjfLWE",
    "check if ns::fact_123(\"hello é\t😁\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test022_default_symbols default" {
  let actual = run_official_sample(
    "EoUDCpoCGAMiCAoGCAASAhAAIggKBggBEgIQASIICgYIAhICEAIiCAoGCAMSAhADIggKBggEEgIQBCIICgYIBRICEAUiCAoGCAYSAhAGIggKBggHEgIQByIICgYICBICEAgiCAoGCAkSAhAJIggKBggKEgIQCiIICgYICxICEAsiCAoGCAwSAhAMIggKBggNEgIQDSIICgYIDhICEA4iCAoGCA8SAhAPIggKBggQEgIQECIICgYIERICEBEiCAoGCBISAhASIggKBggTEgIQEyIICgYIFBICEBQiCAoGCBUSAhAVIggKBggWEgIQFiIICgYIFxICEBciCAoGCBgSAhAYIggKBggZEgIQGSIICgYIGhICEBoiCAoGCBsSAhAbEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQHXOSNSW_Sj5mQWQF4OhukbX_41p-dNk0VRv1zAGAm6uUYSa0RkKSuUhoKEmn5xpUeImr7qPzST6UPZ5FiQ5rgkiIgogmeh7DpFYUx7utQP_FSZuKyPColB7E4ydGx8qtFjfLWE",
    "check if read(0), write(1), resource(2), operation(3), right(4), time(5), role(6), owner(7), tenant(8), namespace(9), user(10), team(11), service(12), admin(13), email(14), group(15), member(16), ip_address(17), client(18), client_ip(19), domain(20), path(21), version(22), cluster(23), node(24), hostname(25), nonce(26), query(27);\n\nallow if true;\n",
    false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test023_execution_scope default" {
  let actual = run_official_sample(
    "EocBCh0KDmF1dGhvcml0eV9mYWN0GAMiCQoHCIAIEgIQARIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkD5tJhmyu9eznvhTsWps22YyoHQazBusLTFfNdDavF29A7pcvQJA_h-xEYKuLGt_L-psZsgppVaHo2ufYiyB2AFGoQBChoKC2Jsb2NrMV9mYWN0GAMiCQoHCIEIEgIQARIkCAASINRCTR4SkTOhR5fjTNxfqdqnTCsbZ6r-T7XRsz692lrRGkCIkFS5EZ5EQOVNobYyZqmND2ZGzeGV_vIG79ixM8-y7nvkmzKppZJezkUuZPnm9tgNq0IukWxZlnXdaM3qBTgCGpUBCisKA3ZhchgDMhAKDgoCCBsSCAiACBIDCIIIMhAKDgoCCBsSCAiBCBIDCIIIEiQIABIgNsPtY--GEIVJZtTwQgeNeP3rxwWlAq0rkPP8ZPe-u5caQAqF_78n4IqiNmW6DZaphbJ010dVbJ8Bb9f1kMZB7Q5BMykVIapEKzIO6c6A9a1wG5FKDIez36DMkmKdzpQgGAYiIgogE2rE5I8ZBdaX-BnfT6KkEgJ-WaDv6E-3MFpA5_6dK1c",
    "allow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test024_third_party default" {
  let actual = run_official_sample(
    "ErABCkYYBCIICgYIBBICGAAyEgoQCgIIGxIGCA8SAhgNIgIQAEIkCAASIKzdbVtTv-5Hi_aJ-OAS_nmIv3VePXxRUpR6vBSbwgGJEiQIABIg1EJNHhKRM6FHl-NM3F-p2qdMKxtnqv5PtdGzPr3aWtEaQEcOS_eqKgGrOcmBUL0GqhW0ql2GUJBEqICahjTNjPK0ImmlGndLZdELrJNp0BMHCwAYeSUZao5oAQhHPxHPjwMa8gEKHBgFIggKBggPEgIYDTIOCgwKAggbEgYIBBICGAASJAgAEiA2w-1j74YQhUlm1PBCB414_evHBaUCrSuQ8_xk9767lxpAkBsq9NrPM0WNLZGsSEtgutlI6NEPqpaVsJYFTVtG6DKpd7YLF0ZMrPVFrQgB9UnqRUZ18KyIxBNAaSXir4P_CCJoCkCo38e8sEEVD7PJ920Pcnb-nkG1CeS8bnK0FsUPQmnxQlTgNlgGvDOHLpFWySqY3abg0da-TzpPpdQGgrUa-4MGEiQIABIgrN1tW1O_7keL9on44BL-eYi_dV49fFFSlHq8FJvCAYkoASIiCiATasTkjxkF1pf4Gd9PoqQSAn5ZoO_oT7cwWkDn_p0rVw",
    "allow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test025_check_all A, B" {
  let actual = run_official_sample(
    "EtsBCnEKEmFsbG93ZWRfb3BlcmF0aW9ucwoBQQoBQgoCb3AKB2FsbG93ZWQYBCITChEIgAgSDDoKCgMYgQgKAxiCCDIxCi0KAggbEgcIAxIDCIMIEggIgAgSAwiECBoUCgUKAwiECAoFCgMIgwgKBBoCCAUQARIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkDEVoFwEuHVI8bRRbbWo0ddn33UODxTVFT_P3Rez0I0mEzgm53sBVHz14Or6FD4Js5DsS8f2RmZpHU6Vuz0xW0NIiIKIJnoew6RWFMe7rUD_xUmbisjwqJQexOMnRsfKrRY3y1h",
    "operation(\"A\");\noperation(\"B\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test025_check_all A, invalid" {
  let actual = run_official_sample(
    "EtsBCnEKEmFsbG93ZWRfb3BlcmF0aW9ucwoBQQoBQgoCb3AKB2FsbG93ZWQYBCITChEIgAgSDDoKCgMYgQgKAxiCCDIxCi0KAggbEgcIAxIDCIMIEggIgAgSAwiECBoUCgUKAwiECAoFCgMIgwgKBBoCCAUQARIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkDEVoFwEuHVI8bRRbbWo0ddn33UODxTVFT_P3Rez0I0mEzgm53sBVHz14Or6FD4Js5DsS8f2RmZpHU6Vuz0xW0NIiIKIJnoew6RWFMe7rUD_xUmbisjwqJQexOMnRsfKrRY3y1h",
    "operation(\"A\");\noperation(\"invalid\");\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test025_check_all no matches" {
  let actual = run_official_sample(
    "EtsBCnEKEmFsbG93ZWRfb3BlcmF0aW9ucwoBQQoBQgoCb3AKB2FsbG93ZWQYBCITChEIgAgSDDoKCgMYgQgKAxiCCDIxCi0KAggbEgcIAxIDCIMIEggIgAgSAwiECBoUCgUKAwiECAoFCgMIgwgKBBoCCAUQARIkCAASIBBVx1CxoVBZN68VN8YmujJjmVwzpkdYqq-xJ1sDEuKEGkDEVoFwEuHVI8bRRbbWo0ddn33UODxTVFT_P3Rez0I0mEzgm53sBVHz14Or6FD4Js5DsS8f2RmZpHU6Vuz0xW0NIiIKIJnoew6RWFMe7rUD_xUmbisjwqJQexOMnRsfKrRY3y1h",
    "allow if true;\n", false,
  )
  assert_eq(actual, "denied")
}

///|
test "official test026_public_keys_interning default" {
  let actual = run_official_sample(
    "ErQBCkoYBCIICgYIGxICEAAyFgoUCgIIGxoGCgQKAjABIgIIASICEABCJAgAEiCs3W1bU7_uR4v2ifjgEv55iL91Xj18UVKUerwUm8IBiRIkCAASIIN6_pA8Mqwmol0hAhqX_48-3ihU8F_JXykq175eyBKAGkA3cc7-cb6yHq01pZyBFu6CYnpXF8ApXzWYBmKrzLFZ_hs3hIyxgY5Uhla9T9iC0AlKLaq2McdrK3LjoJORS_4EGoEDCqoBGAUiCAoGCBsSAhABKiAKCggbEgIQARICEAISBggbEgIQARIGCBsSAhACIgIQADIaChgKAggbEgYIGxICEAISBggbEgIQAyICEAAyEgoQCgIIGxIGCBsSAhABIgIQAUIkCAASIKBgJw236cnwbo-cwzpk6Z9llq8SywHEtjjfivx7ZCRjQiQIABIgrN1tW1O_7keL9on44BL-eYi_dV49fFFSlHq8FJvCAYkSJAgAEiCgiR2m2QbNJvnenIjeDYhBIwkW2IxVPSOFVfbJOXNDoRpAcRPU27O2iLgOlB82WixjQtSAx37QOTe8z4XcXMNVTHUXiHsbDJAhOIpx5sqQR6q6qtWuW1EaKICQJWhESpjlCyJoCkAV1wK_83HfYc395nniwC1QRJOG5ea8jIxzKxU-RjRfWCoSrNAHo36OqdFtML-_GncG_WWYD_ZhCHkI1YHkhGUPEiQIABIgrN1tW1O_7keL9on44BL-eYi_dV49fFFSlHq8FJvCAYkoARrfAgqIARgFIggKBggbEgIQAjIaChgKAggbEgYIGxICEAISBggbEgIQAyICEAAyEgoQCgIIGxIGCBsSAhABIgIQAUIkCAASIKBgJw236cnwbo-cwzpk6Z9llq8SywHEtjjfivx7ZCRjQiQIABIgrN1tW1O_7keL9on44BL-eYi_dV49fFFSlHq8FJvCAYkSJAgAEiCGoqcBLrRLNsggZKowDkkVUT8GKA9dmCbG0yvovyQN4hpA0OP8S70bcyACKACvkJWFqpBvZ3xMp5wnWhC2d59mk4TEZO6EobBPE4d6JXYah0dINiwGX00VqMq1xeFsNAdEAyJoCkAduSh45KYh4oXIJKDkuQsXkSFmaWkdBcJ1Pq7w7mTCnVrcwzwbnMkF9vfIIxKAZR4J8hxEw-bvkm8ex7e3X04HEiQIABIgoGAnDbfpyfBuj5zDOmTpn2WWrxLLAcS2ON-K_HtkJGMoARrfAgqIARgFIggKBggbEgIQAzIaChgKAggbEgYIGxICEAISBggbEgIQAyICEAAyEgoQCgIIGxIGCBsSAhABIgIQAUIkCAASIKBgJw236cnwbo-cwzpk6Z9llq8SywHEtjjfivx7ZCRjQiQIABIgrN1tW1O_7keL9on44BL-eYi_dV49fFFSlHq8FJvCAYkSJAgAEiCLVn-BAFsEwrfyhZJlvCsrUR-9YNAsiaP2pYsvFvrE2xpAKbfgofEYphhYFKVSZgxRbENIIETigOeo3oW45-VJR-Cugus517Uk1LcsuYEqekuIcZZPj4JbHB7YXTRMBSgdDSJoCkAoBsFvKd27TzURwSyyH1AVNouNSp2SFDKJwsJjMQKWdkNJS0Jez65kjCg7sA_5NS36n-2KUh5wCReJjX6YC-8MEiQIABIgoGAnDbfpyfBuj5zDOmTpn2WWrxLLAcS2ON-K_HtkJGMoARrtAQqAARgEIggKBggbEgIQBDISChAKAggbEgYIGxICEAIiAhABMhIKEAoCCBsSBggbEgIQBCICEAJCJAgAEiCgYCcNt-nJ8G6PnMM6ZOmfZZavEssBxLY434r8e2QkY0IkCAASIPmNqMHPkHhWQxv8Pch1MeDqrbqQ-RntwjJAW4WHfvE2EiQIABIg6Y2LHUEc4nsDTuX5O51lJd82HM_MACDk5yi3DJOx4IAaQMClBdTZIaiy0LiFkX1C4ryoe1MC0TJJphr284Aq9E1pHECmJPkB1ndyR0DLl0oYiuscOZLBVlrA--w6pPaNrAooASIiCiDcaWgZWoQNvBi-HNPjboy9M_zf7Vs7DRKnqB2NeUSOMA",
    "check if query(1, 2) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189, ed25519/a060270db7e9c9f06e8f9cc33a64e99f6596af12cb01c4b638df8afc7b642463;\n\ndeny if query(3);\ndeny if query(1, 2);\ndeny if query(0) trusting ed25519/acdd6d5b53bfee478bf689f8e012fe7988bf755e3d7c5152947abc149bc20189;\nallow if true;\n",
    false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test027_integer_wraparound default" {
  let actual = run_official_sample(
    "Ev4BCpMBGAQyLgosCgIIGxomCggKBhCAyK-gJQoICgYQgMivoCUKBBoCCAsKBAoCEAAKBBoCCBQyLgosCgIIGxomCgwKChD__________38KBAoCEAEKBBoCCAkKBAoCEAAKBBoCCBQyLwotCgIIGxonCg0KCxCAgICAgICAgIABCgQKAhABCgQaAggKCgQKAhAACgQaAggUEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQPteesK7iS9c8vtZZ3z60flt6rvI4Vjj_Rte58S2lJyZniFpGHy-5TuUPuva2q9ogydHuqjP-i_594AlofVfRAwiIgogmeh7DpFYUx7utQP_FSZuKyPColB7E4ydGx8qtFjfLWE",
    "allow if true;\n", false,
  )
  assert_eq(actual, "overflow")
}

///|
test "official test028_expressions_v4 default" {
  let actual = run_official_sample(
    "EvkCCo4CCgdhYmNEMTJ4CgZhYmNEMTIYBDIaChgKAggbGhIKBAoCMAEKBAoCMAAKBBoCCBQyGgoYCgIIGxoSCgQKAhABCgQKAhADCgQaAggUMjIKMAoCCBsaKgoECgIQAQoECgIQAgoEGgIIEgoECgIQAwoEGgIIEwoECgIQAAoEGgIIBDIcChoKAggbGhQKBQoDGIAICgUKAxiBCAoEGgIIFDIiCiAKAggbGhoKCAoGIIHZsZwGCggKBiCBi6j-BQoEGgIIFDIfCh0KAggbGhcKBwoFKgMSq80KBgoEKgISqwoEGgIIFDIqCigKAggbGiIKDAoKOggKAhABCgIQBAoMCgo6CAoCEAEKAhACCgQaAggUEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQJQCwHkjqjO8kR3oDmHziPXEUz5rNuRTF9wdsea8x2ZO0MHFBNDKiSUggAiWHZW728Nvbj2RsxczacwZ7WJemgwiIgogmeh7DpFYUx7utQP_FSZuKyPColB7E4ydGx8qtFjfLWE",
    "allow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test029_reject_if default" {
  let actual = run_official_sample(
    "EpEBCiUKBHRlc3QYBjIbChcKAggbEggIgAgSAwiACBoHCgUKAwiACBACEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQI0XUyn3zxYfPLW63FLw4i5SCVbNtWXtvtlj6bBHsgoxSn3hyeumt7v2ImNlFqs8x_kVcq6UYdMVKCXg7OUSegooASIiCiCZ6HsOkVhTHu61A_8VJm4rI8KiUHsTjJ0bHyq0WN8tYQ",
    "test(false);\n\nallow if true;\n", false,
  )
  assert_eq(actual, "ok")
}

///|
test "official test029_reject_if rejection" {
  let actual = run_official_sample(
    "EpEBCiUKBHRlc3QYBjIbChcKAggbEggIgAgSAwiACBoHCgUKAwiACBACEiQIABIgEFXHULGhUFk3rxU3xia6MmOZXDOmR1iqr7EnWwMS4oQaQI0XUyn3zxYfPLW63FLw4i5SCVbNtWXtvtlj6bBHsgoxSn3hyeumt7v2ImNlFqs8x_kVcq6UYdMVKCXg7OUSegooASIiCiCZ6HsOkVhTHu61A_8VJm4rI8KiUHsTjJ0bHyq0WN8tYQ",
    "test(true);\n\nallow if true;\n", false,
  )
  assert_eq(actual, "denied")
}
