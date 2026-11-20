// Learn more about moon.mod configuration:
// https://docs.moonbitlang.com/en/latest/toolchain/moon/module.html
//
// To add a dependency, run this command in your terminal:
//   moon add moonbitlang/x
//
// Or manually declare it in `import`, for example:
// import {
//   "moonbitlang/x@0.4.6",
// }

name = "Zcxssxx/biscuit"

version = "0.1.0"

readme = "README.md"

repository = "https://github.com/Zcxssxx/biscuit-moonbit"

license = "Apache-2.0"

keywords = [ "biscuit", "authorization", "datalog", "ed25519" ]

preferred_target = "wasm"

description = "An experimental Biscuit authorization token implementation for MoonBit"

import {
  "hustcer/ed25519@0.6.1",
  "moonbitstack/mooncrypt@0.3.1",
}
