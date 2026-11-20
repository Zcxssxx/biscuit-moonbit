///|
fn required(name : String) -> String {
  @env.get_env_var(name).unwrap_or_else(() => abort("missing " + name))
}

///|
fn algorithm(value : String) -> @biscuit.SignatureAlgorithm {
  match value {
    "0" => @biscuit.Ed25519
    "1" => @biscuit.Secp256r1
    _ => abort("unknown algorithm")
  }
}

///|
fn check_decision(
  token : Bytes,
  root : @biscuit.VerificationKey,
  operation : String,
) -> Bool raise {
  let policy = @biscuit.parse_policy("allow if right(\"" + operation + "\")")
  try {
    let result = @biscuit.authorize_with_key(
      token,
      root,
      [],
      [],
      [],
      [policy],
      1000,
      100,
      @biscuit.ExternalFunctions::{ unary: Map([]), binary: Map([]), },
    )
    result.decision == @biscuit.Allow
  } catch {
    @biscuit.FailedCheck(_) | @biscuit.NoMatchingPolicy => false
    _ => abort("unexpected algorithm authorization error")
  }
}

///|
fn main {
  try {
    let root_algorithm = algorithm(required("ROOT_ALGORITHM"))
    let next_algorithm = algorithm(required("NEXT_ALGORITHM"))
    if required("MATRIX_MODE") == "mint" {
      let external_algorithm = algorithm(required("EXTERNAL_ALGORITHM"))
      let root = @biscuit.SigningKey::{
        algorithm: root_algorithm,
        secret: Bytes::make(32, b'\x21'),
      }
      let next = @biscuit.SigningKey::{
        algorithm: next_algorithm,
        secret: Bytes::make(32, b'\x22'),
      }
      let external = @biscuit.SigningKey::{
        algorithm: external_algorithm,
        secret: Bytes::make(32, b'\x24'),
      }
      let public_root = @biscuit.verification_key(root)
      let scope = @biscuit.trust_verification_key(
        @biscuit.verification_key(external),
      )
      let query = @biscuit.parse_query_body("approval(true)")
      let scoped_query = @biscuit.Query::{
        body: query.body,
        conditions: query.conditions,
        scopes: [scope],
      }
      let base = @biscuit.issue_with_keys(
        [@biscuit.parse_fact("right(\"read\")")],
        [],
        [@biscuit.Check::{ mode: @biscuit.Any, queries: [scoped_query], }],
        [],
        6,
        root,
        next,
      )
      assert_false(check_decision(base, public_root, "read"))
      let following_algorithm = if root_algorithm == next_algorithm &&
        root_algorithm == external_algorithm {
        next_algorithm
      } else if next_algorithm == @biscuit.Ed25519 {
        @biscuit.Secp256r1
      } else {
        @biscuit.Ed25519
      }
      let narrowed = @biscuit.attenuate_with_key(
        base,
        public_root,
        [],
        [],
        [@biscuit.parse_check("check if right(\"read\")")],
        [],
        6,
        @biscuit.SigningKey::{
          algorithm: following_algorithm,
          secret: Bytes::make(32, b'\x23'),
        },
      )
      let request = @biscuit.third_party_request_with_key(narrowed, public_root)
      let payload = @biscuit.encode_block(
        [@biscuit.parse_fact("approval(true)")],
        [],
        [],
        6,
      )
      let signed = @biscuit.sign_third_party_with_key(
        request, payload, external,
      )
      let approved = @biscuit.append_third_party_with_key(
        narrowed,
        public_root,
        @biscuit.ThirdPartyBlockContents::{
          payload,
          external_signature: signed,
        },
        @biscuit.SigningKey::{
          algorithm: root_algorithm,
          secret: Bytes::make(32, b'\x25'),
        },
      )
      assert_true(check_decision(approved, public_root, "read"))
      assert_false(check_decision(approved, public_root, "write"))
      let sealed_token = @biscuit.seal_with_key(approved, public_root)
      assert_true(check_decision(sealed_token, public_root, "read"))
      println("ROOT_KEY=" + @hex.encode(public_root.key))
      println("TOKEN=" + @biscuit.token_to_base64url(approved))
      println("SEALED=" + @biscuit.token_to_base64url(sealed_token))
    } else {
      let root = @biscuit.VerificationKey::{
        algorithm: root_algorithm,
        key: @hex.decode(required("ROOT_KEY")),
      }
      let token = @biscuit.token_from_base64url(required("TOKEN"))
      @biscuit.verify_with_key(token, root)
      assert_true(check_decision(token, root, "read"))
      assert_false(check_decision(token, root, "write"))
      if required("MATRIX_MODE") == "append" {
        let attenuated = @biscuit.attenuate_with_key(
          token,
          root,
          [],
          [],
          [@biscuit.parse_check("check if right(\"read\")")],
          [],
          6,
          @biscuit.SigningKey::{
            algorithm: next_algorithm,
            secret: Bytes::make(32, b'\x26'),
          },
        )
        assert_true(check_decision(attenuated, root, "read"))
        println("TOKEN=" + @biscuit.token_to_base64url(attenuated))
      } else {
        let rejected = try {
          ignore(
            @biscuit.append_with_key(
              token,
              root,
              @biscuit.encode_block([], [], [], 6),
              @biscuit.SigningKey::{
                algorithm: next_algorithm,
                secret: Bytes::make(32, b'\x26'),
              },
            ),
          )
          false
        } catch {
          @biscuit.Unsupported(_) => true
          _ => false
        }
        assert_true(rejected)
        println("SEALED_VALID")
      }
    }
  } catch {
    _ => abort("algorithm matrix fixture failed")
  }
}
