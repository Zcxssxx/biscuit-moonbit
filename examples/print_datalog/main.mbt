///|
fn main {
  try {
    let fact = @biscuit.parse_fact("member(10)")
    let rule = @biscuit.parse_rule(
      "eligible($n) <- member($n), $n >= 10 trusting authority",
    )
    let check = @biscuit.parse_check("check if eligible($n)")
    let policy = @biscuit.parse_policy("allow if eligible($n)")
    let source = @biscuit.print_fact(fact) +
      ";\n" +
      @biscuit.print_rule(rule) +
      ";\n" +
      @biscuit.print_check(check) +
      ";\n" +
      @biscuit.print_policy(policy) +
      ";"
    println(source)
  } catch {
    _ => println("Datalog printing failed")
  }
}
