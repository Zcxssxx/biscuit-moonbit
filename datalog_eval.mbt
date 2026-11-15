///|
priv enum RuntimeValue {
  RuntimePlain(Value)
  RuntimeClosure(ExpressionClosure)
}

///|
priv struct ExpressionBudget {
  mut remaining : Int32
}

///|
fn ExpressionBudget::consume(
  self : ExpressionBudget,
) -> Unit raise AuthorizationError {
  if self.remaining <= 0 {
    raise Expression(StepLimit)
  }
  self.remaining -= 1
}

///|
fn validate_expression_program(
  operations : Array[ExpressionOp],
  _parameters : Int32,
) -> Unit raise TokenError {
  if operations.length() == 0 {
    raise Malformed("empty expression program")
  }
  let stack : Array[Int32] = []
  for operation in operations {
    match operation {
      Value(_) => stack.push(-1)
      Closure(closure) => {
        validate_expression_program(
          closure.operations,
          closure.parameters.length(),
        )
        stack.push(closure.parameters.length())
      }
      Unary(_) => {
        if stack.length() < 1 {
          raise Malformed("expression stack underflow at unary operator")
        }
        if stack.pop() != Some(-1) {
          raise Malformed("unary operator received a closure")
        }
        stack.push(-1)
      }
      Binary(operator) => {
        if stack.length() < 2 {
          raise Malformed("expression stack underflow at binary operator")
        }
        let right = stack.pop()
        let left = stack.pop()
        match operator {
          Any | All | LazyAnd | LazyOr => {
            let arity = match operator {
              Any | All => 1
              _ => 0
            }
            if right != Some(arity) || left != Some(-1) {
              raise Malformed("operator received an invalid closure")
            }
          }
          TryOr =>
            if left != Some(0) || right != Some(-1) {
              raise Malformed(
                "try operator expects a closure and fallback value",
              )
            }
          _ =>
            if right != Some(-1) || left != Some(-1) {
              raise Malformed("binary operator received a closure")
            }
        }
        stack.push(-1)
      }
    }
  }
  if stack.length() != 1 || stack[0] != -1 {
    raise Malformed("expression must leave exactly one value on the stack")
  }
}

///|
pub fn evaluate_expression_with_externals(
  operations : Array[ExpressionOp],
  bindings : Map[String, Value],
  max_steps : Int32,
  externals : ExternalFunctions,
) -> Value raise AuthorizationError {
  if max_steps <= 0 {
    raise Expression(StepLimit)
  }
  let budget = ExpressionBudget::{ remaining: max_steps, }
  evaluate_expression_ops(operations, bindings, budget, externals)
}

///|
fn evaluate_expression_ops(
  operations : Array[ExpressionOp],
  bindings : Map[String, Value],
  budget : ExpressionBudget,
  externals : ExternalFunctions,
) -> Value raise AuthorizationError {
  let stack : Array[RuntimeValue] = []
  for operation in operations {
    budget.consume()
    match operation {
      Value(Literal(value)) => stack.push(RuntimePlain(value))
      Value(Reference(name)) =>
        match bindings.get(name) {
          Some(value) => stack.push(RuntimePlain(value))
          None => raise Expression(UnboundVariable(name))
        }
      Closure(closure) => stack.push(RuntimeClosure(closure))
      Unary(operator) => {
        let value = pop_runtime_value(stack)
        stack.push(RuntimePlain(evaluate_unary(operator, value, externals)))
      }
      Binary(LazyAnd) => {
        let closure = pop_runtime_closure(stack)
        let left = pop_runtime_value(stack)
        match left {
          Boolean(false) => stack.push(RuntimePlain(Boolean(false)))
          Boolean(true) =>
            match eval_zero_arg_closure(closure, bindings, budget, externals) {
              Boolean(value) => stack.push(RuntimePlain(Boolean(value)))
              _ => raise Expression(TypeMismatch("&& expects booleans"))
            }
          _ => raise Expression(TypeMismatch("&& expects booleans"))
        }
      }
      Binary(LazyOr) => {
        let closure = pop_runtime_closure(stack)
        let left = pop_runtime_value(stack)
        match left {
          Boolean(true) => stack.push(RuntimePlain(Boolean(true)))
          Boolean(false) =>
            match eval_zero_arg_closure(closure, bindings, budget, externals) {
              Boolean(value) => stack.push(RuntimePlain(Boolean(value)))
              _ => raise Expression(TypeMismatch("|| expects booleans"))
            }
          _ => raise Expression(TypeMismatch("|| expects booleans"))
        }
      }
      Binary(Any) => {
        let closure = pop_runtime_closure(stack)
        let collection = pop_runtime_value(stack)
        stack.push(
          RuntimePlain(
            evaluate_collection_closure(
              collection, closure, bindings, budget, externals, true,
            ),
          ),
        )
      }
      Binary(All) => {
        let closure = pop_runtime_closure(stack)
        let collection = pop_runtime_value(stack)
        stack.push(
          RuntimePlain(
            evaluate_collection_closure(
              collection, closure, bindings, budget, externals, false,
            ),
          ),
        )
      }
      Binary(TryOr) => {
        let fallback = pop_runtime_value(stack)
        let closure = pop_runtime_closure(stack)
        let result = eval_zero_arg_closure(closure, bindings, budget, externals) catch {
          Expression(StepLimit) => raise Expression(StepLimit)
          Expression(_) => fallback
          error => raise error
        }
        stack.push(RuntimePlain(result))
      }
      Binary(operator) => {
        let right = pop_runtime_value(stack)
        let left = pop_runtime_value(stack)
        stack.push(
          RuntimePlain(evaluate_binary(operator, left, right, externals)),
        )
      }
    }
  }
  match stack.pop() {
    Some(RuntimePlain(value)) if stack.length() == 0 => value
    _ => raise Expression(MalformedProgram)
  }
}

///|
fn pop_runtime_value(
  stack : Array[RuntimeValue],
) -> Value raise AuthorizationError {
  match stack.pop() {
    Some(RuntimePlain(value)) => value
    Some(RuntimeClosure(_)) => raise Expression(MalformedProgram)
    None => raise Expression(MalformedProgram)
  }
}

///|
fn pop_runtime_closure(
  stack : Array[RuntimeValue],
) -> ExpressionClosure raise AuthorizationError {
  match stack.pop() {
    Some(RuntimeClosure(closure)) => closure
    _ => raise Expression(MalformedProgram)
  }
}

///|
fn eval_zero_arg_closure(
  closure : ExpressionClosure,
  bindings : Map[String, Value],
  budget : ExpressionBudget,
  externals : ExternalFunctions,
) -> Value raise AuthorizationError {
  if closure.parameters.length() != 0 {
    raise Expression(MalformedProgram)
  }
  evaluate_expression_ops(closure.operations, bindings, budget, externals)
}

///|
fn evaluate_collection_closure(
  collection : Value,
  closure : ExpressionClosure,
  bindings : Map[String, Value],
  budget : ExpressionBudget,
  externals : ExternalFunctions,
  any_mode : Bool,
) -> Value raise AuthorizationError {
  if closure.parameters.length() != 1 {
    raise Expression(MalformedProgram)
  }
  let items : Array[Value] = match collection {
    ArrayValue(values) => values
    SetValue(values) => values
    MapValue(entries) =>
      entries.map(entry => {
        let key = match entry.0 {
          IntegerKey(value) => Number(value)
          StringKey(value) => Text(value)
        }
        ArrayValue([key, entry.1])
      })
    _ => raise Expression(TypeMismatch("any/all expects a set, array or map"))
  }
  let parameter = closure.parameters[0]
  if bindings.get(parameter) is Some(_) {
    raise Expression(ShadowedVariable(parameter))
  }
  for item in items {
    let local_bindings = copy_bindings(bindings)
    local_bindings[parameter] = item
    let matched = match
      evaluate_expression_ops(
        closure.operations,
        local_bindings,
        budget,
        externals,
      ) {
      Boolean(value) => value
      _ =>
        raise Expression(TypeMismatch("any/all closure must return a boolean"))
    }
    if any_mode && matched {
      return Boolean(true)
    }
    if !any_mode && !matched {
      return Boolean(false)
    }
  }
  Boolean(!any_mode)
}

///|
fn copy_bindings(bindings : Map[String, Value]) -> Map[String, Value] {
  let result : Map[String, Value] = Map([])
  for (name, value) in bindings {
    result[name] = value
  }
  result
}

///|
fn evaluate_unary(
  operator : UnaryOperator,
  value : Value,
  externals : ExternalFunctions,
) -> Value raise AuthorizationError {
  match operator {
    Negate =>
      match value {
        Boolean(value) => Boolean(!value)
        _ => raise Expression(TypeMismatch("! expects a boolean"))
      }
    Parens => value
    Length =>
      match value {
        Text(value) => Number(@utf8.encode(value).length().to_int64())
        ByteString(value) => Number(value.length().to_int64())
        SetValue(value) => Number(value.length().to_int64())
        ArrayValue(value) => Number(value.length().to_int64())
        MapValue(value) => Number(value.length().to_int64())
        _ =>
          raise Expression(TypeMismatch("length is not defined for this value"))
      }
    TypeOf => Text(value_type_name(value))
    ExternalUnary(name) =>
      match externals.unary.get(name) {
        Some(callback) => callback(value)
        None => raise Expression(MissingExternal(name))
      }
  }
}

///|
fn value_type_name(value : Value) -> String {
  match value {
    Number(_) => "integer"
    Text(_) => "string"
    Date(_) => "date"
    ByteString(_) => "bytes"
    Boolean(_) => "bool"
    Null => "null"
    SetValue(_) => "set"
    ArrayValue(_) => "array"
    MapValue(_) => "map"
  }
}

///|
fn evaluate_binary(
  operator : BinaryOperator,
  left : Value,
  right : Value,
  externals : ExternalFunctions,
) -> Value raise AuthorizationError {
  match operator {
    StrictEqual => Boolean(strict_equal(left, right))
    StrictNotEqual => Boolean(!strict_equal(left, right))
    LenientEqual => Boolean(same_value_type(left, right) && left == right)
    LenientNotEqual => Boolean(!(same_value_type(left, right) && left == right))
    LessThan => Boolean(compare_values(left, right, 0))
    GreaterThan => Boolean(compare_values(left, right, 1))
    LessOrEqual => Boolean(compare_values(left, right, 2))
    GreaterOrEqual => Boolean(compare_values(left, right, 3))
    Contains => Boolean(contains_value(left, right))
    Prefix => Boolean(prefix_value(left, right))
    Suffix => Boolean(suffix_value(left, right))
    Regex => regex_value(left, right)
    Add => add_values(left, right)
    Subtract => arithmetic_values(left, right, Subtract)
    Multiply => arithmetic_values(left, right, Multiply)
    Divide => arithmetic_values(left, right, Divide)
    EagerAnd => boolean_binary(left, right, true)
    EagerOr => boolean_binary(left, right, false)
    Intersection => set_binary(left, right, true)
    Union => set_binary(left, right, false)
    BitwiseAnd => bitwise_values(left, right, 0)
    BitwiseOr => bitwise_values(left, right, 1)
    BitwiseXor => bitwise_values(left, right, 2)
    Get => get_value(left, right)
    ExternalBinary(name) =>
      match externals.binary.get(name) {
        Some(callback) => callback(left, right)
        None => raise Expression(MissingExternal(name))
      }
    LazyAnd | LazyOr | Any | All | TryOr => raise Expression(MalformedProgram)
  }
}

///|
fn same_value_type(left : Value, right : Value) -> Bool {
  match (left, right) {
    (Text(_), Text(_))
    | (Number(_), Number(_))
    | (Date(_), Date(_))
    | (ByteString(_), ByteString(_))
    | (ArrayValue(_), ArrayValue(_))
    | (SetValue(_), SetValue(_))
    | (MapValue(_), MapValue(_))
    | (Boolean(_), Boolean(_))
    | (Null, Null) => true
    _ => false
  }
}

///|
fn strict_equal(left : Value, right : Value) -> Bool raise AuthorizationError {
  if !same_value_type(left, right) {
    raise Expression(TypeMismatch("strict equality requires matching types"))
  }
  left == right
}

///|
fn compare_values(
  left : Value,
  right : Value,
  mode : Int32,
) -> Bool raise AuthorizationError {
  let (a, b) : (Int64, Int64) = match (left, right) {
    (Number(a), Number(b)) | (Date(a), Date(b)) => (a, b)
    _ =>
      raise Expression(
        TypeMismatch("ordering expects two integers or two dates"),
      )
  }
  match mode {
    0 => a < b
    1 => a > b
    2 => a <= b
    _ => a >= b
  }
}

///|
fn contains_value(left : Value, right : Value) -> Bool raise AuthorizationError {
  match (left, right) {
    (Text(haystack), Text(needle)) => haystack.contains(needle)
    (ArrayValue(values), value) => values.contains(value)
    (SetValue(values), SetValue(subset)) =>
      subset.all(value => values.contains(value))
    (SetValue(values), value) => values.contains(value)
    (MapValue(entries), Number(key)) =>
      entries.any(entry => entry.0 == IntegerKey(key))
    (MapValue(entries), Text(key)) =>
      entries.any(entry => entry.0 == StringKey(key))
    (MapValue(_), _) => false
    _ =>
      raise Expression(TypeMismatch("contains is not defined for these values"))
  }
}

///|
fn prefix_value(left : Value, right : Value) -> Bool raise AuthorizationError {
  match (left, right) {
    (Text(value), Text(prefix)) => value.has_prefix(prefix)
    (ArrayValue(values), ArrayValue(prefix)) => array_has_prefix(values, prefix)
    _ => raise Expression(TypeMismatch("prefix expects strings or arrays"))
  }
}

///|
fn suffix_value(left : Value, right : Value) -> Bool raise AuthorizationError {
  match (left, right) {
    (Text(value), Text(suffix)) => value.has_suffix(suffix)
    (ArrayValue(values), ArrayValue(suffix)) => array_has_suffix(values, suffix)
    _ => raise Expression(TypeMismatch("suffix expects strings or arrays"))
  }
}

///|
fn array_has_prefix(values : Array[Value], prefix : Array[Value]) -> Bool {
  if prefix.length() > values.length() {
    return false
  }
  for i = 0; i < prefix.length(); i = i + 1 {
    if values[i] != prefix[i] {
      return false
    }
  }
  true
}

///|
fn array_has_suffix(values : Array[Value], suffix : Array[Value]) -> Bool {
  if suffix.length() > values.length() {
    return false
  }
  let offset = values.length() - suffix.length()
  for i = 0; i < suffix.length(); i = i + 1 {
    if values[offset + i] != suffix[i] {
      return false
    }
  }
  true
}

///|
fn regex_value(left : Value, right : Value) -> Value raise AuthorizationError {
  match (left, right) {
    (Text(value), Text(pattern)) => {
      let regex = @string.Regex(pattern) catch {
        _ => raise Expression(InvalidRegex(pattern))
      }
      Boolean(regex.execute(value) is Some(_))
    }
    _ => raise Expression(TypeMismatch("regex expects two strings"))
  }
}

///|
fn add_values(left : Value, right : Value) -> Value raise AuthorizationError {
  match (left, right) {
    (Text(a), Text(b)) => Text(a + b)
    (Number(a), Number(b)) => Number(checked_add(a, b))
    _ => raise Expression(TypeMismatch("+ expects two integers or two strings"))
  }
}

///|
fn arithmetic_values(
  left : Value,
  right : Value,
  operator : BinaryOperator,
) -> Value raise AuthorizationError {
  let (a, b) = match (left, right) {
    (Number(a), Number(b)) => (a, b)
    _ => raise Expression(TypeMismatch("arithmetic expects two integers"))
  }
  match operator {
    Subtract => Number(checked_subtract(a, b))
    Multiply => Number(checked_multiply(a, b))
    Divide => {
      if b == 0L {
        raise Expression(DivisionByZero)
      }
      if a == -9223372036854775808L && b == -1L {
        raise Expression(IntegerOverflow)
      }
      Number(a / b)
    }
    _ => raise Expression(MalformedProgram)
  }
}

///|
fn checked_add(a : Int64, b : Int64) -> Int64 raise AuthorizationError {
  let maximum = 9223372036854775807L
  let minimum = -9223372036854775808L
  if (b > 0L && a > maximum - b) || (b < 0L && a < minimum - b) {
    raise Expression(IntegerOverflow)
  }
  a + b
}

///|
fn checked_subtract(a : Int64, b : Int64) -> Int64 raise AuthorizationError {
  let maximum = 9223372036854775807L
  let minimum = -9223372036854775808L
  if (b < 0L && a > maximum + b) || (b > 0L && a < minimum + b) {
    raise Expression(IntegerOverflow)
  }
  a - b
}

///|
fn checked_multiply(a : Int64, b : Int64) -> Int64 raise AuthorizationError {
  let maximum = 9223372036854775807L
  let minimum = -9223372036854775808L
  if a == 0L || b == 0L {
    return 0L
  }
  let overflow = (a == minimum && b == -1L) ||
    (b == minimum && a == -1L) ||
    (a > 0L && b > 0L && a > maximum / b) ||
    (a > 0L && b < 0L && b < minimum / a) ||
    (a < 0L && b > 0L && a < minimum / b) ||
    (a < 0L && b < 0L && a < maximum / b)
  if overflow {
    raise Expression(IntegerOverflow)
  }
  a * b
}

///|
fn boolean_binary(
  left : Value,
  right : Value,
  and_mode : Bool,
) -> Value raise AuthorizationError {
  match (left, right) {
    (Boolean(a), Boolean(b)) => Boolean(if and_mode { a && b } else { a || b })
    _ => raise Expression(TypeMismatch("boolean operator expects booleans"))
  }
}

///|
fn set_binary(
  left : Value,
  right : Value,
  intersect_mode : Bool,
) -> Value raise AuthorizationError {
  match (left, right) {
    (SetValue(a), SetValue(b)) => {
      let result = if intersect_mode {
        a.filter(value => b.contains(value))
      } else {
        let values = a.copy()
        for value in b {
          if !values.contains(value) {
            values.push(value)
          }
        }
        values
      }
      SetValue(result)
    }
    _ => raise Expression(TypeMismatch("set operation expects two sets"))
  }
}

///|
fn bitwise_values(
  left : Value,
  right : Value,
  mode : Int32,
) -> Value raise AuthorizationError {
  match (left, right) {
    (Number(a), Number(b)) =>
      Number(
        match mode {
          0 => a & b
          1 => a | b
          _ => a ^ b
        },
      )
    _ => raise Expression(TypeMismatch("bitwise operator expects two integers"))
  }
}

///|
fn get_value(left : Value, right : Value) -> Value raise AuthorizationError {
  match (left, right) {
    (ArrayValue(values), Number(index)) =>
      if index < 0L || index >= values.length().to_int64() {
        Null
      } else {
        values[index.to_int()]
      }
    (MapValue(entries), Number(key)) => {
      for (entry_key, value) in entries {
        if entry_key == IntegerKey(key) {
          return value
        }
      }
      Null
    }
    (MapValue(entries), Text(key)) => {
      for (entry_key, value) in entries {
        if entry_key == StringKey(key) {
          return value
        }
      }
      Null
    }
    (ArrayValue(_), _) =>
      raise Expression(TypeMismatch("array index must be an integer"))
    (MapValue(_), _) => Null
    _ => raise Expression(TypeMismatch("get expects an array or map"))
  }
}

///|
priv struct FactOrigin {
  fact : Fact
  origins : Array[Int32]
} derive(Eq)

///|
priv struct OriginBindings {
  values : Map[String, Value]
  origins : Array[Int32]
}

///|
priv struct ScopedRule {
  rule : Rule
  origin : Int32
  visible_origins : Array[Int32]
}

///|
fn union_origins(left : Array[Int32], right : Array[Int32]) -> Array[Int32] {
  let result = left.copy()
  for origin in right {
    if !result.contains(origin) {
      result.push(origin)
    }
  }
  result
}

///|
fn scoped_rule_bindings(
  rule : Rule,
  facts : Array[FactOrigin],
  visible_origins : Array[Int32],
  max_bindings : Int32,
) -> Array[OriginBindings] raise AuthorizationError {
  let mut environments : Array[OriginBindings] = [
    { values: Map([]), origins: [], },
  ]
  for predicate in rule.body {
    let next_environments : Array[OriginBindings] = []
    for environment in environments {
      for fact in facts {
        if fact.origins.all(origin => visible_origins.contains(origin)) {
          match unify(predicate, fact.fact, environment.values) {
            Some(values) => {
              if next_environments.length() >= max_bindings {
                raise FactLimit
              }
              next_environments.push({
                values,
                origins: union_origins(environment.origins, fact.origins),
              })
            }
            None => ()
          }
        }
      }
    }
    environments = next_environments
    if environments.length() == 0 {
      break
    }
  }
  environments
}

///|
fn derive_scoped_facts(
  initial : Array[FactOrigin],
  rules : Array[ScopedRule],
  max_facts : Int32,
  max_iterations : Int32,
  externals : ExternalFunctions,
) -> Array[FactOrigin] raise AuthorizationError {
  if initial.length() > max_facts {
    raise FactLimit
  }
  let facts = initial.copy()
  let mut iteration : Int32 = 0
  let mut stable = false
  while iteration < max_iterations && !stable {
    stable = true
    for scoped in rules {
      for
        environment in scoped_rule_bindings(
          scoped.rule,
          facts,
          scoped.visible_origins,
          max_facts,
        ) {
        if scoped.rule.conditions.all(condition => {
            condition_matches_with_externals(
              condition,
              environment.values,
              externals,
            )
          }) {
          match instantiate(scoped.rule, environment.values) {
            Some(fact) => {
              let origins = union_origins(environment.origins, [scoped.origin])
              let derived = FactOrigin::{ fact, origins, }
              if !facts.contains(derived) {
                if facts.length() >= max_facts {
                  raise FactLimit
                }
                facts.push(derived)
                stable = false
              }
            }
            None => ()
          }
        }
      }
    }
    iteration += 1
  }
  if !stable {
    raise IterationLimit
  }
  facts
}

///|
fn scoped_query_matches(
  query : Query,
  facts : Array[FactOrigin],
  visible_origins : Array[Int32],
  externals : ExternalFunctions,
) -> Bool raise AuthorizationError {
  let rule = Rule::{
    head: Predicate::{ name: "__query_result", terms: [], },
    body: query.body,
    conditions: query.conditions,
    scopes: [],
  }
  for environment in scoped_rule_bindings(rule, facts, visible_origins, 10000) {
    if query.conditions.all(condition => {
        condition_matches_with_externals(
          condition,
          environment.values,
          externals,
        )
      }) {
      return true
    }
  }
  false
}

///|
fn scoped_query_all_matches(
  query : Query,
  facts : Array[FactOrigin],
  visible_origins : Array[Int32],
  externals : ExternalFunctions,
) -> Bool raise AuthorizationError {
  let rule = Rule::{
    head: Predicate::{ name: "__query_result", terms: [], },
    body: query.body,
    conditions: query.conditions,
    scopes: [],
  }
  let bindings = scoped_rule_bindings(rule, facts, visible_origins, 10000)
  if bindings.length() == 0 {
    return false
  }
  for environment in bindings {
    if !query.conditions.all(condition => {
        condition_matches_with_externals(
          condition,
          environment.values,
          externals,
        )
      }) {
      return false
    }
  }
  true
}
