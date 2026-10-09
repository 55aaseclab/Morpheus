import KernelFacts

from string section, string key, string value
where
  exists(Expr expression |
    kernelExpression(expression) and
    section = "expression" and
    key = expressionKey(expression) and
    value = "{\"id\":" + quoted(key) +
      ",\"function\":" + quoted(expression.getEnclosingFunction().getName()) +
      ",\"location\":" + locationJson(expression) +
      ",\"type\":" + quoted(typeName(expression.getType())) +
      ",\"class\":" + quoted(expression.getAPrimaryQlClass()) +
      ",\"text\":" + quoted(expressionText(expression)) + "}"
  )
  or
  exists(Function function |
    exists(function.getBlock()) and
    section = "function" and key = locationKey(function) and
    value = "{\"id\":" + quoted(key) + ",\"name\":" + quoted(function.getName()) +
      ",\"location\":" + locationJson(function) + "}"
  )
  or
  exists(Expr expression, string kind, string details |
    kernelExpression(expression) and sourceFact(expression, kind, details) and
    section = "source" and key = expressionKey(expression) and value = details
  )
  or
  exists(FunctionCall call, Expr bit |
    call.getTarget().getName() = "virtio_has_feature" and
    bit = call.getArgument(1) and exists(bit.getValue()) and
    section = "guard" and key = expressionKey(call) and
    value = "{\"kind\":\"BitSet\",\"bit\":" + bit.getValue() +
      ",\"function\":" + quoted(call.getEnclosingFunction().getName()) +
      ",\"location\":" + locationJson(call) + "}"
  )
  or
  exists(Expr sink, Expr operand, string operation |
    kernelExpression(sink) and sinkOperand(sink, operand, operation) and
    section = "sink" and key = expressionKey(sink) + ":" + expressionKey(operand) and
    value = "{\"expression\":" + quoted(expressionKey(sink)) +
      ",\"operand\":" + quoted(expressionKey(operand)) +
      ",\"operation\":" + quoted(operation) +
      ",\"function\":" + quoted(sink.getEnclosingFunction().getName()) +
      ",\"location\":" + locationJson(sink) + "}"
  )
  or
  exists(Expr previous, Expr following, string reason |
    kernelExpression(previous) and kernelExpression(following) and
    valueStep(previous, following, reason) and
    section = "step" and key = expressionKey(previous) + "->" + expressionKey(following) and
    value = "{\"src\":" + quoted(expressionKey(previous)) +
      ",\"dst\":" + quoted(expressionKey(following)) +
      ",\"reason\":" + quoted(reason) + "}"
  )
  or
  exists(Call call, Function callee |
    kernelExpression(call) and callBinding(call, callee) and
    section = "call" and key = expressionKey(call) + "->" + locationKey(callee) and
    value = "{\"call\":" + quoted(expressionKey(call)) +
      ",\"callee\":" + quoted(locationKey(callee)) +
      ",\"name\":" + quoted(callee.getName()) + "}"
  )
select section, key, value
