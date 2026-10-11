import KernelFlow
import KernelInterrupts

string pathKey(DeviceFlow::PathNode node) {
  result = min(Location location | location = node.getLocation() |
    location.getFile().getRelativePath() + ":" +
    location.getStartLine().toString() + ":" + location.getStartColumn().toString()) + ":" +
    min(node.toStringWithContext()) + ":" +
    concat(string key | key = pathExpression(node) | key, ";" order by key)
}

string pathExpression(DeviceFlow::PathNode node) {
  if exists(node.getNode().asExpr()) then result = expressionKey(node.getNode().asExpr())
  else if exists(node.getNode().asDefinition()) then result = expressionKey(node.getNode().asDefinition())
  else if exists(node.getNode().asIndirectArgument())
  then result = expressionKey(node.getNode().asIndirectArgument())
  else if exists(node.getNode().asDefiningArgument())
  then result = expressionKey(node.getNode().asDefiningArgument())
  else if exists(node.getNode().asParameter(0))
  then result = parameterKey(node.getNode().asParameter(0))
  else result = ""
}

from string section, string key, string value
where
  exists(DeviceFlow::PathNode source, Expr sourceExpression, Expr guard, Expr sink, Expr operand,
         string operation, boolean branch |
    sourceExpression = source.getNode().asExpr() and sourceFact(sourceExpression, _, _) and
    guardedMemory(guard, sink, operand, operation, branch) and
    exists(DeviceFlow::PathNode endpoint |
      DeviceFlow::flowPath(source, endpoint) and guardValue(guard, endpoint.getNode().asExpr())
    ) and
    section = "control_dependency" and
    key = pathKey(source) + ":" + expressionKey(guard) + ":" + branch.toString() + ":" + expressionKey(sink) + ":" + expressionKey(operand) and
    value = "{\"source\":" + quoted(pathKey(source)) +
      ",\"source_expr\":" + quoted(expressionKey(sourceExpression)) +
      ",\"guard\":" + quoted(expressionKey(guard)) + ",\"branch\":" + branch.toString() +
      ",\"sink_key\":" + quoted(expressionKey(sink) + ":" + expressionKey(operand)) +
      ",\"endpoints\":[" + concat(DeviceFlow::PathNode endpoint |
        DeviceFlow::flowPath(source, endpoint) and guardValue(guard, endpoint.getNode().asExpr()) |
        quoted(pathKey(endpoint)), "," order by pathKey(endpoint)) + "]}"
  )
  or
  exists(Call call, Function callee |
    interruptReachable(call.getEnclosingFunction()) and callBinding(call, callee) and
    section = "control_call" and key = expressionKey(call) + "->" + functionKey(callee) and
    value = "{\"call\":" + quoted(expressionKey(call)) +
      ",\"caller\":" + quoted(functionKey(call.getEnclosingFunction())) +
      ",\"callee\":" + quoted(functionKey(callee)) +
      ",\"location\":" + locationJson(call) + "}"
  )
  or
  exists(Expr sink, Expr operand, string operation |
    interruptReachable(sink.getEnclosingFunction()) and sinkOperand(sink, operand, operation) and
    section = "control_sink" and key = expressionKey(sink) + ":" + expressionKey(operand) and
    value = "{\"function\":" + quoted(functionKey(sink.getEnclosingFunction())) +
      ",\"sink\":" + quoted(key) + "}"
  )
  or
  exists(DeviceFlow::PathNode source, DeviceFlow::PathNode sink, Expr sourceExpression, Expr sinkExpression |
    DeviceFlow::flowPath(source, sink) and section = "flow" and
    sourceExpression = source.getNode().asExpr() and sourceFact(sourceExpression, _, _) and
    sinkExpression = sink.getNode().asExpr() and sinkOperand(_, sinkExpression, _) and
    key = pathKey(source) + "->" + pathKey(sink) + ":" + expressionKey(sourceExpression) + ":" + expressionKey(sinkExpression) and
    value = "{\"source\":" + quoted(pathKey(source)) +
      ",\"sink\":" + quoted(pathKey(sink)) +
      ",\"source_expr\":" + quoted(expressionKey(sourceExpression)) +
      ",\"sink_expr\":" + quoted(expressionKey(sinkExpression)) + "}"
  )
  or
  exists(DeviceFlow::PathNode node |
    section = "flow_node" and key = pathKey(node) and
    value = "{\"expressions\":[" + concat(string expression |
      expression = pathExpression(node) and expression != "" |
      quoted(expression), "," order by expression) +
      "],\"text\":" + quoted(min(node.toStringWithContext())) +
      ",\"location\":" + min(Location location | location = node.getLocation() |
        "{\"file\":" + quoted(location.getFile().getRelativePath()) +
        ",\"line\":" + location.getStartLine().toString() + "}") + "}"
  )
  or
  exists(DeviceFlow::PathNode previous, DeviceFlow::PathNode following |
    following = previous.getASuccessor() and section = "flow_step" and
    key = pathKey(previous) + "->" + pathKey(following) and
    value = "{\"src\":" + quoted(pathKey(previous)) +
      ",\"dst\":" + quoted(pathKey(following)) + "}"
  )
select section, key, value
