import KernelFlow

string pathKey(DeviceFlow::PathNode node) {
  result = node.getLocation().getFile().getRelativePath() + ":" +
    node.getLocation().getStartLine().toString() + ":" +
    node.getLocation().getStartColumn().toString() + ":" + node.toStringWithContext()
}

string pathExpression(DeviceFlow::PathNode node) {
  if exists(node.getNode().asExpr()) then result = expressionKey(node.getNode().asExpr())
  else if exists(node.getNode().asDefinition()) then result = expressionKey(node.getNode().asDefinition())
  else result = ""
}

from string section, string key, string value
where
  exists(DeviceFlow::PathNode source, DeviceFlow::PathNode sink |
    DeviceFlow::flowPath(source, sink) and section = "flow" and
    key = pathKey(source) + "->" + pathKey(sink) and
    value = "{\"source\":" + quoted(pathKey(source)) +
      ",\"sink\":" + quoted(pathKey(sink)) +
      ",\"source_expr\":" + quoted(pathExpression(source)) +
      ",\"sink_expr\":" + quoted(pathExpression(sink)) + "}"
  )
  or
  exists(DeviceFlow::PathNode node |
    section = "flow_node" and key = pathKey(node) and
    value = "{\"expression\":" + quoted(pathExpression(node)) +
      ",\"text\":" + quoted(node.toStringWithContext()) +
      ",\"location\":{\"file\":" + quoted(node.getLocation().getFile().getRelativePath()) +
      ",\"line\":" + node.getLocation().getStartLine().toString() + "}}"
  )
  or
  exists(DeviceFlow::PathNode previous, DeviceFlow::PathNode following |
    following = previous.getASuccessor() and section = "flow_step" and
    key = pathKey(previous) + "->" + pathKey(following) and
    value = "{\"src\":" + quoted(pathKey(previous)) +
      ",\"dst\":" + quoted(pathKey(following)) + "}"
  )
select section, key, value
