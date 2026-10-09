import cpp
import semmle.code.cpp.controlflow.DefinitionsAndUses
import semmle.code.cpp.pointsto.CallGraph

bindingset[value]
string quoted(string value) {
  result = "\"" + value.replaceAll("\\", "\\\\").replaceAll("\"", "\\\"") + "\""
}

string locationKey(Locatable element) {
  result = element.getFile().getRelativePath() + ":" +
    element.getLocation().getStartLine().toString() + ":" +
    element.getLocation().getStartColumn().toString()
}

string locationJson(Locatable element) {
  result = "{\"file\":" + quoted(element.getFile().getRelativePath()) +
    ",\"line\":" + element.getLocation().getStartLine().toString() +
    ",\"column\":" + element.getLocation().getStartColumn().toString() + "}"
}

string expressionKey(Expr expression) {
  result = locationKey(expression) + ":" + expression.getAPrimaryQlClass()
}

string expressionText(Expr expression) {
  result = expression.toString().replaceAll("\\", "\\\\").replaceAll("\"", "\\\"")
}

string configOffsetText(Expr expression) {
  exists(BuiltInOperationBuiltInOffsetOf offset |
    expression = offset |
    result = offset.getChild(0).toString() + "." + offset.getChild(1).toString()
  )
  or
  result = expressionText(expression)
}

string configOffsetValue(Expr expression) {
  exists(BuiltInOperationBuiltInOffsetOf offset |
    expression = offset and exists(offset.getValue()) |
    result = offset.getValue()
  )
  or result = ""
}

predicate kernelExpression(Expr expression) {
  exists(Function function |
    function = expression.getEnclosingFunction() and exists(function.getBlock())
  )
}

string typeName(Type type) { result = type.toString() }

predicate ioRead(FunctionCall call, int width) {
  exists(string name |
    name = call.getTarget().getName() |
    (name.regexpMatch("^(__raw_)?readb(_relaxed)?$") or name = "ioread8") and width = 1
    or (name.regexpMatch("^(__raw_)?readw(_relaxed)?$") or name.regexpMatch("^ioread16.*$")) and width = 2
    or (name.regexpMatch("^(__raw_)?readl(_relaxed)?$") or name.regexpMatch("^ioread32.*$")) and width = 4
    or (name.regexpMatch("^(__raw_)?readq(_relaxed)?$") or name.regexpMatch("^ioread64.*$")) and width = 8
  )
}

predicate configRead(FunctionCall call, int width) {
  call.getTarget().getName().regexpMatch("^virtio_cread(8|16|32|64)(_le)?$") and
  width = call.getTarget().getType().getSize()
}

predicate sourceFact(Expr expression, string kind, string json) {
  exists(FunctionCall call, int width |
    expression = call and ioRead(call, width) |
    kind = "MmioRead" and
    json = "{\"kind\":\"MmioRead\",\"size_bytes\":" + width.toString() +
      ",\"address\":" + quoted(expressionKey(call.getArgument(0))) +
      ",\"function\":" + quoted(call.getEnclosingFunction().getName()) +
      ",\"location\":" + locationJson(call) + "}"
  )
  or
  exists(FunctionCall call, int width |
    expression = call and configRead(call, width) |
    kind = "MmioRead" and
    json = "{\"kind\":\"MmioRead\",\"access\":\"config\",\"size_bytes\":" +
      width.toString() + ",\"offset_expr\":" + quoted(configOffsetText(call.getArgument(1))) +
      ",\"offset_value\":" + quoted(configOffsetValue(call.getArgument(1))) +
      ",\"function\":" + quoted(call.getEnclosingFunction().getName()) +
      ",\"location\":" + locationJson(call) + "}"
  )
}

predicate sinkOperand(Expr sink, Expr operand, string operation) {
  exists(FunctionCall call, string name, int index |
    call.getTarget().getName() = name and
    (
      name in ["memcpy", "memmove", "memset", "__memcpy", "__memmove", "__memset",
               "__builtin_memcpy", "__builtin_memmove", "__builtin_memset",
               "strscpy", "strncpy", "copy_to_user", "copy_from_user"] and index = 2
      or name in ["kmalloc", "kzalloc", "kvmalloc", "kvzalloc", "alloc_skb",
                  "alloc_pages_exact", "kmalloc_noprof", "kzalloc_noprof"] and index = 0
      or name in ["skb_put", "__skb_put", "skb_push", "__skb_push", "skb_pull",
                  "pskb_may_pull", "devm_kmalloc", "devm_kzalloc"] and index = 1
      or name in ["kcalloc", "kvcalloc", "kcalloc_noprof", "kvcalloc_noprof"] and index in [0, 1]
    ) and operand = call.getArgument(index) |
    sink = call and operation = name
  )
  or
  exists(ArrayExpr access |
    sink = access and operand = access.getArrayOffset() and operation = "Index"
  )
  or
  exists(PointerDereferenceExpr access |
    sink = access and operand = access.getOperand() and operation = "Dereference"
  )
}

predicate valueStep(Expr previous, Expr following, string reason) {
  exists(SemanticStackVariable variable |
    definitionUsePair(variable, previous, following)
  ) and reason = "definition"
  or
  exists(Assignment assignment |
    previous = assignment.getRValue().getFullyConverted() and
    following = assignment.getLValue()
  ) and reason = "assignment"
}

predicate callBinding(Call call, Function callee) {
  resolvedCall(call, callee) and exists(callee.getBlock())
}
