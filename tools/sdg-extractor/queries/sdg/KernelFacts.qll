import cpp
import KernelExpressions
import KernelDma
import KernelCoherent
import KernelPages
import KernelPagePool
import KernelMmio
import semmle.code.cpp.controlflow.DefinitionsAndUses
import semmle.code.cpp.pointsto.CallGraph

predicate kernelExpression(Expr expression) {
  exists(expression.getEnclosingFunction().getBlock()) and not expression.isUnevaluated()
}

private string ioByteOrder(FunctionCall call) {
  if call.getTarget().getName().regexpMatch("ioread(16|32|64)be") then result = "Big"
  else if call.getTarget().getName().matches("__raw_%") then result = targetByteOrder()
  else result = "Little"
}

predicate configRead(FunctionCall call, int width) {
  call.getTarget().getName().regexpMatch("virtio_cread(8|16|32|64)(_le)?") and
  width = call.getTarget().getType().getSize() and
  exists(VariableCall access |
    access.getEnclosingFunction() = call.getTarget() and
    access.getVariable().getName() = "get" and
    access.getNumberOfArguments() = 4
  )
}

predicate configTransport(FunctionCall call, Variable operations, Function handler, Assignment install) {
  exists(VariableCall access, ClassAggregateLiteral initializer, FunctionAccess callback, VariableAccess reference |
    access.getEnclosingFunction() = call.getTarget() and access.getVariable().getName() = "get" and
    initializer = operations.getInitializer().getExpr() and
    callback = initializer.getAFieldExpr(access.getVariable().(Field)).getUnconverted() and
    handler = callback.getTarget() and
    reference.getTarget() = operations and reference = install.getRValue().getAChild*() and
    install.getLValue().(FieldAccess).getTarget().getName() = "config" and
    exists(FunctionCall read | read.getEnclosingFunction() = handler and ioRead(read, _))
  )
}

private string configBase(Function handler) {
  result = min(Expr literal, MacroInvocation invocation |
    invocation.getMacro().getName() = "VIRTIO_MMIO_CONFIG" and
    literal = invocation.getAnExpandedElement() and
    literal instanceof Literal and literal.getEnclosingFunction() = handler |
    literal.getValue()
  )
}

private string optionalConfigBase(Function handler) {
  if exists(configBase(handler)) then result = quoted(configBase(handler)) else result = "null"
}

private string optionalValue(Expr expression) {
  if exists(expression.getValue()) then result = quoted(expression.getValue())
  else if exists(expression.getFullyConverted().getValue())
  then result = quoted(expression.getFullyConverted().getValue())
  else result = "null"
}

private string configByteOrder(FunctionCall call) {
  if call.getTarget().getType().getSize() = 1 or call.getTarget().getName().matches("%_le") then result = "Little"
  else result = "Runtime"
}

predicate sourceFact(Expr expression, string kind, string json) {
  kernelExpression(expression) and
  (deviceReadFact(expression, kind, json) or dmaSourceFact(expression, kind, json) or
   pageDmaSourceFact(expression, kind, json) or pagePoolSourceFact(expression, kind, json) or
   coherentSourceFact(expression, kind, json))
}

private predicate deviceReadFact(Expr expression, string kind, string json) {
  exists(FunctionCall call, int width |
    expression = call and ioRead(call, width) and
    not ioHelper(call.getEnclosingFunction()) |
    kind = "MmioRead" and
    json = "{\"kind\":\"MmioRead\",\"size_bytes\":" + width.toString() +
      ",\"byte_order\":" + quoted(ioByteOrder(call)) +
      ",\"address\":" + quoted(expressionKey(call.getArgument(0).getFullyConverted())) +
      mmioMappingsJson(call) +
      ",\"function\":" + quoted(functionKey(call.getEnclosingFunction())) +
      ",\"location\":" + locationJson(call) + "}"
  )
  or
  exists(FunctionCall call, int width, Variable operations, Function handler, Assignment install |
    expression = call and configRead(call, width) and configTransport(call, operations, handler, install) |
    kind = "MmioRead" and
    json = "{\"kind\":\"MmioRead\",\"access\":\"config\",\"size_bytes\":" +
      width.toString() +
      ",\"byte_order\":" + quoted(configByteOrder(call)) +
      ",\"decoding_function\":" + quoted(functionKey(call.getTarget())) +
      ",\"relative_offset\":" + optionalValue(call.getArgument(1)) +
      ",\"config_base\":" + optionalConfigBase(handler) +
      ",\"transport_condition\":{\"operations\":" + quoted(operations.getName()) +
      ",\"handler\":" + quoted(functionKey(handler)) +
      ",\"registration\":" + locationJson(install) + "}" +
      ",\"offset_expr\":" + quoted(expressionKey(call.getArgument(1))) +
      ",\"function\":" + quoted(functionKey(call.getEnclosingFunction())) +
      ",\"location\":" + locationJson(call) + "}"
  )
}

predicate sinkOperand(Expr sink, Expr operand, string operation) {
  kernelExpression(sink) and memoryOperand(sink, operand, operation)
}

private predicate memoryOperand(Expr sink, Expr operand, string operation) {
  exists(FunctionCall call, string name, int index |
    call.getTarget().getName() = name and
    (
      name in ["memcpy", "memmove", "memset", "__memcpy", "__memmove", "__memset",
               "__builtin_memcpy", "__builtin_memmove", "__builtin_memset",
               "strscpy", "strncpy", "copy_to_user", "copy_from_user"] and index = 2
      or name in ["memcpy", "memmove", "__memcpy", "__memmove", "__builtin_memcpy", "__builtin_memmove",
                  "strscpy", "strncpy", "copy_to_user", "copy_from_user"] and index in [0, 1]
      or name in ["memset", "__memset", "__builtin_memset"] and index = 0
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
    sink = access and evaluatedMemoryAccess(access) and operand = access.getArrayOffset() and operation = "Index"
  )
  or
  exists(ArrayExpr access |
    sink = access and evaluatedMemoryAccess(access) and operand = access.getArrayBase() and operation = "ArrayBase"
  )
  or
  exists(PointerDereferenceExpr access |
    sink = access and evaluatedMemoryAccess(access) and operand = access.getOperand() and operation = "Dereference"
  )
  or
  exists(FieldAccess access |
    sink = access and evaluatedMemoryAccess(access) and operand = memoryBase(access).getUnconverted() and operation = "FieldAccess"
  )
  or
  exists(FieldAccess access, Expr index, int stride |
    sink = access and evaluatedMemoryAccess(access) and memoryIndex(access, index, stride) and
    operand = index.getUnconverted() and operation = "Index"
  )
}

private predicate evaluatedMemoryAccess(Expr expression) {
  not expression.getUnspecifiedType() instanceof ArrayType and
  not exists(AddressOfExpr address | address.getOperand().getUnconverted() = expression) and
  not exists(FieldAccess field |
    field.getQualifier().getUnconverted() = expression and expression.getUnspecifiedType() instanceof Class
  )
}

string sinkAccessJson(Expr sink, Expr operand) {
  if sink instanceof Call
  then result = ",\"argument\":" + min(int index | sink.(Call).getArgument(index) = operand | index).toString() +
    memoryCallWidthJson(sink)
  else if sink instanceof FieldAccess
  then result = ",\"offset_bytes\":" + memoryOffset(sink).toString() +
    ",\"width_bytes\":" + sink.getType().getSize().toString() + memoryStrideJson(sink, operand) +
    memoryAccessIndicesJson(sink)
  else if exists(sink.getType().getSize())
  then result = ",\"width_bytes\":" + sink.getType().getSize().toString() + memoryAccessIndicesJson(sink)
  else result = ""
}

private string memoryCallWidthJson(Call call) {
  if call.getTarget().getName() in ["memcpy", "memmove", "memset", "__memcpy", "__memmove", "__memset",
      "__builtin_memcpy", "__builtin_memmove", "__builtin_memset"]
  then result = ",\"width_expression\":" + quoted(expressionKey(call.getArgument(2).getFullyConverted()))
  else result = ""
}

private string memoryAccessIndicesJson(Expr access) {
  result = ",\"access_indices\":[" + concat(Expr index, int stride | memoryIndex(access, index, stride) |
    "{\"expression\":" + quoted(expressionKey(index)) + ",\"stride\":" + stride.toString() + "}",
    "," order by expressionKey(index), stride) + "]"
}

private string memoryStrideJson(Expr sink, Expr operand) {
  if memoryIndex(sink, operand.getFullyConverted(), _)
  then result = ",\"stride\":" + min(int stride | memoryIndex(sink, operand.getFullyConverted(), stride) | stride).toString()
  else result = ""
}

predicate valueStep(Expr previous, Expr following, string reason) {
  exists(SemanticStackVariable variable |
    definitionUsePair(variable, previous, following) and
    if exists(VariableAccess access | access.getTarget() = variable and definitionByReference(access, previous))
    then reason = "call_write"
    else if exists(AsmStmt statement | statement.getAChild() = previous)
    then reason = "assembly_write"
    else reason = "definition"
  )
}

predicate outputParameterStore(Function function, Parameter parameter, Assignment store) {
  parameter = function.getAParameter() and store.getEnclosingFunction() = function and
  exists(PointerDereferenceExpr destination |
    destination = store.getLValue() and
    DataFlow::localFlow(DataFlow::parameterNode(parameter), DataFlow::exprNode(destination.getOperand()))
  )
}

predicate closedOutputStores(Function function, Parameter parameter) {
    outputParameterStore(function, parameter, _) and
    not exists(Assignment other |
      other.getEnclosingFunction() = function and other.getLValue() instanceof PointerDereferenceExpr and
      not outputParameterStore(function, parameter, other)
    ) and
    not exists(Call inner, Expr argument |
      inner.getEnclosingFunction() = function and argument = inner.getAnArgument() and
      DataFlow::localFlow(DataFlow::parameterNode(parameter), DataFlow::exprNode(argument))
    ) and
    not exists(Assignment escaped |
      escaped.getEnclosingFunction() = function and
      DataFlow::localFlow(DataFlow::parameterNode(parameter), DataFlow::exprNode(escaped.getRValue())) and
      (escaped.getLValue() instanceof FieldAccess or escaped.getLValue() instanceof ArrayExpr or
       escaped.getLValue().(VariableAccess).getTarget() instanceof GlobalVariable)
    )
}

string outputStoresClosedJson(Function function, Parameter parameter) {
  if closedOutputStores(function, parameter) then result = "true" else result = "false"
}

string outputStoreCompleteJson(Function function, Parameter parameter, Assignment store) {
  if dominates(store, function) and closedOutputStores(function, parameter) and
    not exists(Assignment other | outputParameterStore(function, parameter, other) and other != store)
  then result = "true" else result = "false"
}

predicate callBinding(Call call, Function callee) {
  resolvedCall(call, callee) and exists(callee.getBlock())
}

string capacityJson(Expr sink) {
  if exists(FunctionCall call, ArrayType buffer |
    call = sink and call.getTarget().getName() in ["memcpy", "memmove", "memset"] and
    buffer = call.getArgument(0).getUnconverted().getUnspecifiedType() and
    buffer.getSize() > 0
  )
  then result = ",\"capacity\":" + min(ArrayType buffer |
    buffer = sink.(Call).getArgument(0).getUnconverted().getUnspecifiedType() |
    buffer.getSize()).toString()
  else result = ""
}
