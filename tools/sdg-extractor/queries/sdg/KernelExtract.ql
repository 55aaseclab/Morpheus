import KernelFlow
import KernelInterrupts
import KernelFeatures
import semmle.code.cpp.controlflow.Guards
import semmle.code.cpp.controlflow.Dominance

predicate controllingCondition(Expr condition, Expr expression, boolean branch) {
  condition.(GuardCondition).controls(expression.getBasicBlock(), branch)
  or
  exists(IfStmt conditional |
    condition = conditional.getCondition() and
    (
      expression.getEnclosingStmt().getParentStmt*() = conditional.getThen() and branch = true
      or
      expression.getEnclosingStmt().getParentStmt*() = conditional.getElse() and branch = false
    )
  )
}

predicate exitCondition(Expr condition, Stmt exit, boolean branch) {
  exists(IfStmt conditional |
    condition = conditional.getCondition() and
    (
      exit.getParentStmt*() = conditional.getThen() and branch = true
      or
      exit.getParentStmt*() = conditional.getElse() and branch = false
    )
  )
}

predicate reachableBefore(BasicBlock block, BasicBlock avoided) {
  block.getEnclosingFunction() = avoided.getEnclosingFunction() and block != avoided and
  (
    block = avoided.getEnclosingFunction().getEntryPoint().getBasicBlock()
    or
    exists(BasicBlock previous | block = previous.getASuccessor() and reachableBefore(previous, avoided))
  )
}

predicate blockingExit(Stmt exit, Expr target) {
  (exit instanceof ReturnStmt or exit instanceof GotoStmt) and
  exit.getEnclosingFunction() = target.getEnclosingFunction() and
  not target.getBasicBlock() = exit.getBasicBlock().getASuccessor*() and
  not exit.getBasicBlock() = target.getBasicBlock().getASuccessor*() and
  reachableBefore(exit.getBasicBlock(), target.getBasicBlock()) and
  exitCondition(_, exit, _)
}

predicate dominatingConstantStore(Assignment store, Expr read) {
  (store.getLValue() instanceof FieldAccess or store.getLValue() instanceof ArrayExpr or
   store.getLValue() instanceof PointerDereferenceExpr) and
  scalarMemoryValueRead(read) and
  (
    store.getLValue().(FieldAccess).getTarget() = read.(FieldAccess).getTarget()
    or
    sameArrayCell(store.getLValue(), read)
    or
    store.getLValue() instanceof PointerDereferenceExpr and read instanceof PointerDereferenceExpr and
    exists(DataFlow::Node writtenValue, DataFlow::Node readValue |
      writtenValue.asExpr() = store.getRValue() and readValue.asExpr() = read and
      DataFlow::localFlow(writtenValue, readValue)
    )
  ) and matchingMemoryCell(store.getLValue(), read) and
  exists(store.getRValue().getFullyConverted().getValue()) and
  store.getEnclosingFunction() = read.getEnclosingFunction() and
  dominates(store.getBasicBlock(), read.getBasicBlock()) and
  not store = read.getASuccessor*()
}

// Guard dependencies need stores that are absent from the primary taint
// witness, including constant stores inside feature-selected branches.
predicate localFieldStore(Assignment store, FieldAccess read) {
  exists(FieldAccess written, DataFlow::Node origin, DataFlow::Node first, DataFlow::Node second |
    written = store.getLValue() and written.getTarget() = read.getTarget() and
    store.getEnclosingFunction() = read.getEnclosingFunction() and
    orderedOnPath(store, read) and
    first.asExpr() = written.getQualifier().getUnconverted() and
    second.asExpr() = read.getQualifier().getUnconverted() and
    DataFlow::localFlow(origin, first) and DataFlow::localFlow(origin, second)
  )
}

string storeDominatesJson(Assignment store, Expr read) {
  if store.getEnclosingFunction() = read.getEnclosingFunction() and dominates(store, read)
  then result = "true" else result = "false"
}

predicate relevantExpression(Expr expression) {
  sourceFact(expression, _, _)
  or
  mmioReadMapping(_, expression, _)
  or
  mmioReadMapping(_, _, expression)
  or
  mmioWriteContext(_, expression)
  or
  dmaSource(_, expression, _)
  or
  dmaSource(_, _, expression)
  or
  coherentSource(_, expression, _)
  or
  coherentSource(_, _, expression)
  or
  pageDmaSource(_, expression, _, _)
  or
  pageDmaSource(_, _, expression, _)
  or
  pageDmaSource(_, _, _, expression)
  or
  pagePoolSource(_, expression, _)
  or
  pagePoolSource(_, _, expression)
  or
  interruptRegistration(expression, _, _)
  or
  interruptReachable(expression.getEnclosingFunction()) and
  (sinkOperand(expression, _, _) or expression instanceof Call)
  or
  exists(DeviceFlow::PathNode node |
    expression = node.getNode().asExpr() or expression = node.getNode().asDefinition() or
    expression = node.getNode().asIndirectArgument() or expression = node.getNode().asDefiningArgument()
  )
  or
  exists(DeviceFlow::PathNode node, Expr guard |
    guardValue(guard, node.getNode().asExpr()) and guardedMemory(guard, expression, _, _, _)
  )
  or
  exists(Expr parent | relevantExpression(parent) and expressionChild(parent, expression, _))
  or
  exists(Expr following | relevantExpression(following) and valueStep(expression, following, _))
  or
  exists(Expr controlled | relevantExpression(controlled) and controllingCondition(expression, controlled, _))
  or
  exists(Stmt exit, Expr controlled |
    relevantExpression(controlled) and
    (controlled instanceof Call or controlled instanceof Assignment) and
    blockingExit(exit, controlled) and exitCondition(expression, exit, _)
  )
  or
  exists(Expr operand | relevantExpression(operand) and sinkOperand(expression, operand, _))
  or
  exists(Expr sink | relevantExpression(sink) and sinkOperand(sink, expression, _))
  or
  exists(Expr child | relevantExpression(child) and expression = child.getParent+().(Call))
  or
  exists(Call call, Function callee, ReturnStmt returned |
    relevantExpression(call) and callBinding(call, callee) and
    returned.getEnclosingFunction() = callee and expression = returned.getExpr()
  )
  or
  exists(Call call, Function callee, Parameter parameter |
    referenceWriteCall(call) and callBinding(call, callee) and outputParameterStore(callee, parameter, expression)
  )
  or
  exists(Expr original | relevantExpression(original) and expression = original.getFullyConverted())
  or
  exists(Expr read |
    relevantExpression(read) and dominatingConstantStore(expression, read)
  )
  or
  exists(FieldAccess read | relevantExpression(read) and localFieldStore(expression, read))
}

predicate referenceWriteCall(Call call) {
  exists(Expr argument, Expr use |
    argument = call.getAnArgument() and relevantExpression(use) and valueStep(argument, use, "call_write")
  )
}

predicate pathStore(Assignment store) {
  (store.getLValue() instanceof FieldAccess or store.getLValue() instanceof ArrayExpr or
   store.getLValue() instanceof PointerDereferenceExpr) and
  exists(DeviceFlow::PathNode node |
    store = node.getNode().asExpr() or store = node.getNode().asDefinition()
  )
  or
  exists(Expr read | relevantExpression(read) and dominatingConstantStore(store, read))
}

module StoredValueConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    exists(Assignment store | pathStore(store) and node.asExpr() = store.getRValue())
  }

  predicate isSink(DataFlow::Node node) {
    scalarMemoryValueRead(node.asExpr()) and relevantExpression(node.asExpr())
  }
}

module StoredValueFlow = DataFlow::Global<StoredValueConfig>;

private int constantMemoryOffset(Expr expression) {
  not exists(Expr index, int stride | memoryIndex(expression, index, stride) and not exists(index.getValue())) and
  result = memoryOffset(expression) + sum(Expr index, int stride |
    memoryIndex(expression, index, stride) | index.getValue().toInt() * stride)
}

bindingset[written, read]
pragma[inline]
private predicate matchingMemoryCell(Expr written, Expr read) {
  written.getType().getSize() = read.getType().getSize() and
  not exists(int leftOffset, int rightOffset |
    leftOffset = constantMemoryOffset(written) and rightOffset = constantMemoryOffset(read) and leftOffset != rightOffset
  ) and
  (not written instanceof FieldAccess or not read instanceof FieldAccess or
   written.(FieldAccess).getTarget() = read.(FieldAccess).getTarget())
}

private predicate sameArrayCell(Expr first, Expr second) {
  exists(VariableAccess firstBase, VariableAccess secondBase, Variable variable |
    firstBase = memoryBase(first).getUnconverted() and secondBase = memoryBase(second).getUnconverted() and
    firstBase.getTarget() = variable and secondBase.getTarget() = variable and
    variable.getType().getUnspecifiedType() instanceof ArrayType and
    first.getType().getSize() = second.getType().getSize() and
    constantMemoryOffset(first) = constantMemoryOffset(second)
  )
}

private predicate replacedMemoryStore(Assignment store, Expr read) {
  exists(AssignExpr later |
    sameArrayCell(store.getLValue(), later.getLValue()) and sameArrayCell(later.getLValue(), read) and
    orderedOnPath(store, later) and dominates(later, read)
  )
}

private string memoryIndicesJson(Expr expression) {
  result = "[" + concat(Expr index, int stride | memoryIndex(expression, index, stride) |
    "{\"expression\":" + quoted(expressionKey(index)) + ",\"stride\":" + stride.toString() + "}",
    "," order by expressionKey(index), stride) + "]"
}

from string section, string key, string value
where
  exists(Variable driver, Function probe, Variable table |
    registeredDriver(driver, probe, table) and
    section = "feature_driver" and key = functionKey(probe) and
    value = "{\"driver\":" + quoted(declarationKey(driver)) +
      ",\"probe\":" + quoted(functionKey(probe)) +
      ",\"bits\":" + driverFeaturesJson(table) +
      ",\"location\":" + locationJson(driver) + "}"
  )
  or
  exists(Variable operations, Function getter |
    registeredFeatureGetter(operations, getter) and
    section = "feature_getter" and key = declarationKey(operations) and
    value = "{\"operations\":" + quoted(operations.getName()) +
      ",\"getter\":" + quoted(functionKey(getter)) +
      ",\"location\":" + locationJson(operations) + "}"
  )
  or
  exists(Expr expression |
    relevantExpression(expression) and
    section = "expression" and key = expressionKey(expression) and
    value = expressionJson(expression)
  )
  or
  exists(Parameter parameter |
    (exists(VariableAccess access | relevantExpression(access) and parameterUsePair(parameter, access)) or
     exists(DeviceFlow::PathNode node | node.getNode().asParameter(0) = parameter)) and
    section = "expression" and key = parameterKey(parameter) and value = parameterJson(parameter)
  )
  or
  exists(Parameter parameter, VariableAccess access |
    relevantExpression(access) and parameterUsePair(parameter, access) and
    section = "definition" and key = parameterKey(parameter) + "->" + expressionKey(access) and
    value = "{\"src\":" + quoted(parameterKey(parameter)) +
      ",\"dst\":" + quoted(expressionKey(access)) + "}"
  )
  or
  exists(Parameter parameter, VariableAccess access, Expr later |
    relevantExpression(access) and parameterUsePair(parameter, access) and valueStep(later, access, _) and
    section = "definition_order" and key = expressionKey(access) + ":" + parameterKey(parameter) + "->" + expressionKey(later) and
    value = "{\"use\":" + quoted(expressionKey(access)) +
      ",\"earlier\":" + quoted(parameterKey(parameter)) +
      ",\"later\":" + quoted(expressionKey(later.getFullyConverted())) + "}"
  )
  or
  exists(Function function |
    (exists(Expr expression | relevantExpression(expression) and expression.getEnclosingFunction() = function) or
     interruptReachable(function)) and section = "function" and
    key = functionKey(function) and
    value = "{\"id\":" + quoted(key) + ",\"name\":" + quoted(function.getName()) +
      ",\"location\":" + locationJson(function) + "}"
  )
  or
  exists(Expr expression |
    kernelExpression(expression) and sourceFact(expression, _, value) and
    section = "source" and key = expressionKey(expression)
  )
  or
  exists(FunctionCall registration, Function handler, string phase |
    interruptRegistration(registration, handler, phase) and
    section = "irq" and key = interruptKey(registration, handler, phase) and
    value = interruptJson(registration, handler, phase)
  )
  or
  exists(Expr sink, Expr operand, string operation |
    relevantExpression(sink) and sinkOperand(sink, operand, operation) and
    section = "sink" and key = expressionKey(sink) + ":" + expressionKey(operand) and
    value = "{\"expression\":" + quoted(expressionKey(sink)) +
      ",\"operand\":" + quoted(expressionKey(operand.getFullyConverted())) +
      ",\"flow_operand\":" + quoted(expressionKey(operand)) +
      ",\"operation\":" + quoted(operation) +
      ",\"function\":" + quoted(functionKey(sink.getEnclosingFunction())) +
      capacityJson(sink) + sinkAccessJson(sink, operand) + ",\"location\":" + locationJson(sink) + "}"
  )
  or
  exists(Expr previous, Expr following, string reason |
    relevantExpression(following) and
    valueStep(previous, following, reason) and reason = "definition" and section = "definition" and
    key = expressionKey(previous) + "->" + expressionKey(following) and
    value = "{\"src\":" + quoted(expressionKey(previous.getFullyConverted())) +
      ",\"dst\":" + quoted(expressionKey(following)) + "}"
  )
  or
  exists(Expr previous, Expr following, string reason |
    relevantExpression(following) and valueStep(previous, following, reason) and reason != "definition" and
    section = "write_definition" and key = expressionKey(previous) + "->" + expressionKey(following) and
    value = "{\"site\":" + quoted(expressionKey(previous)) + ",\"dst\":" + quoted(expressionKey(following)) +
      ",\"kind\":" + quoted(reason) + ",\"calls\":[" + concat(Call call, int position |
        previous = call.getArgument(position) |
        "{\"call\":" + quoted(expressionKey(call)) + ",\"argument\":" + position.toString() + "}",
        "," order by expressionKey(call), position) + "]}"
  )
  or
  exists(Call call, Function function, Parameter parameter, Assignment store |
    referenceWriteCall(call) and callBinding(call, function) and outputParameterStore(function, parameter, store) and
    section = "output_store" and key = functionKey(function) + ":" + expressionKey(store) + ":" + parameter.getIndex().toString() and
    value = "{\"function\":" + quoted(functionKey(function)) +
      ",\"argument\":" + parameter.getIndex().toString() +
      ",\"store\":" + quoted(expressionKey(store)) +
      ",\"src\":" + quoted(expressionKey(store.getRValue().getFullyConverted())) +
      ",\"width_bytes\":" + store.getLValue().getType().getSize().toString() +
      ",\"closed\":" + outputStoresClosedJson(function, parameter) +
      ",\"predecessors\":[" + concat(Assignment previous |
        outputParameterStore(function, parameter, previous) and orderedOnPath(previous, store) |
        quoted(expressionKey(previous)), "," order by expressionKey(previous)) + "]" +
      ",\"complete\":" + outputStoreCompleteJson(function, parameter, store) + "}"
  )
  or
  exists(Expr earlier, Expr later, Expr use |
    relevantExpression(use) and valueStep(earlier, use, _) and valueStep(later, use, _) and
    earlier != later and later = earlier.getASuccessor+() and not earlier = later.getASuccessor+() and
    section = "definition_order" and
    key = expressionKey(use) + ":" + expressionKey(earlier) + "->" + expressionKey(later) and
    value = "{\"use\":" + quoted(expressionKey(use)) +
      ",\"earlier\":" + quoted(expressionKey(earlier.getFullyConverted())) +
      ",\"later\":" + quoted(expressionKey(later.getFullyConverted())) + "}"
  )
  or
  exists(Expr definition, Expr use |
    relevantExpression(use) and valueStep(definition, use, _) and
    definition = definition.getASuccessor+() and section = "definition_cycle" and
    key = expressionKey(use) and value = "true"
  )
  or
  exists(Assignment store, Expr read, DataFlow::Node previous, DataFlow::Node following |
    pathStore(store) and previous.asExpr() = store.getRValue() and following.asExpr() = read and
    StoredValueFlow::flow(previous, following) and
    scalarMemoryValueRead(read) and matchingMemoryCell(store.getLValue(), read) and
    not replacedMemoryStore(store, read) and
    section = "store_use" and key = expressionKey(store) + "->" + expressionKey(read) and
    value = "{\"store\":" + quoted(expressionKey(store)) +
      ",\"src\":" + quoted(expressionKey(store.getRValue().getFullyConverted())) +
      ",\"dst\":" + quoted(expressionKey(read)) +
      ",\"write_offset\":" + memoryOffset(store.getLValue()).toString() +
      ",\"read_offset\":" + memoryOffset(read).toString() +
      ",\"write_indices\":" + memoryIndicesJson(store.getLValue()) +
      ",\"read_indices\":" + memoryIndicesJson(read) +
      ",\"dominates\":" + storeDominatesJson(store, read) + "}"
  )
  or
  exists(Assignment store, FieldAccess read |
    relevantExpression(read) and localFieldStore(store, read) and
    section = "local_store" and key = expressionKey(store) + "->" + expressionKey(read) and
    value = "{\"store\":" + quoted(expressionKey(store)) +
      ",\"src\":" + quoted(expressionKey(store.getRValue().getFullyConverted())) +
      ",\"dst\":" + quoted(expressionKey(read)) +
      ",\"field\":" + quoted(declarationKey(read.getTarget())) +
      ",\"receiver\":" + quoted(expressionKey(read.getQualifier().getUnconverted())) +
      ",\"dominates\":" + storeDominatesJson(store, read) +
      ",\"predecessors\":[" + concat(Assignment previous |
        localFieldStore(previous, read) and orderedOnPath(previous, store) |
        quoted(expressionKey(previous)), "," order by expressionKey(previous)) + "]}"
  )
  or
  exists(Stmt exit, Expr controlled |
    relevantExpression(controlled) and
    (controlled instanceof Call or controlled instanceof Assignment) and
    blockingExit(exit, controlled) and
    section = "exit_guard" and key = syntaxKey(exit) + "->" + expressionKey(controlled) and
    value = "{\"target\":" + quoted(expressionKey(controlled)) +
      ",\"location\":" + locationJson(exit) + ",\"conditions\":[" +
      concat(Expr condition, boolean branch | exitCondition(condition, exit, branch) |
        "{\"condition\":" + quoted(expressionKey(condition)) +
        ",\"branch\":" + branch.toString() + "}",
        "," order by expressionKey(condition), branch) + "]}"
  )
  or
  exists(Call call, Function callee |
    relevantExpression(call) and callBinding(call, callee) and
    section = "call" and key = expressionKey(call) + "->" + functionKey(callee) and
    value = "{\"call\":" + quoted(expressionKey(call)) +
      ",\"callee\":" + quoted(functionKey(callee)) +
      ",\"parameters\":[" + concat(Parameter parameter |
        parameter = callee.getAParameter() |
        "{\"index\":" + parameter.getIndex().toString() +
        ",\"declaration\":" + quoted(declarationKey(parameter)) + "}",
        "," order by parameter.getIndex()) + "]}"
  )
  or
  exists(ReturnStmt statement, Expr returned |
    returned = statement.getExpr() and relevantExpression(returned) and
    section = "return" and key = expressionKey(returned) and
    value = "{\"function\":" + quoted(functionKey(returned.getEnclosingFunction())) +
      ",\"expression\":" + quoted(expressionKey(returned.getFullyConverted())) + "}"
  )
  or
  exists(Expr guard, Expr expression, boolean branch |
    relevantExpression(expression) and controllingCondition(guard, expression, branch) and
    section = "guard" and
    key = expressionKey(guard) + ":" + branch.toString() + ":" + expressionKey(expression) and
    value = "{\"condition\":" + quoted(expressionKey(guard)) +
      ",\"target\":" + quoted(expressionKey(expression)) +
      ",\"branch\":" + branch.toString() + "}"
  )
select section, key, value
