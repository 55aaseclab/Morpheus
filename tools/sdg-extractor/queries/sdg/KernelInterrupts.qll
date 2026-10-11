import KernelFacts
import semmle.code.cpp.dataflow.new.DataFlow

predicate interruptArgument(FunctionCall call, Expr argument, string phase, int irqIndex, int contextIndex) {
  exists(string name, int handlerIndex |
    name = call.getTarget().getName() and
    (
      name in ["request_irq", "request_any_context_irq", "request_nmi"] and
      handlerIndex = 1 and irqIndex = 0 and contextIndex = 4 and phase = "hardirq"
      or
      name = "request_threaded_irq" and irqIndex = 0 and contextIndex = 5 and
      (handlerIndex = 1 and phase = "hardirq" or handlerIndex = 2 and phase = "thread")
      or
      name in ["devm_request_irq", "devm_request_any_context_irq", "devm_request_nmi"] and
      handlerIndex = 2 and irqIndex = 1 and contextIndex = 5 and phase = "hardirq"
      or
      name = "devm_request_threaded_irq" and irqIndex = 1 and contextIndex = 6 and
      (handlerIndex = 2 and phase = "hardirq" or handlerIndex = 3 and phase = "thread")
      or
      name in ["request_percpu_irq", "request_percpu_nmi"] and
      handlerIndex = 1 and irqIndex = 0 and contextIndex = 3 and phase = "hardirq"
    ) and argument = call.getArgument(handlerIndex)
  )
}

predicate interruptRegistrationCall(FunctionCall call, Expr argument, string phase, int irqIndex, int contextIndex) {
  kernelExpression(call) and interruptArgument(call, argument, phase, irqIndex, contextIndex) and
  not exists(FunctionCall caller |
    caller.getTarget() = call.getEnclosingFunction() and interruptArgument(caller, _, _, _, _)
  )
}

module InterruptHandlerConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    node.asExpr() instanceof FunctionAccess
  }

  predicate isSink(DataFlow::Node node) {
    interruptRegistrationCall(_, node.asExpr(), _, _, _)
  }
}

module InterruptHandlerFlow = DataFlow::Global<InterruptHandlerConfig>;

predicate interruptRegistration(FunctionCall registration, Function handler, string phase) {
  exists(Expr argument, FunctionAccess callback, DataFlow::Node source, DataFlow::Node sink |
    interruptRegistrationCall(registration, argument, phase, _, _) and
    source.asExpr() = callback and sink.asExpr() = argument and
    InterruptHandlerFlow::flow(source, sink) and
    handler = callback.getTarget() and exists(handler.getBlock())
  )
}

string interruptKey(FunctionCall registration, Function handler, string phase) {
  interruptRegistration(registration, handler, phase) and
  result = "irq:" + expressionKey(registration) + ":" + functionKey(handler) + ":" + phase
}

predicate interruptReachable(Function function) {
  interruptRegistration(_, function, _)
  or
  exists(Call call | interruptReachable(call.getEnclosingFunction()) and callBinding(call, function))
}

string interruptJson(FunctionCall registration, Function handler, string phase) {
  exists(int irqIndex, int contextIndex |
    interruptRegistrationCall(registration, _, phase, irqIndex, contextIndex) |
    result = "{\"kind\":\"Irq\",\"handler\":" + quoted(handler.getName()) +
      ",\"function\":" + quoted(functionKey(handler)) +
      ",\"registration\":" + quoted(expressionKey(registration)) +
      ",\"irq\":" + quoted(expressionKey(registration.getArgument(irqIndex))) +
      ",\"context\":" + quoted(expressionKey(registration.getArgument(contextIndex))) +
      ",\"phase\":" + quoted(phase) +
      ",\"location\":" + locationJson(registration) + "}"
  )
}
