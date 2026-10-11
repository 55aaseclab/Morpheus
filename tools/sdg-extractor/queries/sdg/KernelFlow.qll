import KernelFacts
import KernelGuards
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

module KernelFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    sourceFact(node.asExpr(), _, _)
  }

  predicate isSink(DataFlow::Node node) {
    sinkOperand(_, node.asExpr(), _) or memoryGuardValue(node.asExpr())
  }

  predicate includeHiddenNodes() { any() }

  predicate isAdditionalFlowStep(DataFlow::Node previous, DataFlow::Node following) {
    exists(FunctionCall call |
      call.getTarget().getName() in ["__builtin_bswap16", "__builtin_bswap32", "__builtin_bswap64",
                                   "__builtin_expect", "__builtin_expect_with_probability"] and
      previous.asExpr() = call.getArgument(0) and following.asExpr() = call
    )
    or
    exists(ConditionalExpr conditional |
      previous.asExpr() = conditional.getCondition() and following.asExpr() = conditional
    )
    or
    exists(GuardCondition condition, ReturnStmt returned, ReturnStmt other |
      returned.getEnclosingFunction() = other.getEnclosingFunction() and returned != other and
      exists(returned.getExpr()) and exists(other.getExpr()) and
      condition.controls(returned.getExpr().getBasicBlock(), _) and
      previous.asExpr() = condition and following.asExpr() = returned.getExpr()
    )
  }

}

module DeviceFlow = TaintTracking::Global<KernelFlowConfig>;
