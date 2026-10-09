import KernelFacts
import semmle.code.cpp.dataflow.new.DataFlow
import semmle.code.cpp.dataflow.new.TaintTracking

module KernelFlowConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    sourceFact(node.asExpr(), _, _)
  }

  predicate isSink(DataFlow::Node node) {
    sinkOperand(_, node.asExpr(), _)
  }

  predicate isAdditionalFlowStep(DataFlow::Node previous, DataFlow::Node following) {
    exists(Assignment assignment, FieldAccess write, FieldAccess read |
      assignment.getLValue() = write and
      write.getTarget() = read.getTarget() and
      write.isModified() and read.isRValue() and
      previous.asExpr() = assignment.getRValue() and following.asExpr() = read
    )
  }

}

module DeviceFlow = TaintTracking::Global<KernelFlowConfig>;
