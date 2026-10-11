import cpp
import semmle.code.cpp.controlflow.BasicBlocks
import semmle.code.cpp.controlflow.Dominance

private predicate forwardBlockStep(BasicBlock previous, BasicBlock following) {
  following = previous.getASuccessor() and not bbDominates(following, previous)
}

bindingset[previous, following]
pragma[inline]
predicate orderedOnPath(ControlFlowNode previous, ControlFlowNode following) {
  previous.getControlFlowScope() = following.getControlFlowScope() and
  (
    previous.getBasicBlock() != following.getBasicBlock() and
    forwardBlockStep+(previous.getBasicBlock(), following.getBasicBlock())
    or
    previous.getBasicBlock() = following.getBasicBlock() and
    strictlyDominates(previous, following)
  )
}
