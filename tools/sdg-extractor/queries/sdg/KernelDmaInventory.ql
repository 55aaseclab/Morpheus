import KernelDma
import KernelAllocations
import semmle.code.cpp.pointsto.PointsTo

class DmaCandidateAddress extends PointsToExpr {
  override predicate interesting() {
    exists(Expr read, FunctionCall barrier |
      scalarMemoryRead(read, this, _) and
      barrier.getEnclosingFunction() = read.getEnclosingFunction() and
      barrier.getTarget().getName() in ["virtio_rmb", "dma_rmb", "rmb"]
    )
  }
}

from Element allocation, Expr read, Expr address, string provenance
where
  scalarMemoryRead(read, address, _) and
  (
    address.(DmaCandidateAddress).pointsTo() = allocation and provenance = "points-to"
    or
    exists(DataFlow::Node origin, DataFlow::Node destination |
      coherentAllocation(allocation) and origin.asExpr() = allocation and
      destination.asExpr().getFullyConverted() = address and
      DmaAddressFlow::flow(origin, destination) and provenance = "native"
    )
  )
select locationKey(allocation.(Locatable)) as allocation_location, locationKey(read) as read_location,
  functionKey(read.getEnclosingFunction()) as function, expressionKey(read) as expression,
  read.toString() as value, allocation.toString() as origin, provenance
