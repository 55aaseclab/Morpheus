import KernelDma
import KernelAllocations
import semmle.code.cpp.pointsto.PointsTo

predicate coherentObservation(Expr read, FunctionCall barrier) {
  barrier.getTarget().getName() in ["virtio_rmb", "dma_rmb", "rmb"] and
  dominates(barrier, read)
}

class CoherentReadAddress extends PointsToExpr {
  override predicate interesting() {
    exists(Expr read | scalarMemoryRead(read, this, _) and coherentObservation(read, _))
  }
}

predicate coherentSource(Expr read, FunctionCall allocation, FunctionCall barrier) {
  exists(CoherentReadAddress address |
    scalarMemoryRead(read, address, _) and coherentObservation(read, barrier) and
    coherentAllocation(allocation) and address.pointsTo() = allocation and
    not exists(Element other | other = address.pointsTo() and not coherentAllocation(other)) and
    not exists(AssignExpr write, DataFlow::Node stored, DataFlow::Node loaded |
      write.getEnclosingFunction() = read.getEnclosingFunction() and dominates(write, read) and
      stored.asExpr() = write.getRValue() and loaded.asExpr() = read and DataFlow::localFlow(stored, loaded)
    ) and not dmaSource(read, _, _)
  )
}

predicate coherentSourceFact(Expr read, string kind, string json) {
  exists(Expr address, int offset |
    scalarMemoryRead(read, address, offset) and coherentSource(read, _, _) and kind = "DmaReadCoherent" and
    json = "{\"kind\":\"DmaReadCoherent\",\"size_bytes\":" + read.getType().getSize().toString() +
      ",\"byte_order\":" + quoted(targetByteOrder()) +
      ",\"address\":" + quoted(expressionKey(address)) +
      ",\"field_offset\":" + offset.toString() + dmaReadIndicesJson(read) + dmaReadFieldJson(read) +
      ",\"bindings\":[" + concat(FunctionCall allocation, FunctionCall barrier, int sizeIndex |
        coherentSource(read, allocation, barrier) and sizeIndex = allocation.getTarget().(KernelAllocationFunction).getSizeArg() |
        "{\"mapping\":" + quoted(expressionKey(allocation)) +
        ",\"allocation\":" + quoted(expressionKey(allocation)) +
        ",\"completion\":" + quoted(expressionKey(barrier)) +
        ",\"buffer\":" + quoted(expressionKey(allocation)) +
        ",\"size\":" + quoted(expressionKey(allocation.getArgument(sizeIndex).getFullyConverted())) +
        ",\"location\":" + locationJson(allocation) + "}",
        "," order by expressionKey(allocation), expressionKey(barrier)) +
      "],\"lifetime_unresolved\":true,\"function\":" + quoted(functionKey(read.getEnclosingFunction())) +
      ",\"location\":" + locationJson(read) + "}"
  )
}
