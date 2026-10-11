import KernelExpressions
import KernelOrdering
import semmle.code.cpp.controlflow.Dominance
import semmle.code.cpp.controlflow.DefinitionsAndUses
import semmle.code.cpp.dataflow.new.DataFlow

predicate ioRead(FunctionCall call, int width) {
  exists(string name |
    name = call.getTarget().getName() |
    (name.regexpMatch("(__raw_)?readb(_relaxed)?") or name = "ioread8") and width = 1
    or (name.regexpMatch("(__raw_)?readw(_relaxed)?") or name.regexpMatch("ioread16(be)?")) and width = 2
    or (name.regexpMatch("(__raw_)?readl(_relaxed)?") or name.regexpMatch("ioread32(be)?")) and width = 4
    or (name.regexpMatch("(__raw_)?readq(_relaxed)?") or name.regexpMatch("ioread64(be)?")) and width = 8
  )
}

predicate ioHelper(Function function) {
  exists(FunctionCall call | call.getTarget() = function and ioRead(call, _))
}

predicate ioWrite(FunctionCall call, int width) {
  exists(string name |
    name = call.getTarget().getName() |
    (name.regexpMatch("(__raw_)?writeb(_relaxed)?") or name = "iowrite8") and width = 1
    or (name.regexpMatch("(__raw_)?writew(_relaxed)?") or name.regexpMatch("iowrite16(be)?")) and width = 2
    or (name.regexpMatch("(__raw_)?writel(_relaxed)?") or name.regexpMatch("iowrite32(be)?")) and width = 4
    or (name.regexpMatch("(__raw_)?writeq(_relaxed)?") or name.regexpMatch("iowrite64(be)?")) and width = 8
  )
}

predicate mmioMapping(FunctionCall call) {
  call.getTarget().getName() in [
    "ioremap", "ioremap_np", "ioremap_wc", "ioremap_cache", "ioremap_prot",
    "devm_ioremap", "devm_ioremap_wc", "devm_ioremap_resource", "devm_ioremap_resource_wc",
    "devm_platform_ioremap_resource", "devm_platform_ioremap_resource_byname",
    "devm_platform_get_and_ioremap_resource", "pci_iomap", "pci_iomap_wc",
    "pci_iomap_range", "pci_iomap_wc_range", "of_iomap"
  ]
}

private predicate addressPredecessor(Expr address, Expr previous) {
  previous = address.(Conversion).getExpr()
  or
  exists(BinaryArithmeticOperation arithmetic |
    address = arithmetic and arithmetic.getOperator() in ["+", "-"] and
    previous = arithmetic.getLeftOperand().getFullyConverted() and
    previous.getUnspecifiedType() instanceof PointerType
  )
  or
  exists(AddExpr addition |
    address = addition and previous = addition.getRightOperand().getFullyConverted() and
    previous.getUnspecifiedType() instanceof PointerType
  )
  or
  exists(SemanticStackVariable variable |
    definitionUsePair(variable, previous, address)
  )
}

predicate mmioAddressRoot(Expr address, Expr root) {
  address = root and not addressPredecessor(address, _)
  or
  exists(Expr previous | addressPredecessor(address, previous) and mmioAddressRoot(previous, root))
}

predicate mmioReadRoot(FunctionCall read, Expr root) {
  ioRead(read, _) and not ioHelper(read.getEnclosingFunction()) and
  mmioAddressRoot(read.getArgument(0).getFullyConverted(), root)
}

predicate mmioWriteRoot(FunctionCall write, Expr root) {
  ioWrite(write, _) and mmioAddressRoot(write.getArgument(1).getFullyConverted(), root)
}

module MmioMappingConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) { mmioMapping(node.asExpr()) }
  predicate isSink(DataFlow::Node node) {
    mmioReadRoot(_, node.asExpr()) or mmioWriteRoot(_, node.asExpr())
  }
}

module MmioMappingFlow = DataFlow::Global<MmioMappingConfig>;

predicate mmioReadMapping(FunctionCall read, Expr root, FunctionCall mapping) {
  mmioReadRoot(read, root) and mmioRootMapping(root, mapping)
}

private predicate mmioRootMapping(Expr root, FunctionCall mapping) {
  exists(DataFlow::Node origin, DataFlow::Node destination |
    origin.asExpr() = mapping and destination.asExpr() = root and
    MmioMappingFlow::flow(origin, destination)
  )
}

bindingset[left, right]
pragma[inline]
private predicate sameLocalAddress(Expr left, Expr right) {
  left = right
  or
  exists(DataFlow::Node origin, DataFlow::Node first, DataFlow::Node second |
    first.asExpr() = left and second.asExpr() = right and
    DataFlow::localFlow(origin, first) and DataFlow::localFlow(origin, second)
  )
}

bindingset[left, right]
pragma[inline]
private predicate sameAddressBase(Expr left, Expr right) {
  mmioReadRoot(_, left) and mmioWriteRoot(_, right) and
  (
    sameLocalAddress(left, right)
    or
    exists(PointerFieldAccess first, PointerFieldAccess second |
      left = first and right = second and first.getTarget() = second.getTarget() and
      sameLocalAddress(first.getQualifier().getUnconverted(), second.getQualifier().getUnconverted()) and
      not exists(Expr update |
        update.getEnclosingFunction() = first.getEnclosingFunction() and
        (update.(Assignment).getLValue() instanceof FieldAccess or
         update.(Assignment).getLValue() instanceof ArrayExpr or
         update.(Assignment).getLValue() instanceof PointerDereferenceExpr or
         update instanceof Call and not ioRead(update, _) and not ioWrite(update, _)) and
        (orderedOnPath(first, update) and orderedOnPath(update, second) or
         orderedOnPath(second, update) and orderedOnPath(update, first))
      )
    )
  )
}

predicate mmioWriteContext(FunctionCall read, FunctionCall write) {
  read.getEnclosingFunction() = write.getEnclosingFunction() and dominates(write, read) and
  exists(Expr readRoot, Expr writeRoot |
    mmioReadRoot(read, readRoot) and mmioWriteRoot(write, writeRoot) and
    (sameAddressBase(readRoot, writeRoot) or
     exists(FunctionCall mapping | mmioRootMapping(readRoot, mapping) and mmioRootMapping(writeRoot, mapping)))
  )
}

string mmioMappingsJson(FunctionCall read) {
  result = ",\"mapping_bindings\":[" + concat(Expr root, FunctionCall mapping |
    mmioReadMapping(read, root, mapping) |
    "{\"base\":" + quoted(expressionKey(root)) +
    ",\"mapping\":" + quoted(expressionKey(mapping)) +
    ",\"location\":" + locationJson(mapping) + "}",
    "," order by expressionKey(root), expressionKey(mapping)) + "]" +
    ",\"access_context\":[" + concat(FunctionCall write, int width |
      mmioWriteContext(read, write) and ioWrite(write, width) |
      "{\"write\":" + quoted(expressionKey(write)) +
      ",\"address\":" + quoted(expressionKey(write.getArgument(1).getFullyConverted())) +
      ",\"value\":" + quoted(expressionKey(write.getArgument(0).getFullyConverted())) +
      ",\"size_bytes\":" + width.toString() + ",\"predecessors\":[" +
      concat(FunctionCall previous |
        mmioWriteContext(read, previous) and orderedOnPath(previous, write) |
        quoted(expressionKey(previous)), "," order by expressionKey(previous)) + "]}",
      "," order by expressionKey(write)) + "]"
}
