import KernelExpressions
import KernelOrdering
import semmle.code.cpp.controlflow.Dominance
import semmle.code.cpp.dataflow.new.DataFlow

predicate dmaMapping(FunctionCall call, Expr buffer, Expr size, Expr direction) {
  call.getTarget().getName() in ["dma_map_single", "dma_map_single_attrs", "virtqueue_map_single_attrs"] and
  buffer = call.getArgument(1) and size = call.getArgument(2) and direction = call.getArgument(3)
}

predicate dmaPageMapping(FunctionCall call, Expr page, Expr offset, Expr size, Expr direction) {
  call.getTarget().getName() in ["dma_map_page", "dma_map_page_attrs", "virtqueue_map_page_attrs"] and
  page = call.getArgument(1) and offset = call.getArgument(2) and
  size = call.getArgument(3) and direction = call.getArgument(4)
}

predicate pageAddressView(FunctionCall view, Expr page) {
  view.getTarget().getName() in ["page_address", "lowmem_page_address", "page_to_virt"] and
  page = view.getArgument(0)
}

predicate inversePageView(FunctionCall view, Expr address) {
  view.getTarget().getName() in ["virt_to_page", "virt_to_head_page"] and address = view.getArgument(0)
}

predicate pagePoolSyncCall(FunctionCall call) {
  call.getTarget().getName() = "page_pool_dma_sync_for_cpu" and call.getNumberOfArguments() = 4
}

predicate dmaCompletion(FunctionCall call, Expr handle, Expr direction) {
  call.getTarget().getName() in ["dma_unmap_single", "dma_unmap_single_attrs", "dma_unmap_page", "dma_unmap_page_attrs",
    "dma_sync_single_for_cpu", "virtqueue_unmap_page_attrs"] and
  handle = call.getArgument(1) and direction = call.getArgument(3)
  or
  call.getTarget().getName() in ["dma_sync_single_range_for_cpu", "virtqueue_map_sync_single_range_for_cpu"] and
  handle = call.getArgument(1) and direction = call.getArgument(4)
}

predicate deviceWritableDirection(Expr direction) {
  exists(EnumConstant constant |
    constant.getName() in ["DMA_FROM_DEVICE", "DMA_BIDIRECTIONAL"] and
    direction.getFullyConverted().getValue() = constant.getValue()
  )
}

predicate compoundArrayBase(Expr expression, Expr base) {
  base = expression.(ArrayExpr).getArrayBase().getUnconverted() and
  base.getUnspecifiedType() instanceof ArrayType and
  (base instanceof FieldAccess or base instanceof ArrayExpr or base instanceof PointerDereferenceExpr)
}

Expr memoryBase(Expr expression) {
  expression instanceof PointerFieldAccess and result = expression.(PointerFieldAccess).getQualifier().getFullyConverted()
  or
  expression instanceof ValueFieldAccess and result = memoryBase(expression.(ValueFieldAccess).getQualifier().getUnconverted())
  or
  expression instanceof ArrayExpr and
  (exists(Expr base | compoundArrayBase(expression, base) and result = memoryBase(base))
   or not compoundArrayBase(expression, _) and result = expression.(ArrayExpr).getArrayBase().getFullyConverted())
  or
  expression instanceof PointerDereferenceExpr and result = expression.(PointerDereferenceExpr).getOperand().getFullyConverted()
  or
  exists(VariableAccess access, AddressOfExpr address |
    expression = access and address.getOperand().getUnconverted().(VariableAccess).getTarget() = access.getTarget() and
    address.getEnclosingFunction() = access.getEnclosingFunction() and result = address
  )
}

int memoryOffset(Expr expression) {
  expression instanceof PointerFieldAccess and result = expression.(PointerFieldAccess).getTarget().getByteOffset()
  or
  expression instanceof ValueFieldAccess and
  result = memoryOffset(expression.(ValueFieldAccess).getQualifier().getUnconverted()) + expression.(ValueFieldAccess).getTarget().getByteOffset()
  or
  expression instanceof ArrayExpr and
  (exists(Expr base | compoundArrayBase(expression, base) and result = memoryOffset(base))
   or not compoundArrayBase(expression, _) and result = 0)
  or
  (expression instanceof PointerDereferenceExpr or expression instanceof VariableAccess and not expression instanceof FieldAccess) and result = 0
}

predicate memoryIndex(Expr expression, Expr index, int stride) {
  expression instanceof ArrayExpr and index = expression.(ArrayExpr).getArrayOffset().getFullyConverted() and
  stride = expression.getType().getSize()
  or
  exists(Expr base | compoundArrayBase(expression, base) and memoryIndex(base, index, stride))
  or
  expression instanceof ValueFieldAccess and memoryIndex(expression.(ValueFieldAccess).getQualifier().getUnconverted(), index, stride)
}

predicate scalarMemoryValueRead(Expr expression) {
  exists(expression.getEnclosingFunction().getBlock()) and not expression.isUnevaluated() and
  expression.getUnspecifiedType() instanceof IntegralType and
  expression.getType().getSize() in [1, 2, 4, 8] and
  not exists(AssignExpr assignment | assignment.getLValue() = expression) and
  not exists(AddressOfExpr addressOf | addressOf.getOperand() = expression) and
  (expression instanceof FieldAccess or expression instanceof ArrayExpr or expression instanceof PointerDereferenceExpr)
}

predicate scalarMemoryRead(Expr expression, Expr address, int offset) {
  scalarMemoryValueRead(expression) and address = memoryBase(expression) and offset = memoryOffset(expression)
}

module DmaAddressConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    not node.isGLValue() and
    node.getType().getUnspecifiedType() instanceof PointerType and
    (
      exists(node.asParameter(0))
      or
      node.asExpr() instanceof Call or node.asExpr() instanceof AddressOfExpr or node.asExpr() instanceof VariableAccess
    )
  }

  predicate isSink(DataFlow::Node node) {
    dmaMapping(_, node.asExpr(), _, _) or dmaPageMapping(_, node.asExpr(), _, _, _) or
    pageAddressView(_, node.asExpr()) or inversePageView(_, node.asExpr()) or
    exists(FunctionCall completion | pagePoolSyncCall(completion) and node.asExpr() = completion.getArgument(1)) or
    scalarMemoryRead(_, node.asExpr().getFullyConverted(), _)
  }

  predicate isAdditionalFlowStep(DataFlow::Node previous, DataFlow::Node following) {
    exists(AddExpr addition |
      following.asExpr() = addition and previous.asExpr() = addition.getAnOperand() and
      previous.getType().getUnspecifiedType() instanceof PointerType
    )
    or
    exists(SubExpr subtraction |
      following.asExpr() = subtraction and previous.asExpr() = subtraction.getLeftOperand() and
      previous.getType().getUnspecifiedType() instanceof PointerType
    )
    or
    exists(PointerFieldAccess field |
      field.getUnspecifiedType() instanceof ArrayType and
      following.asExpr() = field and previous.asExpr() = field.getQualifier()
    )
  }
}

module DmaAddressFlow = DataFlow::Global<DmaAddressConfig>;

module DmaHandleConfig implements DataFlow::ConfigSig {
  predicate isSource(DataFlow::Node node) {
    dmaMapping(node.asExpr(), _, _, _) or dmaPageMapping(node.asExpr(), _, _, _, _) or
    node.asExpr().(FunctionCall).getTarget().getName() = "page_pool_get_dma_addr"
  }
  predicate isSink(DataFlow::Node node) { dmaCompletion(_, node.asExpr(), _) }
}

module DmaHandleFlow = DataFlow::Global<DmaHandleConfig>;

predicate dmaSource(Expr read, FunctionCall mapping, FunctionCall completion) {
  exists(Expr buffer, Expr size, Expr direction, Expr handle, Expr completedDirection, Expr address,
         DataFlow::Node origin, DataFlow::Node mapped, DataFlow::Node loaded,
         DataFlow::Node mappedHandle, DataFlow::Node completedHandle |
    dmaMapping(mapping, buffer, size, direction) and deviceWritableDirection(direction) and
    dmaCompletion(completion, handle, completedDirection) and deviceWritableDirection(completedDirection) and
    mappedHandle.asExpr() = mapping and completedHandle.asExpr() = handle and
    DmaHandleFlow::flow(mappedHandle, completedHandle) and
    scalarMemoryRead(read, address, _) and
    mapped.asExpr() = buffer and loaded.asExpr().getFullyConverted() = address and
    DmaAddressFlow::flow(origin, mapped) and DmaAddressFlow::flow(origin, loaded) and
    dominates(mapping, completion) and orderedOnPath(completion, read) and
    not exists(AssignExpr write, DataFlow::Node stored, DataFlow::Node loadedValue |
      orderedOnPath(completion, write) and dominates(write, read) and
      stored.asExpr() = write.getRValue() and loadedValue.asExpr() = read and
      DataFlow::localFlow(stored, loadedValue)
    )
  )
}

string dmaReadIndicesJson(Expr read) {
  result = ",\"indices\":[" + concat(Expr index, int stride | memoryIndex(read, index, stride) |
    "{\"expression\":" + quoted(expressionKey(index)) + ",\"stride\":" + stride.toString() + "}",
    "," order by expressionKey(index), stride) + "]"
}

string dmaReadFieldJson(Expr read) {
  if read instanceof FieldAccess
  then result = ",\"field\":" + quoted(read.(FieldAccess).getTarget().getName())
  else result = ""
}

predicate dmaSourceFact(Expr expression, string kind, string json) {
  exists(Expr address, int offset |
    scalarMemoryRead(expression, address, offset) and dmaSource(expression, _, _) and
    kind = "DmaReadStreaming" and
    json = "{\"kind\":\"DmaReadStreaming\",\"size_bytes\":" + expression.getType().getSize().toString() +
      ",\"byte_order\":" + quoted(targetByteOrder()) +
      ",\"address\":" + quoted(expressionKey(address.getFullyConverted())) +
      ",\"field_offset\":" + offset.toString() + dmaReadIndicesJson(expression) + dmaReadFieldJson(expression) +
      ",\"bindings\":[" + concat(FunctionCall mapping, FunctionCall completion, Expr buffer, Expr size, Expr direction |
        dmaSource(expression, mapping, completion) and dmaMapping(mapping, buffer, size, direction) |
        "{\"mapping\":" + quoted(expressionKey(mapping)) +
        ",\"completion\":" + quoted(expressionKey(completion)) +
        ",\"buffer\":" + quoted(expressionKey(buffer.getFullyConverted())) +
        ",\"size\":" + quoted(expressionKey(size.getFullyConverted())) +
        ",\"direction\":" + quoted(expressionKey(direction.getFullyConverted())) +
        ",\"location\":" + locationJson(mapping) + "}", "," order by expressionKey(mapping), expressionKey(completion)) +
      "],\"function\":" + quoted(functionKey(expression.getEnclosingFunction())) +
      ",\"location\":" + locationJson(expression) + "}"
  )
}
