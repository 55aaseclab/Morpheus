import KernelExpressions
import semmle.code.cpp.models.interfaces.Allocation

class KernelAllocationFunction extends AllocationFunction {
  int sizeIndex;

  KernelAllocationFunction() {
    this.getName() in ["kmalloc", "kmalloc_noprof", "kzalloc", "kzalloc_noprof", "kvmalloc", "kvzalloc",
      "kmalloc_node", "kmalloc_node_noprof", "kzalloc_node", "alloc_pages_exact", "__alloc_pages_exact"] and sizeIndex = 0
    or
    this.getName() in ["dma_alloc_coherent", "dma_alloc_attrs", "dmam_alloc_coherent", "dmam_alloc_attrs"] and sizeIndex = 1
    or
    this.getName() = "virtqueue_map_alloc_coherent" and sizeIndex = 2
  }

  override int getSizeArg() { result = sizeIndex }
}

class KernelSkbAllocationFunction extends AllocationFunction {
  KernelSkbAllocationFunction() { this.getName() in ["alloc_skb", "__alloc_skb"] }
}

class KernelArrayAllocationFunction extends AllocationFunction {
  KernelArrayAllocationFunction() {
    this.getName() in ["kcalloc", "kcalloc_noprof", "kvcalloc", "kvcalloc_noprof", "kmalloc_array", "kmalloc_array_noprof"]
  }

  override int getSizeArg() { result = 0 }
  override int getSizeMult() { result = 1 }
}

predicate coherentAllocation(FunctionCall call) {
  call.getTarget().getName() in ["dma_alloc_coherent", "dma_alloc_attrs", "dmam_alloc_coherent", "dmam_alloc_attrs",
    "virtqueue_map_alloc_coherent"]
}
