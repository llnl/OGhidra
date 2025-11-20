//////////////////////////////////////////////////////////////////////////////
// Copyright (c) 2016-22, Lawrence Livermore National Security, LLC
// and RAJA project contributors. See the RAJA/LICENSE file for details.
//
// SPDX-License-Identifier: (BSD-3-Clause)
//////////////////////////////////////////////////////////////////////////////
#include "RAJA/RAJA.hpp"

template <typename T>
T *allocate(std::size_t size)
{
  T *ptr;
#if defined(RAJA_ENABLE_CUDA)
  cudaErrchk(
      cudaMallocManaged((void **)&ptr, sizeof(T) * size, cudaMemAttachGlobal));
#else
  ptr = new T[size];
#endif
  return ptr;
}

template <typename T>
void deallocate(T *&ptr)
{
  if (ptr) {
#if defined(RAJA_ENABLE_CUDA)
    cudaErrchk(cudaFree(ptr));
#else
    delete[] ptr;
#endif
    ptr = nullptr;
  }
}

int main(int RAJA_UNUSED_ARG(argc), char** RAJA_UNUSED_ARG(argv[]))
{
#if defined(RAJA_ENABLE_CUDA)
  using policy = RAJA::cuda_exec<256>;
  const std::string policy_name = "CUDA";
#elif defined(RAJA_ENABLE_OPENMP)
  using policy = RAJA::omp_parallel_for_exec;
  const std::string policy_name = "OpenMP";
#else
  using policy = RAJA::seq_exec;
  const std::string policy_name = "sequential";
#endif

  std::cout << "Running vector addition with RAJA using the " << policy_name << " backend...";

  constexpr int N = 1000000;

  int *a = allocate<int>(N);
  int *b = allocate<int>(N);
  int *c = allocate<int>(N);

  RAJA::forall<policy>(RAJA::TypedRangeSegment<int>(0, N), [=] RAJA_HOST_DEVICE (int i) { 
    a[i] = -i;
    b[i] = i;
  });

  RAJA::forall<policy>(RAJA::TypedRangeSegment<int>(0, N), [=] RAJA_HOST_DEVICE (int i) { 
    c[i] = a[i] + b[i]; 
  });

  std::cout << "done." << std::endl;

  deallocate(a);
  deallocate(b);
  deallocate(c);
}
