###############################################################################
# Copyright (c) 2016-22, Lawrence Livermore National Security, LLC
# and RAJA project contributors. See the RAJA/LICENSE file for details.
#
# SPDX-License-Identifier: (BSD-3-Clause)
###############################################################################
cmake_minimum_required(VERSION 3.8)

project( raja-example )

set (ENABLE_TESTS Off CACHE BOOL "")
set (ENABLE_EXAMPLES Off CACHE BOOL "")
set (ENABLE_REPRODUCERS Off CACHE BOOL "")
set (ENABLE_EXERCISES Off CACHE BOOL "")
set (ENABLE_DOCUMENTATION Off CACHE BOOL "")
set (ENABLE_BENCHMARKS Off CACHE BOOL "")

include(blt/SetupBLT.cmake)

if (DEFINED RAJA_DIR)
  find_package(RAJA REQUIRED)
  blt_print_target_properties(TARGET RAJA)
else ()
  add_subdirectory(tpl/raja)
endif ()

if (ENABLE_CUDA)
  set (CMAKE_CUDA_FLAGS "${CMAKE_CUDA_FLAGS} --expt-extended-lambda")
endif ()

add_subdirectory(src)
