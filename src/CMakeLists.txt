###############################################################################
# Copyright (c) 2016-22, Lawrence Livermore National Security, LLC
# and RAJA project contributors. See the RAJA/LICENSE file for details.
#
# SPDX-License-Identifier: (BSD-3-Clause)
###############################################################################

set(example_depends RAJA)

if (ENABLE_OPENMP)
  set(example_depends 
    ${example_depends}
    openmp)
endif ()

if (ENABLE_CUDA)
  set(example_depends 
    ${example_depends}
    cuda)
endif ()

blt_add_executable(
  NAME example.exe
  SOURCES example.cpp
  DEPENDS_ON ${example_depends})
