# - Try to find libdebuginfod
# Once done this will define
#
#  LIBDEBUGINFOD_FOUND - system has libdebuginfod
#  LIBDEBUGINFOD_INCLUDE_DIRS - the libdebuginfod include directory
#  LIBDEBUGINFOD_LIBRARIES - Link these to use libdebuginfod
#

find_package(PkgConfig QUIET)
if(PKG_CONFIG_FOUND)
  pkg_check_modules(PC_LIBDEBUGINFOD QUIET libdebuginfod)
endif()

find_path(LIBDEBUGINFOD_INCLUDE_DIRS
  NAMES
    debuginfod.h
    elfutils/debuginfod.h
  HINTS
    ${PC_LIBDEBUGINFOD_INCLUDEDIR}
    ${PC_LIBDEBUGINFOD_INCLUDE_DIRS}
  PATHS
    ENV CPATH)

find_library(LIBDEBUGINFOD_LIBRARIES
  NAMES
    debuginfod
  HINTS
    ${PC_LIBDEBUGINFOD_LIBDIR}
    ${PC_LIBDEBUGINFOD_LIBRARY_DIRS}
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include(FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibDebuginfod "libdebuginfod not found (debuginfod support disabled)"
  LIBDEBUGINFOD_LIBRARIES
  LIBDEBUGINFOD_INCLUDE_DIRS)

mark_as_advanced(LIBDEBUGINFOD_INCLUDE_DIRS LIBDEBUGINFOD_LIBRARIES)
