# - Try to find libentize
# Once done this will define
#
#  LIBENTIZE_FOUND - system has libentize
#  LIBENTIZE_INCLUDE_DIRS - the libentize include directory
#  LIBENTIZE_LIBRARIES - Link these to use libentize
#


find_path (LIBENTIZE_INCLUDE_DIRS
  NAMES
    entize.h
  PATHS
    ENV CPATH)

find_library (LIBENTIZE_LIBRARIES
  NAMES
    entize_c
  PATHS
    ENV LIBRARY_PATH
    ENV LD_LIBRARY_PATH)

include (FindPackageHandleStandardArgs)

FIND_PACKAGE_HANDLE_STANDARD_ARGS(LibEntize "Please install the libentize development package"
  LIBENTIZE_LIBRARIES
  LIBENTIZE_INCLUDE_DIRS)

mark_as_advanced(LIBENTIZE_INCLUDE_DIRS LIBENTIZE_LIBRARIES)
