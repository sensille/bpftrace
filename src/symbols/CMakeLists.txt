add_library(symbols STATIC
  elf_parser.cpp
  kernel.cpp
  user.cpp
  )

target_compile_definitions(symbols PUBLIC KERNEL_HEADERS_DIR="${KERNEL_HEADERS_DIR}")

find_package(LibLZMA)
target_link_libraries(symbols util btf ${LIBELF_LIBRARIES} ${ZLIB_LIBRARIES})
if(LIBLZMA_FOUND)
  target_compile_definitions(symbols PRIVATE HAVE_LIBLZMA)
  target_include_directories(symbols PRIVATE ${LIBLZMA_INCLUDE_DIRS})
  target_link_libraries(symbols ${LIBLZMA_LIBRARIES})
endif()
