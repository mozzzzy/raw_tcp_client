add_library(tcp_segment tcp_segment.cc)

target_include_directories(tcp_segment
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )
