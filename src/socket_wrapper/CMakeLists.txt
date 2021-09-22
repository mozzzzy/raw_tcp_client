add_library(socket_wrapper socket_wrapper.cc)

target_include_directories(socket_wrapper
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )
