add_library(transmission_control_block transmission_control_block.cc)

target_link_libraries(transmission_control_block
  PRIVATE
    tcp_segment
  )

target_include_directories(transmission_control_block
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )
