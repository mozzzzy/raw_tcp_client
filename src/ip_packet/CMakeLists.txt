add_library(ip_packet ip_packet.cc)

target_include_directories(ip_packet
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )
