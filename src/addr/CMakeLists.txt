add_library(mac_addr
  addr.cc
  mac_addr.cc
  )

target_include_directories(mac_addr
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )

add_library(ip_addr
  addr.cc
  ip_addr.cc
  )

target_include_directories(ip_addr
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )


