add_library(name_resolver
  name_resolver.cc
  )

target_link_libraries(name_resolver
  PRIVATE
    arp_message
    ip_addr
    mac_addr
    socket_wrapper
  )

target_include_directories(name_resolver
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )
