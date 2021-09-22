add_library(arp_message
  arp_message.cc
  )

target_include_directories(arp_message
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
  )
