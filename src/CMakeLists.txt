add_executable(main main.cc)

add_subdirectory(addr)
add_subdirectory(arp)
add_subdirectory(ioctl_util)
add_subdirectory(ip_packet)
add_subdirectory(socket_wrapper)
add_subdirectory(tcp)

target_link_libraries(main
  PRIVATE
    arp_message
    ioctl_util
    ip_addr
    ip_packet
    mac_addr
    name_resolver
    socket_wrapper
    tcp_segment
    transmission_control_block
  )
