# TODO ip_addr.h が見つからない
add_library(ioctl_util ioctl_util.cc)

target_link_libraries(ioctl_util
  PRIVATE
    ip_addr
    mac_addr
  )

target_include_directories(ioctl_util
  PUBLIC
    ${CMAKE_CURRENT_LIST_DIR}
    #PRIVATE
    #${PROJECT_SOURCE_DIR}/addr
  )
