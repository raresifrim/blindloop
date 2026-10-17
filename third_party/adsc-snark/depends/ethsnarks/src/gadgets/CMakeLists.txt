file(GLOB gadget_sources "*.cpp")
add_library(ethsnarks_gadgets STATIC ${gadget_sources})
target_link_libraries(ethsnarks_gadgets ethsnarks_common)