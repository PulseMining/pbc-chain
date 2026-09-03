set(webui_sources pbc_webui.cpp)

add_executable(pbc-webui ${webui_sources})

target_link_libraries(pbc-webui
  PRIVATE
    Threads::Threads
)

set_property(TARGET pbc-webui PROPERTY OUTPUT_NAME "pbc-webui")

install(TARGETS pbc-webui DESTINATION bin)

# Install web assets alongside binary
install(DIRECTORY ${CMAKE_SOURCE_DIR}/web/ DESTINATION web)
