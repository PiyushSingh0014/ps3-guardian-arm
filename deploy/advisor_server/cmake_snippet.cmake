
# --- PS3 Guardian advisor_server (added by ps3-guardian/deploy/advisor_server/build_pi4.sh) ---
# Built exactly like llama_main above: same libraries, flags and rpath.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/advisor_server.cpp)
  add_executable(advisor_server advisor_server.cpp)
  target_include_directories(advisor_server PUBLIC ${_common_include_directories})
  target_link_libraries(advisor_server PUBLIC llama_runner ${link_libraries})
  target_compile_options(advisor_server PUBLIC ${_common_compile_options})
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options_gc_sections(advisor_server)
    target_link_options(advisor_server PRIVATE "LINKER:-s")
  endif()
  set_target_properties(advisor_server PROPERTIES LINK_FLAGS "-Wl,-rpath='$ORIGIN'")
endif()
