
# --- PS3 Guardian advisor_server (added by ps3-guardian/deploy/advisor_server/build_pi4.sh) ---
# Built exactly like llama_main above: same libraries, flags and rpath.
if(EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/advisor_server.cpp)
  add_executable(advisor_server advisor_server.cpp)
  target_include_directories(advisor_server PUBLIC ${_common_include_directories})
  target_link_libraries(advisor_server PUBLIC llama_runner ${link_libraries})
  target_compile_options(advisor_server PUBLIC ${_common_compile_options})
  if(CMAKE_SYSTEM_PROCESSOR MATCHES "arm64|aarch64")
    # custom_ops hands -march=armv8.2-a+dotprod to every program that links it, which
    # lets the compiler put Armv8.1 atomics (LSE) straight into this file. The Pi 4
    # (Cortex-A72) is Armv8.0 and stops on them, so compile this file for armv8-a
    # again. Per-file options come last on the command line, so this one wins.
    set_source_files_properties(advisor_server.cpp PROPERTIES COMPILE_OPTIONS "-march=armv8-a")
  endif()
  if(CMAKE_BUILD_TYPE STREQUAL "Release")
    target_link_options_gc_sections(advisor_server)
    target_link_options(advisor_server PRIVATE "LINKER:-s")
  endif()
  set_target_properties(advisor_server PROPERTIES LINK_FLAGS "-Wl,-rpath='$ORIGIN'")
endif()
# --- end PS3 Guardian advisor_server ---
