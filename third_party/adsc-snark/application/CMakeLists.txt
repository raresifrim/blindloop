add_executable(
        controller_scenario
        EXCLUDE_FROM_ALL

        controller/controller_scenario.cpp
        controller/scenario_network.cpp
        gadgets/utils.cpp
)

target_link_libraries(
        controller_scenario

        snark
        snark_crypto
        ${Boost_LIBRARIES}
)

add_executable(
        flightcontrol_scenario
        EXCLUDE_FROM_ALL

        controller/flightcontrol_scenario.cpp
        controller/scenario_network.cpp
        gadgets/utils.cpp
)

target_link_libraries(
        flightcontrol_scenario

        snark
        snark_crypto
        ${Boost_LIBRARIES}
)


