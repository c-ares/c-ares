# CMAKE_CONFIGURATION_TYPES is empty on non-IDE generators (Ninja, NMake)
# and that's why we also use CMAKE_BUILD_TYPE to cover for those generators.
# For IDE generators, CMAKE_BUILD_TYPE is usually empty
FOREACH (config_type ${CMAKE_CONFIGURATION_TYPES} ${CMAKE_BUILD_TYPE})
    STRING (TOUPPER ${config_type} upper_config_type)
    SET (flag_var "CMAKE_C_FLAGS_${upper_config_type}")
    IF (${flag_var} MATCHES "/MD")
        STRING (REGEX REPLACE "/MD" "/MT" ${flag_var} "${${flag_var}}")
    ENDIF ()
ENDFOREACH ()

# clean up
SET (upper_config_type)
SET (config_type)
SET (flag_var)
