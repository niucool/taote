# Manual imported-target detection for the engine libraries whose vcpkg ports
# ship raw headers/libs without CMake config files (unicorn, keystone).
#
# unicorn  : header  unicorn/unicorn.h   lib  unicorn
# keystone : header  keystone/keystone.h  lib  keystone
#
# Creates unicorn::unicorn and keystone::keystone, mirroring the config-file
# targets the other dependencies (capstone, pe-parse, ...) provide.

include(GNUInstallDirs)

function(_qiling_engine_dep target pkg header libname)
    find_path(${pkg}_INCLUDE_DIR NAMES ${header}
        PATHS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/${CMAKE_INSTALL_INCLUDEDIR}"
        NO_DEFAULT_PATH)
    find_library(${pkg}_LIBRARY NAMES ${libname}
        PATHS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/${CMAKE_INSTALL_LIBDIR}"
        NO_DEFAULT_PATH)

    include(FindPackageHandleStandardArgs)
    find_package_handle_standard_args(${pkg}
        REQUIRED_VARS ${pkg}_LIBRARY ${pkg}_INCLUDE_DIR)

    if(NOT TARGET ${target})
        add_library(${target} UNKNOWN IMPORTED)
        set_target_properties(${target} PROPERTIES
            IMPORTED_LOCATION "${${pkg}_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${${pkg}_INCLUDE_DIR}")
    endif()
    mark_as_advanced(${pkg}_INCLUDE_DIR ${pkg}_LIBRARY)
endfunction()

_qiling_engine_dep(unicorn::unicorn unicorn unicorn/unicorn.h unicorn)
_qiling_engine_dep(keystone::keystone keystone keystone/keystone.h keystone)
