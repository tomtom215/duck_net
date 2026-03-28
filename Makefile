PROJ_DIR := $(dir $(abspath $(lastword $(MAKEFILE_LIST))))

# Extension name must match the cdylib output name
EXTENSION_NAME=duck_net

# Include DuckDB extension build infrastructure
include extension-ci-tools/makefiles/c_api_extensions/base.Makefile
include extension-ci-tools/makefiles/c_api_extensions/rust.Makefile
