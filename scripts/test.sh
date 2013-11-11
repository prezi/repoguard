#!/bin/sh

# Jenkins script that runs your tests. #build#tests#idoc

. $(dirname $0)/common

RELEASE_ID=$1; shift

cd "${root}"

${root}/setup.sh

## Example below is for Python project using virtualenv and nosetests for testing

# ensure_virtualenv
# sb install -q -r "${root}/requirements-test.txt"
# nosetests