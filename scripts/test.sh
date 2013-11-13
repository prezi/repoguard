#!/bin/sh

# Jenkins script that runs your tests. #build#tests#idoc

. $(dirname $0)/common

RELEASE_ID=$1; shift

cd "${root}"

${root}/scripts/setup.sh

ensure_virtualenv
sb install -q -r "${root}/requirements-test.txt"
cd repoguard
python run_unit_tests.py