#!/bin/bash
set -ev
if [ "${TRAVIS_BRANCH}" = "dev" ]; then
  make prepare_git
  make patch_git
  make update_linuxkit
  cd ./build/linuxkit
  git remote add to_push https://${GITHUB_KEY}@github.com/CamFlow/linuxkit.git > /dev/null 2>&1
  git pull --allow-unrelated-histories
  git push --set-upstream to_push master
  cd ../..
fi
