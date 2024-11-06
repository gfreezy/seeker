#!/bin/bash
# 检查当前的分支是否是 master 分支
current_branch=$(git symbolic-ref --short -q HEAD)
if [ "$current_branch" != "master" ]; then
  echo "Current branch is $current_branch, not master. Please checkout master branch before tagging."
  exit 1
fi

# 检查工作区是否干净
if [ -n "$(git status --porcelain)" ]; then
  echo "Working directory is not clean. Please commit or stash your changes before tagging."
  exit 1
fi

# 获取今天的日期，格式为 YYYYMMDD
major=$(date +"%Y%m%d")
minor=0
patch=0

# 查找是否存在类似的版本号
existing_tags=$(git tag | grep "${major}\.${minor}\.[0-9]\+")

echo "Existing tags: $existing_tags"

if [ -z "$existing_tags" ]; then
    # 如果没有类似的版本号，使用 0 作为 patch
    new_version="${major}.${minor}.${patch}"
else
    # 如果有类似的版本号，找到 patch 最大的版本号
    max_patch=$(echo "$existing_tags" | awk -F'.' '{print $3}' | sort -nr | head -n 1)
    new_patch=$((max_patch + 1))
    new_version="${major}.${minor}.${new_patch}"
fi

echo "New version: $new_version"

cargo release --execute $new_version
