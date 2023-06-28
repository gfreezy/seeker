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

# 获取今天的日期
DATE=$(date +%Y%m%d)

# 定义标签前缀
PREFIX="v"

# 定义标签
TAG="${PREFIX}${DATE}"

# 检查是否存在指定的标签
if git tag | grep -q "^${TAG}$"; then
    # 如果存在，找出带有数字后缀的最大标签
    MAX=$(git tag | grep "^${TAG}-" | sed "s/^${TAG}-//g" | sort -nr | head -n1)

    # 如果没有找到带有数字后缀的标签，设置默认值为 1
    if [ -z "$MAX" ]; then
        MAX=1
    else
        # 移除数字前的0
        MAX=$(echo $MAX | sed 's/^0*//')
    fi

    # 递增后缀数字
    TAG="${TAG}-$(printf "%02d" $((MAX + 1)))"
fi

# 创建新的标签
git tag $TAG

# 打印新的标签
echo "Created new tag: $TAG"

git push origin $TAG
