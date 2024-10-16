# 使用官方的 Python 基础镜像
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 安装 Flask
RUN pip install flask

# 将当前目录的内容复制到容器中的 /app 目录
COPY . .

# 暴露端口 8000
EXPOSE 8000

# 启动 Flask 应用
CMD ["python", "main.py"]