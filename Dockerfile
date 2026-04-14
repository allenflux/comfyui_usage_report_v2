# syntax=docker/dockerfile:1

FROM golang:1.24-alpine AS builder

WORKDIR /src

# 先拷贝依赖文件，利用缓存
COPY go.mod go.sum ./
RUN go mod download

# 再拷贝项目源码
COPY . .

# 编译
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o /out/comfyui_usage_report ./cmd/server
# 运行镜像
FROM alpine:3.20

RUN apk add --no-cache ca-certificates tzdata && mkdir -p /app/credentials

WORKDIR /app

COPY --from=builder /out/comfyui_usage_report /app/comfyui_usage_report
COPY ./web /app/web
COPY ./config.yaml.example /app/config.yaml

ENV GOOGLE_SHEETS_CREDENTIALS_FILE=/app/credentials/google-service-account.json

EXPOSE 8080

CMD ["/app/comfyui_usage_report", "/app/config.yaml"]