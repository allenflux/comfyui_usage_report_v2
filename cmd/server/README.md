# comfyui_usage_report_v2

docker build --no-cache -t comfyui-usage-report:latest .

docker run --rm -d -p 8080:8080   -v $(pwd)/google-service-account.json:/app/credentials/google-service-account.json   comfyui-usage-report:latest