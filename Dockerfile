FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONPATH=/app/src
RUN useradd --system --create-home --uid 10001 sentinel
WORKDIR /app
COPY src/ /app/src/
USER sentinel
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=2).status==200 else 1)"
# Mount a data volume at /data containing sentinel.db and tokens.json.
CMD ["python", "-m", "sentinel", "serve", "--db", "/data/sentinel.db", "--tokens", "/data/tokens.json", "--host", "0.0.0.0", "--port", "8080"]
