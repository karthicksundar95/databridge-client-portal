FROM python:3.13-slim
WORKDIR /app
RUN addgroup --system databridge && adduser --system --ingroup databridge databridge
COPY pyproject.toml .
COPY app ./app
COPY scripts ./scripts
RUN pip install --no-cache-dir .
USER databridge
EXPOSE 8081
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8081"]
