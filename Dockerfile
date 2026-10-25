# One image, two roles (WAF + toy backend). Multi-stage, slim base, non-root.
FROM python:3.12-slim AS build
WORKDIR /src
COPY pyproject.toml ./
COPY src ./src
RUN pip install --no-cache-dir --prefix=/install .

FROM python:3.12-slim
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --uid 10001 --no-create-home --shell /usr/sbin/nologin app
COPY --from=build /install /usr/local
WORKDIR /app
COPY backend ./backend
USER 10001
EXPOSE 8080
CMD ["uvicorn", "sentinel.main:app_factory", "--factory", "--host", "0.0.0.0", "--port", "8080"]
