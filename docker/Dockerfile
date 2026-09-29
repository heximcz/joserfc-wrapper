ARG PYTHON_VERSION=3.11
FROM python:${PYTHON_VERSION}-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    POETRY_VIRTUALENVS_CREATE=false \
    POETRY_NO_INTERACTION=1

RUN pip install poetry

WORKDIR /app

# dependencies first for better layer caching
COPY pyproject.toml poetry.lock* README.md LICENSE ./
RUN poetry install --no-root --with dev

# project in editable mode, the source is mounted over /app at runtime
COPY joserfc_wrapper ./joserfc_wrapper
RUN poetry install --only-root

CMD ["sleep", "infinity"]
