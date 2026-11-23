# SBVF — Search-Based Vulnerability Framework
# Self-contained image: the UI boots the benchmark apps internally. Standard library
# only, so no pip install step is required for the core framework.
FROM python:3.12-slim

# git is required by the dashboard's "scan a repository URL" feature, which
# shallow-clones a GitHub/GitLab/Bitbucket repo into a temp dir, scans it, and
# deletes it. The slim base image does not ship git.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sbvf/ ./sbvf/
COPY testbed/ ./testbed/
COPY ui/ ./ui/
COPY tests/ ./tests/

ENV PYTHONUNBUFFERED=1 \
    SBVF_UI_HOST=0.0.0.0 \
    SBVF_UI_PORT=8080

EXPOSE 8080

# Run the real-time dashboard by default. Override the command to run experiments,
# e.g.  docker run --rm sbvf python -m sbvf.experiment --split test --runs 20
CMD ["python", "-m", "ui.server"]
