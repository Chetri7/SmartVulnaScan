FROM python:3.12-slim

# set workdir
WORKDIR /app

# copy requirements and install if present
COPY requirements.txt ./
RUN if [ -s requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; fi

# copy project
COPY . .

# create non-root user and set permissions
RUN useradd -m scanner && chown -R scanner:scanner /app
USER scanner

# default entrypoint
ENTRYPOINT ["python", "SmartVulnaScan.py"]
CMD []
