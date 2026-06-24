FROM projectdiscovery/nuclei:latest

USER root

RUN apk add --no-cache python3 py3-pip

WORKDIR /app

COPY . .

RUN pip install --no-cache-dir --break-system-packages -r requirements.txt

RUN mkdir -p results

RUN nuclei -update-templates || true

ENV PORT=10000

ENTRYPOINT []

EXPOSE 10000

CMD gunicorn app:app --bind 0.0.0.0:$PORT --workers 1 --timeout 360
