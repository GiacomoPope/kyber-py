FROM alpine

RUN apk add musl-dev gcc py3-pip
RUN pip install kyber-py

ENTRYPOINT ["python"]
