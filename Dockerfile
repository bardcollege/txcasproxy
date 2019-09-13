FROM python:3.7-alpine as base
FROM base as builder
#FROM debian:jessie

#RUN apt-get update && apt-get install -y \
#    git \
#    libxml2-dev \
#    libxslt-dev \
#    python-lxml \
#    python \
#    build-essential \
#    make \
#    gcc \
#    python-dev \
#    locales \
#    python-pip \
#    openssl \
#    libssl-dev \
#    python-twisted \
#    libffi-dev
RUN apk add --no-cache --virtual .build-deps \
	build-base git libffi-dev openssl libxml2-dev openssl-dev py3-libxml2 \
	libxslt-dev 
FROM builder
ADD . /txcasproxy/
WORKDIR /txcasproxy
RUN pip install -r requirements.txt \
	&& find /usr/local \
		\( -type d -a -name test -o -name tests \) \
		-o \( -type f -a -name '*.pyc' -o -name '*.pyo' \) \
		-exec rm -rf '{}' + \
	&& runDeps="$( \
		scanelf --needed --nobanner --recursive /usr/local \
			| awk '{ gsub(/,/, "\nso:", $2); print "so:" $2}' \
			| sort -u \
			| xargs -r apk info --installed \
			| sort -u \
		)" \
	&& apk add --virtual .rundeps $runDeps \
	&& apk del .build-deps


ENTRYPOINT ["python3", "-m" "twisted"]

CMD ["casproxy", "--help"]
