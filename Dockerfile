FROM certbot/certbot:v5.8.0@sha256:f70ad0adbb7e117f0fe42a63c553f28ea451edabc0148757b6efcd9735acaa20 as build

COPY . src/certbot-dns-namecheap
RUN pip install --no-cache-dir --editable src/certbot-dns-namecheap

####################
FROM build as test

RUN pip install pytest
RUN pytest src/certbot-dns-namecheap

####################
FROM build

RUN apk add curl
