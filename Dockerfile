FROM certbot/certbot as build

COPY . src/certbot-dns-namecheap
RUN pip install --no-cache-dir --editable src/certbot-dns-namecheap

####################
FROM build as test

RUN pip install pytest
RUN pytest src/certbot-dns-namecheap

####################
FROM build

RUN apk add curl
