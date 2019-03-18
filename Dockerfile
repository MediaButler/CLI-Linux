FROM alpine:3.9
LABEL maintainer="MediaButler"
COPY ./ /app/

RUN apk add --no-cache bash \
        curl \
        sed \
        jq && \
        chmod +x /app/mb-linux-cli-utility.sh

CMD ["/app/mb-linux-cli-utility.sh"]
