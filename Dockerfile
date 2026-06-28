FROM alpine:latest
RUN apk --no-cache add ca-certificates
COPY mamori /usr/local/bin/mamori
ENTRYPOINT ["mamori"]
