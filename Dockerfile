FROM gcr.io/distroless/static-debian12
COPY mamori /usr/local/bin/mamori
ENTRYPOINT ["/usr/local/bin/mamori"]
