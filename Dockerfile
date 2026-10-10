FROM golang:1.23-alpine AS b
WORKDIR /s
COPY go.mod *.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /swagui .

FROM scratch
COPY --from=b /swagui /swagui
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 CMD ["/swagui", "healthcheck"]
ENTRYPOINT ["/swagui"]
