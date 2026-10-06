FROM golang:1.23-alpine AS b
WORKDIR /s
COPY go.mod main.go ./
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /swagui .

FROM scratch
COPY --from=b /swagui /swagui
EXPOSE 8080
ENTRYPOINT ["/swagui"]
