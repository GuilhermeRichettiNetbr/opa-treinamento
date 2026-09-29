FROM golang:1.23-alpine AS build
WORKDIR /app
COPY go.mod ./
COPY *.go ./
RUN CGO_ENABLED=0 go build -o /servico-produtos .

FROM alpine:3.20
COPY --from=build /servico-produtos /servico-produtos
EXPOSE 8080
ENTRYPOINT ["/servico-produtos"]
