FROM golang:1.25-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /stile .

FROM scratch
COPY --from=build /stile /stile
USER 1000:1000
VOLUME /data
EXPOSE 9092
ENTRYPOINT ["/stile"]
