FROM golang:1.22-alpine AS build
WORKDIR /src
COPY . .
RUN go build -o /out/app .

FROM alpine:3.19
COPY --from=build /out/app /usr/local/bin/app
USER nobody
ENTRYPOINT ["/usr/local/bin/app"]