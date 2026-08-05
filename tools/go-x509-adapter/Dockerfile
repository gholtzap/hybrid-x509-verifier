FROM golang:1.26.4-bookworm@sha256:b305420a68d0f229d91eb3b3ed9e519fcf2cf5461da4bef997bf927e8c0bfd2b AS build
WORKDIR /source
COPY go.mod *.go ./
RUN go test ./... && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -buildid=" -o /adapter .

FROM scratch
COPY --from=build /adapter /adapter
USER 65532:65532
ENTRYPOINT ["/adapter"]
