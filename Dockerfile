FROM --platform=$BUILDPLATFORM golang:1.27.1 AS build

ARG TARGETOS=linux
ARG TARGETARCH
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags="-s -w" -o /out/kubelego ./cmd/kubelego

FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=build /out/kubelego /kubelego
USER nonroot:nonroot
ENTRYPOINT ["/kubelego"]
