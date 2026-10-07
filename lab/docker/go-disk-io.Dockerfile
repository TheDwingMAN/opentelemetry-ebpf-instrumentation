FROM docker.io/library/debian:bookworm-slim@sha256:98f4b71de414932439ac6ac690d7060df1f27161073c5036a7553723881bffbe
COPY go-disk-io /go-disk-io
CMD ["/go-disk-io"]
