# Lab-only image: packages a host-built obi binary, because build containers can't reach the Go proxy here.
FROM docker.io/library/ubuntu@sha256:d1e2e92c075e5ca139d51a140fff46f84315c0fdce203eab2807c7e495eff4f9
COPY obi /obi
ENTRYPOINT [ "/obi" ]
