FROM gcr.io/distroless/static:nonroot
WORKDIR /
ADD grafana-promalert-syncer grafana-promalert-syncer
USER 65532:65532

ENTRYPOINT ["/grafana-promalert-syncer"]
