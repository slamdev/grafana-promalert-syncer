# grafana-promalert-syncer

A simple tool that exports all PrometheusRule resources from a cluster and converts them to a set of files in
[native rule format](https://cortexmetrics.io/docs/api/#example-response) that is readable by cortex or mimir.

This tool is ment to be used as a CronJob together with [cortextool](https://github.com/grafana/cortex-tools) or
[mimirtool](https://grafana.com/docs/mimir/latest/operators-guide/tools/mimirtool/).

E.g.:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: rule-syncer
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          initContainers:
            - name: grafana-promalert-syncer
              image: slamdev/grafana-promalert-syncer
              args: [ '--exclude-alert-rules=true', '--output-dir=/out' ]
              volumeMounts:
                - name: rules
                  mountPath: /out
          containers:
            - name: rule-syncer
              image: grafana/mimirtool:2.2.0
              args: [ 'rules', 'sync', '--address=http://mimir', '--id=anonymous', '--rule-dirs=/in' ]
              volumeMounts:
                - name: rules
                  mountPath: /in
          volumes:
            - name: rules
              emptyDir: { }
```
