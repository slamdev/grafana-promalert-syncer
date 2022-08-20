# grafana-promalert-syncer

A simple tool that exports all PrometheusRule alert resources from a cluster and sync them to 
[grafana alerts](https://grafana.com/docs/grafana/latest/alerting/).

This tool is meant to be used as a CronJob.

E.g.:

```yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: alert-syncer
spec:
  schedule: "*/5 * * * *"
  jobTemplate:
    spec:
      template:
        spec:
          restartPolicy: OnFailure
          containers:
            - name: grafana-promalert-syncer
              image: slamdev/grafana-promalert-syncer
              args: [ '--grafana-url=http://grafana', '--grafana-api-key=glsa_XXX' ]
```
