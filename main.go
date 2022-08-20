package main

import (
	"context"
	"flag"
	"fmt"
	gapi "github.com/grafana/grafana-api-golang-client"
	monitoring "github.com/prometheus-operator/prometheus-operator/pkg/apis/monitoring/v1"
	"github.com/prometheus/common/model"
	"golang.org/x/exp/maps"
	"hash/fnv"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/config"
	"strconv"
	"strings"
	"time"
)

func main() {
	var grafanaUrl string
	flag.StringVar(&grafanaUrl, "grafana-url", "", "Url to grafana service")
	var grafanaAPIKey string
	flag.StringVar(&grafanaAPIKey, "grafana-api-key", "", "Grafana API Key")

	flag.Parse()

	ctx := context.Background()
	kclient, err := client.New(config.GetConfigOrDie(), client.Options{})
	if err != nil {
		klog.Fatal(err)
	}
	if err := monitoring.AddToScheme(kclient.Scheme()); err != nil {
		klog.Fatal(err)
	}

	ruleList := monitoring.PrometheusRuleList{}

	if err := kclient.List(ctx, &ruleList, &client.ListOptions{}); err != nil {
		klog.Fatal(err)
	}

	klog.Infof("found [%d] PrometheusRule resources in all namespaces", len(ruleList.Items))

	groupsByNamespace := map[string]map[string]monitoring.RuleGroup{}

	for _, rule := range ruleList.Items {
		groups := rule.Spec.Groups
		if existingGroupsByNamespace, ok := groupsByNamespace[rule.Namespace]; ok {
			for _, group := range groups {
				klog.Infof("processing [%s] group", group.Name)

				filteredRules := filterRules(group.Rules)
				group.Rules = filteredRules
				if len(group.Rules) == 0 {
					klog.Infof("no rules are left in [%s] group after filtering; skipping", group.Name)
					continue
				}

				if existingGroup, ok := existingGroupsByNamespace[group.Name]; ok {
					existingGroup.Rules = append(existingGroup.Rules, group.Rules...)
				} else {
					existingGroupsByNamespace[group.Name] = group
				}
				klog.Infof("[%s] group with [%d] rules is added to [%s] namespace", group.Name, len(group.Rules), rule.Namespace)
			}
		} else {
			groupsByName := map[string]monitoring.RuleGroup{}
			for _, group := range groups {
				klog.Infof("processing [%s] group", group.Name)

				filteredRules := filterRules(group.Rules)
				group.Rules = filteredRules
				if len(group.Rules) == 0 {
					klog.Infof("no rules are left in [%s] group after filtering; skipping", group.Name)
					continue
				}

				groupsByName[group.Name] = group
				klog.Infof("[%s] group with [%d] rules is added to [%s] namespace", group.Name, len(group.Rules), rule.Namespace)
			}

			if len(groupsByName) != 0 {
				groupsByNamespace[rule.Namespace] = groupsByName
			}
		}
	}

	gclient, _ := gapi.New(grafanaUrl, gapi.Config{
		APIKey:     grafanaAPIKey,
		NumRetries: 3,
	})

	for namespace, groupsByName := range groupsByNamespace {
		if _, err := gclient.NewFolder(namespace, namespace); err != nil {
			if !strings.Contains(err.Error(), "the folder has been changed by someone else") {
				klog.ErrorS(err, "failed to create new folder", "folder", namespace)
				continue
			}
		}
		groups := maps.Values(groupsByName)
		for _, group := range groups {
			ruleGroup, err := convertGroup(group, namespace)
			if err != nil {
				klog.ErrorS(err, "failed to convert [%s]:[%s] group to grafana representation", namespace, group.Name)
				continue
			}
			alertRules := ruleGroup.Rules
			ruleGroup.Rules = nil

			if err := gclient.SetAlertRuleGroup(ruleGroup); err != nil {
				klog.ErrorS(err, "failed to update rule group in gapi", "group", ruleGroup)
				continue
			}
			for _, rule := range alertRules {
				if _, err := gclient.NewAlertRule(&rule); err != nil {
					klog.ErrorS(err, "failed to create rule in gapi", "rule", rule.UID)
					continue
				}
			}
		}
		klog.Infof("[%d] groups are synced to grafana in [%s] namespace", len(groups), namespace)
	}
}

func convertGroup(group monitoring.RuleGroup, namespace string) (gapi.RuleGroup, error) {
	rules := map[string]gapi.AlertRule{}
	for _, rule := range group.Rules {
		if !hasKey(rule.Annotations, "description") {
			rule.Annotations["description"] = rule.Annotations["message"]
			delete(rule.Annotations, "message")
		}

		// Alerts in grafana should have uniq names but prometheus doesn't have this limitation
		// so if we find an existing alert with the same name we add D suffix to the duplicate one
		for hasKey(rules, rule.Alert) {
			rule.Alert = rule.Alert + "D"
		}

		uid := strings.ToLower(fmt.Sprintf("%s-%s-%s", namespace, group.Name, rule.Alert))
		if len(uid) > 40 {
			h := hash(uid)
			uid = fmt.Sprintf("%s-%s", uid[0:40-len(h)-1], h)
			uid = strings.ReplaceAll(uid, "--", "-")
		}

		rules[rule.Alert] = gapi.AlertRule{
			UID:         uid,
			Title:       fmt.Sprintf("%s: %s", group.Name, rule.Alert),
			Annotations: rule.Annotations,
			Condition:   "B",
			OrgID:       1,
			FolderUID:   namespace,
			RuleGroup:   group.Name,
			Data: []*gapi.AlertQuery{
				{
					RefID: "A",
					RelativeTimeRange: gapi.RelativeTimeRange{
						From: 3600,
					},
					DatasourceUID: "prometheus",
					Model: map[string]interface{}{
						"expr": rule.Expr,
					},
				},
				{
					RefID:         "B",
					DatasourceUID: "-100",
					Model: map[string]interface{}{
						"expression": "A",
						"reducer":    "mean",
						"type":       "reduce",
					},
				},
			},
			NoDataState:  gapi.NoDataOk,
			ExecErrState: gapi.ErrError,
			Labels:       rule.Labels,
			For:          rule.For,
		}
	}

	interval := 1 * time.Minute
	if group.Interval != "" {
		promInterval, err := model.ParseDuration(group.Interval)
		if err != nil {
			return gapi.RuleGroup{}, fmt.Errorf("failed to parse duration [%s] in [%s]:[%s] group", group.Interval, namespace, group.Name)
		}
		interval = time.Duration(promInterval)
	}
	return gapi.RuleGroup{
		FolderUID: namespace,
		Title:     group.Name,
		Interval:  int64(interval.Seconds()),
		Rules:     maps.Values(rules),
	}, nil
}

func filterRules(rules []monitoring.Rule) []monitoring.Rule {
	var res []monitoring.Rule
	for _, rule := range rules {
		if rule.Record != "" {
			continue
		}
		res = append(res, rule)
	}
	return res
}

func hash(text string) string {
	algorithm := fnv.New32a()
	_, _ = algorithm.Write([]byte(text))
	return strconv.FormatUint(uint64(algorithm.Sum32()), 10)
}

func hasKey[M ~map[K]V, K comparable, V any](m M, k K) bool {
	_, ok := m[k]
	return ok
}
