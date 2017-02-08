mackerel-plugin-aws-waf
=======================

AWS WAF custom metrics plugin for mackerel.io agent.

## Synopsis

```shell
mackerel-plugin-aws-waf -web-acl=<aws-waf-web-acl> [-region=<aws-region>] [-access-key-id=<id>] [-secret-access-key=<key>] [-tempfile=<tempfile>]
```

## AWS IAM Policy
the credential provided manually or fetched automatically by IAM Role should have the policy that includes an action, 'cloudwatch:GetMetricStatistics'

## Example of mackerel-agent.conf

```
[plugin.metrics.aws-waf]
command = "/path/to/mackerel-plugin-aws-waf -web-acl=your-web-acl"
```
