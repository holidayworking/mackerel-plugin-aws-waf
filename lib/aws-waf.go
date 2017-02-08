package mpawswaf

import (
	"errors"
	"flag"
	"log"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/ec2metadata"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/cloudwatch"
	mp "github.com/mackerelio/go-mackerel-plugin"
)

var graphdef = map[string]mp.Graphs{
	"waf.Requests": {
		Label: "AWS WAF Requests",
		Unit:  "integer",
		Metrics: []mp.Metrics{
			{Name: "AllowedRequests", Label: "AllowedRequests"},
			{Name: "BlockedRequests", Label: "BlockedRequests"},
			{Name: "CountedRequests", Label: "CountedRequests"},
		},
	},
}

type WafPlugin struct {
	Region          string
	AccessKeyID     string
	SecretAccessKey string
	WebAcl          string
	CloudWatch      *cloudwatch.CloudWatch
}

func (p *WafPlugin) prepare() error {
	sess, err := session.NewSession()
	if err != nil {
		return err
	}

	config := aws.NewConfig()
	if p.AccessKeyID != "" && p.SecretAccessKey != "" {
		config = config.WithCredentials(credentials.NewStaticCredentials(p.AccessKeyID, p.SecretAccessKey, ""))
	}
	if p.Region != "" {
		config = config.WithRegion(p.Region)
	}

	p.CloudWatch = cloudwatch.New(sess, config)
	return nil
}

func (p WafPlugin) getLastPoint(dimensions []*cloudwatch.Dimension, metricName string) (float64, error) {
	now := time.Now()

	response, err := p.CloudWatch.GetMetricStatistics(&cloudwatch.GetMetricStatisticsInput{
		Namespace:  aws.String("WAF"),
		MetricName: aws.String(metricName),
		StartTime:  aws.Time(now.Add(time.Duration(180) * time.Second * -1)),
		EndTime:    aws.Time(now),
		Period:     aws.Int64(60),
		Statistics: []*string{aws.String("Sum")},
		Dimensions: dimensions,
	})

	if err != nil {
		return 0, err
	}

	datapoints := response.Datapoints
	if len(datapoints) == 0 {
		return 0, errors.New("fetched no datapoints")
	}

	latest := time.Unix(0, 0)
	var latestVal float64
	for _, dp := range datapoints {
		if dp.Timestamp.Before(latest) {
			continue
		}

		latest = *dp.Timestamp
		latestVal = *dp.Sum
	}

	return latestVal, nil
}

func (p WafPlugin) FetchMetrics() (map[string]float64, error) {
	stat := make(map[string]float64)

	dimensions := []*cloudwatch.Dimension{
		{
			Name:  aws.String("Rule"),
			Value: aws.String("ALL"),
		},
		{
			Name:  aws.String("WebACL"),
			Value: aws.String(p.WebAcl),
		},
	}

	for _, met := range [...]string{
		"AllowedRequests",
		"BlockedRequests",
		"CountedRequests",
	} {
		v, err := p.getLastPoint(dimensions, met)
		if err == nil {
			stat[met] = v
		} else {
			log.Printf("%s: %s", met, err)
		}
	}

	return stat, nil
}

func (p WafPlugin) GraphDefinition() map[string]mp.Graphs {
	return graphdef
}

func Do() {
	optAccessKeyID := flag.String("access-key-id", "", "AWS Access Key ID")
	optSecretAccessKey := flag.String("secret-access-key", "", "AWS Secret Access Key")
	optRegion := flag.String("region", "", "AWS Region")
	optWebAcl := flag.String("web-acl", "", "AWS Web ACL name")
	optTempfile := flag.String("tempfile", "", "Temp file name")
	flag.Parse()

	var waf WafPlugin

	if *optRegion == "" {
		ec2metadata := ec2metadata.New(session.New())
		if ec2metadata.Available() {
			waf.Region, _ = ec2metadata.Region()
		}
	} else {
		waf.Region = *optRegion
	}

	waf.WebAcl = *optWebAcl
	waf.AccessKeyID = *optAccessKeyID
	waf.SecretAccessKey = *optSecretAccessKey

	err := waf.prepare()
	if err != nil {
		log.Fatalln(err)
	}

	helper := mp.NewMackerelPlugin(waf)
	helper.Tempfile = *optTempfile

	if os.Getenv("MACKEREL_AGENT_PLUGIN_META") != "" {
		helper.OutputDefinitions()
	} else {
		helper.OutputValues()
	}
}
