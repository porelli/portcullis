package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/smithy-go"

	"github.com/portcullis/domains/internal/dnssec"
)

// route53DNSSEC reads a hosted zone's DNSSEC status and DS (GetDNSSEC).
// Signing on Route 53 needs a customer-managed KMS key: it stays manual,
// so this is only a StatusReader.
type route53DNSSEC struct {
	client *route53.Client
	zoneID string // hosted_zone_id, "" = looked up by name
}

// errNoProviderData: the credentials may not read DNSSEC (the chain check
// alone decides then).
var errNoProviderData = errors.New("route53: the credentials may not read DNSSEC (route53:GetDNSSEC): using the public chain check only")

func newRoute53DNSSEC(c map[string]string, endpoint string) *route53DNSSEC {
	o := route53.Options{
		Region:      "us-east-1",
		Credentials: aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(c["access_key_id"], c["secret_access_key"], "")),
		HTTPClient:  &http.Client{Timeout: providerTimeout},
	}
	if endpoint != "" {
		o.BaseEndpoint = aws.String(endpoint)
		o.RetryMaxAttempts = 1
	}
	return &route53DNSSEC{client: route53.New(o), zoneID: strings.TrimPrefix(c["hosted_zone_id"], "/hostedzone/")}
}

func denied(err error) bool {
	var ae smithy.APIError
	if errors.As(err, &ae) {
		c := ae.ErrorCode()
		return c == "AccessDenied" || c == "AccessDeniedException"
	}
	return false
}

func (r *route53DNSSEC) hostedZone(ctx context.Context, zone string) (string, error) {
	if r.zoneID != "" {
		return r.zoneID, nil
	}
	name := strings.ToLower(strings.TrimSuffix(zone, ".")) + "."
	out, err := r.client.ListHostedZonesByName(ctx, &route53.ListHostedZonesByNameInput{DNSName: aws.String(name), MaxItems: aws.Int32(1)})
	if err != nil {
		if denied(err) {
			return "", errNoProviderData
		}
		return "", fmt.Errorf("route53: finding the hosted zone %s: %w", name, err)
	}
	for _, z := range out.HostedZones {
		if strings.EqualFold(aws.ToString(z.Name), name) {
			return strings.TrimPrefix(aws.ToString(z.Id), "/hostedzone/"), nil
		}
	}
	return "", fmt.Errorf("route53: no hosted zone %s", name)
}

// DNSSECStatus: the serve-signature status (SIGNING, NOT_SIGNING, …) and
// the DS of every active KSK.
func (r *route53DNSSEC) DNSSECStatus(ctx context.Context, zone string) (string, []dnssec.DS, error) {
	id, err := r.hostedZone(ctx, zone)
	if err != nil {
		return "", nil, err
	}
	out, err := r.client.GetDNSSEC(ctx, &route53.GetDNSSECInput{HostedZoneId: aws.String(id)})
	if err != nil {
		if denied(err) {
			return "", nil, errNoProviderData
		}
		return "", nil, fmt.Errorf("route53: GetDNSSEC: %w", err)
	}
	status := ""
	if out.Status != nil {
		status = aws.ToString(out.Status.ServeSignature)
	}
	var ds []dnssec.DS
	for _, k := range out.KeySigningKeys {
		if s := aws.ToString(k.Status); s != "" && s != "ACTIVE" {
			continue
		}
		if aws.ToString(k.DigestValue) == "" {
			continue
		}
		ds = append(ds, dnssec.DS{KeyTag: uint16(k.KeyTag), Algorithm: uint8(k.SigningAlgorithmType),
			DigestType: uint8(k.DigestAlgorithmType), Digest: strings.ToUpper(aws.ToString(k.DigestValue))})
	}
	return status, ds, nil
}
