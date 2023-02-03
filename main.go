package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1"
	"github.com/cert-manager/cert-manager/pkg/acme/webhook/cmd"
	"github.com/cert-manager/cert-manager/pkg/issuer/acme/dns/util"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/errors"
	"github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/common/profile"
	dnspod "github.com/tencentcloud/tencentcloud-sdk-go/tencentcloud/dnspod/v20210323"
	v1 "k8s.io/api/core/v1"
	extapi "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

var GroupName = os.Getenv("GROUP_NAME")

func main() {
	if GroupName == "" {
		panic("GROUP_NAME must be specified")
	}

	// This will register our custom DNS provider with the webhook serving
	// library, making it available as an API under the provided GroupName.
	// You can register multiple DNS provider implementations with a single
	// webhook, where the Name() method will be used to disambiguate between
	// the different implementations.
	cmd.RunWebhookServer(GroupName,
		&customDNSProviderSolver{},
	)
}

func extractRecordName(fqdn, zone string) string {
	if idx := strings.Index(fqdn, "."+zone); idx != -1 {
		return fqdn[:idx]
	}
	return util.UnFqdn(fqdn)
}

// customDNSProviderSolver implements the provider-specific logic needed to
// 'present' an ACME challenge TXT record for your own DNS provider.
// To do so, it must implement the `github.com/cert-manager/cert-manager/pkg/acme/webhook.Solver`
// interface.
type customDNSProviderSolver struct {
	// If a Kubernetes 'clientset' is needed, you must:
	// 1. uncomment the additional `client` field in this structure below
	// 2. uncomment the "k8s.io/client-go/kubernetes" import at the top of the file
	// 3. uncomment the relevant code in the Initialize method below
	// 4. ensure your webhook's service account has the required RBAC role
	//    assigned to it for interacting with the Kubernetes APIs you need.
	k8sClient *kubernetes.Clientset
}

// customDNSProviderConfig is a structure that is used to decode into when
// solving a DNS01 challenge.
// This information is provided by cert-manager, and may be a reference to
// additional configuration that's needed to solve the challenge for this
// particular certificate or issuer.
// This typically includes references to Secret resources containing DNS
// provider credentials, in cases where a 'multi-tenant' DNS solver is being
// created.
// If you do *not* require per-issuer or per-certificate configuration to be
// provided to your webhook, you can skip decoding altogether in favour of
// using CLI flags or similar to provide configuration.
// You should not include sensitive information here. If credentials need to
// be used by your provider here, you should reference a Kubernetes Secret
// resource and fetch these credentials using a Kubernetes clientset.
type customDNSProviderConfig struct {
	// Change the two fields below according to the format of the configuration
	// to be decoded.
	// These fields will be set by users in the
	// `issuer.spec.acme.dns01.providers.webhook.config` field.

	//Email           string `json:"email"`
	//APIKeySecretRef v1alpha1.SecretKeySelector `json:"apiKeySecretRef"`

	SecretIdRef  v1.SecretKeySelector `json:"secretIdRef"`
	SecretKeyRef v1.SecretKeySelector `json:"secretKeyRef"`
}

func (s *customDNSProviderSolver) getSecretData(ns string, selector v1.SecretKeySelector) ([]byte, error) {
	secret, err := s.k8sClient.CoreV1().Secrets(ns).Get(context.TODO(), selector.Name, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}
	data, ok := secret.Data[selector.Key]
	if !ok {
		return nil, fmt.Errorf("failed to load secret %s/%s/%s", ns, selector.Name, selector.Key)
	}
	return data, nil
}

func (s *customDNSProviderSolver) getCredential(ns string, config *customDNSProviderConfig) (*common.Credential, error) {
	secretId, err := s.getSecretData(ns, config.SecretIdRef)
	if err != nil {
		return nil, err
	}

	secretKey, err := s.getSecretData(ns, config.SecretKeyRef)
	if err != nil {
		return nil, err
	}
	return common.NewCredential(string(secretId), string(secretKey)), nil
}

func (s *customDNSProviderSolver) getClient(ch *v1alpha1.ChallengeRequest) (*dnspod.Client, error) {
	config, err := loadConfig(ch.Config)
	if err != nil {
		return nil, err
	}

	credential, err := s.getCredential(ch.ResourceNamespace, &config)
	if err != nil {
		return nil, err
	}

	client, err := dnspod.NewClient(credential, "", profile.NewClientProfile())
	if err != nil {
		return nil, err
	}

	return client, nil
}

// Name is used as the name for this DNS solver when referencing it on the ACME
// Issuer resource.
// This should be unique **within the group name**, i.e. you can have two
// solvers configured with the same Name() **so long as they do not co-exist
// within a single webhook deployment**.
// For example, `cloudflare` may be used as the name of a solver.
func (c *customDNSProviderSolver) Name() string {
	return "dnspod"
}

func (s *customDNSProviderSolver) getDomain(client *dnspod.Client, ch *v1alpha1.ChallengeRequest) (string, error) {
	req := dnspod.NewDescribeDomainListRequest()
	response, err := client.DescribeDomainList(req)
	if err != nil {
		return "", err
	}
	for _, item := range response.Response.DomainList {
		if strings.HasSuffix(ch.ResolvedZone, *item.Name+".") {
			return *item.Name, nil
		}
	}
	return "", fmt.Errorf("failed to get domain for zone %s", ch.ResolvedZone)
}

func (s *customDNSProviderSolver) getRecordList(client *dnspod.Client, ch *v1alpha1.ChallengeRequest) ([]*dnspod.RecordListItem, error) {
	domain, err := s.getDomain(client, ch)
	if err != nil {
		return []*dnspod.RecordListItem{}, err
	}
	recordName := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone)
	req := dnspod.NewDescribeRecordListRequest()
	req.Domain = &domain
	req.Subdomain = &recordName
	req.RecordType = common.StringPtr("TXT")
	fmt.Println(req.ToJsonString())
	response, err := client.DescribeRecordList(req)
	fmt.Println(response.ToJsonString())

	if sdkError, ok := err.(*errors.TencentCloudSDKError); ok {
		fmt.Printf("An API error has returned: %s", err)
		if sdkError.Code == "ResourceNotFound.NoDataOfRecord" {
			return []*dnspod.RecordListItem{}, nil
		}
	}
	if err != nil {
		return nil, err
	}

	return response.Response.RecordList, nil
}

// Present is responsible for actually presenting the DNS record with the
// DNS provider.
// This method should tolerate being called multiple times with the same value.
// cert-manager itself will later perform a self check to ensure that the
// solver has correctly configured the DNS provider.
func (s *customDNSProviderSolver) Present(ch *v1alpha1.ChallengeRequest) error {
	client, err := s.getClient(ch)
	if err != nil {
		return err
	}

	domain, err := s.getDomain(client, ch)
	if err != nil {
		return err
	}

	recordList, err := s.getRecordList(client, ch)
	if err != nil {
		return err
	}

	recordNotExists := true
	for _, record := range recordList {
		if *record.Value == ch.Key {
			recordNotExists = false
			break
		}
	}

	if recordNotExists {
		recordName := extractRecordName(ch.ResolvedFQDN, ch.ResolvedZone)
		req := dnspod.NewCreateRecordRequest()
		req.Domain = &domain
		req.SubDomain = &recordName
		req.RecordType = common.StringPtr("TXT")
		req.RecordLine = common.StringPtr("默认")
		req.Value = &ch.Key
		fmt.Println(req.ToJsonString())
		_, err := client.CreateRecord(req)
		if err != nil {
			return err
		}
	}

	return nil
}

// CleanUp should delete the relevant TXT record from the DNS provider console.
// If multiple TXT records exist with the same record name (e.g.
// _acme-challenge.example.com) then **only** the record with the same `key`
// value provided on the ChallengeRequest should be cleaned up.
// This is in order to facilitate multiple DNS validations for the same domain
// concurrently.
func (s *customDNSProviderSolver) CleanUp(ch *v1alpha1.ChallengeRequest) error {
	// TODO: add code that deletes a record from the DNS provider's console

	client, err := s.getClient(ch)
	if err != nil {
		return err
	}

	domain, err := s.getDomain(client, ch)
	if err != nil {
		return err
	}

	recordList, err := s.getRecordList(client, ch)
	if err != nil {
		return err
	}

	for _, record := range recordList {
		if *record.Value == ch.Key {
			req := dnspod.NewDeleteRecordRequest()
			req.Domain = &domain
			req.RecordId = record.RecordId
			fmt.Println(req.ToJsonString())
			_, err := client.DeleteRecord(req)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

// Initialize will be called when the webhook first starts.
// This method can be used to instantiate the webhook, i.e. initialising
// connections or warming up caches.
// Typically, the kubeClientConfig parameter is used to build a Kubernetes
// client that can be used to fetch resources from the Kubernetes API, e.g.
// Secret resources containing credentials used to authenticate with DNS
// provider accounts.
// The stopCh can be used to handle early termination of the webhook, in cases
// where a SIGTERM or similar signal is sent to the webhook process.
func (c *customDNSProviderSolver) Initialize(kubeClientConfig *rest.Config, stopCh <-chan struct{}) error {
	///// UNCOMMENT THE BELOW CODE TO MAKE A KUBERNETES CLIENTSET AVAILABLE TO
	///// YOUR CUSTOM DNS PROVIDER

	cl, err := kubernetes.NewForConfig(kubeClientConfig)
	if err != nil {
		return err
	}
	c.k8sClient = cl

	///// END OF CODE TO MAKE KUBERNETES CLIENTSET AVAILABLE
	return nil
}

// loadConfig is a small helper function that decodes JSON configuration into
// the typed config struct.
func loadConfig(cfgJSON *extapi.JSON) (customDNSProviderConfig, error) {
	cfg := customDNSProviderConfig{}
	// handle the 'base case' where no configuration has been provided
	if cfgJSON == nil {
		return cfg, nil
	}
	if err := json.Unmarshal(cfgJSON.Raw, &cfg); err != nil {
		return cfg, fmt.Errorf("error decoding solver config: %v", err)
	}

	return cfg, nil
}
