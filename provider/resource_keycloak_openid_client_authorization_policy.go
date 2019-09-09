package provider

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/helper/validation"
	"github.com/mrparkers/terraform-provider-keycloak/keycloak"
)

var (
	keycloakOpenidClientResourcePolicyDecisionStrategies = []string{"UNANIMOUS", "AFFIRMATIVE", "CONSENSUS"}
	keycloakOpenidClientPolicyLogic                      = []string{"POSITIVE", "NEGATIVE"}
	keycloakOpenidClientPolicyTypes                      = []string{"role"}
)

func resourceKeycloakOpenidClientAuthorizationPolicy() *schema.Resource {
	return &schema.Resource{
		Create: resourceKeycloakOpenidClientAuthorizationPolicyCreate,
		Read:   resourceKeycloakOpenidClientAuthorizationPolicyRead,
		Delete: resourceKeycloakOpenidClientAuthorizationPolicyDelete,
		Update: resourceKeycloakOpenidClientAuthorizationPolicyUpdate,
		Importer: &schema.ResourceImporter{
			State: resourceKeycloakOpenidClientAuthorizationPolicyImport,
		},
		Schema: map[string]*schema.Schema{
			"resource_server_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"realm_id": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"description": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"logic": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice(keycloakOpenidClientPolicyLogic, false),
				Default:      "POSITIVE",
			},
			"decision_strategy": {
				Type:         schema.TypeString,
				Optional:     true,
				ValidateFunc: validation.StringInSlice(keycloakOpenidClientResourcePolicyDecisionStrategies, false),
				Default:      "UNANIMOUS",
			},
			"roles": {
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"type": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringInSlice(keycloakOpenidClientPolicyTypes, false),
			},
		},
	}
}

func getOpenidClientAuthorizationPolicyFromData(data *schema.ResourceData) *keycloak.OpenidClientAuthorizationPolicy {
	var roles []keycloak.OpenidClientAuthorizationPolicyRole
	if v, ok := data.GetOk("roles"); ok {
		for _, role := range v.(*schema.Set).List() {
			roles = append(roles, keycloak.OpenidClientAuthorizationPolicyRole{
				Id: role.(string),
			})
		}
	}
	policy := keycloak.OpenidClientAuthorizationPolicy{
		Id:               data.Id(),
		ResourceServerId: data.Get("resource_server_id").(string),
		RealmId:          data.Get("realm_id").(string),
		Description:      data.Get("description").(string),
		Name:             data.Get("name").(string),
		DecisionStrategy: data.Get("decision_strategy").(string),
		Type:             data.Get("type").(string),
		Logic:            data.Get("logic").(string),
		Roles:            roles,
	}
	return &policy
}

func setOpenidClientAuthorizationPolicyDataResource(data *schema.ResourceData, policy *keycloak.OpenidClientAuthorizationPolicy) {
	var roles []string
	for _, r := range policy.Roles {
		roles = append(roles, r.Id)
	}
	data.SetId(policy.Id)
	data.Set("resource_server_id", policy.ResourceServerId)
	data.Set("realm_id", policy.RealmId)
	data.Set("description", policy.Description)
	data.Set("name", policy.Name)
	data.Set("decision_strategy", policy.DecisionStrategy)
	data.Set("logic", policy.Logic)
	data.Set("type", policy.Type)
	data.Set("roles", roles)
}

func resourceKeycloakOpenidClientAuthorizationPolicyCreate(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	policy := getOpenidClientAuthorizationPolicyFromData(data)

	err := keycloakClient.NewOpenidClientAuthorizationPolicy(policy)
	if err != nil {
		return err
	}

	setOpenidClientAuthorizationPolicyDataResource(data, policy)

	return resourceKeycloakOpenidClientAuthorizationPolicyRead(data, meta)
}

func resourceKeycloakOpenidClientAuthorizationPolicyRead(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	resourceServerId := data.Get("resource_server_id").(string)
	policyType := data.Get("type").(string)
	id := data.Id()

	policy, err := keycloakClient.GetOpenidClientAuthorizationPolicy(realmId, resourceServerId, policyType, id)
	if err != nil {
		return handleNotFoundError(err, data)
	}

	setOpenidClientAuthorizationPolicyData(data, policy)

	return nil
}

func resourceKeycloakOpenidClientAuthorizationPolicyUpdate(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	policy := getOpenidClientAuthorizationPolicyFromData(data)

	err := keycloakClient.UpdateOpenidClientAuthorizationPolicy(policy)
	if err != nil {
		return err
	}

	setOpenidClientAuthorizationPolicyData(data, policy)

	return nil
}

func resourceKeycloakOpenidClientAuthorizationPolicyDelete(data *schema.ResourceData, meta interface{}) error {
	keycloakClient := meta.(*keycloak.KeycloakClient)

	realmId := data.Get("realm_id").(string)
	resourceServerId := data.Get("resource_server_id").(string)
	policyType := data.Get("type").(string)
	id := data.Id()

	return keycloakClient.DeleteOpenidClientAuthorizationPolicy(realmId, resourceServerId, policyType, id)
}

func resourceKeycloakOpenidClientAuthorizationPolicyImport(d *schema.ResourceData, _ interface{}) ([]*schema.ResourceData, error) {
	parts := strings.Split(d.Id(), "/")
	if len(parts) != 4 {
		return nil, fmt.Errorf("Invalid import. Supported import formats: {{realmId}}/{{resourceServerId}}/{{policyType}}/{{policyId}}")
	}
	d.Set("realm_id", parts[0])
	d.Set("resource_server_id", parts[1])
	d.Set("type", parts[2])
	d.SetId(parts[3])

	return []*schema.ResourceData{d}, nil
}
