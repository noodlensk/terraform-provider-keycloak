package keycloak

import (
	"encoding/json"
	"fmt"
)

type OpenidClientAuthorizationPolicyRole struct {
	Id      string `json:"id"`
	Requied bool   `json:"required"`
}
type OpenidClientAuthorizationPolicy struct {
	Id               string                                `json:"id,omitempty"`
	RealmId          string                                `json:"-"`
	ResourceServerId string                                `json:"-"`
	Name             string                                `json:"name"`
	Description      string                                `json:"description"`
	Owner            string                                `json:"owner"`
	DecisionStrategy string                                `json:"decisionStrategy"`
	Logic            string                                `json:"logic"`
	Policies         []string                              `json:"policies"`
	Resources        []string                              `json:"resources"`
	Scopes           []string                              `json:"scopes"`
	Type             string                                `json:"type"`
	Roles            []OpenidClientAuthorizationPolicyRole `json:"roles,omitempty"`
}

func (keycloakClient *KeycloakClient) GetClientAuthorizationPolicyByName(realmId, resourceServerId, name string) (*OpenidClientAuthorizationPolicy, error) {
	policies := []OpenidClientAuthorizationPolicy{}
	params := map[string]string{"name": name}
	err := keycloakClient.get(fmt.Sprintf("/realms/%s/clients/%s/authz/resource-server/policy", realmId, resourceServerId), &policies, params)
	if err != nil {
		return nil, err
	}
	policy := policies[0]
	policy.RealmId = realmId
	policy.ResourceServerId = resourceServerId
	policy.Name = name
	return &policy, nil
}

func (keycloakClient *KeycloakClient) GetOpenidClientAuthorizationPolicy(realm, resourceServerId, policyType, id string) (*OpenidClientAuthorizationPolicy, error) {
	policy := OpenidClientAuthorizationPolicy{
		RealmId:          realm,
		ResourceServerId: resourceServerId,
		Id:               id,
		Type:             policyType,
	}

	err := keycloakClient.get(fmt.Sprintf("/realms/%s/clients/%s/authz/resource-server/policy/%s/%s", realm, resourceServerId, policyType, id), &policy, nil)
	if err != nil {
		return nil, err
	}

	return &policy, nil
}

func (keycloakClient *KeycloakClient) NewOpenidClientAuthorizationPolicy(policy *OpenidClientAuthorizationPolicy) error {
	body, _, err := keycloakClient.post(fmt.Sprintf("/realms/%s/clients/%s/authz/resource-server/policy/%s", policy.RealmId, policy.ResourceServerId, policy.Type), policy)
	if err != nil {
		return err
	}
	err = json.Unmarshal(body, &policy)
	if err != nil {
		return err
	}
	return nil
}

func (keycloakClient *KeycloakClient) UpdateOpenidClientAuthorizationPolicy(policy *OpenidClientAuthorizationPolicy) error {
	err := keycloakClient.put(fmt.Sprintf("/realms/%s/clients/%s/authz/resource-server/policy/%s/%s", policy.RealmId, policy.ResourceServerId, policy.Type, policy.Id), policy)
	if err != nil {
		return err
	}
	return nil
}

func (keycloakClient *KeycloakClient) DeleteOpenidClientAuthorizationPolicy(realmId, resourceServerId, policyType, policyId string) error {
	return keycloakClient.delete(fmt.Sprintf("/realms/%s/clients/%s/authz/resource-server/policy/%s/%s", realmId, resourceServerId, policyType, policyId), nil)
}
