//Copyright (c) 2025 Securosys SA.

package hsm

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"

	log "github.com/hashicorp/go-hclog"
	"github.com/mitchellh/cli"
)

// Struct storing generated data
type Key struct {
	// Key label from Securosys TSB
	RSALabel      string `mapstructure:"RSALabel"`
	RSAPublicKey  string `mapstructure:"RSAPublicKey"`
	KeyAttributes KeyAttributes
	RSAPassword   string
}

// Struct contains settings options
type Settings struct {
	// Authorization has been on of this consts [NONE,TOKEN,CERT]
	Auth string
	// BearerToken needed is needed only with Auth=TOKEN
	BearerToken string
	// BasicToken needed is needed only with Auth=BASIC or if not exists You Have to prive UserName and Password
	// CertPath needed is needed only with Auth=CERT
	CertPath string
	// KeyPath needed is needed only with Auth=CERT
	KeyPath string
	// Rest Api url where is located Securosys HSM
	RestApi string
	// Integer as Number in seconds for checking approval interval
	CheckEvery int
	// ApprovalTimeout must be bigger then CheckEvery and lower then VAULT_CLIENT_TIMEOUT. Default: 60s
	ApprovalTimeout int
	// Enables/Disables debug on Securosys Requests. If not exists in config, then debug logs will be only awaylable in Tests
	Debug                  *bool
	ApiKeys                ApiKeyTypes
	ApplicationKeyPair     KeyPair
	CurrentApiKeyTypeIndex ApiKeyTypesRetry
}

// Main struct of securosys_hsm YML
type Configurations struct {
	// Struct With Application Settings
	Settings Settings `mapstructure:"Settings"`
	// List of Name - Public Key needed for Securosys HSM with policy
	Policy *Policy `mapstructure:"Policy"`
	// Autogenerated data from application. Do not change this manually!
	Key Key `mapstructure:"Generated"`
}

type Logging struct {
	UI     cli.Ui
	Logger log.Logger
}

// STRUCTS

type approval struct {
	TypeOfKey string  `json:"type"`
	Name      *string `json:"name"`
	Value     *string `json:"value"`
}
type group struct {
	Name      string     `json:"name"`
	Quorum    int        `json:"quorum"`
	Approvals []approval `json:"approvals"`
}
type token struct {
	Name     string  `json:"name"`
	Timelock int     `json:"timelock"`
	Timeout  int     `json:"timeout"`
	Groups   []group `json:"groups"`
}
type rule struct {
	Tokens []token `json:"tokens"`
}
type keyStatus struct {
	Blocked bool `json:"blocked"`
}

// Policy structure for rules use, block, unblock, modify
type Policy struct {
	RuleUse     rule       `json:"ruleUse"`
	RuleBlock   *rule      `json:"ruleBlock"`
	RuleUnBlock *rule      `json:"ruleUnblock"`
	RuleModify  *rule      `json:"ruleModify"`
	KeyStatus   *keyStatus `json:"keyStatus,omitempty"`
}

// Structure for all asychnronous operations
type RequestResponse struct {
	Id               string   `json:"id"`
	Status           string   `json:"status"`
	ExecutionTime    string   `json:"executionTime"`
	ApprovedBy       []string `json:"approvedBy"`
	NotYetApprovedBy []string `json:"notYetApprovedBy"`
	RejectedBy       []string `json:"rejectedBy"`
	Result           string   `json:"result"`
}

// Structure for get key attributes response
type KeyAttributes struct {
	Label              string
	Attributes         map[string]bool
	KeySize            float64
	Policy             Policy
	PublicKey          string
	Algorithm          string
	AlgorithmOid       string
	CurveOid           string
	Version            string
	Active             bool
	Xml                string
	XmlSignature       string
	AttestationKeyName string
}

func (r *Policy) ToJSON() (string, error) {
	jsonStr, err := json.Marshal(r)
	if err != nil {
		return "", err
	}
	return string(jsonStr[:]), nil
}

// Function that helps fill a policy structure
func PreparePolicy(policyString string, simplifiedVersion int) (*Policy, error) {
	return PrepareFullPolicy(policyString, simplifiedVersion, true)
}

// This function preparing Policy structure for generating asynchronous keys
func PrepareFullPolicy(policyString string, simplifiedVersion int, addKeyStatus bool) (*Policy, error) {
	var PolicyObj Policy
	if simplifiedVersion == 1 {
		var simplePolicy map[string]string
		err := json.Unmarshal([]byte(policyString), &simplePolicy)
		if err != nil {
			return nil, err
		}
		token := PreparePolicyTokens(simplePolicy)
		PolicyObj.RuleUse.Tokens = append(PolicyObj.RuleUse.Tokens, token)
		PolicyObj.RuleBlock = new(rule)
		PolicyObj.RuleBlock.Tokens = append(PolicyObj.RuleBlock.Tokens, token)
		PolicyObj.RuleUnBlock = new(rule)
		PolicyObj.RuleUnBlock.Tokens = append(PolicyObj.RuleUnBlock.Tokens, token)
		PolicyObj.RuleModify = new(rule)
		PolicyObj.RuleModify.Tokens = append(PolicyObj.RuleModify.Tokens, token)
		if addKeyStatus == true {
			PolicyObj.KeyStatus = new(keyStatus)
			PolicyObj.KeyStatus.Blocked = false
		}
	} else if simplifiedVersion == 2 {
		var simplePolicy map[string]map[string]string
		err := json.Unmarshal([]byte(policyString), &simplePolicy)
		if err != nil {
			return nil, err
		}
		if simplePolicy["use"] != nil {
			token := PreparePolicyTokens(simplePolicy["use"])
			PolicyObj.RuleUse.Tokens = append(PolicyObj.RuleUse.Tokens, token)
		} else {
			token := PreparePolicyTokens(make(map[string]string))
			PolicyObj.RuleUse.Tokens = append(PolicyObj.RuleUse.Tokens, token)
		}
		if simplePolicy["block"] != nil {
			token := PreparePolicyTokens(simplePolicy["block"])
			PolicyObj.RuleBlock.Tokens = append(PolicyObj.RuleBlock.Tokens, token)
		} else {
			token := PreparePolicyTokens(make(map[string]string))
			PolicyObj.RuleBlock.Tokens = append(PolicyObj.RuleBlock.Tokens, token)
		}
		if simplePolicy["unblock"] != nil {
			token := PreparePolicyTokens(simplePolicy["unblock"])
			PolicyObj.RuleUnBlock.Tokens = append(PolicyObj.RuleUnBlock.Tokens, token)
		} else {
			token := PreparePolicyTokens(make(map[string]string))
			PolicyObj.RuleUnBlock.Tokens = append(PolicyObj.RuleUnBlock.Tokens, token)
		}
		if simplePolicy["modify"] != nil {
			token := PreparePolicyTokens(simplePolicy["modify"])
			PolicyObj.RuleModify.Tokens = append(PolicyObj.RuleModify.Tokens, token)
		} else {
			token := PreparePolicyTokens(make(map[string]string))
			PolicyObj.RuleModify.Tokens = append(PolicyObj.RuleModify.Tokens, token)
		}

		if addKeyStatus == true {
			PolicyObj.KeyStatus = new(keyStatus)
			PolicyObj.KeyStatus.Blocked = false
		}

	} else {
		err := json.Unmarshal([]byte(policyString), &PolicyObj)
		if err != nil {
			return nil, err
		}
		if addKeyStatus == false {
			PolicyObj.KeyStatus = nil
		}

	}
	return &PolicyObj, nil
}

// This function groups from simplePolicy parameter sended with keys

func PreparePolicyTokens(policy map[string]string) token {
	var group group
	group.Name = "main"
	group.Quorum = len(policy)
	for name, element := range policy {
		var approval approval
		_, err := ReadCertificate(element)
		if err == nil {
			approval.TypeOfKey = "certificate"
			approval.Value = &element
		} else {
			_, err := ParsePublicKeyString(element)
			if err == nil {
				approval.TypeOfKey = "public_key"
				approval.Name = &name
				approval.Value = &element
			} else {
				approval.TypeOfKey = "onboarded_approver_certificate"
				approval.Name = &element
			}
		}
		group.Approvals = append(group.Approvals, approval)
	}

	var token token
	token.Name = "main"
	token.Timeout = 0
	token.Timelock = 0
	if len(policy) == 0 {
		token.Groups = nil
	} else {
		token.Groups = append(token.Groups, group)
	}

	return token
}

type KeyPair struct {
	PrivateKey *string `json:"privateKey,omitempty"`
	PublicKey  *string `json:"publicKey,omitempty"`
}

type ApiKeyTypes struct {
	KeyManagementToken         []string `json:"KeyManagementToken,omitempty"`
	KeyOperationToken          []string `json:"KeyOperationToken,omitempty"`
	ApproverToken              []string `json:"ApproverToken,omitempty"`
	ServiceToken               []string `json:"ServiceToken,omitempty"`
	ApproverKeyManagementToken []string `json:"ApproverKeyManagementToken,omitempty"`
}
type ApiKeyTypesRetry struct {
	KeyManagementTokenIndex         int
	KeyOperationTokenIndex          int
	ApproverTokenIndex              int
	ServiceTokenIndex               int
	ApproverKeyManagementTokenIndex int
}

const (
	KeyManagementTokenName         = "KeyManagementToken"
	KeyOperationTokenName          = "KeyOperationToken"
	ApproverTokenName              = "ApproverToken"
	ServiceTokenName               = "ServiceToken"
	ApproverKeyManagementTokenName = "ApproverKeyManagementToken"
)

// END STRUCTS
func ReadCertificate(possibleCertificate string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(WrapCertificateWithHeaders(possibleCertificate)))
	if block == nil {
		return nil, fmt.Errorf("Cannot parse certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	return cert, nil
}
func WrapCertificateWithHeaders(certificate string) []byte {
	return []byte("-----BEGIN CERTIFICATE-----\n" + certificate + "\n-----END CERTIFICATE-----")

}
func WrapPublicKeyWithHeaders(publicKey string) []byte {
	return []byte("-----BEGIN RSA PUBLIC KEY-----\n" + publicKey + "\n-----END RSA PUBLIC KEY-----")

}
