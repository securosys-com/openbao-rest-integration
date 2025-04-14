/*
Copyright (c) 2024 Securosys SA, authors: Tomasz Madej
This work is licensed under the terms of the GNU Lesser General Public License license.

See terms of license at gnu.org.

This work is free software; you can redistribute it and/or modify it under the terms of the
GNU Lesser General Public License as published by the Free Software Foundation;
either version 2.1 of the license, or (at your option) any later version.
This work is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
*/

package pki

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/openbao/openbao/sdk/v2/framework"

	"github.com/openbao/openbao/sdk/v2/helper/certutil"
	"github.com/openbao/openbao/sdk/v2/helper/errutil"
	"github.com/openbao/openbao/sdk/v2/logical"
)

const (
	managedKeyNameArg = "managed_key_name"
	managedKeyIdArg   = "managed_key_id"

	defaultRef = "default"

	// Constants for If-Modified-Since operation
	headerIfModifiedSince = "If-Modified-Since"
	headerLastModified    = "Last-Modified"
)

var (
	nameMatcher          = regexp.MustCompile("^" + framework.GenericNameRegex(issuerRefParam) + "$")
	errIssuerNameInUse   = errutil.UserError{Err: "issuer name already in use"}
	errIssuerNameIsEmpty = errutil.UserError{Err: "expected non-empty issuer name"}
	errKeyNameInUse      = errutil.UserError{Err: "key name already in use"}
)

func serialFromCert(cert *x509.Certificate) string {
	return serialFromBigInt(cert.SerialNumber)
}

func serialFromBigInt(serial *big.Int) string {
	return strings.TrimSpace(certutil.GetHexFormatted(serial.Bytes(), ":"))
}

func normalizeSerialFromBigInt(serial *big.Int) string {
	return strings.TrimSpace(certutil.GetHexFormatted(serial.Bytes(), "-"))
}

func normalizeSerial(serial string) string {
	return strings.ReplaceAll(strings.ToLower(serial), ":", "-")
}

func denormalizeSerial(serial string) string {
	return strings.ReplaceAll(strings.ToLower(serial), "-", ":")
}

func serialToBigInt(serial string) (*big.Int, bool) {
	norm := normalizeSerial(serial)
	hex := strings.ReplaceAll(norm, "-", "")
	return big.NewInt(0).SetString(hex, 16)
}

func kmsRequested(input *inputBundle) bool {
	return kmsRequestedFromFieldData(input.apiData)
}

func kmsRequestedFromFieldData(data *framework.FieldData) bool {
	exportedStr, ok := data.GetOk("exported")
	if !ok {
		return false
	}
	return exportedStr.(string) == "kms"
}
func securosysHSMKeyRequested(input *inputBundle) bool {
	return securosysHSMKeyRequestedFromFieldData(input.apiData)
}
func securosysHSMKeyRequestedFromFieldData(data *framework.FieldData) bool {
	exportedStr, ok := data.GetOk("exported")
	if !ok {
		return false
	}
	return exportedStr.(string) == "securosys-hsm"
}

func existingKeyRequested(input *inputBundle) bool {
	return existingKeyRequestedFromFieldData(input.apiData)
}

func existingKeyRequestedFromFieldData(data *framework.FieldData) bool {
	exportedStr, ok := data.GetOk("exported")
	if !ok {
		return false
	}
	return exportedStr.(string) == "existing"
}

type managedKeyId interface {
	String() string
}

type (
	UUIDKey string
	NameKey string
)

func (u UUIDKey) String() string {
	return string(u)
}

func (n NameKey) String() string {
	return string(n)
}

type managedKeyInfo struct {
	publicKey crypto.PublicKey
	keyType   certutil.PrivateKeyType
	name      NameKey
	uuid      UUIDKey
}

// getManagedKeyId returns a NameKey or a UUIDKey, whichever was specified in the
// request API data.
func getManagedKeyId(data *framework.FieldData) (managedKeyId, error) {
	name, UUID, err := getManagedKeyNameOrUUID(data)
	if err != nil {
		return nil, err
	}

	var keyId managedKeyId = NameKey(name)
	if len(UUID) > 0 {
		keyId = UUIDKey(UUID)
	}

	return keyId, nil
}

func getKeyRefWithErr(data *framework.FieldData) (string, error) {
	keyRef := getKeyRef(data)

	if len(keyRef) == 0 {
		return "", errutil.UserError{Err: "missing argument key_ref for existing type"}
	}

	return keyRef, nil
}

func getManagedKeyNameOrUUID(data *framework.FieldData) (name string, UUID string, err error) {
	getApiData := func(argName string) (string, error) {
		arg, ok := data.GetOk(argName)
		if !ok {
			return "", nil
		}

		argValue, ok := arg.(string)
		if !ok {
			return "", errutil.UserError{Err: fmt.Sprintf("invalid type for argument %s", argName)}
		}

		return strings.TrimSpace(argValue), nil
	}

	keyName, err := getApiData(managedKeyNameArg)
	keyUUID, err2 := getApiData(managedKeyIdArg)
	switch {
	case err != nil:
		return "", "", err
	case err2 != nil:
		return "", "", err2
	case len(keyName) == 0 && len(keyUUID) == 0:
		return "", "", errutil.UserError{Err: fmt.Sprintf("missing argument %s or %s", managedKeyNameArg, managedKeyIdArg)}
	case len(keyName) > 0 && len(keyUUID) > 0:
		return "", "", errutil.UserError{Err: fmt.Sprintf("only one argument of %s or %s should be specified", managedKeyNameArg, managedKeyIdArg)}
	}

	return keyName, keyUUID, nil
}

func getIssuerName(sc *storageContext, data *framework.FieldData) (string, error) {
	issuerName := ""
	issuerNameIface, ok := data.GetOk("issuer_name")
	if ok {
		issuerName = strings.TrimSpace(issuerNameIface.(string))
		if len(issuerName) == 0 {
			return issuerName, errIssuerNameIsEmpty
		}
		if strings.ToLower(issuerName) == defaultRef {
			return issuerName, errutil.UserError{Err: "reserved keyword 'default' can not be used as issuer name"}
		}
		if !nameMatcher.MatchString(issuerName) {
			return issuerName, errutil.UserError{Err: "issuer name contained invalid characters"}
		}
		issuerId, err := sc.resolveIssuerReference(issuerName)
		if err == nil {
			return issuerName, errIssuerNameInUse
		}

		if err != nil && issuerId != IssuerRefNotFound {
			return issuerName, errutil.InternalError{Err: err.Error()}
		}
	}
	return issuerName, nil
}

func getKeyName(sc *storageContext, data *framework.FieldData) (string, error) {
	keyName := ""
	keyNameIface, ok := data.GetOk(keyNameParam)
	if ok {
		keyName = strings.TrimSpace(keyNameIface.(string))

		if strings.ToLower(keyName) == defaultRef {
			return "", errutil.UserError{Err: "reserved keyword 'default' can not be used as key name"}
		}

		if !nameMatcher.MatchString(keyName) {
			return "", errutil.UserError{Err: "key name contained invalid characters"}
		}
		keyId, err := sc.resolveKeyReference(keyName)
		if err == nil {
			return "", errKeyNameInUse
		}

		if err != nil && keyId != KeyRefNotFound {
			return "", errutil.InternalError{Err: err.Error()}
		}
	}
	keyIdIface, ok := data.GetOk(keyRefParam)
	if ok {
		keyEntry, err := sc.getExistingKeyFromRef(keyIdIface.(string))

		if err != nil {
			return "", err
		}
		if keyEntry.PublicKey != "" {
			return keyEntry.Name, nil
		}

	}
	return keyName, nil
}

func getIssuerRef(data *framework.FieldData) string {
	return extractRef(data, issuerRefParam)
}

func getKeyRef(data *framework.FieldData) string {
	return extractRef(data, keyRefParam)
}

func extractRef(data *framework.FieldData, paramName string) string {
	value := strings.TrimSpace(data.Get(paramName).(string))
	if strings.EqualFold(value, defaultRef) {
		return defaultRef
	}
	return value
}

func isStringArrayDifferent(a, b []string) bool {
	if len(a) != len(b) {
		return true
	}

	for i, v := range a {
		if v != b[i] {
			return true
		}
	}

	return false
}

func hasHeader(header string, req *logical.Request) bool {
	var hasHeader bool
	headerValue := req.Headers[header]
	if len(headerValue) > 0 {
		hasHeader = true
	}

	return hasHeader
}

func parseIfNotModifiedSince(req *logical.Request) (time.Time, error) {
	var headerTimeValue time.Time
	headerValue := req.Headers[headerIfModifiedSince]

	headerTimeValue, err := time.Parse(time.RFC1123, headerValue[0])
	if err != nil {
		return headerTimeValue, fmt.Errorf("failed to parse given value for '%s' header: %w", headerIfModifiedSince, err)
	}

	return headerTimeValue, nil
}

type ifModifiedReqType int

const (
	ifModifiedUnknown  ifModifiedReqType = iota
	ifModifiedCA                         = iota
	ifModifiedCRL                        = iota
	ifModifiedDeltaCRL                   = iota
)

type IfModifiedSinceHelper struct {
	req       *logical.Request
	reqType   ifModifiedReqType
	issuerRef issuerID
}

func sendNotModifiedResponseIfNecessary(helper *IfModifiedSinceHelper, sc *storageContext, resp *logical.Response) (bool, error) {
	responseHeaders := map[string][]string{}
	if !hasHeader(headerIfModifiedSince, helper.req) {
		return false, nil
	}

	before, err := sc.isIfModifiedSinceBeforeLastModified(helper, responseHeaders)
	if err != nil {
		return false, err
	}

	if !before {
		return false, nil
	}

	// Fill response
	resp.Data = map[string]interface{}{
		logical.HTTPContentType: "",
		logical.HTTPStatusCode:  304,
	}
	resp.Headers = responseHeaders

	return true, nil
}

func (sc *storageContext) isIfModifiedSinceBeforeLastModified(helper *IfModifiedSinceHelper, responseHeaders map[string][]string) (bool, error) {
	// False return --> we were last modified _before_ the requester's
	// time --> keep using the cached copy and return 304.
	var err error
	var lastModified time.Time
	ifModifiedSince, err := parseIfNotModifiedSince(helper.req)
	if err != nil {
		return false, err
	}

	switch helper.reqType {
	case ifModifiedCRL, ifModifiedDeltaCRL:
		if sc.Backend.crlBuilder.invalidate.Load() {
			// When we see the CRL is invalidated, respond with false
			// regardless of what the local CRL state says. We've likely
			// renamed some issuers or are about to rebuild a new CRL....
			//
			// We do this earlier, ahead of config load, as it saves us a
			// potential error condition.
			return false, nil
		}

		crlConfig, err := sc.getLocalCRLConfig()
		if err != nil {
			return false, err
		}

		lastModified = crlConfig.LastModified
		if helper.reqType == ifModifiedDeltaCRL {
			lastModified = crlConfig.DeltaLastModified
		}
	case ifModifiedCA:
		issuerId, err := sc.resolveIssuerReference(string(helper.issuerRef))
		if err != nil {
			return false, err
		}

		issuer, err := sc.fetchIssuerById(issuerId)
		if err != nil {
			return false, err
		}

		lastModified = issuer.LastModified
	default:
		return false, fmt.Errorf("unknown if-modified-since request type: %v", helper.reqType)
	}

	if !lastModified.IsZero() && lastModified.Before(ifModifiedSince) {
		responseHeaders[headerLastModified] = []string{lastModified.Format(http.TimeFormat)}
		return true, nil
	}

	return false, nil
}

func addWarnings(resp *logical.Response, warnings []string) *logical.Response {
	for _, warning := range warnings {
		resp.AddWarning(warning)
	}
	return resp
}

// sliceToMapKey return a map that who's keys are entries in a map.
func sliceToMapKey(s []string) map[string]struct{} {
	var empty struct{}
	myMap := make(map[string]struct{}, len(s))
	for _, s := range s {
		myMap[s] = empty
	}
	return myMap
}
