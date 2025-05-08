// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package mock

import (
	"github.com/openbao/openbao/command/agentproxyshared/sink"
)

type mockSink struct {
	token string
}

func NewSink(token string) sink.Sink {
	return &mockSink{
		token: token,
	}
}

func (m *mockSink) WriteToken(token string) error {
	m.token = token
	return nil
}

func (m *mockSink) Token() string {
	return m.token
}
