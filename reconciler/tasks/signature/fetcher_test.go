// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package signature

import (
	"context"
	"errors"
	"testing"

	corev1 "github.com/agntcy/dir/api/core/v1"
	signv1 "github.com/agntcy/dir/api/sign/v1"
	"github.com/agntcy/dir/server/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"
)

var _ types.ReferrerStoreAPI = (*fakeReferrerStore)(nil)

// fakeReferrerStore walks a fixed list of referrers, or fails the walk.
type fakeReferrerStore struct {
	referrers []*corev1.RecordReferrer
	walkErr   error
}

func (f *fakeReferrerStore) PushReferrer(context.Context, string, *corev1.RecordReferrer) (*corev1.ReferrerRef, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeReferrerStore) WalkReferrers(_ context.Context, _ string, referrerType string, walkFn func(*corev1.RecordReferrer) error) error {
	if f.walkErr != nil {
		return f.walkErr
	}

	for _, ref := range f.referrers {
		if referrerType != "" && ref.GetType() != referrerType {
			continue
		}

		if err := walkFn(ref); err != nil {
			return err
		}
	}

	return nil
}

func (f *fakeReferrerStore) DeleteReferrer(context.Context, string, string, string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func (f *fakeReferrerStore) DeleteReferrers(context.Context, string, []string, string) ([]string, error) {
	return nil, errors.New("not implemented")
}

func signatureReferrer(t *testing.T, sig *signv1.Signature) *corev1.RecordReferrer {
	t.Helper()

	ref, err := sig.MarshalReferrer()
	require.NoError(t, err)

	return ref
}

func publicKeyReferrer(t *testing.T, key string) *corev1.RecordReferrer {
	t.Helper()

	ref, err := (&signv1.PublicKey{Key: key}).MarshalReferrer()
	require.NoError(t, err)

	return ref
}

// junkReferrer is a referrer of referrerType whose payload does not decode as
// the type's message: field holds a number where a string is expected.
func junkReferrer(t *testing.T, referrerType, field string) *corev1.RecordReferrer {
	t.Helper()

	data, err := structpb.NewStruct(map[string]any{field: 123})
	require.NoError(t, err)

	return &corev1.RecordReferrer{
		Type:        referrerType,
		Data:        data,
		ReferrerRef: &corev1.ReferrerRef{Cid: "junk"},
	}
}

func TestStoreFetcher_PullSignatures(t *testing.T) {
	valid := &signv1.Signature{Signature: "c2lnbmF0dXJl", Algorithm: "ecdsa-p256"}

	tests := []struct {
		name    string
		store   *fakeReferrerStore
		want    []string
		wantErr string
	}{
		{
			name:  "returns the record's signatures",
			store: &fakeReferrerStore{referrers: []*corev1.RecordReferrer{signatureReferrer(t, valid)}},
			want:  []string{valid.GetSignature()},
		},
		{
			name: "skips a referrer whose payload is not a signature",
			store: &fakeReferrerStore{referrers: []*corev1.RecordReferrer{
				junkReferrer(t, corev1.SignatureReferrerType, "signature"),
				signatureReferrer(t, valid),
			}},
			want: []string{valid.GetSignature()},
		},
		{
			name: "skips a referrer without data",
			store: &fakeReferrerStore{referrers: []*corev1.RecordReferrer{
				{Type: corev1.SignatureReferrerType},
				signatureReferrer(t, valid),
			}},
			want: []string{valid.GetSignature()},
		},
		{
			name: "leaves referrers of other types out",
			store: &fakeReferrerStore{referrers: []*corev1.RecordReferrer{
				publicKeyReferrer(t, "-----BEGIN PUBLIC KEY-----"),
				signatureReferrer(t, valid),
			}},
			want: []string{valid.GetSignature()},
		},
		{
			name:    "fails when the store cannot be walked",
			store:   &fakeReferrerStore{walkErr: errors.New("registry unavailable")},
			wantErr: "registry unavailable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sigs, err := NewStoreFetcher(tc.store).PullSignatures(t.Context(), &corev1.RecordRef{Cid: "cid"})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)

			got := make([]string, 0, len(sigs))
			for _, sig := range sigs {
				got = append(got, sig.GetSignature())
			}

			assert.Equal(t, tc.want, got)
		})
	}
}

func TestStoreFetcher_PullPublicKeys(t *testing.T) {
	const key = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"

	tests := []struct {
		name    string
		store   *fakeReferrerStore
		want    []string
		wantErr string
	}{
		{
			name:  "returns the record's public keys",
			store: &fakeReferrerStore{referrers: []*corev1.RecordReferrer{publicKeyReferrer(t, key)}},
			want:  []string{key},
		},
		{
			name: "skips a referrer whose payload is not a public key and one with an empty key",
			store: &fakeReferrerStore{referrers: []*corev1.RecordReferrer{
				junkReferrer(t, corev1.PublicKeyReferrerType, "key"),
				publicKeyReferrer(t, ""),
				publicKeyReferrer(t, key),
			}},
			want: []string{key},
		},
		{
			name:    "fails when the store cannot be walked",
			store:   &fakeReferrerStore{walkErr: errors.New("registry unavailable")},
			wantErr: "registry unavailable",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			keys, err := NewStoreFetcher(tc.store).PullPublicKeys(t.Context(), &corev1.RecordRef{Cid: "cid"})
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tc.want, keys)
		})
	}
}
