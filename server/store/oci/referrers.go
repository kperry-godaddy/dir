// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package oci

import (
	"context"
	"errors"
	"fmt"
	"io"

	corev1 "github.com/agntcy/dir/api/core/v1"
	"github.com/agntcy/dir/utils/logging"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"oras.land/oras-go/v2"
	"oras.land/oras-go/v2/errdef"
)

var referrersLogger = logging.Logger("store/oci/referrers")

// ReferrerMatcher reports whether a referrer descriptor is of the expected
// referrer type. Its error means the descriptor could not be read.
type ReferrerMatcher func(ctx context.Context, referrer ocispec.Descriptor) (bool, error)

// ReferrersLister interface for repositories that support the OCI Referrers API.
type ReferrersLister interface {
	Referrers(ctx context.Context, desc ocispec.Descriptor, artifactType string, fn func(referrers []ocispec.Descriptor) error) error
}

// errMalformedReferrer marks a listed referrer whose content is not a
// referrer. Anyone who can push referrers can attach one, so a walk skips it
// rather than let it hide the record's other referrers.
var errMalformedReferrer = errors.New("referrer content does not decode")

// unreadablePolicy is what a walk does with a referrer whose manifest or blob
// cannot be read from the registry.
type unreadablePolicy int

const (
	// failOnUnreadable ends the walk with the read error, so the caller never
	// takes a partial list of referrers for the whole.
	failOnUnreadable unreadablePolicy = iota

	// skipUnreadable logs the referrer and continues. Deletion uses it so that
	// the readable referrers of a record stay deletable.
	skipUnreadable
)

// PushReferrer pushes a generic RecordReferrer as an OCI artifact that references a record as its subject.
// For signature referrers, it uses cosign to attach the signature.
func (s *store) PushReferrer(ctx context.Context, recordCID string, referrer *corev1.RecordReferrer) (*corev1.ReferrerRef, error) {
	referrersLogger.Debug("Pushing referrer to OCI store", "recordCID", recordCID, "type", referrer.GetType())

	if referrer == nil {
		return nil, status.Error(codes.InvalidArgument, "referrer is required") //nolint:wrapcheck
	}

	if recordCID == "" {
		return nil, status.Error(codes.InvalidArgument, "record CID is required") //nolint:wrapcheck
	}

	if referrer.GetType() == "" {
		return nil, status.Error(codes.InvalidArgument, "referrer type is required") //nolint:wrapcheck
	}

	if referrer.GetRecordRef() == nil {
		referrer.RecordRef = &corev1.RecordRef{Cid: recordCID}
	} else if referrer.GetRecordRef().GetCid() != recordCID {
		return nil, status.Error(codes.InvalidArgument, "referrer's record CID must match record CID") //nolint:wrapcheck
	}

	// Check if record exists before pushing referrer
	_, err := s.Lookup(ctx, &corev1.RecordRef{Cid: recordCID})
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "record not found for CID %s: %v", recordCID, err)
	}

	// Route based on referrer type
	switch referrer.GetType() {
	case corev1.SignatureReferrerType:
		// TODO: validate signature
		return s.pushReferrer(ctx, recordCID, referrer)

	case corev1.PublicKeyReferrerType:
		// TODO: validate public key
		return s.pushReferrer(ctx, recordCID, referrer)

	default:
		// Store as generic OCI referrer
		return s.pushReferrer(ctx, recordCID, referrer)
	}
}

// pushReferrer pushes a referrer as a generic OCI artifact.
func (s *store) pushReferrer(ctx context.Context, recordCID string, referrer *corev1.RecordReferrer) (*corev1.ReferrerRef, error) {
	// Map API type to internal OCI artifact type
	ociArtifactType := apiToOCIType(referrer.GetType())

	// Marshal the referrer to JSON
	referrerBytes, err := referrer.Marshal()
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to marshal referrer: %v", err)
	}

	// Push the referrer blob using internal OCI artifact type
	blobDesc, err := oras.PushBytes(ctx, s.repo, ociArtifactType, referrerBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to push referrer blob: %w", err)
	}

	referrerCID, err := corev1.ConvertDigestToCID(blobDesc.Digest)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to convert digest to CID: %v", err)
	}

	// Resolve the record manifest to get its descriptor for the subject field
	recordManifestDesc, err := s.repo.Resolve(ctx, recordCID)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve record manifest for subject: %w", err)
	}

	// Create annotations for the referrer manifest
	annotations := make(map[string]string)
	annotations[corev1.ReferrerTypeAnnotationKey] = referrer.GetType()
	annotations[ManifestKeyCid] = referrerCID

	if referrer.GetCreatedAt() != "" {
		annotations[corev1.ReferrerCreatedAtAnnotationKey] = referrer.GetCreatedAt()
	}
	// Add custom annotations from the referrer
	for key, value := range referrer.GetAnnotations() {
		annotations[corev1.ReferrerAnnotationPrefix+key] = value
	}

	// Create the referrer manifest with proper OCI subject field
	manifestDesc, err := oras.PackManifest(ctx, s.repo, oras.PackManifestVersion1_1, ocispec.MediaTypeImageManifest,
		oras.PackManifestOptions{
			Subject:             &recordManifestDesc,
			ManifestAnnotations: annotations,
			Layers: []ocispec.Descriptor{
				blobDesc,
			},
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to pack referrer manifest: %w", err)
	}

	// Deliberately not tagged. A referrer is reached through its subject's Referrers API, so a
	// tag adds nothing to discovery while making every referrer a top-level entry in the
	// registry's tag list and index - which is what made that index outgrow the records it
	// describes. The CID stays available as a manifest annotation.
	referrersLogger.Debug("Referrer pushed successfully", "digest", manifestDesc.Digest.String(), "type", referrer.GetType())

	return &corev1.ReferrerRef{Cid: referrerCID}, nil
}

// WalkReferrers walks through referrers for a given record CID, calling walkFn for each referrer.
// If referrerType is empty, all referrers are walked, otherwise only referrers of the specified type.
// A referrer whose content does not decode is skipped and logged. A referrer that cannot be read
// ends the walk with the error, so the caller never takes a partial list for the whole.
func (s *store) WalkReferrers(ctx context.Context, recordCID string, referrerType string, walkFn func(*corev1.RecordReferrer) error) error {
	if walkFn == nil {
		return status.Error(codes.InvalidArgument, "walkFn is required") //nolint:wrapcheck
	}

	return s.walkReferrers(ctx, recordCID, referrerType, failOnUnreadable,
		func(referrer *corev1.RecordReferrer, _ ocispec.Descriptor) error {
			return walkFn(referrer)
		},
	)
}

// walkReferrers is WalkReferrers, additionally handing walkFn the referrer's manifest descriptor.
//
// Deletion needs that descriptor: a referrer CID addresses the referrer's blob, not its manifest,
// so the manifest is reachable only by its own digest or by a tag - and the tag is what we are
// removing.
func (s *store) walkReferrers(ctx context.Context, recordCID string, referrerType string, policy unreadablePolicy, walkFn func(*corev1.RecordReferrer, ocispec.Descriptor) error) error {
	referrersLogger.Debug("Walking referrers from OCI store", "recordCID", recordCID, "type", referrerType)

	if recordCID == "" {
		return status.Error(codes.InvalidArgument, "record CID is required") //nolint:wrapcheck
	}

	if walkFn == nil {
		return status.Error(codes.InvalidArgument, "walkFn is required") //nolint:wrapcheck
	}

	// Get the record manifest descriptor
	recordManifestDesc, err := s.repo.Resolve(ctx, recordCID)
	if err != nil {
		return status.Errorf(codes.NotFound, "failed to resolve record manifest for CID %s: %v", recordCID, err)
	}

	// Determine the matcher based on referrerType
	var matcher ReferrerMatcher

	if referrerType != "" {
		// Map API type to internal OCI artifact type for matching
		ociArtifactType := apiToOCIType(referrerType)

		matcher = s.MediaTypeReferrerMatcher(ociArtifactType)
	}

	// Try the OCI Referrers API first (available on remote registries)
	referrersLister, ok := s.repo.(ReferrersLister)
	if !ok {
		// Fall back to graph Predecessors for local OCI stores
		return s.walkReferrersViaPredecessors(ctx, recordManifestDesc, recordCID, matcher, policy, walkFn)
	}

	var walkErr error

	err = referrersLister.Referrers(ctx, recordManifestDesc, "", func(referrers []ocispec.Descriptor) error {
		for _, referrerDesc := range referrers {
			if err := s.visitReferrer(ctx, referrerDesc, recordCID, matcher, policy, walkFn); err != nil {
				walkErr = err

				return err // Stop walking on error
			}
		}

		return nil // Continue with next batch
	})

	if walkErr != nil {
		return walkErr
	}

	if err != nil {
		return status.Errorf(codes.Internal, "failed to walk referrers for manifest %s: %v", recordManifestDesc.Digest.String(), err)
	}

	referrersLogger.Debug("Successfully walked referrers", "recordCID", recordCID, "type", referrerType)

	return nil
}

// walkReferrersViaPredecessors walks referrers using the graph Predecessors API.
func (s *store) walkReferrersViaPredecessors(ctx context.Context, subjectDesc ocispec.Descriptor, recordCID string, matcher ReferrerMatcher, policy unreadablePolicy, walkFn func(*corev1.RecordReferrer, ocispec.Descriptor) error) error {
	predecessors, err := s.repo.Predecessors(ctx, subjectDesc)
	if err != nil {
		return status.Errorf(codes.Internal, "failed to get predecessors for manifest %s: %v", subjectDesc.Digest.String(), err)
	}

	for _, predDesc := range predecessors {
		if predDesc.MediaType != ocispec.MediaTypeImageManifest {
			continue
		}

		if err := s.visitReferrer(ctx, predDesc, recordCID, matcher, policy, walkFn); err != nil {
			return err
		}
	}

	referrersLogger.Debug("Successfully walked referrers via predecessors", "recordCID", recordCID)

	return nil
}

// visitReferrer reads one listed referrer and hands it to walkFn. Content that
// does not decode is skipped; a referrer that cannot be read is skipped or ends
// the walk as policy says. An error from walkFn is returned as is.
func (s *store) visitReferrer(ctx context.Context, desc ocispec.Descriptor, recordCID string, matcher ReferrerMatcher, policy unreadablePolicy, walkFn func(*corev1.RecordReferrer, ocispec.Descriptor) error) error {
	if matcher != nil {
		match, err := matcher(ctx, desc)
		if err != nil {
			return unreadable(desc, err, policy)
		}

		if !match {
			return nil
		}
	}

	referrer, err := s.extractReferrerFromManifest(ctx, desc, recordCID)
	if err != nil {
		if errors.Is(err, errMalformedReferrer) {
			referrersLogger.Warn("Skipping referrer whose content does not decode", "digest", desc.Digest.String(), "error", err)

			return nil
		}

		return unreadable(desc, err, policy)
	}

	if err := walkFn(referrer, desc); err != nil {
		return err
	}

	referrersLogger.Debug("Referrer processed successfully", "digest", desc.Digest.String(), "type", referrer.GetType())

	return nil
}

// unreadable applies the walk's policy to a referrer that could not be read.
func unreadable(desc ocispec.Descriptor, err error, policy unreadablePolicy) error {
	if policy == skipUnreadable {
		referrersLogger.Error("Skipping referrer that cannot be read", "digest", desc.Digest.String(), "error", err)

		return nil
	}

	return err
}

// extractReferrerFromManifest extracts the referrer data from a referrer manifest. A manifest or
// blob that cannot be read yields the read error; content that is not a referrer yields an error
// wrapping errMalformedReferrer.
func (s *store) extractReferrerFromManifest(ctx context.Context, manifestDesc ocispec.Descriptor, recordCID string) (*corev1.RecordReferrer, error) {
	manifest, err := s.fetchAndParseManifestFromDescriptor(ctx, manifestDesc)
	if err != nil {
		return nil, err // Error already includes proper gRPC status
	}

	if len(manifest.Layers) == 0 {
		return nil, fmt.Errorf("%w: referrer manifest %s has no layers", errMalformedReferrer, manifestDesc.Digest.String())
	}

	blobDesc := manifest.Layers[0]

	reader, err := s.repo.Fetch(ctx, blobDesc)
	if err != nil {
		if errors.Is(err, errdef.ErrNotFound) {
			return nil, status.Errorf(codes.NotFound, "referrer blob %s not found for CID %s: %v", blobDesc.Digest.String(), recordCID, err)
		}

		return nil, status.Errorf(codes.Internal, "failed to fetch referrer blob %s for CID %s: %v", blobDesc.Digest.String(), recordCID, err)
	}
	defer reader.Close()

	referrerData, err := io.ReadAll(reader)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to read referrer data for CID %s: %v", recordCID, err)
	}

	referrer := &corev1.RecordReferrer{}

	if err := protojson.Unmarshal(referrerData, referrer); err != nil {
		return nil, fmt.Errorf("%w: referrer blob %s for CID %s: %w", errMalformedReferrer, blobDesc.Digest.String(), recordCID, err)
	}

	// Map internal OCI artifact type back to Dir API type
	if referrer.GetType() != "" {
		referrer.Type = ociToAPIType(referrer.GetType())
	}

	// The CID addresses the referrer blob, so it can be recomputed when the annotation is
	// absent. Referrers pushed before the annotation existed would otherwise carry no
	// ReferrerRef, and an empty CID makes deletion and pull-by-CID skip them in silence.
	referrerCID, ok := manifest.Annotations[ManifestKeyCid]
	if !ok {
		referrerCID, err = corev1.ConvertDigestToCID(blobDesc.Digest)
		if err != nil {
			return nil, fmt.Errorf("%w: referrer blob digest %s for CID %s: %w", errMalformedReferrer, blobDesc.Digest.String(), recordCID, err)
		}
	}

	referrer.ReferrerRef = &corev1.ReferrerRef{Cid: referrerCID}

	return referrer, nil
}

// MediaTypeReferrerMatcher creates a ReferrerMatcher that checks for a specific media type.
func (s *store) MediaTypeReferrerMatcher(expectedMediaType string) ReferrerMatcher {
	return func(ctx context.Context, referrer ocispec.Descriptor) (bool, error) {
		manifest, err := s.fetchAndParseManifestFromDescriptor(ctx, referrer)
		if err != nil {
			return false, err
		}

		return len(manifest.Layers) > 0 && manifest.Layers[0].MediaType == expectedMediaType, nil
	}
}

// DeleteReferrer deletes the referrer identified by referrerCID, or every referrer of
// referrerType when referrerCID is empty.
func (s *store) DeleteReferrer(
	ctx context.Context,
	recordCID string,
	referrerCID string,
	referrerType string,
) ([]string, error) {
	if referrerCID == "" {
		return s.deleteReferrers(ctx, recordCID, referrerType, func(string) bool { return true })
	}

	return s.deleteReferrers(ctx, recordCID, referrerType, func(cid string) bool { return cid == referrerCID })
}

// DeleteReferrers deletes the named referrers in a single pass over the record's referrers.
//
// Callers that already know which referrers to remove should prefer this to a loop of
// DeleteReferrer. Every delete needs the referrer's manifest descriptor, which only a walk can
// supply, so a loop re-walks the entire referrer set once per deletion.
//
// An empty referrerCIDs deletes nothing. Deleting every referrer of a type stays an explicit
// request through DeleteReferrer with an empty CID, so a caller that computed an empty set cannot
// clear the record by accident.
func (s *store) DeleteReferrers(
	ctx context.Context,
	recordCID string,
	referrerCIDs []string,
	referrerType string,
) ([]string, error) {
	if len(referrerCIDs) == 0 {
		return []string{}, nil
	}

	targets := make(map[string]struct{}, len(referrerCIDs))
	for _, cid := range referrerCIDs {
		targets[cid] = struct{}{}
	}

	return s.deleteReferrers(ctx, recordCID, referrerType, func(cid string) bool {
		_, ok := targets[cid]

		return ok
	})
}

// deleteReferrers walks the record's referrers once and deletes the ones match selects.
func (s *store) deleteReferrers(
	ctx context.Context,
	recordCID string,
	referrerType string,
	match func(referrerCID string) bool,
) ([]string, error) {
	type target struct {
		cid  string
		desc ocispec.Descriptor
	}

	// Collected during the walk and deleted after it, so deletion does not mutate the referrer
	// set being iterated.
	var targets []target

	err := s.walkReferrers(ctx, recordCID, referrerType, skipUnreadable,
		func(referrer *corev1.RecordReferrer, desc ocispec.Descriptor) error {
			cid := referrer.GetReferrerRef().GetCid()
			if cid == "" || !match(cid) {
				return nil
			}

			targets = append(targets, target{cid: cid, desc: desc})

			return nil
		},
	)
	if err != nil {
		return nil, err //nolint:wrapcheck
	}

	deleted := []string{}

	for _, t := range targets {
		if err := s.deleteReferrerManifest(ctx, t.cid, t.desc); err != nil {
			return deleted, err
		}

		deleted = append(deleted, t.cid)
	}

	return deleted, nil
}
