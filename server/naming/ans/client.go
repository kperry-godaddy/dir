// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package ans

import (
	"context"
	"errors"
	"time"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// breakerClient is the scitt.Client the verifier reaches a transparency log
// through. Every fetch runs under its own deadline, is reported to the host's
// circuit breaker, and is logged with the identifiers needed to trace it when
// it fails, so no fetch can bypass the breaker.
type breakerClient struct {
	inner   scitt.Client
	host    string
	breaker *breaker
	clock   scitt.ClockFunc
	timeout time.Duration
}

func (c *breakerClient) FetchRootKeys(ctx context.Context) ([]string, error) {
	return observeFetch(ctx, c, stageRootKeys, "", c.inner.FetchRootKeys)
}

func (c *breakerClient) FetchStatusToken(ctx context.Context, agentID string) ([]byte, error) {
	return observeFetch(ctx, c, stageStatusToken, agentID, func(ctx context.Context) ([]byte, error) {
		return c.inner.FetchStatusToken(ctx, agentID)
	})
}

func (c *breakerClient) FetchReceipt(ctx context.Context, agentID string) ([]byte, error) {
	return observeFetch(ctx, c, stageReceipt, agentID, func(ctx context.Context) ([]byte, error) {
		return c.inner.FetchReceipt(ctx, agentID)
	})
}

// observeFetch runs one log request under the per-fetch deadline and records
// its outcome with the breaker.
func observeFetch[T any](ctx context.Context, c *breakerClient, stage, agentID string, do func(context.Context) (T, error)) (T, error) {
	fetchCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()

	started := time.Now()

	out, err := do(fetchCtx)
	if err == nil {
		c.breaker.observe(c.host, false, c.clock())

		return out, nil
	}

	strike := countsAsStrike(err, fetchCtx, ctx)

	c.logFailure(stage, agentID, err, time.Since(started), strike)

	if until, tripped := c.breaker.observe(c.host, strike, c.clock()); tripped {
		logger.Warn("Transparency log circuit opened after consecutive connection failures",
			"logHost", c.host,
			"failures", breakerThreshold,
			"until", until)
	}

	return out, err
}

// countsAsStrike reports whether a failed fetch counts toward its host's
// circuit breaker. The caller's cancellation never does. A deadline counts
// only when the fetch's own deadline fired while the lookup still had budget,
// so time spent on DNS is not held against the log. Otherwise a strike is a
// connection-level failure: the log produced no HTTP response.
func countsAsStrike(err error, fetchCtx, lookupCtx context.Context) bool {
	if errors.Is(err, context.Canceled) {
		return false
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return fetchCtx.Err() != nil && lookupCtx.Err() == nil
	}

	return isConnectionFailure(err)
}

// logFailure records one failed fetch. The SDK's transport error prints
// without its cause, which is where the network detail lives.
func (c *breakerClient) logFailure(stage, agentID string, err error, elapsed time.Duration, strike bool) {
	attrs := []any{
		"stage", stage,
		"logHost", c.host,
		"elapsedMs", elapsed.Milliseconds(),
		"strike", strike,
		"cause", causeText(err),
	}

	if agentID != "" {
		attrs = append(attrs, "agentId", agentID)
	}

	if transportErr, ok := errors.AsType[*scitt.TransportError](err); ok && transportErr.StatusCode != 0 {
		attrs = append(attrs, "statusCode", transportErr.StatusCode)
	}

	logger.Warn("Transparency log fetch failed", attrs...)
}

func causeText(err error) string {
	if transportErr, ok := errors.AsType[*scitt.TransportError](err); ok && transportErr.Cause != nil {
		return transportErr.Cause.Error()
	}

	return err.Error()
}
