// Copyright AGNTCY Contributors (https://github.com/agntcy)
// SPDX-License-Identifier: Apache-2.0

package service

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/agntcy/dir/reconciler/tasks"
	"github.com/agntcy/dir/reconciler/tasks/name"
	ansconfig "github.com/agntcy/dir/server/naming/ans/config"
	servertypes "github.com/agntcy/dir/server/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockTask implements tasks.Task for testing.
type mockTask struct {
	name     string
	interval time.Duration
	enabled  bool
	runErr   error
	runCalls int
	runMu    sync.Mutex
}

func (m *mockTask) Name() string            { return m.name }
func (m *mockTask) Interval() time.Duration { return m.interval }
func (m *mockTask) IsEnabled() bool         { return m.enabled }
func (m *mockTask) Run(_ context.Context) error {
	m.runMu.Lock()
	m.runCalls++
	m.runMu.Unlock()

	return m.runErr
}

func newTestService() *Service {
	return &Service{
		tasks:  []tasks.Task{},
		stopCh: make(chan struct{}),
	}
}

func TestNewService(t *testing.T) {
	s := newTestService()
	require.NotNil(t, s)
	assert.NotNil(t, s.stopCh)
	assert.Empty(t, s.tasks)
}

func TestAddTask(t *testing.T) {
	s := newTestService()
	task := &mockTask{name: "test", interval: time.Second, enabled: true}

	s.addTask(task)

	require.Len(t, s.tasks, 1)
	assert.Same(t, task, s.tasks[0])
}

func TestAddTask_Multiple(t *testing.T) {
	s := newTestService()
	t1 := &mockTask{name: "task1", interval: time.Second, enabled: true}
	t2 := &mockTask{name: "task2", interval: 2 * time.Second, enabled: false}

	s.addTask(t1)
	s.addTask(t2)

	require.Len(t, s.tasks, 2)
	assert.Same(t, t1, s.tasks[0])
	assert.Same(t, t2, s.tasks[1])
}

func TestIsReady(t *testing.T) {
	t.Run("no tasks", func(t *testing.T) {
		s := newTestService()
		assert.False(t, s.IsReady(context.Background()))
	})

	t.Run("with tasks", func(t *testing.T) {
		s := newTestService()
		s.addTask(&mockTask{name: "t", interval: time.Second, enabled: true})
		assert.True(t, s.IsReady(context.Background()))
	})
}

func TestStart_StartsOnlyEnabledTasks(t *testing.T) {
	s := newTestService()
	enabled := &mockTask{name: "enabled", interval: 10 * time.Millisecond, enabled: true}
	disabled := &mockTask{name: "disabled", interval: time.Second, enabled: false}

	s.addTask(disabled)
	s.addTask(enabled)

	ctx := t.Context()

	err := s.Start(ctx)
	require.NoError(t, err)

	// Give the enabled task a chance to run at least once
	time.Sleep(30 * time.Millisecond)

	enabled.runMu.Lock()
	calls := enabled.runCalls
	enabled.runMu.Unlock()
	assert.GreaterOrEqual(t, calls, 1, "enabled task should have run at least once")

	disabled.runMu.Lock()
	assert.Equal(t, 0, disabled.runCalls, "disabled task should not run")
	disabled.runMu.Unlock()

	// Stop to clean up
	s.Stop() //nolint:errcheck
}

func TestStart_ContextCancelStopsTaskLoop(t *testing.T) {
	s := newTestService()
	task := &mockTask{name: "loop", interval: 5 * time.Millisecond, enabled: true}
	s.addTask(task)

	ctx, cancel := context.WithCancel(context.Background())
	err := s.Start(ctx)
	require.NoError(t, err)

	time.Sleep(15 * time.Millisecond)
	cancel()
	time.Sleep(20 * time.Millisecond)

	// Stop to release WaitGroup
	s.Stop() //nolint:errcheck

	task.runMu.Lock()
	calls := task.runCalls
	task.runMu.Unlock()
	assert.GreaterOrEqual(t, calls, 1)
}

// Ensure mockTask satisfies tasks.Task.
var _ tasks.Task = (*mockTask)(nil)

// fakeStore is a store without referrer support.
type fakeStore struct{ servertypes.StoreAPI }

// fakeReferrerStore is a store with referrer support. Registration calls no
// method on it.
type fakeReferrerStore struct {
	servertypes.StoreAPI
	servertypes.ReferrerStoreAPI
}

type fakeDB struct{ servertypes.DatabaseAPI }

func TestRegisterNameTask(t *testing.T) {
	const logHost = "log.example.com"

	tests := []struct {
		name      string
		cfg       name.Config
		store     servertypes.StoreAPI
		wantTasks int
		wantErr   string
	}{
		{
			name:      "store without referrers registers nothing",
			cfg:       name.Config{Enabled: true},
			store:     fakeStore{},
			wantTasks: 0,
		},
		{
			name:      "ans disabled registers the name task",
			cfg:       name.Config{Enabled: true},
			store:     fakeReferrerStore{},
			wantTasks: 1,
		},
		{
			name: "ans enabled registers the name task",
			cfg: name.Config{Enabled: true, ANS: ansconfig.Config{
				Enabled:               true,
				TrustedLogHosts:       []string{logHost},
				AllowUnpinnedRootKeys: true,
			}},
			store:     fakeReferrerStore{},
			wantTasks: 1,
		},
		{
			name:    "ans enabled without trusted hosts fails",
			cfg:     name.Config{Enabled: true, ANS: ansconfig.Config{Enabled: true}},
			store:   fakeReferrerStore{},
			wantErr: "trusted_log_hosts",
		},
		{
			name: "ans timeout not shorter than record timeout fails",
			cfg: name.Config{Enabled: true, RecordTimeout: 10 * time.Second, ANS: ansconfig.Config{
				Enabled:               true,
				TrustedLogHosts:       []string{logHost},
				AllowUnpinnedRootKeys: true,
				Timeout:               10 * time.Second,
			}},
			store:   fakeReferrerStore{},
			wantErr: "must be shorter than record_timeout",
		},
		{
			name: "unparseable root key fails verifier construction",
			cfg: name.Config{Enabled: true, ANS: ansconfig.Config{
				Enabled:         true,
				TrustedLogHosts: []string{logHost},
				RootKeys:        []string{"not-a-root-key"},
			}},
			store:   fakeReferrerStore{},
			wantErr: "failed to create ans name verifier",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := newTestService()

			err := s.registerNameTask(tt.cfg, fakeDB{}, tt.store)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				assert.Empty(t, s.tasks)

				return
			}

			require.NoError(t, err)
			assert.Len(t, s.tasks, tt.wantTasks)
		})
	}
}
