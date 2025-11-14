package reitunnel

import (
	"context"
	"sync"
)

// ExecutionStrategy defines how the HookManager handles errors during hook execution
type ExecutionStrategy int

const (
	// StopOnError halts execution when a hook returns an error (default)
	StopOnError ExecutionStrategy = iota
	// CollectAndContinue collects errors but continues executing remaining hooks
	CollectAndContinue
)

// HookManager manages the registration and execution of hooks in the Reitunnel system.
// It is safe for concurrent use by multiple goroutines.
type HookManager struct {
	hooks    []Hook
	strategy ExecutionStrategy
	mu       sync.RWMutex
}

// NewHookManager creates a new HookManager with StopOnError as the default strategy
func NewHookManager() *HookManager {
	return &HookManager{
		hooks:    make([]Hook, 0),
		strategy: StopOnError,
	}
}

// Register adds a hook to the manager. Hooks are executed in registration order.
// This method is safe for concurrent use.
func (hm *HookManager) Register(hook Hook) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.hooks = append(hm.hooks, hook)
}

// SetStrategy configures the error handling strategy for hook execution.
// This method is safe for concurrent use.
func (hm *HookManager) SetStrategy(strategy ExecutionStrategy) {
	hm.mu.Lock()
	defer hm.mu.Unlock()
	hm.strategy = strategy
}

// ExecuteServerStart invokes OnServerStart on all registered hooks
func (hm *HookManager) ExecuteServerStart(ctx context.Context) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnServerStart(ctx)
	}, hooks, strategy)
}

// ExecuteServerStop invokes OnServerStop on all registered hooks
func (hm *HookManager) ExecuteServerStop(ctx context.Context) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnServerStop(ctx)
	}, hooks, strategy)
}

// ExecuteClientConnect invokes OnClientConnect on all registered hooks
func (hm *HookManager) ExecuteClientConnect(ctx context.Context, clientID string) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnClientConnect(ctx, clientID)
	}, hooks, strategy)
}

// ExecuteClientDisconnect invokes OnClientDisconnect on all registered hooks
func (hm *HookManager) ExecuteClientDisconnect(ctx context.Context, clientID string, reason error) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnClientDisconnect(ctx, clientID, reason)
	}, hooks, strategy)
}

// ExecuteTunnelOpen invokes OnTunnelOpen on all registered hooks
func (hm *HookManager) ExecuteTunnelOpen(ctx context.Context, tunnelID string, meta map[string]string) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnTunnelOpen(ctx, tunnelID, meta)
	}, hooks, strategy)
}

// ExecuteTunnelClose invokes OnTunnelClose on all registered hooks
func (hm *HookManager) ExecuteTunnelClose(ctx context.Context, tunnelID string) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnTunnelClose(ctx, tunnelID)
	}, hooks, strategy)
}

// ExecuteDataSent invokes OnDataSent on all registered hooks
func (hm *HookManager) ExecuteDataSent(ctx context.Context, tunnelID string, bytes int64) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnDataSent(ctx, tunnelID, bytes)
	}, hooks, strategy)
}

// ExecuteDataReceived invokes OnDataReceived on all registered hooks
func (hm *HookManager) ExecuteDataReceived(ctx context.Context, tunnelID string, bytes int64) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnDataReceived(ctx, tunnelID, bytes)
	}, hooks, strategy)
}

// ExecuteError invokes OnError on all registered hooks
func (hm *HookManager) ExecuteError(ctx context.Context, err error, meta map[string]string) error {
	hm.mu.RLock()
	hooks := hm.hooks
	strategy := hm.strategy
	hm.mu.RUnlock()

	return hm.executeHooks(ctx, func(hook Hook) error {
		return hook.OnError(ctx, err, meta)
	}, hooks, strategy)
}

// executeHooks is a helper method that executes a hook function on all hooks
// according to the configured execution strategy
func (hm *HookManager) executeHooks(ctx context.Context, fn func(Hook) error, hooks []Hook, strategy ExecutionStrategy) error {
	if len(hooks) == 0 {
		return nil
	}

	switch strategy {
	case StopOnError:
		for _, hook := range hooks {
			if err := fn(hook); err != nil {
				return err
			}
		}
		return nil

	case CollectAndContinue:
		var errors []error
		for _, hook := range hooks {
			if err := fn(hook); err != nil {
				errors = append(errors, err)
			}
		}
		if len(errors) > 0 {
			return &MultiError{Errors: errors}
		}
		return nil

	default:
		return nil
	}
}

// MultiError represents multiple errors collected during hook execution
type MultiError struct {
	Errors []error
}

// Error implements the error interface
func (me *MultiError) Error() string {
	if len(me.Errors) == 0 {
		return "no errors"
	}
	if len(me.Errors) == 1 {
		return me.Errors[0].Error()
	}
	msg := me.Errors[0].Error()
	for i := 1; i < len(me.Errors); i++ {
		msg += "; " + me.Errors[i].Error()
	}
	return msg
}

// Unwrap returns the underlying errors for error inspection
func (me *MultiError) Unwrap() []error {
	return me.Errors
}
