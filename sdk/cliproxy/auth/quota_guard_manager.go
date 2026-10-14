package auth

import "context"

// SetQuotaGuard installs the in-memory guard on current and future auth snapshots.
func (m *Manager) SetQuotaGuard(guard *QuotaGuard) {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.quotaGuardCancel != nil {
		m.quotaGuardCancel()
		m.quotaGuardCancel = nil
	}
	m.quotaGuard = guard
	for _, auth := range m.auths {
		if guard != nil {
			guard.Attach(auth)
		} else if auth != nil {
			auth.quotaGuard = nil
		}
	}
	m.mu.Unlock()
}

// StartQuotaGuard installs and starts the guard without refreshing credentials.
func (m *Manager) StartQuotaGuard(ctx context.Context, guard *QuotaGuard) {
	if m == nil || guard == nil {
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}
	m.mu.Lock()
	if m.quotaGuardCancel != nil {
		m.quotaGuardCancel()
	}
	guardCtx, cancel := context.WithCancel(ctx)
	m.quotaGuard = guard
	m.quotaGuardCancel = cancel
	for _, auth := range m.auths {
		guard.Attach(auth)
	}
	m.mu.Unlock()
	guard.Start(guardCtx, m)
}
