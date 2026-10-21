package auth

import "context"

// attachQuotaGuardLocked keeps guard ownership in Manager while publishing the
// current pointer on internal scheduler/auth snapshots for legacy selector code.
func (m *Manager) attachQuotaGuardLocked(auth *Auth) {
	if auth == nil {
		return
	}
	if m != nil {
		auth.quotaGuard = m.quotaGuard
	}
}

func (m *Manager) cloneAuthLocked(auth *Auth) *Auth {
	if auth == nil {
		return nil
	}
	clone := auth.Clone()
	m.attachQuotaGuardLocked(clone)
	return clone
}

func (m *Manager) cloneAuthSnapshot(id string) *Auth {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.cloneAuthLocked(m.auths[id])
}

// SetQuotaGuard installs the manager-owned guard on current and future auth snapshots.
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
	var schedulerSnapshots []*Auth
	for _, auth := range m.auths {
		m.attachQuotaGuardLocked(auth)
		if m.scheduler != nil {
			schedulerSnapshots = append(schedulerSnapshots, m.cloneAuthLocked(auth))
		}
	}
	m.mu.Unlock()
	for _, snapshot := range schedulerSnapshots {
		m.scheduler.upsertAuth(snapshot)
	}
}

// StartQuotaGuard installs and starts one cancellable poller. A replacement
// always cancels the previous lifetime before publishing the new one.
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
	for _, auth := range m.auths {
		m.attachQuotaGuardLocked(auth)
	}
	m.quotaGuardCancel = cancel
	m.mu.Unlock()
	guard.Start(guardCtx, m)
}

// StopQuotaGuard cancels the active poller and removes the guard from future
// local snapshots. Home dispatch is remote and is not affected by this state.
func (m *Manager) StopQuotaGuard() {
	if m == nil {
		return
	}
	m.mu.Lock()
	if m.quotaGuardCancel != nil {
		m.quotaGuardCancel()
		m.quotaGuardCancel = nil
	}
	m.quotaGuard = nil
	for _, auth := range m.auths {
		m.attachQuotaGuardLocked(auth)
	}
	m.mu.Unlock()
}
