package cliproxy

import (
	"context"
	"sync"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/discovery"
	log "github.com/sirupsen/logrus"
)

type discoveryAdvertiserManager struct {
	mu         sync.Mutex
	advertiser discovery.Advertiser
	enabled    bool
	lastSpec   discovery.ServiceSpec
	generation uint64
}

func newDiscoveryAdvertiserManager() *discoveryAdvertiserManager {
	return &discoveryAdvertiserManager{}
}

func (s *Service) getDiscoveryManager() *discoveryAdvertiserManager {
	if s == nil {
		return nil
	}
	s.cfgMu.Lock()
	defer s.cfgMu.Unlock()
	if s.discoveryManager == nil {
		s.discoveryManager = newDiscoveryAdvertiserManager()
	}
	return s.discoveryManager
}

func (s *Service) applyDiscoveryConfig(cfg *config.Config) {
	s.applyDiscoveryConfigContext(context.Background(), cfg)
}

func (s *Service) applyDiscoveryConfigContext(ctx context.Context, cfg *config.Config) bool {
	if s == nil || cfg == nil || (ctx != nil && ctx.Err() != nil) {
		return false
	}
	mgr := s.getDiscoveryManager()
	if mgr == nil {
		return false
	}
	return mgr.ApplyContext(ctx, cfg, cfg.Port, cfg.TLS.Enable)
}

func (s *Service) shutdownDiscovery() error {
	if s == nil {
		return nil
	}
	mgr := s.getDiscoveryManager()
	if mgr == nil {
		return nil
	}
	return mgr.Shutdown()
}

func (m *discoveryAdvertiserManager) ApplyContext(ctx context.Context, cfg *config.Config, port int, tlsEnabled bool) bool {
	m.mu.Lock()

	if !cfg.Discovery.Enabled {
		oldAdv := m.advertiser
		m.advertiser = nil
		m.enabled = false
		m.lastSpec = discovery.ServiceSpec{}
		m.generation++
		m.mu.Unlock()

		if oldAdv != nil {
			log.Info("discovery: stopping mDNS advertisement (disabled by config)")
			_ = oldAdv.Stop()
		}
		return true
	}

	spec, err := discovery.BuildServiceSpec(cfg, port, tlsEnabled)
	if err != nil {
		m.mu.Unlock()
		log.Warnf("discovery: failed to build service spec: %v", err)
		return false
	}

	// Idempotence check: if already running and spec is unchanged, skip restart
	if m.enabled && m.advertiser != nil && specEqual(m.lastSpec, spec) {
		m.mu.Unlock()
		return true
	}

	// Prepare two-phase swap: detach old advertiser and bump generation
	oldAdv := m.advertiser
	m.advertiser = nil
	m.generation++
	gen := m.generation
	m.mu.Unlock()

	// Perform network stop outside lock
	if oldAdv != nil {
		_ = oldAdv.Stop()
	}

	// Perform network start outside lock
	adv := discovery.NewZeroconfAdvertiser()
	errStart := adv.Start(ctx, spec)

	// Commit new advertiser under lock only if generation matches
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.generation != gen {
		// A newer reload or shutdown occurred while starting
		if adv != nil {
			_ = adv.Stop()
		}
		return false
	}

	if errStart != nil {
		m.enabled = false
		log.Warnf("discovery: failed to start mDNS advertiser: %v (degraded, HTTP intact)", errStart)
		return false
	}

	m.advertiser = adv
	m.enabled = true
	m.lastSpec = spec
	log.Infof("discovery: advertising as '%s.%s' on port %d", spec.InstanceName, spec.ServiceType, port)
	return true
}

func (m *discoveryAdvertiserManager) Shutdown() error {
	m.mu.Lock()
	oldAdv := m.advertiser
	m.advertiser = nil
	m.enabled = false
	m.lastSpec = discovery.ServiceSpec{}
	m.generation++
	m.mu.Unlock()

	if oldAdv != nil {
		return oldAdv.Stop()
	}
	return nil
}

func specEqual(a, b discovery.ServiceSpec) bool {
	if a.InstanceName != b.InstanceName ||
		a.ServiceType != b.ServiceType ||
		a.Domain != b.Domain ||
		a.Port != b.Port ||
		len(a.Subtypes) != len(b.Subtypes) ||
		len(a.TextRecords) != len(b.TextRecords) ||
		len(a.Interfaces) != len(b.Interfaces) ||
		len(a.AdvertisedIPs) != len(b.AdvertisedIPs) {
		return false
	}
	for i := range a.Subtypes {
		if a.Subtypes[i] != b.Subtypes[i] {
			return false
		}
	}
	for i := range a.TextRecords {
		if a.TextRecords[i] != b.TextRecords[i] {
			return false
		}
	}
	for i := range a.Interfaces {
		if a.Interfaces[i].Name != b.Interfaces[i].Name {
			return false
		}
	}
	for i := range a.AdvertisedIPs {
		if a.AdvertisedIPs[i] != b.AdvertisedIPs[i] {
			return false
		}
	}
	return true
}
