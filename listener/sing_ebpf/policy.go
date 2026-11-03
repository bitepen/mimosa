//go:build with_ebpf && (linux || android)

package sing_ebpf

import (
	"io"
	"net/netip"

	ECommon "github.com/CHIZI-0618/sing-ebpf"
	"github.com/metacubex/mihomo/component/bypass"
	P "github.com/metacubex/mihomo/constant/provider"
	"github.com/metacubex/mihomo/log"

	E "github.com/metacubex/sing/common/exceptions"

	"go4.org/netipx"
)

type toIpCidr interface {
	ToIpCidr() *netipx.IPSet
}

func (i *Inbound) startBypassRuleSets() error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if i.localBypassRuleSetStarted && i.sharedBypassRuleSetStarted {
		return nil
	}
	rp, ok := i.tunnel.(P.Tunnel)
	if !ok {
		return E.New("tunnel does not expose rule providers")
	}
	register := func(started *bool, callback *io.Closer) {
		if *started {
			return
		}
		*started = true
		*callback = rp.RuleUpdateCallback().Register(i.updateBypassRuleSet)
	}
	register(&i.localBypassRuleSetStarted, &i.localBypassRuleSetCB)
	register(&i.sharedBypassRuleSetStarted, &i.sharedBypassRuleSetCB)
	if i.bypassPublisher == nil {
		i.bypassPublisher = bypass.Global().Register("ebpf")
	}
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		// Roll the registrations back on failure so a later retry does not
		// leave the inbound marked started with callbacks still registered.
		i.stopBypassRuleSetsLocked()
		return err
	}
	return nil
}

func (i *Inbound) stopBypassRuleSets() {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	i.stopBypassRuleSetsLocked()
}

func (i *Inbound) stopBypassRuleSetsLocked() {
	if i.bypassPublisher != nil {
		i.bypassPublisher.Close()
		i.bypassPublisher = nil
	}
	for _, current := range []struct {
		started  *bool
		callback *io.Closer
	}{
		{&i.localBypassRuleSetStarted, &i.localBypassRuleSetCB},
		{&i.sharedBypassRuleSetStarted, &i.sharedBypassRuleSetCB},
	} {
		if *current.callback != nil {
			_ = (*current.callback).Close()
			*current.callback = nil
		}
		*current.started = false
	}
}

func (i *Inbound) updateBypassRuleSet(P.RuleProvider) {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.localBypassRuleSetStarted && !i.sharedBypassRuleSetStarted {
		return
	}
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		log.Errorln("[EBPF] refresh eBPF bypass_rule_set; keeping previous policy: %s", err.Error())
		i.bypassRuleSetNeedsRetry = true
		i.notifyTCInterfaceUpdate()
		return
	}
	i.bypassRuleSetNeedsRetry = false
}

func collectBypassPrefixes(ruleSets []P.RuleProvider) []netip.Prefix {
	var prefixes []netip.Prefix
	for _, ruleSet := range ruleSets {
		strategy := ruleSet.Strategy()
		ipCidrStrategy, ok := strategy.(toIpCidr)
		if !ok {
			log.Warnln("[EBPF] bypass_rule_set %s: rule-set behavior has no IP-CIDR view, silently ignored (use behavior: ipcidr or classical)", ruleSet.Name())
			continue
		}
		ipSet := ipCidrStrategy.ToIpCidr()
		if ipSet == nil {
			// The provider has not finished loading yet (rule sets initialize
			// asynchronously after config parse). Every rule-set update re-runs
			// this refresh, so the CIDRs are applied automatically once the
			// provider is ready. Stay quiet here: a rule-set flagged on every
			// unrelated update while still downloading only spams the log.
			continue
		}
		prefixes = append(prefixes, ipSet.Prefixes()...)
	}
	return prefixes
}

func (i *Inbound) refreshBypassCIDRsLocked() error {
	localPrefixes := collectBypassPrefixes(i.localBypassRuleSet)
	sharedPrefixes := collectBypassPrefixes(i.sharedBypassRuleSet)
	allPrefixes := make([]netip.Prefix, 0, len(localPrefixes)+len(sharedPrefixes))
	allPrefixes = append(allPrefixes, localPrefixes...)
	allPrefixes = append(allPrefixes, sharedPrefixes...)
	if conflicts := i.fakeIPBypassConflictCount(allPrefixes); conflicts > 0 {
		log.Warnln("[EBPF] FakeIP force interception overrides bypass_rule_set CIDRs: overlaps=%d", conflicts)
	}
	i.bypassCIDR = allPrefixes
	decisions := func(prefixes []netip.Prefix) []ECommon.CIDRDecision {
		decisions := make([]ECommon.CIDRDecision, 0, len(prefixes))
		for _, prefix := range prefixes {
			decisions = append(decisions, ECommon.CIDRDecision{Prefix: prefix, Action: ECommon.DecisionPass})
		}
		return decisions
	}
	// The kernel pass set is the union of the static private-address ranges
	// and the dynamic rule-set prefixes. sing-ebpf replaces the destination
	// pass map transactionally and derives the per-family bypass gate from
	// what it receives, so pass the full set (matching sing-box's
	// combineDestinationDecisions) instead of only the rule-set CIDRs. The
	// DNS fake-ip set above stays rule-set-only: private addresses are not
	// domains and never need a real-IP resolution.
	localPassPrefixes := localPrefixes
	if i.localPolicy.BypassPrivateAddress {
		localPassPrefixes = append(append([]netip.Prefix(nil), eBPFPrivateDestinationPrefixes...), localPrefixes...)
	}
	sharedPassPrefixes := sharedPrefixes
	if i.sharedBypassPrivate {
		sharedPassPrefixes = append(append([]netip.Prefix(nil), eBPFPrivateDestinationPrefixes...), sharedPrefixes...)
	}
	localDecisions := decisions(localPassPrefixes)
	sharedDecisions := decisions(sharedPassPrefixes)
	if backend := i.tcBackend(); backend != nil {
		if i.localTCEnabled() {
			if _, err := backend.UpdateLocalDestinationDecisions(localDecisions); err != nil {
				return err
			}
		}
		if i.sharedSocketAssignEnabled() {
			if _, err := backend.UpdateSharedDestinationDecisions(sharedDecisions); err != nil {
				return err
			}
		}
	}
	if backend := i.cgroupBackendInstance(); backend != nil {
		if _, err := backend.UpdateDestinationDecisions(localDecisions); err != nil {
			return err
		}
	}
	if i.sharedRewrite != nil {
		if backend := i.sharedRewrite.sharedBackendInstance(); backend != nil {
			if _, err := backend.UpdateDestinationDecisions(sharedDecisions); err != nil {
				return err
			}
		}
	}
	// Publish the effective bypass CIDR set to the DNS fake-ip middleware so
	// domains whose real addresses fall inside it keep their real IP and the
	// kernel eBPF bypass can engage.
	if i.bypassPublisher != nil {
		i.bypassPublisher.Publish(i.bypassCIDR)
	}
	return nil
}

type bypassCIDRBackendVersion struct {
	version uint64
	known   bool
}

// retryBypassRuleSetIfNeededLocked retries a previously failed bypass
// rule-set refresh on the scheduler's next round.
func (i *Inbound) retryBypassRuleSetIfNeededLocked() tcSharedRewriteOutcome {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()
	if !i.localBypassRuleSetStarted && !i.sharedBypassRuleSetStarted {
		return tcSharedRewriteSettled
	}
	if i.bypassRuleSetBackendRequiresRebuildLocked() {
		i.bypassRuleSetNeedsRetry = false
		return tcSharedRewriteUnrecoverable
	}
	if !i.bypassRuleSetNeedsRetry {
		return tcSharedRewriteSettled
	}
	i.bypassRuleSetRetryCount++
	if err := i.refreshBypassCIDRsLocked(); err != nil {
		log.Errorln("[EBPF] retry eBPF bypass_rule_set refresh: %s", err.Error())
		return tcSharedRewriteRecoverable
	}
	i.bypassRuleSetNeedsRetry = false
	return tcSharedRewriteSettled
}

func (i *Inbound) bypassRuleSetBackendRequiresRebuildLocked() bool {
	if backend := i.tcBackend(); backend != nil && backend.RequiresRebuild() {
		return true
	}
	if backend := i.cgroupBackendInstance(); backend != nil && backend.RequiresRebuild() {
		return true
	}
	if shared := i.sharedRewriteInstance(); shared != nil {
		if backend := shared.sharedBackendInstance(); backend != nil && backend.RequiresRebuild() {
			return true
		}
	}
	return false
}

// 以下是新引入的内核墓碑机制
// -------------------------------------------------------------
// 追加在 policy.go 最底部
// -------------------------------------------------------------

var (
	allIPv4Prefix = netip.MustParsePrefix("0.0.0.0/0")
	allIPv6Prefix = netip.MustParsePrefix("::/0")
)

// SetScreenOffBypass 动态切换 eBPF 内核放手状态
// bypassAll=true: 向内核写入全 0 网段，所有流量原地直连放行
// bypassAll=false: 重新下发原有的分流规则和私有 IP 拦截策略
func (i *Inbound) SetScreenOffBypass(bypassAll bool) error {
	i.bypassRuleSetAccess.Lock()
	defer i.bypassRuleSetAccess.Unlock()

	// 亮屏或透气恢复：直接复用文件里原有的刷新函数
	if !bypassAll {
		err := i.refreshBypassCIDRsLocked()
		if err == nil {
			log.Infoln("[EBPF] Screen ON/Breathe: Restored normal interception")
		}
		return err
	}

	// 熄屏放手：构造 0.0.0.0/0 和 ::/0，动作全部设为 DecisionPass
	allPassDecisions := []ECommon.CIDRDecision{
		{Prefix: allIPv4Prefix, Action: ECommon.DecisionPass},
		{Prefix: allIPv6Prefix, Action: ECommon.DecisionPass},
	}

	// 1. 如果启用了 cgroup 模式，更新 cgroup 的 DestinationDecisions Map
	if backend := i.cgroupBackendInstance(); backend != nil {
		if _, err := backend.UpdateDestinationDecisions(allPassDecisions); err != nil {
			return err
		}
	}

	// 2. 如果启用了 TC 模式，同步更新 TC 的 Local Map
	if backend := i.tcBackend(); backend != nil {
		if i.localTCEnabled() {
			if _, err := backend.UpdateLocalDestinationDecisions(allPassDecisions); err != nil {
				return err
			}
		}
	}

	log.Infoln("[EBPF] Screen OFF: Kernel eBPF bypassed (pass all)")
	return nil
}