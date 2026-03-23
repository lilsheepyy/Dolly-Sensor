package flowspec

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"
)

type Blocker interface {
	Block(ctx context.Context, match Match) error
	RateLimit(ctx context.Context, match Match, pps int) error
}

type Match struct {
	SourceIP          string
	SourcePort        uint16
	IncludeSourcePort bool
}

type CommandBlocker struct {
	command       string
	args          []string
	rateLimitArgs []string

	mu      sync.Mutex
	seen    map[string]struct{}
	pending map[string]struct{}
	jobs    chan request
}

type request struct {
	ctx     context.Context
	command string
	args    []string
	match   Match
	pps     int
	result  chan error
}

func NewCommandBlocker(command string, args []string, rateLimitArgs []string, maxWorkers int, queueSize int) *CommandBlocker {
	if maxWorkers <= 0 {
		maxWorkers = 8
	}
	if queueSize <= 0 {
		queueSize = 256
	}

	b := &CommandBlocker{
		command:       command,
		args:          append([]string(nil), args...),
		rateLimitArgs: append([]string(nil), rateLimitArgs...),
		seen:          make(map[string]struct{}),
		pending:       make(map[string]struct{}),
		jobs:          make(chan request, queueSize),
	}

	for i := 0; i < maxWorkers; i++ {
		go b.worker()
	}

	return b
}

func (b *CommandBlocker) worker() {
	for req := range b.jobs {
		req.result <- runCommand(req.ctx, req.command, req.args, req.match, req.pps)
		close(req.result)
	}
}

func (b *CommandBlocker) Block(ctx context.Context, match Match) error {
	key := dedupeKey("block", match)
	if !b.begin(key) {
		return nil
	}
	return b.submit(ctx, key, b.args, match, 0)
}

func (b *CommandBlocker) RateLimit(ctx context.Context, match Match, pps int) error {
	key := dedupeKey("ratelimit", match)
	if !b.begin(key) {
		return nil
	}
	return b.submit(ctx, key, b.rateLimitArgs, match, pps)
}

func dedupeKey(prefix string, match Match) string {
	key := fmt.Sprintf("%s:%s", prefix, match.SourceIP)
	if match.IncludeSourcePort {
		key = fmt.Sprintf("%s:%d", key, match.SourcePort)
	}
	return key
}

func (b *CommandBlocker) begin(key string) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	if _, ok := b.seen[key]; ok {
		return false
	}
	if _, ok := b.pending[key]; ok {
		return false
	}

	b.pending[key] = struct{}{}
	return true
}

func (b *CommandBlocker) submit(ctx context.Context, key string, args []string, match Match, pps int) error {
	req := request{
		ctx:     ctx,
		command: b.command,
		args:    args,
		match:   match,
		pps:     pps,
		result:  make(chan error, 1),
	}

	select {
	case b.jobs <- req:
	case <-ctx.Done():
		b.finish(key, ctx.Err())
		return ctx.Err()
	default:
		err := fmt.Errorf("flowspec queue full")
		b.finish(key, err)
		return err
	}

	err := <-req.result
	b.finish(key, err)
	return err
}

func (b *CommandBlocker) finish(key string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	delete(b.pending, key)
	if err == nil {
		b.seen[key] = struct{}{}
	}
}

func runCommand(ctx context.Context, command string, args []string, match Match, pps int) error {
	if command == "" {
		return fmt.Errorf("empty FlowSpec command")
	}

	ip := net.ParseIP(match.SourceIP)
	if ip == nil {
		return fmt.Errorf("invalid source IP %q", match.SourceIP)
	}

	family := "ipv4"
	prefix := match.SourceIP + "/32"
	if ip.To4() == nil {
		family = "ipv6"
		prefix = match.SourceIP + "/128"
	}

	resolvedArgs := make([]string, len(args))
	for i, arg := range args {
		if !match.IncludeSourcePort && (arg == "source-port" || strings.Contains(arg, "{{source_port}}")) {
			continue
		}
		arg = strings.ReplaceAll(arg, "{{source_ip}}", match.SourceIP)
		arg = strings.ReplaceAll(arg, "{{source_prefix}}", prefix)
		arg = strings.ReplaceAll(arg, "{{source_port}}", fmt.Sprintf("%d", match.SourcePort))
		arg = strings.ReplaceAll(arg, "{{rate_limit_pps}}", fmt.Sprintf("%d", pps))
		arg = strings.ReplaceAll(arg, "{{family}}", family)
		resolvedArgs[i] = arg
	}

	filteredArgs := make([]string, 0, len(resolvedArgs))
	for _, arg := range resolvedArgs {
		if arg == "" {
			continue
		}
		filteredArgs = append(filteredArgs, arg)
	}

	runCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(runCtx, command, filteredArgs...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		trimmed := strings.TrimSpace(string(out))
		if trimmed != "" {
			return fmt.Errorf("%w: %s", err, trimmed)
		}
		return err
	}

	return nil
}
