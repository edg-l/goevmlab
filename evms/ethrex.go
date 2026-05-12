// Adapter for the `ethrex-evm` binary (lambdaclass/ethrex). ethrex-evm matches
// the conventional `statetest --trace --trace.format=json` CLI surface and the
// EIP-3155 streaming output shape, including the `{"stateRoot": "0x..."}`
// terminator goevmlab's parser searches for.

package evms

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

// EthrexEVM is an Evm-interface wrapper around the `ethrex-evm` binary.
type EthrexEVM struct {
	path  string
	name  string
	stats *VMStat
}

func NewEthrexEVM(path string, name string) Evm {
	return &EthrexEVM{
		path:  path,
		name:  name,
		stats: &VMStat{},
	}
}

func (evm *EthrexEVM) Instance(int) Evm { return evm }
func (evm *EthrexEVM) Name() string     { return evm.name }
func (evm *EthrexEVM) Close()           {}

// GetStateRoot runs the test without tracing and parses the stateRoot line.
func (evm *EthrexEVM) GetStateRoot(path string) (root, command string, err error) {
	// ethrex-evm always emits a `{"stateRoot": "..."}` terminator on stderr,
	// whether or not --trace is set.
	cmd := exec.Command(evm.path, "statetest", path)
	data, err := cmd.CombinedOutput()
	if err != nil {
		return "", cmd.String(), err
	}
	root, err = evm.ParseStateRoot(data)
	if err != nil {
		log.Error("Failed to find stateroot", "vm", evm.Name(), "cmd", cmd.String())
		return "", cmd.String(), err
	}
	return root, cmd.String(), err
}

// ParseStateRoot looks for the literal `"stateRoot": "0x..."` byte sequence
// (matching the same parser geth's adapter uses).
func (evm *EthrexEVM) ParseStateRoot(data []byte) (string, error) {
	start := bytes.Index(data, []byte(`"stateRoot": "`))
	end := start + 14 + 66
	if start == -1 || end >= len(data) {
		return "", fmt.Errorf("%v: no stateroot found", evm.Name())
	}
	return string(data[start+14 : end]), nil
}

// RunStateTest streams an EIP-3155 trace to `out` and returns timing info.
func (evm *EthrexEVM) RunStateTest(path string, out io.Writer, speedTest bool) (*tracingResult, error) {
	var (
		t0     = time.Now()
		stderr io.ReadCloser
		err    error
		cmd    = exec.Command(evm.path, "statetest", "--trace", "--trace.format=json",
			"--trace.nomemory=true", "--trace.noreturndata=true", path)
	)
	if speedTest {
		// No tracing — just produce the stateRoot terminator.
		cmd = exec.Command(evm.path, "statetest", path)
	}
	if stderr, err = cmd.StderrPipe(); err != nil {
		return &tracingResult{Cmd: cmd.String()}, err
	}
	if err = cmd.Start(); err != nil {
		return &tracingResult{Cmd: cmd.String()}, err
	}
	evm.Copy(out, stderr)
	_, _ = io.ReadAll(stderr)
	err = cmd.Wait()
	duration, slow := evm.stats.TraceDone(t0)

	return &tracingResult{
		Slow:     slow,
		ExecTime: duration,
		Cmd:      cmd.String(),
	}, err
}

// Copy filters the trace stream and writes normalised opLog entries to `out`.
func (evm *EthrexEVM) Copy(out io.Writer, input io.Reader) {
	evm.copyUntilEnd(out, input)
}

func (evm *EthrexEVM) copyUntilEnd(out io.Writer, input io.Reader) stateRoot {
	scanner := NewJsonlScanner("ethrex", input, os.Stderr)
	defer scanner.Release()
	var stateRoot stateRoot
	for {
		var elem opLog
		if err := scanner.Next(&elem); err != nil {
			break
		}
		if len(elem.StateRoot1) != 0 {
			stateRoot.StateRoot = elem.StateRoot1
			break
		}
		// Drop entries that fail to unmarshal (depth == 0 indicates the
		// summary line or a malformed entry).
		if elem.Depth == 0 {
			continue
		}
		// Skip virtual STOPs at end-of-code; ethrex emits a real STOP for the
		// implicit terminator, so this filter is a safety net for parity with
		// other clients' adapters.
		if elem.Op == 0x0 {
			continue
		}
		data := CustomMarshal(&elem)
		if _, err := out.Write(append(data, '\n')); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing to out: %v\n", err)
		}
	}
	// Re-emit the stateRoot as a final record so goevmlab's file-level diff
	// can see it; the re-marshaled line drops the wire colon-space, which is
	// fine since CompareFiles is JSON-aware via the scanner.
	rootJSON, _ := json.Marshal(stateRoot)
	if _, err := out.Write(append(rootJSON, '\n')); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing to out: %v\n", err)
	}
	return stateRoot
}

// Stats returns the accumulated runtime stats.
func (evm *EthrexEVM) Stats() []any { return evm.stats.Stats() }

// Compile-time interface check.
var _ Evm = (*EthrexEVM)(nil)
