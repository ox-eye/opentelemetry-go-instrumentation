package grpc

import (
	"bytes"
	"encoding/binary"
	"errors"
	"github.com/cilium/ebpf"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/bpffs"
	"os"
	"strings"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/inject"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/context"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/events"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/log"
	"go.opentelemetry.io/otel/attribute"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags $CFLAGS bpf ./bpf/probe.bpf.c

type GrpcEvent struct {
	StartTime         uint64
	EndTime           uint64
	Method            [50]byte
	Target            [50]byte
	SpanContext       context.EbpfSpanContext
	ParentSpanContext context.EbpfSpanContext
}

type grpcInstrumentor struct {
	bpfObjects        *bpfObjects
	uprobe            link.Link
	returnProbs       []link.Link
	writeHeadersProbe []link.Link
	eventsReader      *perf.Reader
}

func New() *grpcInstrumentor {
	return &grpcInstrumentor{}
}

func (g *grpcInstrumentor) LibraryName() string {
	return "google.golang.org/grpc"
}

func (g *grpcInstrumentor) FuncNames() []string {
	return []string{"google.golang.org/grpc.(*ClientConn).Invoke",
		"google.golang.org/grpc/internal/transport.(*http2Client).createHeaderFields"}
}

func (g *grpcInstrumentor) Load(ctx *context.InstrumentorContext) error {
	libVersion, exists := ctx.TargetDetails.Libraries[g.LibraryName()]
	if !exists {
		libVersion = ""
	}
	spec, err := ctx.Injector.Inject(loadBpf, g.LibraryName(), libVersion, []*inject.InjectStructField{
		{
			VarName:    "clientconn_target_ptr_pos",
			StructName: "google.golang.org/grpc.ClientConn",
			Field:      "target",
		},
	}, true)

	if err != nil {
		return err
	}

	g.bpfObjects = &bpfObjects{}
	err = spec.LoadAndAssign(g.bpfObjects, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: bpffs.BpfFsPath,
		},
	})
	if err != nil {
		return err
	}

	offset, err := ctx.TargetDetails.GetFunctionOffset(g.FuncNames()[0])
	if err != nil {
		return err
	}

	up, err := ctx.Executable.Uprobe("", g.bpfObjects.UprobeClientConnInvoke, &link.UprobeOptions{
		Offset: offset,
	})
	if err != nil {
		return err
	}

	g.uprobe = up
	retOffsets, err := ctx.TargetDetails.GetFunctionReturns(g.FuncNames()[0])
	if err != nil {
		return err
	}

	for _, ret := range retOffsets {
		retProbe, err := ctx.Executable.Uprobe("", g.bpfObjects.UprobeClientConnInvokeReturns, &link.UprobeOptions{
			Offset: ret,
		})
		if err != nil {
			return err
		}
		g.returnProbs = append(g.returnProbs, retProbe)
	}

	rd, err := perf.NewReader(g.bpfObjects.Events, os.Getpagesize())
	if err != nil {
		return err
	}
	g.eventsReader = rd

	// Write headers probe
	whOffsets, err := ctx.TargetDetails.GetFunctionReturns(g.FuncNames()[1])
	if err != nil {
		return err
	}
	for _, whOffset := range whOffsets {
		whProbe, err := ctx.Executable.Uprobe("", g.bpfObjects.UprobeHttp2ClientCreateHeaderFields, &link.UprobeOptions{
			Offset: whOffset,
		})
		if err != nil {
			return err
		}

		g.writeHeadersProbe = append(g.writeHeadersProbe, whProbe)
	}

	return nil
}

func (g *grpcInstrumentor) Run(eventsChan chan<- *events.Event) {
	logger := log.Logger.WithName("grpc-instrumentor")
	var event GrpcEvent
	for {
		record, err := g.eventsReader.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return
			}
			logger.Error(err, "error reading from perf reader")
			continue
		}

		if record.LostSamples != 0 {
			logger.V(0).Info("perf event ring buffer full", "dropped", record.LostSamples)
			continue
		}

		if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &event); err != nil {
			logger.Error(err, "error parsing perf event")
			continue
		}

		eventsChan <- g.convertEvent(&event)
	}
}

// According to https://github.com/open-telemetry/opentelemetry-specification/blob/main/specification/trace/semantic_conventions/rpc.md
func (g *grpcInstrumentor) convertEvent(e *GrpcEvent) *events.Event {
	method := unix.ByteSliceToString(e.Method[:])
	target := unix.ByteSliceToString(e.Target[:])
	var attrs []attribute.KeyValue

	// remove port
	if parts := strings.Split(target, ":"); len(parts) > 1 {
		target = parts[0]
		attrs = append(attrs, semconv.NetPeerPortKey.String(parts[1]))
	}

	attrs = append(attrs, semconv.RPCSystemKey.String("grpc"),
		semconv.RPCServiceKey.String(method),
		semconv.NetPeerIPKey.String(target),
		semconv.NetPeerNameKey.String(target))

	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID:    e.SpanContext.TraceID,
		SpanID:     e.SpanContext.SpanID,
		TraceFlags: trace.FlagsSampled,
	})

	var pscPtr *trace.SpanContext
	if e.ParentSpanContext.TraceID.IsValid() {
		psc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    e.ParentSpanContext.TraceID,
			SpanID:     e.ParentSpanContext.SpanID,
			TraceFlags: trace.FlagsSampled,
			Remote:     true,
		})
		pscPtr = &psc
	} else {
		pscPtr = nil
	}

	log.Logger.V(0).Info("got spancontext", "trace_id", e.SpanContext.TraceID.String(), "span_id", e.SpanContext.SpanID.String())
	return &events.Event{
		Library:           g.LibraryName(),
		Name:              method,
		Kind:              trace.SpanKindClient,
		StartTime:         int64(e.StartTime),
		EndTime:           int64(e.EndTime),
		Attributes:        attrs,
		SpanContext:       &sc,
		ParentSpanContext: pscPtr,
	}
}

func (g *grpcInstrumentor) Close() {
	log.Logger.V(0).Info("closing gRPC instrumentor")
	if g.eventsReader != nil {
		g.eventsReader.Close()
	}

	if g.uprobe != nil {
		g.uprobe.Close()
	}

	for _, r := range g.returnProbs {
		r.Close()
	}

	for _, r := range g.writeHeadersProbe {
		r.Close()
	}

	if g.bpfObjects != nil {
		g.bpfObjects.Close()
	}
}
