package goroutine_tracker

import (
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/inject"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/bpffs"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/context"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/instrumentors/events"
	"github.com/keyval-dev/opentelemetry-go-instrumentation/pkg/log"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang -cflags $CFLAGS bpf ./bpf/tracker.bpf.c

type Tracker struct {
	bpfObjects  *bpfObjects
	uprobe      link.Link
	returnProbs []link.Link
}

type GoRoutineTrackerEvent struct {
	StartTime   uint64
	EndTime     uint64
	SpanContext context.EbpfSpanContext
}

func (g *Tracker) LibraryName() string {
	return "go"
}

func (g *Tracker) FuncNames() []string {
	return []string{"runtime.casgstatus", "runtime.newproc1"}
}

func (g *Tracker) Load(ctx *context.InstrumentorContext) error {

	spec, err := ctx.Injector.Inject(loadBpf, g.LibraryName(), ctx.TargetDetails.GoVersion.Original(), []*inject.InjectStructField{{
		VarName:    "goid_pos",
		StructName: "runtime.g",
		Field:      "goid",
	},
	}, false)

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

	uprobeObj := g.bpfObjects.UprobeRuntimeCasgstatus

	uprobeOffset, err := ctx.TargetDetails.GetFunctionOffset(g.FuncNames()[0])
	if err != nil {
		return err
	}
	up, err := ctx.Executable.Uprobe("", uprobeObj, &link.UprobeOptions{
		Offset: uprobeOffset,
	})
	if err != nil {
		return err
	}

	g.uprobe = up

	retOffsets, err := ctx.TargetDetails.GetFunctionReturns(g.FuncNames()[1])
	if err != nil {
		return err
	}

	for _, ret := range retOffsets {
		retProbe, err := ctx.Executable.Uprobe("", g.bpfObjects.UprobeRuntimeNewproc1Returns, &link.UprobeOptions{
			Offset: ret,
		})
		if err != nil {
			return err
		}
		g.returnProbs = append(g.returnProbs, retProbe)
	}

	log.Logger.V(0).Info("goroutine tracker loaded")
	return nil
}

func (g *Tracker) Run(eventsChan chan<- *events.Event) {

}

func New() *Tracker {
	return &Tracker{}
}

func (g *Tracker) Close() {
	log.Logger.V(0).Info("closing goroutine tracker")

	if g.uprobe != nil {
		g.uprobe.Close()
	}

	if g.bpfObjects != nil {
		g.bpfObjects.Close()
	}

	for _, r := range g.returnProbs {
		r.Close()
	}
}
