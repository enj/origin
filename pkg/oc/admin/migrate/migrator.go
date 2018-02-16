package migrate

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/cobra"

	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/sets"
	"k8s.io/kubernetes/pkg/kubectl"
	kcmdutil "k8s.io/kubernetes/pkg/kubectl/cmd/util"
	"k8s.io/kubernetes/pkg/kubectl/resource"

	"github.com/openshift/origin/pkg/oc/cli/util/clientcmd"
)

// MigrateVisitFunc is invoked for each returned object, and may return a
// Reporter that can contain info to be used by save.
type MigrateVisitFunc func(info *resource.Info) (Reporter, error)

// MigrateActionFunc is expected to persist the altered info.Object. The
// Reporter returned from Visit is passed to this function and may be used
// to carry additional information about what to save on an object.
type MigrateActionFunc func(info *resource.Info, reporter Reporter) error

// MigrateFilterFunc can return false to skip an item, or an error.
type MigrateFilterFunc func(info *resource.Info) (bool, error)

// Reporter indicates whether a resource requires migration.
type Reporter interface {
	// Changed returns true if the resource requires migration.
	Changed() bool
}

// ReporterBool implements the Reporter interface for a boolean.
type ReporterBool bool

func (r ReporterBool) Changed() bool {
	return bool(r)
}

func AlwaysRequiresMigration(_ *resource.Info) (Reporter, error) {
	return ReporterBool(true), nil
}

// timeStampNow returns the current time in the same format as glog
func timeStampNow() string {
	return time.Now().Format("0102 15:04:05.000000")
}

var _ io.Writer = &syncedWriter{}

// syncedWriter makes the given writer goroutine safe
type syncedWriter struct {
	lock   sync.Mutex
	writer io.Writer
}

func (w *syncedWriter) Write(p []byte) (n int, err error) {
	w.lock.Lock()
	defer w.lock.Unlock()
	return w.writer.Write(p)
}

// ResourceOptions assists in performing migrations on any object that
// can be retrieved via the API.
type ResourceOptions struct {
	In          io.Reader
	Out, ErrOut io.Writer

	Unstructured  bool
	AllNamespaces bool
	Include       []string
	Filenames     []string
	Confirm       bool
	Output        string
	FromKey       string
	ToKey         string

	OverlappingResources []sets.String
	DefaultExcludes      []schema.GroupResource

	Builder   *resource.Builder
	SaveFn    MigrateActionFunc
	PrintFn   MigrateActionFunc
	FilterFn  MigrateFilterFunc
	DryRun    bool
	Summarize bool

	// Any migrate command that exposes this must make sure that
	// its SaveFn, PrintFn and FilterFn are goroutine safe.
	Parallel int
}

func (o *ResourceOptions) Bind(c *cobra.Command) {
	c.Flags().StringSliceVar(&o.Include, "include", o.Include, "Resource types to migrate. Passing --filename will override this flag.")
	c.Flags().BoolVar(&o.AllNamespaces, "all-namespaces", true, "Migrate objects in all namespaces. Defaults to true.")
	c.Flags().BoolVar(&o.Confirm, "confirm", false, "If true, all requested objects will be migrated. Defaults to false.")

	c.Flags().StringVar(&o.FromKey, "from-key", o.FromKey, "If specified, only migrate items with a key (namespace/name or name) greater than or equal to this value")
	c.Flags().StringVar(&o.ToKey, "to-key", o.ToKey, "If specified, only migrate items with a key (namespace/name or name) less than this value")

	// kcmdutil.PrinterForCommand needs these flags, however they are useless
	// here because oc process returns list of heterogeneous objects that is
	// not suitable for formatting as a table.
	kcmdutil.AddNonDeprecatedPrinterFlags(c)

	usage := "Filename, directory, or URL to docker-compose.yml file to use"
	kubectl.AddJsonFilenameFlag(c, &o.Filenames, usage)
}

func (o *ResourceOptions) Complete(f *clientcmd.Factory, c *cobra.Command) error {
	o.Output = kcmdutil.GetFlagString(c, "output")
	switch {
	case len(o.Output) > 0:
		printer, err := kcmdutil.PrinterForOptions(kcmdutil.ExtractCmdPrintOptions(c, false))
		if err != nil {
			return err
		}
		first := true
		o.PrintFn = func(info *resource.Info, _ Reporter) error {
			obj, err := info.Mapping.ConvertToVersion(info.Object, info.Mapping.GroupVersionKind.GroupVersion())
			if err != nil {
				return err
			}
			// TODO: PrintObj is not correct for YAML - it should inject document separators itself
			if o.Output == "yaml" && !first {
				fmt.Fprintln(o.Out, "---")
			}
			first = false
			printer.PrintObj(obj, o.Out)
			return nil
		}
		o.DryRun = true
	case o.Confirm:
		o.DryRun = false
	default:
		o.DryRun = true
	}

	namespace, explicitNamespace, err := f.DefaultNamespace()
	if err != nil {
		return err
	}
	allNamespaces := !explicitNamespace && o.AllNamespaces

	if len(o.FromKey) > 0 || len(o.ToKey) > 0 {
		o.FilterFn = func(info *resource.Info) (bool, error) {
			var key string
			if info.Mapping.Scope.Name() == meta.RESTScopeNameNamespace {
				key = info.Namespace + "/" + info.Name
			} else {
				if !allNamespaces {
					return false, nil
				}
				key = info.Name
			}
			if len(o.FromKey) > 0 && o.FromKey > key {
				return false, nil
			}
			if len(o.ToKey) > 0 && o.ToKey <= key {
				return false, nil
			}
			return true, nil
		}
	}

	discoveryClient, err := f.DiscoveryClient()
	if err != nil {
		return err
	}
	mapper, _ := f.Object()

	resourceNames := sets.NewString()
	for i, s := range o.Include {
		if resourceNames.Has(s) {
			continue
		}
		if s != "*" {
			resourceNames.Insert(s)
			break
		}

		all, err := clientcmd.FindAllCanonicalResources(discoveryClient, mapper)
		if err != nil {
			return fmt.Errorf("could not calculate the list of available resources: %v", err)
		}
		exclude := sets.NewString()
		for _, gr := range o.DefaultExcludes {
			if len(o.OverlappingResources) > 0 {
				for _, others := range o.OverlappingResources {
					if !others.Has(gr.String()) {
						continue
					}
					exclude.Insert(others.List()...)
					break
				}
			}
			exclude.Insert(gr.String())
		}
		candidate := sets.NewString()
		for _, gr := range all {
			// if the user specifies a resource that matches resource or resource+group, skip it
			if resourceNames.Has(gr.Resource) || resourceNames.Has(gr.String()) || exclude.Has(gr.String()) {
				continue
			}
			candidate.Insert(gr.String())
		}
		candidate.Delete(exclude.List()...)
		include := candidate
		if len(o.OverlappingResources) > 0 {
			include = sets.NewString()
			for _, k := range candidate.List() {
				reduce := k
				for _, others := range o.OverlappingResources {
					if !others.Has(k) {
						continue
					}
					reduce = others.List()[0]
					break
				}
				include.Insert(reduce)
			}
		}
		glog.V(4).Infof("Found the following resources from the server: %v", include.List())
		last := o.Include[i+1:]
		o.Include = append([]string{}, o.Include[:i]...)
		o.Include = append(o.Include, include.List()...)
		o.Include = append(o.Include, last...)
		break
	}

	o.Builder = f.NewBuilder().
		AllNamespaces(allNamespaces).
		FilenameParam(false, &resource.FilenameOptions{Recursive: false, Filenames: o.Filenames}).
		ContinueOnError().
		DefaultNamespace().
		RequireObject(true).
		SelectAllParam(true).
		Flatten()

	if o.Unstructured {
		o.Builder = o.Builder.Unstructured()
	} else {
		o.Builder = o.Builder.Internal()
	}

	if !allNamespaces {
		o.Builder.NamespaceParam(namespace)
	}
	if len(o.Filenames) == 0 {
		o.Builder.ResourceTypes(o.Include...)
	}

	// we need at least one worker
	if !c.Flags().Changed("parallel") {
		o.Parallel = 1
	}

	// make sure we do not print to std out / err from multiple workers at once
	if o.Parallel > 1 {
		o.Out = &syncedWriter{writer: o.Out}
		o.ErrOut = &syncedWriter{writer: o.ErrOut}
	}

	return nil
}

func (o *ResourceOptions) Validate() error {
	if len(o.Filenames) == 0 && len(o.Include) == 0 {
		return fmt.Errorf("you must specify at least one resource or resource type to migrate with --include or --filenames")
	}
	if o.Parallel < 1 {
		return fmt.Errorf("invalid value %d for --parallel, must be at least 1", o.Parallel)
	}
	return nil
}

func (o *ResourceOptions) Visitor() *ResourceVisitor {
	return &ResourceVisitor{
		Out:      o.Out,
		Builder:  o.Builder,
		SaveFn:   o.SaveFn,
		PrintFn:  o.PrintFn,
		FilterFn: o.FilterFn,
		DryRun:   o.DryRun,
		Parallel: o.Parallel,
	}
}

type ResourceVisitor struct {
	Out io.Writer

	Builder *resource.Builder

	SaveFn   MigrateActionFunc
	PrintFn  MigrateActionFunc
	FilterFn MigrateFilterFunc

	DryRun bool

	Parallel int
}

func (o *ResourceVisitor) Visit(fn MigrateVisitFunc) error {
	dryRun := o.DryRun
	summarize := true
	actionFn := o.SaveFn
	switch {
	case o.PrintFn != nil:
		actionFn = o.PrintFn
		dryRun = true
		summarize = false
	case dryRun:
		actionFn = nil
	}
	out := o.Out

	result := o.Builder.Do()
	if result.Err() != nil {
		return result.Err()
	}

	// Ignore any resource that does not support GET
	result.IgnoreErrors(errors.IsMethodNotSupported, errors.IsNotFound)

	// the producer (result.Visit) uses this to send data to the workers
	work := make(chan workData, 1024)
	// the workers use this to send processed work to the consumer (migrateTracker)
	results := make(chan resultData, 1024)

	// migrateTracker tracks stats for this migrate run
	t := &migrateTracker{
		out:                 out,
		dryRun:              dryRun,
		resourcesWithErrors: sets.NewString(),
		results:             results,
	}

	// use wg to track when workers have finished processing
	wg := sync.WaitGroup{}
	// spawn and track all workers
	for w := 0; w < o.Parallel; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			worker := &migrateWorker{
				retries:   10, // how many times should this worker retry per resource
				work:      work,
				results:   results,
				migrateFn: fn,
				actionFn:  actionFn,
				filterFn:  o.FilterFn,
			}
			worker.run()
		}()
	}

	// use wg2 to track when the consumer (migrateTracker) has finished tracking stats
	wg2 := sync.WaitGroup{}
	wg2.Add(1)
	go func() {
		defer wg2.Done()
		t.run()
	}()

	err := result.Visit(func(info *resource.Info, err error) error {
		// send data from producer visitor to workers
		work <- workData{info: info, err: err}
		return nil
	})

	// signal that we are done sending work
	close(work)
	// wait for the workers to finish processing
	wg.Wait()
	// signal that all workers have processed and sent completed work
	close(results)
	// wait for the consumer to finish recording the results from processing
	wg2.Wait()

	if summarize {
		if dryRun {
			fmt.Fprintf(out, "summary (dry run): total=%d errors=%d ignored=%d unchanged=%d migrated=%d\n", t.found, t.errors, t.ignored, t.unchanged, t.found-t.errors-t.unchanged-t.ignored)
		} else {
			fmt.Fprintf(out, "summary: total=%d errors=%d ignored=%d unchanged=%d migrated=%d\n", t.found, t.errors, t.ignored, t.unchanged, t.found-t.errors-t.unchanged-t.ignored)
		}
	}

	if t.resourcesWithErrors.Len() > 0 {
		fmt.Fprintf(out, "info: to rerun only failing resources, add --include=%s\n", strings.Join(t.resourcesWithErrors.List(), ","))
	}

	switch {
	case err != nil:
		fmt.Fprintf(out, "error: exited without processing all resources: %v\n", err)
		err = kcmdutil.ErrExit
	case t.errors > 0:
		fmt.Fprintf(out, "error: %d resources failed to migrate\n", t.errors)
		err = kcmdutil.ErrExit
	}
	return err
}

// ErrUnchanged may be returned by MigrateActionFunc to indicate that the object
// did not need migration (but that could only be determined when the action was taken).
var ErrUnchanged = fmt.Errorf("migration was not necessary")

// ErrRecalculate may be returned by MigrateActionFunc to indicate that the object
// has changed and needs to have its information recalculated prior to being saved.
// Use when a resource requires multiple API operations to persist (for instance,
// both status and spec must be changed).
var ErrRecalculate = fmt.Errorf("recalculate migration")

// MigrateError is an exported alias to error to allow external packages to use ErrRetriable and ErrNotRetriable
type MigrateError error

// ErrRetriable is a wrapper for an error that a migrator may use to indicate the
// specific error can be retried.
type ErrRetriable struct {
	MigrateError
}

func (ErrRetriable) Temporary() bool { return true }

// ErrNotRetriable is a wrapper for an error that a migrator may use to indicate the
// specific error cannot be retried.
type ErrNotRetriable struct {
	MigrateError
}

func (ErrNotRetriable) Temporary() bool { return false }

// TemporaryError is a wrapper interface that is used to determine if an error can be retried.
type TemporaryError interface {
	error
	// Temporary should return true if this is a temporary error
	Temporary() bool
}

// attemptResult is an enumeration of the result of a migration
type attemptResult int

const (
	attemptResultSuccess attemptResult = iota
	attemptResultError
	attemptResultUnchanged
	attemptResultIgnore
)

// workData stores a single item of work that needs to be processed by a worker
type workData struct {
	info *resource.Info
	err  error
}

// resultData stores the processing result from a worker
// note that in the case of retries, a single workData can produce multiple resultData
type resultData struct {
	found  bool
	retry  bool
	result attemptResult
	data   workData
}

// migrateTracker abstracts transforming and saving resources and can be used to keep track
// of how many total resources have been updated.
type migrateTracker struct {
	out io.Writer

	dryRun bool

	found, ignored, unchanged, errors int

	resourcesWithErrors sets.String

	results <-chan resultData
}

// report prints a message to out that includes info about the current resource. If the optional error is
// provided it will be written as well.
func (t *migrateTracker) report(prefix string, info *resource.Info, err error) {
	ns := info.Namespace
	if len(ns) > 0 {
		ns = "-n " + ns
	}
	if err != nil {
		fmt.Fprintf(t.out, "E%s %-10s %s %s/%s: %v\n", timeStampNow(), prefix, ns, info.Mapping.Resource, info.Name, err)
	} else {
		fmt.Fprintf(t.out, "I%s %-10s %s %s/%s\n", timeStampNow(), prefix, ns, info.Mapping.Resource, info.Name)
	}
}

// run executes until t.results is closed
// it processes each result and updates its stats as appropriate
func (t *migrateTracker) run() {
	for r := range t.results {
		if r.found {
			t.found++
		}
		if r.retry {
			t.report("retry:", r.data.info, r.data.err)
			continue // retry attempts do not have results to process
		}

		switch r.result {
		case attemptResultError:
			t.report("error:", r.data.info, r.data.err)
			t.errors++
			t.resourcesWithErrors.Insert(r.data.info.Mapping.Resource)
		case attemptResultIgnore:
			t.ignored++
			if glog.V(2) {
				t.report("ignored:", r.data.info, nil)
			}
		case attemptResultUnchanged:
			t.unchanged++
			if glog.V(2) {
				t.report("unchanged:", r.data.info, nil)
			}
		case attemptResultSuccess:
			if glog.V(1) {
				if t.dryRun {
					t.report("migrated (dry run):", r.data.info, nil)
				} else {
					t.report("migrated:", r.data.info, nil)
				}
			}
		}
	}
}

// migrateWorker processes data sent from t.work and sends the results to t.results
type migrateWorker struct {
	retries   int
	work      <-chan workData
	results   chan<- resultData
	migrateFn MigrateVisitFunc
	actionFn  MigrateActionFunc
	filterFn  MigrateFilterFunc
}

// run processes data until t.work is closed
func (t migrateWorker) run() {
	for data := range t.work {
		// if we have no error and a filter func, determine if we need to ignore this resource
		if data.err == nil && t.filterFn != nil {
			ok, err := t.filterFn(data.info)
			// error if we cannot figure out how to filter this resource
			if err != nil {
				t.results <- resultData{found: true, result: attemptResultError, data: workData{info: data.info, err: err}}
				continue
			}
			// we want to ignore this resource
			if !ok {
				t.results <- resultData{found: true, result: attemptResultIgnore, data: data}
				continue
			}
		}

		// there was an error so do not attempt to process this data
		if data.err != nil {
			t.results <- resultData{result: attemptResultError, data: data}
			continue
		}

		// we have no error and the resource was not ignored, so attempt to process it
		// try to invoke the migrateFn and saveFn on info, retrying any recalculation requests up to t.retries times
		result, err := t.try(data.info, t.retries)
		t.results <- resultData{found: true, result: result, data: workData{info: data.info, err: err}}
	}
}

// try will mutate the info and attempt to save, recalculating if there are any retries left.
// The result of the attempt or an error will be returned.
func (t migrateWorker) try(info *resource.Info, retries int) (attemptResult, error) {
	reporter, err := t.migrateFn(info)
	if err != nil {
		return attemptResultError, err
	}
	if reporter == nil {
		return attemptResultIgnore, nil
	}
	if !reporter.Changed() {
		return attemptResultUnchanged, nil
	}
	if t.actionFn != nil {
		if err := t.actionFn(info, reporter); err != nil {
			if err == ErrUnchanged {
				return attemptResultUnchanged, nil
			}
			if canRetry(err) {
				if retries > 0 {
					if bool(glog.V(1)) && err != ErrRecalculate {
						// signal that we had to retry on this resource
						t.results <- resultData{retry: true, data: workData{info: info, err: err}}
					}
					result, err := t.try(info, retries-1)
					switch result {
					case attemptResultUnchanged, attemptResultIgnore:
						result = attemptResultSuccess
					}
					return result, err
				}
			}
			return attemptResultError, err
		}
	}
	return attemptResultSuccess, nil
}

// canRetry returns true if the provided error indicates a retry is possible.
func canRetry(err error) bool {
	if temp, ok := err.(TemporaryError); ok && temp.Temporary() {
		return true
	}
	return err == ErrRecalculate
}

// DefaultRetriable adds retry information to the provided error, and will refresh the
// info if the client info is stale. If the refresh fails the error is made fatal.
// All other errors are left in their natural state - they will not be retried unless
// they define a Temporary() method that returns true.
func DefaultRetriable(info *resource.Info, err error) error {
	switch {
	case err == nil:
		return nil
	case isNotFoundForInfo(info, err):
		// tolerate the deletion of resources during migration
		// report unchanged since we did not actually migrate this object
		return ErrUnchanged
	case errors.IsMethodNotSupported(err):
		return ErrNotRetriable{err}
	case errors.IsConflict(err):
		if refreshErr := info.Get(); refreshErr != nil {
			// tolerate the deletion of resources during migration
			// report unchanged since we did not actually migrate this object
			if isNotFoundForInfo(info, refreshErr) {
				return ErrUnchanged
			}
			return ErrNotRetriable{err}
		}
		return ErrRetriable{err}
	case errors.IsServerTimeout(err):
		return ErrRetriable{err}
	default:
		return err
	}
}

// isNotFoundForInfo returns true iff the error is a not found for the specific info object.
func isNotFoundForInfo(info *resource.Info, err error) bool {
	if err == nil || !errors.IsNotFound(err) {
		return false
	}
	status, ok := err.(errors.APIStatus)
	if !ok {
		return false
	}
	details := status.Status().Details
	if details == nil {
		return false
	}
	// get schema.GroupKind and Resource from the mapping since the actual object may not have type meta filled out
	gk := info.Mapping.GroupVersionKind.GroupKind()
	mappingResource := info.Mapping.Resource
	// based on case-insensitive string comparisons, the error matches info iff
	// the names match
	// the error's kind matches the mapping's kind or the mapping's resource
	// the groups match, but only if both the error and info specify a group
	return strings.EqualFold(details.Name, info.Name) &&
		(strings.EqualFold(details.Kind, gk.Kind) || strings.EqualFold(details.Kind, mappingResource)) &&
		(len(details.Group) == 0 || len(gk.Group) == 0 || strings.EqualFold(details.Group, gk.Group))
}
