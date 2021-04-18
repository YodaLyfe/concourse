package exec_test

import (
	"context"
	"errors"
	"fmt"
	"time"

	"code.cloudfoundry.org/clock/fakeclock"
	"github.com/concourse/concourse/atc"
	"github.com/concourse/concourse/atc/db"
	"github.com/concourse/concourse/atc/db/dbfakes"
	"github.com/concourse/concourse/atc/db/lock"
	"github.com/concourse/concourse/atc/exec"
	"github.com/concourse/concourse/atc/exec/build"
	"github.com/concourse/concourse/atc/exec/execfakes"
	"github.com/concourse/concourse/atc/resource"
	"github.com/concourse/concourse/atc/runtime"
	"github.com/concourse/concourse/atc/runtime/runtimetest"
	"github.com/concourse/concourse/atc/worker"
	"github.com/concourse/concourse/tracing"
	"github.com/concourse/concourse/vars"
	"github.com/onsi/gomega/gbytes"
	"go.opentelemetry.io/otel/oteltest"

	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

var _ = Describe("GetStep", func() {
	var (
		ctx       context.Context
		cancel    func()
		stdoutBuf *gbytes.Buffer
		stderrBuf *gbytes.Buffer

		fakePool        *execfakes.FakePool
		chosenWorker    *runtimetest.Worker
		chosenContainer *runtimetest.WorkerContainer
		getVolume       *runtimetest.Volume

		fakeResourceCacheFactory *dbfakes.FakeResourceCacheFactory
		fakeResourceCache        *dbfakes.FakeUsedResourceCache

		resourceGetter resource.Getter

		fakeDelegate        *execfakes.FakeGetDelegate
		fakeDelegateFactory *execfakes.FakeGetDelegateFactory

		spanCtx context.Context

		getPlan *atc.GetPlan

		runState           exec.RunState
		artifactRepository *build.Repository

		getStep exec.Step
		stepOk  bool
		stepErr error

		containerMetadata = db.ContainerMetadata{
			WorkingDirectory: resource.ResourcesDir("get"),
			PipelineID:       4567,
			Type:             db.ContainerTypeGet,
			StepName:         "some-step",
		}

		stepMetadata = exec.StepMetadata{
			TeamID:       123,
			TeamName:     "some-team",
			BuildID:      42,
			BuildName:    "some-build",
			PipelineID:   4567,
			PipelineName: "some-pipeline",
		}

		planID = atc.PlanID("56")

		expectedOwner = db.NewBuildStepContainerOwner(stepMetadata.BuildID, planID, stepMetadata.TeamID)
	)

	BeforeEach(func() {
		ctx, cancel = context.WithCancel(context.Background())

		chosenWorker = runtimetest.NewWorker("worker").
			WithContainer(
				expectedOwner,
				runtimetest.NewContainer().WithProcess(
					runtime.ProcessSpec{
						ID:   "resource",
						Path: "/opt/resource/in",
						Args: []string{resource.ResourcesDir("get")},
					},
					runtimetest.ProcessStub{},
				),
				nil,
			)
		chosenContainer = chosenWorker.Containers[0]
		getVolume = runtimetest.NewVolume("get-volume")
		chosenContainer.Mounts = []runtime.VolumeMount{
			{
				Volume:    getVolume,
				MountPath: resource.ResourcesDir("get"),
			},
		}

		fakePool = new(execfakes.FakePool)
		fakePool.FindOrSelectWorkerReturns(chosenWorker, nil)

		fakeResourceCacheFactory = new(dbfakes.FakeResourceCacheFactory)
		fakeResourceCache = new(dbfakes.FakeUsedResourceCache)

		fakeClock := fakeclock.NewFakeClock(time.Unix(0, 123))
		fakeVolumeRepo := new(dbfakes.FakeVolumeRepository)
		resourceGetter = resource.NewGetter(lock.NewInMemoryFactory(), fakeClock, fakeResourceCacheFactory, fakeVolumeRepo)

		runState = exec.NewRunState(noopStepper, vars.StaticVariables{
			"source-var": "super-secret-source",
			"params-var": "super-secret-params",
		}, false)
		artifactRepository = runState.ArtifactRepository()

		fakeDelegate = new(execfakes.FakeGetDelegate)
		stdoutBuf = gbytes.NewBuffer()
		stderrBuf = gbytes.NewBuffer()
		fakeDelegate.StdoutReturns(stdoutBuf)
		fakeDelegate.StderrReturns(stderrBuf)
		spanCtx = context.Background()
		fakeDelegate.StartSpanReturns(spanCtx, tracing.NoopSpan)

		fakeDelegateFactory = new(execfakes.FakeGetDelegateFactory)
		fakeDelegateFactory.GetDelegateReturns(fakeDelegate)

		getPlan = &atc.GetPlan{
			Name:    "some-name",
			Type:    "some-base-type",
			Source:  atc.Source{"some": "((source-var))"},
			Params:  atc.Params{"some": "((params-var))"},
			Version: &atc.Version{"some": "version"},
			VersionedResourceTypes: atc.VersionedResourceTypes{
				{
					ResourceType: atc.ResourceType{
						Name:   "some-custom-type",
						Type:   "another-custom-type",
						Source: atc.Source{"some-custom": "((source-var))"},
						Params: atc.Params{"some-custom": "((params-var))"},
					},
					Version: atc.Version{"some-custom": "version"},
				},
				{
					ResourceType: atc.ResourceType{
						Name:       "another-custom-type",
						Type:       "registry-image",
						Source:     atc.Source{"another-custom": "((source-var))"},
						Privileged: true,
					},
					Version: atc.Version{"another-custom": "version"},
				},
			},
		}
	})

	AfterEach(func() {
		cancel()
	})

	JustBeforeEach(func() {
		plan := atc.Plan{
			ID:  atc.PlanID(planID),
			Get: getPlan,
		}

		fakeResourceCacheFactory.FindOrCreateResourceCacheReturns(fakeResourceCache, nil)

		getStep = exec.NewGetStep(
			plan.ID,
			*plan.Get,
			stepMetadata,
			containerMetadata,
			resourceGetter,
			fakeResourceCacheFactory,
			nil,
			fakeDelegateFactory,
			fakePool,
		)

		stepOk, stepErr = getStep.Run(ctx, runState)
	})

	It("constructs the resource cache correctly", func() {
		_, typ, ver, source, params, types := fakeResourceCacheFactory.FindOrCreateResourceCacheArgsForCall(0)
		Expect(typ).To(Equal("some-base-type"))
		Expect(ver).To(Equal(atc.Version{"some": "version"}))
		Expect(source).To(Equal(atc.Source{"some": "super-secret-source"}))
		Expect(params).To(Equal(atc.Params{"some": "super-secret-params"}))
		Expect(types).To(Equal(atc.VersionedResourceTypes{
			{
				ResourceType: atc.ResourceType{
					Name:   "some-custom-type",
					Type:   "another-custom-type",
					Source: atc.Source{"some-custom": "super-secret-source"},

					// params don't need to be interpolated because it's used for
					// fetching, not constructing the resource config
					Params: atc.Params{"some-custom": "((params-var))"},
				},
				Version: atc.Version{"some-custom": "version"},
			},
			{
				ResourceType: atc.ResourceType{
					Name:       "another-custom-type",
					Type:       "registry-image",
					Source:     atc.Source{"another-custom": "super-secret-source"},
					Privileged: true,
				},
				Version: atc.Version{"another-custom": "version"},
			},
		}))
	})

	Context("when tracing is enabled", func() {
		BeforeEach(func() {
			tracing.ConfigureTraceProvider(oteltest.NewTracerProvider())

			spanCtx, buildSpan := tracing.StartSpan(ctx, "build", nil)
			fakeDelegate.StartSpanReturns(spanCtx, buildSpan)

			chosenContainer.ProcessDefs[0].Stub.Do = func(ctx context.Context, _ *runtimetest.Process) error {
				defer GinkgoRecover()
				// Properly propagates span context
				Expect(tracing.FromContext(ctx)).To(Equal(buildSpan))
				return nil
			}
		})

		AfterEach(func() {
			tracing.Configured = false
		})

		It("populates the TRACEPARENT env var", func() {
			Expect(chosenContainer.Spec.Env).To(ContainElement(MatchRegexp(`TRACEPARENT=.+`)))
		})
	})

	It("runs with the correct ContainerSpec", func() {
		Expect(chosenContainer.Spec).To(Equal(
			&runtime.ContainerSpec{
				ImageSpec: runtime.ImageSpec{
					ResourceType: "some-base-type",
				},
				TeamID:         stepMetadata.TeamID,
				Type:           containerMetadata.Type,
				Env:            stepMetadata.Env(),
				Dir:            resource.ResourcesDir("get"),
				CertsBindMount: true,
			},
		))
	})

	Describe("worker selection", func() {
		var ctx context.Context
		var workerSpec worker.Spec

		JustBeforeEach(func() {
			Expect(fakePool.FindOrSelectWorkerCallCount()).To(Equal(1))
			ctx, _, _, workerSpec, _, _ = fakePool.FindOrSelectWorkerArgsForCall(0)
		})

		It("doesn't enforce a timeout", func() {
			_, ok := ctx.Deadline()
			Expect(ok).To(BeFalse())
		})

		It("calls SelectWorker with the correct WorkerSpec", func() {
			Expect(workerSpec).To(Equal(
				worker.Spec{
					ResourceType: "some-base-type",
					TeamID:       stepMetadata.TeamID,
				},
			))
		})

		It("emits a SelectedWorker event", func() {
			Expect(fakeDelegate.SelectedWorkerCallCount()).To(Equal(1))
			_, workerName := fakeDelegate.SelectedWorkerArgsForCall(0)
			Expect(workerName).To(Equal("worker"))
		})

		Context("when the plan specifies tags", func() {
			BeforeEach(func() {
				getPlan.Tags = atc.Tags{"some", "tags"}
			})

			It("sets them in the WorkerSpec", func() {
				Expect(workerSpec.Tags).To(Equal([]string{"some", "tags"}))
			})
		})

		Context("when selecting a worker fails", func() {
			BeforeEach(func() {
				fakePool.FindOrSelectWorkerReturns(nil, errors.New("nope"))
			})

			It("returns an err", func() {
				Expect(stepErr).To(MatchError(ContainSubstring("nope")))
			})
		})
	})

	Context("when the plan specifies a timeout", func() {
		BeforeEach(func() {
			getPlan.Timeout = "1ms"

			chosenContainer.ProcessDefs[0].Stub.Do = func(ctx context.Context, _ *runtimetest.Process) error {
				select {
				case <-ctx.Done():
					return fmt.Errorf("wrapped: %w", ctx.Err())
				case <-time.After(100 * time.Millisecond):
					return nil
				}
			}
		})

		It("fails without error", func() {
			Expect(stepOk).To(BeFalse())
			Expect(stepErr).To(BeNil())
		})

		It("emits an Errored event", func() {
			Expect(fakeDelegate.ErroredCallCount()).To(Equal(1))
			_, status := fakeDelegate.ErroredArgsForCall(0)
			Expect(status).To(Equal(exec.TimeoutLogMessage))
		})

		Context("when the timeout is bogus", func() {
			BeforeEach(func() {
				getPlan.Timeout = "bogus"
			})

			It("fails miserably", func() {
				Expect(stepErr).To(MatchError("parse timeout: time: invalid duration \"bogus\""))
			})
		})
	})

	Context("when using a custom resource type", func() {
		var fetchedImageSpec runtime.ImageSpec

		BeforeEach(func() {
			getPlan.Type = "some-custom-type"

			fetchedImageSpec = runtime.ImageSpec{
				ImageVolume: "some-volume",
			}

			fakeDelegate.FetchImageReturns(fetchedImageSpec, nil)
		})

		It("fetches the resource type image and uses it for the container", func() {
			Expect(fakeDelegate.FetchImageCallCount()).To(Equal(1))
			_, imageResource, types, privileged := fakeDelegate.FetchImageArgsForCall(0)

			By("fetching the type image")
			Expect(imageResource).To(Equal(atc.ImageResource{
				Name:    "some-custom-type",
				Type:    "another-custom-type",
				Source:  atc.Source{"some-custom": "((source-var))"},
				Params:  atc.Params{"some-custom": "((params-var))"},
				Version: atc.Version{"some-custom": "version"},
			}))

			By("excluding the type from the FetchImage call")
			Expect(types).To(Equal(atc.VersionedResourceTypes{
				{
					ResourceType: atc.ResourceType{
						Name:       "another-custom-type",
						Type:       "registry-image",
						Source:     atc.Source{"another-custom": "((source-var))"},
						Privileged: true,
					},
					Version: atc.Version{"another-custom": "version"},
				},
			}))

			By("not being privileged")
			Expect(privileged).To(BeFalse())
		})

		Context("when the plan configures tags", func() {
			BeforeEach(func() {
				getPlan.Tags = atc.Tags{"plan", "tags"}
			})

			It("fetches using the tags", func() {
				Expect(fakeDelegate.FetchImageCallCount()).To(Equal(1))
				_, imageResource, _, _ := fakeDelegate.FetchImageArgsForCall(0)
				Expect(imageResource.Tags).To(Equal(atc.Tags{"plan", "tags"}))
			})
		})

		Context("when the resource type configures tags", func() {
			BeforeEach(func() {
				taggedType, found := getPlan.VersionedResourceTypes.Lookup("some-custom-type")
				Expect(found).To(BeTrue())

				taggedType.Tags = atc.Tags{"type", "tags"}

				newTypes := getPlan.VersionedResourceTypes.Without("some-custom-type")
				newTypes = append(newTypes, taggedType)

				getPlan.VersionedResourceTypes = newTypes
			})

			It("fetches using the type tags", func() {
				Expect(fakeDelegate.FetchImageCallCount()).To(Equal(1))
				_, imageResource, _, _ := fakeDelegate.FetchImageArgsForCall(0)
				Expect(imageResource.Tags).To(Equal(atc.Tags{"type", "tags"}))
			})

			Context("when the plan ALSO configures tags", func() {
				BeforeEach(func() {
					getPlan.Tags = atc.Tags{"plan", "tags"}
				})

				It("fetches using only the type tags", func() {
					Expect(fakeDelegate.FetchImageCallCount()).To(Equal(1))
					_, imageResource, _, _ := fakeDelegate.FetchImageArgsForCall(0)
					Expect(imageResource.Tags).To(Equal(atc.Tags{"type", "tags"}))
				})
			})
		})

		It("sets the bottom-most type in the worker spec", func() {
			Expect(fakePool.FindOrSelectWorkerCallCount()).To(Equal(1))
			_, _, _, workerSpec, _, _ := fakePool.FindOrSelectWorkerArgsForCall(0)

			Expect(workerSpec).To(Equal(
				worker.Spec{
					TeamID:       stepMetadata.TeamID,
					ResourceType: "registry-image",
				},
			))
		})

		It("runs with the correct ImageSpec", func() {
			Expect(chosenContainer.Spec.ImageSpec).To(Equal(fetchedImageSpec))
		})

		Context("when the resource type is privileged", func() {
			BeforeEach(func() {
				getPlan.Type = "another-custom-type"
			})

			It("fetches the image with privileged", func() {
				Expect(fakeDelegate.FetchImageCallCount()).To(Equal(1))
				_, _, _, privileged := fakeDelegate.FetchImageArgsForCall(0)
				Expect(privileged).To(BeTrue())
			})
		})
	})

	Context("when running the script returns an err", func() {
		disaster := errors.New("oh no")

		BeforeEach(func() {
			chosenContainer.ProcessDefs[0].Stub.Err = disaster.Error()
		})

		It("returns an err", func() {
			Expect(chosenContainer.RunningProcesses()).To(HaveLen(1))
			Expect(stepErr).To(MatchError(disaster))
			Expect(stepOk).To(BeFalse())
		})
	})

	Context("when the script succeeds", func() {
		BeforeEach(func() {
			chosenContainer.ProcessDefs[0].Stub.Output = resource.VersionResult{
				Version:  atc.Version{"some": "version"},
				Metadata: []atc.MetadataField{{Name: "some", Value: "metadata"}},
			}
		})

		It("registers the resulting artifact in the RunState.ArtifactRepository", func() {
			artifact, found := artifactRepository.ArtifactFor(build.ArtifactName(getPlan.Name))
			Expect(artifact).To(Equal(getVolume))
			Expect(found).To(BeTrue())
		})

		It("stores the resource cache as the step result", func() {
			var val interface{}
			Expect(runState.Result(planID, &val)).To(BeTrue())
			Expect(val).To(Equal(fakeResourceCache))
		})

		It("marks the step as succeeded", func() {
			Expect(stepOk).To(BeTrue())
		})

		It("finishes the step via the delegate", func() {
			Expect(fakeDelegate.FinishedCallCount()).To(Equal(1))
			_, status, info := fakeDelegate.FinishedArgsForCall(0)
			Expect(status).To(Equal(exec.ExitStatus(0)))
			Expect(info.Version).To(Equal(atc.Version{"some": "version"}))
			Expect(info.Metadata).To(Equal([]atc.MetadataField{{Name: "some", Value: "metadata"}}))
		})

		Context("when the plan has a resource", func() {
			BeforeEach(func() {
				getPlan.Resource = "some-pipeline-resource"
			})

			It("saves a version for the resource", func() {
				Expect(fakeDelegate.UpdateVersionCallCount()).To(Equal(1))
				_, actualPlan, actualVersionResult := fakeDelegate.UpdateVersionArgsForCall(0)
				Expect(actualPlan.Resource).To(Equal("some-pipeline-resource"))
				Expect(actualVersionResult.Version).To(Equal(atc.Version{"some": "version"}))
				Expect(actualVersionResult.Metadata).To(Equal([]atc.MetadataField{{Name: "some", Value: "metadata"}}))
			})
		})

		Context("when getting an anonymous resource", func() {
			BeforeEach(func() {
				getPlan.Resource = ""
			})

			It("does not save the version", func() {
				Expect(fakeDelegate.UpdateVersionCallCount()).To(Equal(0))
			})
		})

		It("does not return an err", func() {
			Expect(stepErr).ToNot(HaveOccurred())
		})
	})

	Context("when Client.RunGetStep returns a Failed GetResult", func() {
		BeforeEach(func() {
			chosenContainer.ProcessDefs[0].Stub.ExitStatus = 1
		})

		It("does NOT mark the step as succeeded", func() {
			Expect(stepOk).To(BeFalse())
		})

		It("finishes the step via the delegate", func() {
			Expect(fakeDelegate.FinishedCallCount()).To(Equal(1))
			_, actualExitStatus, actualVersionResult := fakeDelegate.FinishedArgsForCall(0)
			Expect(actualExitStatus).ToNot(Equal(exec.ExitStatus(0)))
			Expect(actualVersionResult).To(BeZero())
		})

		It("does not return an err", func() {
			Expect(stepErr).ToNot(HaveOccurred())
		})
	})
})
