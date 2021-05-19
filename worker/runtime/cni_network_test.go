package runtime_test

import (
	"context"
	"errors"
	"github.com/containerd/go-cni"
	"net"
	"strings"

	"github.com/concourse/concourse/worker/runtime"
	"github.com/concourse/concourse/worker/runtime/iptables/iptablesfakes"
	"github.com/concourse/concourse/worker/runtime/libcontainerd/libcontainerdfakes"
	"github.com/concourse/concourse/worker/runtime/runtimefakes"
	"github.com/opencontainers/runtime-spec/specs-go"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
)

type CNINetworkSuite struct {
	suite.Suite
	*require.Assertions

	network  runtime.Network
	cni      *runtimefakes.FakeCNI
	store    *runtimefakes.FakeFileStore
	iptables *iptablesfakes.FakeIptables
}

func (s *CNINetworkSuite) SetupTest() {
	var err error

	s.store = new(runtimefakes.FakeFileStore)
	s.cni = new(runtimefakes.FakeCNI)
	s.iptables = new(iptablesfakes.FakeIptables)

	s.network, err = runtime.NewCNINetwork(
		runtime.WithCNIFileStore(s.store),
		runtime.WithCNIClient(s.cni),
		runtime.WithIptables(s.iptables),
	)
	s.NoError(err)
}

func (s *CNINetworkSuite) TestNewCNINetworkWithInvalidConfigDoesntFail() {
	// CNI defers the actual interpretation of the network configuration to
	// the plugins.
	//
	_, err := runtime.NewCNINetwork(
		runtime.WithCNINetworkConfig(runtime.CNINetworkConfig{
			Subnet: "_____________",
		}),
		runtime.WithIptables(s.iptables),
	)
	s.NoError(err)
}

func (s *CNINetworkSuite) TestSetupMountsEmptyHandle() {
	_, err := s.network.SetupMounts("")
	s.EqualError(err, "empty handle")
}

func (s *CNINetworkSuite) TestSetupMountsFailToCreateHosts() {
	s.store.CreateReturnsOnCall(0, "", errors.New("create-hosts-err"))

	_, err := s.network.SetupMounts("handle")
	s.EqualError(errors.Unwrap(err), "create-hosts-err")

	s.Equal(1, s.store.CreateCallCount())
	fname, _ := s.store.CreateArgsForCall(0)

	s.Equal("handle/hosts", fname)
}

func (s *CNINetworkSuite) TestSetupMountsFailToCreateHostname() {
	s.store.CreateReturnsOnCall(1, "", errors.New("create-hostname-err"))

	_, err := s.network.SetupMounts("handle")
	s.EqualError(errors.Unwrap(err), "create-hostname-err")

	s.Equal(2, s.store.CreateCallCount())
	fname, _ := s.store.CreateArgsForCall(1)

	s.Equal("handle/hostname", fname)
}

func (s *CNINetworkSuite) TestSetupMountsFailToCreateResolvConf() {
	s.store.CreateReturnsOnCall(2, "", errors.New("create-resolvconf-err"))

	_, err := s.network.SetupMounts("handle")
	s.EqualError(errors.Unwrap(err), "create-resolvconf-err")

	s.Equal(3, s.store.CreateCallCount())
	fname, _ := s.store.CreateArgsForCall(2)

	s.Equal("handle/resolv.conf", fname)
}

func (s *CNINetworkSuite) TestSetupMountsReturnsMountpoints() {
	s.store.CreateReturnsOnCall(0, "/tmp/handle/etc/hosts", nil)
	s.store.CreateReturnsOnCall(1, "/tmp/handle/etc/hostname", nil)
	s.store.CreateReturnsOnCall(2, "/tmp/handle/etc/resolv.conf", nil)

	mounts, err := s.network.SetupMounts("some-handle")
	s.NoError(err)

	s.Len(mounts, 3)
	s.Equal(mounts, []specs.Mount{
		{
			Destination: "/etc/hosts",
			Type:        "bind",
			Source:      "/tmp/handle/etc/hosts",
			Options:     []string{"bind", "rw"},
		},
		{
			Destination: "/etc/hostname",
			Type:        "bind",
			Source:      "/tmp/handle/etc/hostname",
			Options:     []string{"bind", "rw"},
		},
		{
			Destination: "/etc/resolv.conf",
			Type:        "bind",
			Source:      "/tmp/handle/etc/resolv.conf",
			Options:     []string{"bind", "rw"},
		},
	})
}

func (s *CNINetworkSuite) TestSetupMountsCallsStoreWithNameServers() {
	network, err := runtime.NewCNINetwork(
		runtime.WithCNIFileStore(s.store),
		runtime.WithNameServers([]string{"6.6.7.7", "1.2.3.4"}),
		runtime.WithIptables(s.iptables),
	)
	s.NoError(err)

	_, err = network.SetupMounts("some-handle")
	s.NoError(err)

	_, resolvConfContents := s.store.CreateArgsForCall(2)
	s.Equal(resolvConfContents, []byte("nameserver 6.6.7.7\nnameserver 1.2.3.4\n"))
}

func (s *CNINetworkSuite) TestSetupMountsCallsStoreWithoutNameServers() {
	network, err := runtime.NewCNINetwork(
		runtime.WithCNIFileStore(s.store),
		runtime.WithIptables(s.iptables),
	)
	s.NoError(err)

	_, err = network.SetupMounts("some-handle")
	s.NoError(err)

	actualResolvContents, err := runtime.ParseHostResolveConf("/etc/resolv.conf")
	s.NoError(err)

	contents := strings.Join(actualResolvContents, "\n") + "\n"

	_, resolvConfContents := s.store.CreateArgsForCall(2)
	s.Equal(resolvConfContents, []byte(contents))
}

func (s *CNINetworkSuite) TestSetupRestrictedNetworksCreatesEmptyAdminChain() {
	network, err := runtime.NewCNINetwork(
		runtime.WithRestrictedNetworks([]string{"1.1.1.1", "8.8.8.8"}),
		runtime.WithIptables(s.iptables),
	)

	err = network.SetupRestrictedNetworks()
	s.NoError(err)

	tablename, chainName := s.iptables.CreateChainOrFlushIfExistsArgsForCall(0)
	s.Equal(tablename, "filter")
	s.Equal(chainName, "CONCOURSE-OPERATOR")

	tablename, chainName, rulespec := s.iptables.AppendRuleArgsForCall(0)
	s.Equal(tablename, "filter")
	s.Equal(chainName, "CONCOURSE-OPERATOR")
	s.Equal(rulespec, []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT"})

	tablename, chainName, rulespec = s.iptables.AppendRuleArgsForCall(1)
	s.Equal(tablename, "filter")
	s.Equal(chainName, "CONCOURSE-OPERATOR")
	s.Equal(rulespec, []string{"-d", "1.1.1.1", "-j", "REJECT"})

	tablename, chainName, rulespec = s.iptables.AppendRuleArgsForCall(2)
	s.Equal(tablename, "filter")
	s.Equal(chainName, "CONCOURSE-OPERATOR")
	s.Equal(rulespec, []string{"-d", "8.8.8.8", "-j", "REJECT"})
}

func (s *CNINetworkSuite) TestAddNilTask() {
	err := s.network.Add(context.Background(), nil, "container-handle")
	s.EqualError(err, "nil task")
}

func (s *CNINetworkSuite) TestAddSetupErrors() {
	s.cni.SetupReturns(nil, errors.New("setup-err"))
	task := new(libcontainerdfakes.FakeTask)

	err := s.network.Add(context.Background(), task, "container-handle")
	s.EqualError(errors.Unwrap(err), "setup-err")
}

func (s *CNINetworkSuite) TestAddInterfaceNotFound() {
	task := new(libcontainerdfakes.FakeTask)
	task.PidReturns(123)
	task.IDReturns("id")

	result := &cni.Result{
		Interfaces: make(map[string]*cni.Config, 0),
	}
	s.cni.SetupReturns(result, nil)
	err := s.network.Add(context.Background(), task, "container-handle")
	s.EqualError(err, "cni net setup: no eth0 interface found")
}

func (s *CNINetworkSuite) TestAdd() {
	task := new(libcontainerdfakes.FakeTask)
	task.PidReturns(123)
	task.IDReturns("id")

	result := &cni.Result{
		Interfaces: make(map[string]*cni.Config, 0),
	}
	result.Interfaces["eth0"] = &cni.Config{
		IPConfigs: []*cni.IPConfig{
			{
				IP: net.IPv4(10, 8, 0, 1),
			},
		},
	}

	s.cni.SetupReturns(result, nil)

	err := s.network.Add(context.Background(), task, "container-handle")
	s.NoError(err)

	s.Equal(1, s.cni.SetupCallCount())
	_, id, netns, _ := s.cni.SetupArgsForCall(0)
	s.Equal("id", id)
	s.Equal("/proc/123/ns/net", netns)
}

func (s *CNINetworkSuite) TestRemoveNilTask() {
	err := s.network.Remove(context.Background(), nil)
	s.EqualError(err, "nil task")
}

func (s *CNINetworkSuite) TestRemoveSetupErrors() {
	s.cni.RemoveReturns(errors.New("remove-err"))
	task := new(libcontainerdfakes.FakeTask)

	err := s.network.Remove(context.Background(), task)
	s.EqualError(errors.Unwrap(err), "remove-err")
}

func (s *CNINetworkSuite) TestRemove() {
	task := new(libcontainerdfakes.FakeTask)
	task.PidReturns(123)
	task.IDReturns("id")

	err := s.network.Remove(context.Background(), task)
	s.NoError(err)

	s.Equal(1, s.cni.RemoveCallCount())
	_, id, netns, _ := s.cni.RemoveArgsForCall(0)
	s.Equal("id", id)
	s.Equal("/proc/123/ns/net", netns)
}
