// nolint: goerr113
package gateway

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	ctypes "github.com/ovrclk/akash/provider/cluster/types"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"

	"github.com/ovrclk/akash/provider"
	pcmock "github.com/ovrclk/akash/provider/cluster/mocks"
	"github.com/ovrclk/akash/provider/manifest"
	pmmock "github.com/ovrclk/akash/provider/manifest/mocks"
	pmock "github.com/ovrclk/akash/provider/mocks"
	"github.com/ovrclk/akash/testutil"
)

func Test_router_Status(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expected := &provider.Status{}
		pclient, _, _ := createMocks()
		pclient.On("Status", mock.Anything).Return(expected, nil)
		withServer(t, pclient, func(host string) {
			client, err := NewClient(host, nil)
			assert.NoError(t, err)
			result, err := client.Status(context.Background())
			assert.NoError(t, err)
			assert.Equal(t, expected, result)
		})
		pclient.AssertExpectations(t)
	})
	t.Run("failure", func(t *testing.T) {
		pclient, _, _ := createMocks()
		pclient.On("Status", mock.Anything).Return(nil, errors.New("oops"))
		withServer(t, pclient, func(host string) {
			client := NewClient(host, nil)
			_, err := client.Status(context.Background())
			assert.Error(t, err)
		})
		pclient.AssertExpectations(t)
	})
}

func Test_router_Manifest(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		req := &manifest.SubmitRequest{
			Deployment: testutil.DeploymentID(t),
		}
		pclient, pmclient, _ := createMocks()
		pmclient.On("Submit", mock.Anything, req).Return(nil)
		withServer(t, pclient, func(host string) {
			client := NewClient(host, nil)
			err := client.SubmitManifest(context.Background(), req)
			assert.NoError(t, err)
		})
		pmclient.AssertExpectations(t)
	})

	t.Run("failure", func(t *testing.T) {
		req := &manifest.SubmitRequest{
			Deployment: testutil.DeploymentID(t),
		}
		pclient, pmclient, _ := createMocks()
		pmclient.On("Submit", mock.Anything, req).Return(errors.New("ded"))
		withServer(t, pclient, func(host string) {
			client := NewClient(host, nil)
			err := client.SubmitManifest(context.Background(), req)
			assert.Error(t, err)
		})
		pmclient.AssertExpectations(t)
	})
}

func Test_router_LeaseStatus(t *testing.T) {

	t.Run("success", func(t *testing.T) {
		expected := &ctypes.LeaseStatus{}
		id := testutil.LeaseID(t)
		pclient, _, pcclient := createMocks()

		pcclient.On("LeaseStatus", mock.Anything, id).Return(expected, nil)
		withServer(t, pclient, func(host string) {
			client := NewClient(host, nil)
			status, err := client.LeaseStatus(context.Background(), id)
			assert.Equal(t, expected, status)
			assert.NoError(t, err)
		})
		pcclient.AssertExpectations(t)
	})

	t.Run("failure", func(t *testing.T) {
		id := testutil.LeaseID(t)
		pclient, _, pcclient := createMocks()

		pcclient.On("LeaseStatus", mock.Anything, id).Return(nil, errors.New("ded"))
		withServer(t, pclient, func(host string) {
			client := NewClient(host, nil)
			status, err := client.LeaseStatus(context.Background(), id)
			assert.Nil(t, status)
			assert.Error(t, err)
		})
		pcclient.AssertExpectations(t)
	})
}

func Test_router_ServiceStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		expected := &ctypes.ServiceStatus{}
		id := testutil.LeaseID(t)
		service := "svc"

		pclient, _, pcclient := createMocks()

		pcclient.On("ServiceStatus", mock.Anything, id, service).Return(expected, nil)
		withServer(t, pclient, func(host string) {
			client := NewClient(host, nil)
			status, err := client.ServiceStatus(context.Background(), id, service)
			assert.NoError(t, err)
			assert.Equal(t, expected, status)
		})
		pcclient.AssertExpectations(t)
	})

	t.Run("failure", func(t *testing.T) {
		id := testutil.LeaseID(t)
		service := "svc"
		pclient, _, pcclient := createMocks()

		pcclient.On("ServiceStatus", mock.Anything, id, service).Return(nil, errors.New("ded"))
		withServer(t, pclient, func(host string) {
			client := NewClient(host, nil)
			status, err := client.ServiceStatus(context.Background(), id, service)
			assert.Nil(t, status)
			assert.Error(t, err)
		})
		pcclient.AssertExpectations(t)
	})
}

func createMocks() (*pmock.Client, *pmmock.Client, *pcmock.Client) {
	var (
		pmclient = &pmmock.Client{}
		pcclient = &pcmock.Client{}
		pclient  = &pmock.Client{}
	)

	pclient.On("Manifest").Return(pmclient)
	pclient.On("Cluster").Return(pcclient)

	return pclient, pmclient, pcclient
}

func withServer(t testing.TB, pclient provider.Client, fn func(string)) {
	t.Helper()
	router := newRouter(testutil.Logger(t), pclient)
	server := httptest.NewServer(router)
	defer server.Close()
	fn("http://" + server.Listener.Addr().String())
}
