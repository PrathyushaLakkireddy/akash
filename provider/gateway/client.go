package gateway

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	cclient "github.com/cosmos/cosmos-sdk/client"
	sdk "github.com/cosmos/cosmos-sdk/types"
	"github.com/gorilla/websocket"
	"github.com/pkg/errors"

	"github.com/ovrclk/akash/provider"
	cltypes "github.com/ovrclk/akash/provider/cluster/types"
	"github.com/ovrclk/akash/provider/manifest"
	cmodule "github.com/ovrclk/akash/x/cert"
	ctypes "github.com/ovrclk/akash/x/cert/types"
	mtypes "github.com/ovrclk/akash/x/market/types"
	pmodule "github.com/ovrclk/akash/x/provider"
	ptypes "github.com/ovrclk/akash/x/provider/types"
)

// Client defines the methods available for connecting to the gateway server.
type Client interface {
	Status(ctx context.Context) (*provider.Status, error)
	SubmitManifest(ctx context.Context, req *manifest.SubmitRequest) error
	LeaseStatus(ctx context.Context, id mtypes.LeaseID) (*cltypes.LeaseStatus, error)
	ServiceStatus(ctx context.Context, id mtypes.LeaseID, service string) (*cltypes.ServiceStatus, error)
	ServiceLogs(ctx context.Context, id mtypes.LeaseID, service string, follow bool, tailLines int64) (*ServiceLogs, error)
}

type ServiceLogMessage struct {
	Name    string `json:"name"`
	Message string `json:"message"`
}

type ServiceLogs struct {
	Stream  <-chan ServiceLogMessage
	OnClose <-chan string
}

type ClientOptions func(Client)

// NewClient returns a new Client
func NewClient(cctx cclient.Context, addr sdk.Address, certs []tls.Certificate) (Client, error) {
	pclient := pmodule.AppModuleBasic{}.GetQueryClient(cctx)

	res, err := pclient.Provider(context.Background(), &ptypes.QueryProviderRequest{Owner: addr.String()})
	if err != nil {
		return nil, err
	}

	uri, err := url.Parse(res.Provider.HostURI)
	if err != nil {
		return nil, err
	}

	cl := &client{
		host:    res.Provider.HostURI,
		addr:    addr,
		qclient: cmodule.AppModuleBasic{}.GetQueryClient(cctx),
	}

	tlsConfig := &tls.Config{
		ServerName:            uri.Host,
		Certificates:          certs,
		InsecureSkipVerify:    true,
		VerifyPeerCertificate: cl.verifyPeerCertificate,
		VerifyConnection:      cl.verifyConnection,
		MinVersion:            tls.VersionTLS13,
	}

	cl.hclient = &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	cl.wsclient = &websocket.Dialer{
		Proxy:            http.ProxyFromEnvironment,
		HandshakeTimeout: 45 * time.Second,
		TLSClientConfig:  tlsConfig,
	}

	return cl, nil
}

type httpClient interface {
	Do(*http.Request) (*http.Response, error)
}

type client struct {
	host     string
	hclient  httpClient
	wsclient *websocket.Dialer
	addr     sdk.Address
	qclient  ctypes.QueryClient
}

type ClientResponseError struct {
	Status  int
	Message string
}

func (err ClientResponseError) Error() string {
	return fmt.Sprintf("remote server returned %d", err.Status)
}

func (err ClientResponseError) ClientError() string {
	return fmt.Sprintf("Remote Server returned %d\n%s", err.Status, err.Message)
}

func (c *client) verifyPeerCertificate(certificates [][]byte, _ [][]*x509.Certificate) error {
	if len(certificates) != 1 {
		return errors.Errorf("tls: invalid certificate chain")
	}

	cert, err := x509.ParseCertificate(certificates[0])
	if err != nil {
		return errors.Wrap(err, "failed to parse certificate")
	}

	// validation
	// 1. CommonName in issuer and Subject must be the same
	if cert.Subject.CommonName != cert.Issuer.CommonName {
		return errors.Wrap(err, "invalid certificate")
	}

	var prov sdk.Address
	if prov, err = sdk.AccAddressFromBech32(cert.Subject.CommonName); err != nil {
		return errors.Wrap(err, "invalid certificate")
	}

	if !c.addr.Equals(prov) {
		return errors.Errorf("tls: hijacked certificate")
	}

	// 2. serial number must be in
	if cert.SerialNumber == nil {
		return errors.Wrap(err, "invalid certificate")
	}

	// 3. look up certificate on chain. it must not be revoked
	var resp *ctypes.QueryCertificatesResponse
	resp, err = c.qclient.Certificates(
		context.Background(),
		&ctypes.QueryCertificatesRequest{
			Filter: ctypes.CertificateFilter{
				Owner:  prov.String(),
				Serial: cert.SerialNumber.String(),
				State:  "valid",
			},
		},
	)
	if err != nil {
		return err
	}

	certPool := x509.NewCertPool()

	if !certPool.AppendCertsFromPEM(resp.Certificates[0].Cert) {
		return errors.Wrap(err, "invalid certificate")
	}

	opts := x509.VerifyOptions{
		Roots:                     certPool,
		CurrentTime:               time.Now(),
		KeyUsages:                 []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		MaxConstraintComparisions: 0,
	}

	if _, err = cert.Verify(opts); err != nil {
		return errors.Wrap(err, "invalid certificate")
	}

	return nil
}

func (c *client) verifyConnection(_ tls.ConnectionState) error {
	return nil
}

func (c *client) Status(ctx context.Context) (*provider.Status, error) {
	uri, err := makeURI(c.host, statusPath())
	if err != nil {
		return nil, err
	}
	var obj provider.Status

	if err := c.getStatus(ctx, uri, &obj); err != nil {
		return nil, err
	}

	return &obj, nil
}

func (c *client) SubmitManifest(ctx context.Context, mreq *manifest.SubmitRequest) error {
	uri, err := makeURI(c.host, submitManifestPath(mreq.DSeq))
	if err != nil {
		return err
	}

	buf, err := json.Marshal(mreq)
	if err != nil {
		return err
	}

	req, err := http.NewRequestWithContext(ctx, "PUT", uri, bytes.NewBuffer(buf))
	if err != nil {
		return err
	}

	req.Header.Set("Content-Type", contentTypeJSON)
	resp, err := c.hclient.Do(req)
	if err != nil {
		return err
	}
	responseBuf := &bytes.Buffer{}
	_, err = io.Copy(responseBuf, resp.Body)
	defer func() {
		_ = resp.Body.Close()
	}()

	if err != nil {
		return err
	}

	return createClientResponseErrorIfNotOK(resp, responseBuf)
}

func (c *client) LeaseStatus(ctx context.Context, id mtypes.LeaseID) (*cltypes.LeaseStatus, error) {
	uri, err := makeURI(c.host, leaseStatusPath(id))
	if err != nil {
		return nil, err
	}

	var obj cltypes.LeaseStatus
	if err := c.getStatus(ctx, uri, &obj); err != nil {
		return nil, err
	}

	return &obj, nil
}

func (c *client) ServiceStatus(ctx context.Context, id mtypes.LeaseID, service string) (*cltypes.ServiceStatus, error) {
	uri, err := makeURI(c.host, serviceStatusPath(id, service))
	if err != nil {
		return nil, err
	}

	var obj cltypes.ServiceStatus
	if err := c.getStatus(ctx, uri, &obj); err != nil {
		return nil, err
	}

	return &obj, nil
}

func (c *client) getStatus(ctx context.Context, uri string, obj interface{}) error {
	fmt.Printf("uri: %s\n", uri)
	req, err := http.NewRequestWithContext(ctx, "GET", uri, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", contentTypeJSON)

	resp, err := c.hclient.Do(req)
	if err != nil {
		return err
	}

	buf := &bytes.Buffer{}
	_, err = io.Copy(buf, resp.Body)
	defer func() {
		_ = resp.Body.Close()
	}()

	if err != nil {
		return err
	}

	err = createClientResponseErrorIfNotOK(resp, buf)
	if err != nil {
		return err
	}

	dec := json.NewDecoder(buf)
	return dec.Decode(obj)
}

func createClientResponseErrorIfNotOK(resp *http.Response, responseBuf *bytes.Buffer) error {
	if resp.StatusCode == http.StatusOK {
		return nil
	}

	return ClientResponseError{
		Status:  resp.StatusCode,
		Message: responseBuf.String(),
	}
}

// makeURI
// for client queries path must not include owner id
func makeURI(host string, path string) (string, error) {
	endpoint, err := url.Parse(host + "/" + path)
	if err != nil {
		return "", err
	}

	return endpoint.String(), nil
}

func (c *client) ServiceLogs(ctx context.Context,
	id mtypes.LeaseID,
	service string,
	follow bool,
	tailLines int64) (*ServiceLogs, error) {

	endpoint, err := url.Parse(c.host + "/" + serviceLogsPath(id, service))
	if err != nil {
		return nil, err
	}

	switch endpoint.Scheme {
	case "ws", "http", "":
		endpoint.Scheme = "ws"
	case "wss", "https":
		endpoint.Scheme = "wss"
	default:
		return nil, errors.Errorf("invalid uri scheme \"%s\"", endpoint.Scheme)
	}

	query := url.Values{}

	query.Set("follow", strconv.FormatBool(follow))
	query.Set("tail", strconv.FormatInt(tailLines, 10))

	endpoint.RawQuery = query.Encode()

	conn, response, err := c.wsclient.DialContext(ctx, endpoint.String(), nil)
	if errors.Is(err, websocket.ErrBadHandshake) {
		buf := &bytes.Buffer{}
		_, err = io.Copy(buf, response.Body)
		if err != nil {
			return nil, err
		}
		return nil, ClientResponseError{
			Status:  response.StatusCode,
			Message: buf.String(),
		}
	}

	if err != nil {
		return nil, err
	}

	// todo (#732) check status

	streamch := make(chan ServiceLogMessage)
	onclose := make(chan string, 1)
	logs := &ServiceLogs{
		Stream:  streamch,
		OnClose: onclose,
	}

	go func(conn *websocket.Conn) {
		defer func() {
			close(streamch)
			close(onclose)
			_ = conn.Close()
		}()

		for {
			e := conn.SetReadDeadline(time.Now().Add(pingWait))
			if e != nil {
				onclose <- e.Error()
				return
			}

			mType, msg, e := conn.ReadMessage()
			if e != nil {
				onclose <- parseCloseMessage(e.Error())
				return
			}

			switch mType {
			case websocket.PingMessage:
				if e = conn.WriteMessage(websocket.PongMessage, []byte{}); e != nil {
					return
				}
			case websocket.TextMessage:
				var logLine ServiceLogMessage
				if e = json.Unmarshal(msg, &logLine); e != nil {
					return
				}

				streamch <- logLine
			case websocket.CloseMessage:
				onclose <- parseCloseMessage(string(msg))
				return
			default:
			}
		}
	}(conn)

	return logs, nil
}

func parseCloseMessage(msg string) string {
	errmsg := strings.SplitN(msg, ": ", 3)
	if len(errmsg) == 3 {
		return errmsg[2]
	}

	return ""
}
