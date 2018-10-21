package targetservice

import (
	"fmt"
	"log"
	"net/http"
	"strings"

	"golang.org/x/net/context"

	"gopkg.in/CanonicalLtd/candidclient.v1"
	"gopkg.in/macaroon-bakery.v2/bakery"
	"gopkg.in/macaroon-bakery.v2/bakery/checkers"
	"gopkg.in/macaroon-bakery.v2/bakery/identchecker"
	"gopkg.in/macaroon-bakery.v2/httpbakery"

	"github.com/albertodonato/macaroon-identity/httpservice"
)

// TargetServiceParams defines parameters to create a TargetService
type TargetServiceParams struct {
	Endpoint       string
	AuthEndpoint   string
	AuthKey        *bakery.PublicKey
	RequiredGroups []string
	Logger         *log.Logger
}

// TargetService is an HTTP service which requires macaroon-based authentication.
type TargetService struct {
	httpservice.HTTPService

	RequiredGroups []string

	authEndpoint string
	authKey      *bakery.PublicKey
	keyPair      *bakery.KeyPair
	bakery       *identchecker.Bakery
}

// New returns a TargetService instance.
func New(params TargetServiceParams) *TargetService {
	key := bakery.MustGenerateKey()

	locator := httpbakery.NewThirdPartyLocator(nil, nil)
	locator.AllowInsecure()

	candidClient, _ := candidclient.New(candidclient.NewParams{
		BaseURL: params.AuthEndpoint,
	})
	authorizer := &authorizer{}
	b := identchecker.NewBakery(identchecker.BakeryParams{
		Key:            key,
		Location:       params.Endpoint,
		Locator:        locator,
		Checker:        httpbakery.NewChecker(),
		IdentityClient: candidClient,
		Authorizer:     authorizer,
	})
	mux := http.NewServeMux()
	t := TargetService{
		HTTPService: httpservice.HTTPService{
			Name:       "serv",
			ListenAddr: params.Endpoint,
			Logger:     params.Logger,
			Mux:        mux,
		},
		RequiredGroups: params.RequiredGroups,
		authEndpoint:   params.AuthEndpoint,
		authKey:        params.AuthKey,
		keyPair:        key,
		bakery:         b,
	}
	authorizer.Service = &t
	mux.Handle("/", t.auth(http.HandlerFunc(t.serveURL)))
	return &t

}

func (t *TargetService) serveURL(w http.ResponseWriter, req *http.Request) {
	t.LogRequest(req)
	fmt.Fprintf(w, `you requested URL "%s"`, req.URL.Path)
}

// auth wraps the given handler with a handler that provides authorization by
// inspecting the HTTP request to decide what authorization is required.
func (t *TargetService) auth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		ctx := httpbakery.ContextWithRequest(context.TODO(), req)
		ops := opsForRequest(req)
		authChecker := t.bakery.Checker.Auth(httpbakery.RequestMacaroons(req)...)
		if _, err := authChecker.Allow(ctx, ops...); err != nil {
			oven := httpbakery.Oven{Oven: t.bakery.Oven}
			httpbakery.WriteError(ctx, w, oven.Error(ctx, req, err))
			return
		}
		h.ServeHTTP(w, req)
	})
}

type authorizer struct {
	Service *TargetService
}

func (a *authorizer) Authorize(ctx context.Context, id identchecker.Identity, ops []bakery.Op) (allowed []bool, caveats []checkers.Caveat, err error) {
	haveID := id != nil
	allowed = make([]bool, len(ops))
	for i := range allowed {
		allowed[i] = haveID
	}

	if haveID && len(a.Service.RequiredGroups) > 0 {
		groups := strings.Join(a.Service.RequiredGroups, " ")
		caveat := checkers.Caveat{
			Location:  a.Service.authEndpoint,
			Condition: checkers.Condition("is-member-of", groups),
			Namespace: checkers.StdNamespace,
		}
		caveats = append(caveats, caveat)
	}
	return
}

// opsForRequest returns the required operations implied by the given HTTP
// request.
func opsForRequest(r *http.Request) []bakery.Op {
	return []bakery.Op{{
		Entity: r.URL.Path,
		Action: r.Method,
	}}
}
