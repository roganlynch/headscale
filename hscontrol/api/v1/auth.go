package apiv1

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func init() {
	registrations = append(registrations, registerAuth)
}

// errAuthRejected is the verdict handed to the waiting registration flow when
// an auth session is rejected.
var errAuthRejected = errors.New("auth request rejected")

// AuthRegisterRequestBody is the v1.AuthRegisterRequest body.
type AuthRegisterRequestBody struct {
	User   string `json:"user,omitempty"`
	AuthID string `json:"authId,omitempty"`
}

// AuthApproveRequestBody is the v1.AuthApproveRequest body.
type AuthApproveRequestBody struct {
	AuthID string `json:"authId,omitempty"`
}

// AuthRejectRequestBody is the v1.AuthRejectRequest body.
type AuthRejectRequestBody struct {
	AuthID string `json:"authId,omitempty"`
}

// AuthRequestSummary is one entry in the listAuthRequests response — enough
// to identify a pending request and let an admin decide whether to approve
// or reject it without already knowing its authId out of band.
type AuthRequestSummary struct {
	AuthID    string    `json:"authId"`
	Kind      string    `enum:"REGISTRATION,SSH_CHECK" json:"kind"`
	CreatedAt time.Time `json:"createdAt"`

	// Populated for Kind == "REGISTRATION"; zero value otherwise.
	Hostname   string `json:"hostname"`
	MachineKey string `json:"machineKey"`

	// Populated for Kind == "SSH_CHECK"; nil otherwise.
	SrcNode *Node `json:"srcNode,omitempty"`
	DstNode *Node `json:"dstNode,omitempty"`
}

type (
	authRegisterInput struct {
		Body AuthRegisterRequestBody
	}
	authRegisterOutput struct {
		Body struct {
			Node Node `json:"node"`
		}
	}
)

type (
	authApproveInput struct {
		Body AuthApproveRequestBody
	}
	authApproveOutput struct {
		Body struct{}
	}
)

type (
	authRejectInput struct {
		Body AuthRejectRequestBody
	}
	authRejectOutput struct {
		Body struct{}
	}
)

type (
	listAuthRequestsInput  struct{}
	listAuthRequestsOutput struct {
		Body struct {
			Requests []AuthRequestSummary `json:"requests" nullable:"false"`
		}
	}
)

func registerAuth(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "authRegister",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/register",
		Summary:     "Register node via auth flow",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authRegisterInput) (*authRegisterOutput, error) {
		// Malformed auth_id is 400; unknown user and missing pending session are
		// 404 via mapError, matching the Approve/Reject handlers.
		registrationID, err := types.AuthIDFromString(in.Body.AuthID)
		if err != nil {
			return nil, huma.Error400BadRequest("registering node", err)
		}

		user, err := b.State.GetUserByName(in.Body.User)
		if err != nil {
			return nil, mapError("looking up user", err)
		}

		node, nodeChange, err := b.State.HandleNodeFromAuthPath(
			registrationID,
			types.UserID(user.ID),
			nil,
			util.RegisterMethodCLI,
		)
		if err != nil {
			return nil, mapError("registering node", err)
		}

		routeChange, err := b.State.AutoApproveRoutes(node)
		if err != nil {
			return nil, huma.Error500InternalServerError("auto approving routes", err)
		}

		b.Change(nodeChange, routeChange)

		out := &authRegisterOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "authApprove",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/approve",
		Summary:     "Approve a pending auth session",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authApproveInput) (*authApproveOutput, error) {
		authReq, err := pendingAuthRequest(b, in.Body.AuthID)
		if err != nil {
			return nil, err
		}

		authReq.FinishAuth(types.AuthVerdict{})

		return &authApproveOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "authReject",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/reject",
		Summary:     "Reject a pending auth session",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authRejectInput) (*authRejectOutput, error) {
		authReq, err := pendingAuthRequest(b, in.Body.AuthID)
		if err != nil {
			return nil, err
		}

		authReq.FinishAuth(types.AuthVerdict{
			Err: errAuthRejected,
		})

		return &authRejectOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listAuthRequests",
		Method:      http.MethodGet,
		Path:        "/api/v1/auth",
		Summary:     "List pending auth requests",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *listAuthRequestsInput) (*listAuthRequestsOutput, error) {
		out := &listAuthRequestsOutput{}
		out.Body.Requests = make([]AuthRequestSummary, 0)

		for _, entry := range b.State.ListAuthCacheEntries() {
			summary := AuthRequestSummary{
				AuthID:    entry.ID.String(),
				CreatedAt: entry.Request.CreatedAt,
			}

			switch {
			case entry.Request.IsRegistration():
				summary.Kind = "REGISTRATION"
				data := entry.Request.RegistrationData()
				summary.Hostname = data.Hostname
				summary.MachineKey = data.MachineKey.String()
			case entry.Request.IsSSHCheck():
				summary.Kind = "SSH_CHECK"

				binding := entry.Request.SSHCheckBinding()

				if srcNode, ok := b.State.GetNodeByID(binding.SrcNodeID); ok {
					src := nodeFromView(srcNode)
					summary.SrcNode = &src
				}

				if dstNode, ok := b.State.GetNodeByID(binding.DstNodeID); ok {
					dst := nodeFromView(dstNode)
					summary.DstNode = &dst
				}
			}

			out.Body.Requests = append(out.Body.Requests, summary)
		}

		return out, nil
	})
}

// pendingAuthRequest looks up the pending session for auth_id. Malformed
// auth_id is 400, unknown is 404.
func pendingAuthRequest(b Backend, rawID string) (*types.AuthRequest, error) {
	authID, err := types.AuthIDFromString(rawID)
	if err != nil {
		return nil, huma.Error400BadRequest("invalid auth_id", err)
	}

	authReq, ok := b.State.GetAuthCacheEntry(authID)
	if !ok {
		return nil, huma.Error404NotFound(
			"no pending auth session for auth_id " + authID.String(),
		)
	}

	return authReq, nil
}
