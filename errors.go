package gorvp

import (
	"net/http"
	"github.com/pkg/errors"
	"encoding/json"
)

var (
	ErrTokenInvalid = errors.New("Token invalid")
	ErrTokenNotFound = errors.New("Authorization header format must be bearer token")
	ErrTokenNotFoundCode = errors.New("Token not found in the post form, name: token")
	ErrTokenNotFoundRefreshToken = errors.New("Token not found in the post form, name: refresh_token")
	ErrPermissionDenied = errors.New("You do not have permission on request resource")
	ErrRecordNotFound = errors.New("Record not found")
	ErrDatabase = errors.New("Database error")
	ErrClientPermission = errors.New("client has no permission on requested scopes")
	ErrConnectionRevoked = errors.New("This connection had been revoked")
	ErrDuplicateTrustedClientName = errors.New("Can not use same client name as official client.")
	ErrInvalidRequest = errors.New("The request is missing a required parameter, includes an invalid parameter value, includes a parameter more than once, or is otherwise malformed")
	ErrUnsupportedAppType =  errors.New("Unsupported app type")
)

type GoRvpError struct {
	Type        string `json:"error_type"`
	Description string `json:"error_description"`
	StatusCode  int    `json:"status_code"`
}

func ErrorToHttpResponse(err error) *GoRvpError {
	switch errors.Cause(err) {
	case ErrTokenInvalid:
		return &GoRvpError{
			Type:        "token_invalid",
			Description: ErrTokenInvalid.Error(),
			StatusCode:  http.StatusUnauthorized,
		}
	case ErrTokenNotFound:
		return &GoRvpError{
			Type:        "token_not_found",
			Description: ErrTokenNotFound.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	case ErrTokenNotFoundCode:
		return &GoRvpError{
			Type:        "token_not_found",
			Description: ErrTokenNotFoundCode.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	case ErrTokenNotFoundRefreshToken:
		return &GoRvpError{
			Type:        "token_not_found",
			Description: ErrTokenNotFoundRefreshToken.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	case ErrPermissionDenied:
		return &GoRvpError{
			Type:        "permission_denied",
			Description: ErrPermissionDenied.Error(),
			StatusCode:  http.StatusForbidden,
		}
	case ErrRecordNotFound:
		return &GoRvpError{
			Type:        "not_found",
			Description: ErrRecordNotFound.Error(),
			StatusCode:  http.StatusNotFound,
		}
	case ErrDatabase:
		return &GoRvpError{
			Type:        "database_error",
			Description: ErrDatabase.Error(),
			StatusCode:  http.StatusInternalServerError,
		}
	case ErrClientPermission:
		return &GoRvpError{
			Type:        "client_permission",
			Description: ErrClientPermission.Error(),
			StatusCode:  http.StatusForbidden,
		}
	case ErrConnectionRevoked:
		return &GoRvpError{
			Type:        "connection_revoked",
			Description: ErrConnectionRevoked.Error(),
			StatusCode:  http.StatusForbidden,
		}
	case ErrDuplicateTrustedClientName:
		return &GoRvpError{
			Type:        "connection_revoked",
			Description: ErrDuplicateTrustedClientName.Error(),
			StatusCode:  http.StatusForbidden,
		}
	case ErrInvalidRequest:
		return &GoRvpError{
			Type:        "invalid_request",
			Description: ErrInvalidRequest.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	case ErrUnsupportedAppType:
		return &GoRvpError{
			Type:        "app_type_unsupported",
			Description: ErrUnsupportedAppType.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	default:
		return &GoRvpError{
			Type:        "unknown_error",
			Description: "unknown error",
			StatusCode:  http.StatusInternalServerError,
		}
	}
}

func WriteError(rw http.ResponseWriter, err error) {
	goRvpErr := ErrorToHttpResponse(err)

	json, err := json.MarshalIndent(goRvpErr, "", "\t")
	if err != nil {
		http.Error(rw, err.Error(), http.StatusInternalServerError)
		return
	}

	rw.Header().Set("Content-Type", "application/json")
	rw.WriteHeader(goRvpErr.StatusCode)
	rw.Write(json)
}