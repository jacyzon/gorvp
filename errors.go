package gorvp

import (
	"net/http"
	"github.com/pkg/errors"
	"encoding/json"
)

var (
	ErrTokenInvalid = errors.New("Token invalid")
	ErrTokenNotFound = errors.New("Authorization header format must be bearer token")
	ErrPermissionDenied = errors.New("You do not have permission on request resource")
	ErrRecordNotFound = errors.New("Record not found")
	ErrDatabase = errors.New("Database error")
	ErrClientPermission = errors.New("client has no permission on requested scopes")
)

type GoRvpError struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	StatusCode  int    `json:"statusCode"`
}

func ErrorToHttpResponse(err error) *GoRvpError {
	switch errors.Cause(err) {
	case ErrTokenInvalid:
		return &GoRvpError{
			Name:        "token_invalid",
			Description: ErrTokenInvalid.Error(),
			StatusCode:  http.StatusUnauthorized,
		}
	case ErrTokenNotFound:
		return &GoRvpError{
			Name:        "token_not_found",
			Description: ErrTokenNotFound.Error(),
			StatusCode:  http.StatusBadRequest,
		}
	case ErrPermissionDenied:
		return &GoRvpError{
			Name:        "permission_denied",
			Description: ErrPermissionDenied.Error(),
			StatusCode:  http.StatusForbidden,
		}
	case ErrRecordNotFound:
		return &GoRvpError{
			Name:        "not_found",
			Description: ErrRecordNotFound.Error(),
			StatusCode:  http.StatusNotFound,
		}
	case ErrDatabase:
		return &GoRvpError{
			Name:        "database_error",
			Description: ErrDatabase.Error(),
			StatusCode:  http.StatusInternalServerError,
		}
	case ErrClientPermission:
		return &GoRvpError{
			Name:        "client_permission",
			Description: ErrClientPermission.Error(),
			StatusCode:  http.StatusForbidden,
		}
	default:
		return &GoRvpError{
			Name:        "unknown_error",
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