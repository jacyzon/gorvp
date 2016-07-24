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
			StatusCode:  http.StatusBadRequest,
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
			StatusCode:  http.StatusBadRequest,
		}
	default:
		return &GoRvpError{
			Name:        "unknown_error",
			Description: ErrTokenInvalid.Error(),
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