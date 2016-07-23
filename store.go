package gorvp

import (
	"github.com/jinzhu/gorm"
	"github.com/ory-am/fosite"
	"encoding/json"
	"golang.org/x/net/context"
	"golang.org/x/crypto/bcrypt"
	"github.com/pilu/xrequestid"
	"github.com/pborman/uuid"
	"github.com/go-errors/errors"
)

type Store struct {
	DB *gorm.DB
	OC *OwnerClient
}

func (db *Store) Migrate() {
	db.DB.AutoMigrate(&GoRvpClient{})
	db.DB.AutoMigrate(&AuthorizeCode{})
	db.DB.AutoMigrate(&Token{})
	db.DB.AutoMigrate(&ScopeInfo{})
	db.DB.AutoMigrate(&ClientRevocation{})
	db.DB.AutoMigrate(&Connection{})
}

// store
func (db *Store) GetClient(id string) (fosite.Client, error) {
	client := &GoRvpClient{}
	err := db.DB.Where(&GoRvpClient{
		ID: id,
	}).First(&client).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	return client, nil
}

func (db *Store) CreateAuthorizeCodeSession(_ context.Context, code string, req fosite.Requester) error {
	dataJSON, _ := json.Marshal(req)
	err := db.DB.Create(&AuthorizeCode{
		Code: code,
		DataJSON: string(dataJSON),
	}).Error
	if err != nil {
		return fosite.ErrServerError
	}
	return nil
}

func (db *Store) GetAuthorizeCodeSession(_ context.Context, code string, _ interface{}) (fosite.Requester, error) {
	var dataJSON string
	err := db.DB.Where(&AuthorizeCode{Code: code }).First(dataJSON).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	req := &fosite.Request{}
	json.Unmarshal([]byte(dataJSON), &req)
	return req, nil
}

func (db *Store) DeleteAuthorizeCodeSession(_ context.Context, code string) error {
	authorizeCode := AuthorizeCode{Code:code}
	err := db.DB.Delete(&authorizeCode).Error
	if err != nil {
		return fosite.ErrNotFound
	}
	return nil
}

func (db *Store) CreateTokenSession(_ context.Context, signature string, req fosite.Requester, refreshToken bool) error {
	dataJSON, _ := json.Marshal(req)
	session := req.GetSession().(*Session)
	err := db.DB.Create(&Token{
		ID: session.JWTClaims.JTI,
		Signature: signature,
		DataJSON: string(dataJSON),
		ClientID: req.GetClient().GetID(),
		UserID: req.GetRequestForm().Get("username"), // TODO or token subject
		RefreshToken: refreshToken,
	}).Error
	if err != nil {
		return fosite.ErrServerError
	}
	return nil
}

func (db *Store) GetTokenSession(_ context.Context, signature string, _ interface{}) (fosite.Requester, error) {
	var dataJSON string
	err := db.DB.Where(&Token{Signature: signature}).First(dataJSON).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	req := &fosite.Request{}
	json.Unmarshal([]byte(dataJSON), &req)
	return req, nil
}

func (db *Store) DeleteTokenSession(_ context.Context, signature string) error {
	token := Token{Signature: signature}
	err := db.DB.Delete(&token).Error
	if err != nil {
		return fosite.ErrNotFound
	}
	return nil
}

func (db *Store) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return db.CreateTokenSession(ctx, signature, req, false)
}

func (db *Store) GetAccessTokenSession(ctx context.Context, signature string, s interface{}) (fosite.Requester, error) {
	return db.GetTokenSession(ctx, signature, s)
}

func (db *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return db.DeleteTokenSession(ctx, signature)
}

func (db *Store) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return db.CreateTokenSession(ctx, signature, req, true)
}

func (db *Store) GetRefreshTokenSession(ctx context.Context, signature string, s interface{}) (fosite.Requester, error) {
	return db.GetTokenSession(ctx, signature, s)
}

func (db *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return db.DeleteTokenSession(ctx, signature)
}

func (db *Store) CreateImplicitAccessTokenSession(ctx context.Context, code string, req fosite.Requester) error {
	return db.CreateTokenSession(ctx, code, req, false)
}

func (db *Store) Authenticate(ctx context.Context, name string, secret string) error {
	return db.OC.Authenticate(ctx, name, secret)
}

func (db *Store) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := db.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return err
	} else if err := db.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := db.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return nil
}

func (db *Store) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := db.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := db.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := db.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return nil
}

func (db *Store) CreateTrustedClient(clientName string) (id string, secret string, err error) {
	// create one if not exist, or override the first created one
	client := &GoRvpClient{}
	err = db.DB.Where(&GoRvpClient{
		AppType: AppTypeOwner,
		Trusted: true,
	}).Order("created_at").First(&client).Error

	if err == nil || err == gorm.ErrRecordNotFound {
		// generate client secret
		h := xrequestid.New(16)
		secret, _ = h.Generate(h.Size)
		encryptedSecret, _ := bcrypt.GenerateFromPassword([]byte(secret), 10)
		secretString := string(encryptedSecret)

		client.AppType = AppTypeOwner
		client.Trusted = true
		client.Secret = secretString
		client.Name = clientName

		if err == gorm.ErrRecordNotFound {
			client.ID = uuid.New()
			db.DB.Create(&client)
		} else if err == nil {
			db.DB.Model(&client).Update(&client)
		}

		return client.ID, secret, nil
	}

	return "", "", err
}

func (db *Store) CreateScopeInfo(config *Config) {
	scopes := make(map[string]bool)
	for _, backend := range config.Backend {
		for _, backendConfig := range backend {
			for _, scope := range backendConfig.Scopes {
				scopes[scope] = true
			}
		}
	}

	for scopeName, _ := range scopes {
		// TODO gorm not yet supports batch insert
		// https://github.com/jinzhu/gorm/issues/255
		scopeInfo := &ScopeInfo{
			Name: scopeName,
			DisplayName: scopeName,
			Description: "",
		}
		db.DB.FirstOrCreate(scopeInfo)
	}
}

func (db *Store) UpdateConnection(client Client, userID string, scopes []string) (error) {
	connection := Connection{
		UserID: userID,
		ClientID: client.GetID(),
	}

	err := db.DB.Where(connection).First(&connection).Error
	// connection found
	if err == nil {
		db.DB.Model(&connection).Update(Connection{
			ScopeString: connection.MergeScope(scopes),
		})
	} else if err == gorm.ErrRecordNotFound {
		db.DB.Create(Connection{
			ID: uuid.New(),
			UserID: userID,
			ClientID: client.GetID(),
			ScopeString: connection.MergeScope(scopes),
		})
	} else {
		return errors.New("database error")
	}
	return nil
}