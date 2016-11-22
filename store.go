package gorvp

import (
	"github.com/jinzhu/gorm"
	"github.com/ory-am/fosite"
	"encoding/json"
	"golang.org/x/net/context"
	"golang.org/x/crypto/bcrypt"
	"github.com/pilu/xrequestid"
	"github.com/pborman/uuid"
	"fmt"
)

type Store struct {
	DB *gorm.DB
	OC *OwnerClient
}

func (store *Store) Migrate() {
	store.DB.AutoMigrate(&GoRvpClient{})
	store.DB.AutoMigrate(&AuthorizationCode{})
	store.DB.AutoMigrate(&Token{})
	store.DB.AutoMigrate(&ScopeInfo{})
	store.DB.AutoMigrate(&ClientRevocation{})
	store.DB.AutoMigrate(&Connection{})
}

func (store *Store) GetClient(id string) (fosite.Client, error) {
	return store.GetRvpClient(id)
}

func (store *Store) GetRvpClient(id string) (*GoRvpClient, error) {
	client := &GoRvpClient{ID: id}
	err := store.DB.Find(client).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	client.UnmarshalScopesJSON()
	return client, nil
}

func (store *Store) GetRvpClients() ([]GoRvpClient, error) {
	clients := []GoRvpClient{}
	err := store.DB.Find(&clients).Error
	if err != nil {
		return nil, fosite.ErrNotFound
	}

	for i, _ := range clients {
		clients[i].UnmarshalScopesJSON()
	}
	return clients, nil
}

func (store *Store) CreateAuthorizeCodeSession(_ context.Context, signature string, req fosite.Requester) error {
	dataJSON, _ := json.Marshal(req)
	session := req.GetSession()
	err := store.DB.Create(&AuthorizationCode{
		Signature: signature,
		DataJSON: string(dataJSON),
		ClientID: req.GetClient().GetID(),
		UserID: session.GetUsername(),
	}).Error
	if err != nil {
		return fosite.ErrServerError
	}
	return nil
}

func (store *Store) GetAuthorizeCode(signature string) (*AuthorizationCode, error) {
	code := &AuthorizationCode{Signature: signature}
	err := store.DB.Find(code).Error
	if err != nil {
		return nil, err
	}
	return code, nil
}

func (store *Store) GetAuthorizeCodeSession(_ context.Context, signature string, _ fosite.Session) (fosite.Requester, error) {
	token, err := store.GetAuthorizeCode(signature)
	if err != nil {
		return nil, fosite.ErrNotFound
	}
	req := &fosite.Request{
		Client: &GoRvpClient{},
		Session: &Session{},
	}
	json.Unmarshal([]byte(token.DataJSON), req)
	return req, nil
}

func (store *Store) DeleteAuthorizeCodeSession(_ context.Context, signature string) error {
	authorizeCode := &AuthorizationCode{Signature: signature}
	err := store.DB.Delete(authorizeCode).Error
	if err != nil {
		return fosite.ErrNotFound
	}
	return nil
}

func (store *Store) CreateTokenSession(_ context.Context, signature string, req fosite.Requester, refreshToken bool) (err error) {
	dataJSON, _ := json.Marshal(req)
	session := req.GetSession()

	token := &Token{
		Signature: signature,
		DataJSON: string(dataJSON),
		ClientID: req.GetClient().GetID(),
		UserID: session.GetUsername(),
		RefreshToken: refreshToken,
	}
	err = store.DB.Create(token).Error

	if err != nil {
		return fosite.ErrServerError
	}
	return nil
}

func (store *Store) GetToken(signature string) (*Token, error) {
	token := &Token{Signature: signature}
	err := store.DB.Find(token).Error
	if err != nil {
		return nil, err
	}
	return token, nil
}

func (store *Store) GetTokenSession(_ context.Context, signature string, _ fosite.Session, isRefresh bool) (fosite.Requester, error) {
	token, err := store.GetToken(signature)
	// check token type
	if (err != nil) || (token.RefreshToken != isRefresh) {
		return nil, fosite.ErrNotFound
	}
	req := &fosite.Request{
		Client: &GoRvpClient{},
		Session: &Session{},
	}
	json.Unmarshal([]byte(token.DataJSON), &req)
	return req, nil
}

func (store *Store) DeleteTokenSession(_ context.Context, signature string) error {
	token := &Token{Signature: signature}
	err := store.DB.Delete(token).Error
	if err != nil {
		return fosite.ErrNotFound
	}
	return nil
}

func (store *Store) CreateAccessTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	return store.CreateTokenSession(ctx, signature, req, false)
}

func (store *Store) GetAccessTokenSession(ctx context.Context, signature string, s fosite.Session) (fosite.Requester, error) {
	return store.GetTokenSession(ctx, signature, s, false)
}

func (store *Store) DeleteAccessTokenSession(ctx context.Context, signature string) error {
	return store.DeleteTokenSession(ctx, signature)
}

func (store *Store) CreateRefreshTokenSession(ctx context.Context, signature string, req fosite.Requester) error {
	if signature == "" {
		// no refresh token was generated, the scope of this session is not an 'offline' type
		return nil
	}
	return store.CreateTokenSession(ctx, signature, req, true)
}

func (store *Store) GetRefreshTokenSession(ctx context.Context, signature string, s fosite.Session) (fosite.Requester, error) {
	return store.GetTokenSession(ctx, signature, s, true)
}

func (store *Store) DeleteRefreshTokenSession(ctx context.Context, signature string) error {
	return store.DeleteTokenSession(ctx, signature)
}

func (store *Store) CreateImplicitAccessTokenSession(ctx context.Context, code string, req fosite.Requester) error {
	return store.CreateTokenSession(ctx, code, req, false)
}

func (store *Store) Authenticate(ctx context.Context, name string, secret string) error {
	return store.OC.Authenticate(ctx, name, secret)
}

func (store *Store) PersistAuthorizeCodeGrantSession(ctx context.Context, authorizeCode, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := store.DeleteAuthorizeCodeSession(ctx, authorizeCode); err != nil {
		return err
	} else if err := store.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := store.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return nil
}

func (store *Store) PersistRefreshTokenGrantSession(ctx context.Context, originalRefreshSignature, accessSignature, refreshSignature string, request fosite.Requester) error {
	if err := store.DeleteRefreshTokenSession(ctx, originalRefreshSignature); err != nil {
		return err
	} else if err := store.CreateAccessTokenSession(ctx, accessSignature, request); err != nil {
		return err
	} else if err := store.CreateRefreshTokenSession(ctx, refreshSignature, request); err != nil {
		return err
	}
	return nil
}

func (store *Store) CreateTrustedClient(trustedClient *TrustedClient) {
	// create one if not exist, or override the first created one
	client := &GoRvpClient{Name: trustedClient.Name}
	err := store.DB.Where(client).First(&client).Error

	if err == nil || err == gorm.ErrRecordNotFound {

		var secret string
		if trustedClient.Secret == "" {
			// generate client secret
			h := xrequestid.New(16)
			secret, _ = h.Generate(h.Size)
			trustedClient.Secret = secret
			encryptedSecret, _ := bcrypt.GenerateFromPassword([]byte(secret), 10)
			secretString := string(encryptedSecret)
			client.Secret = secretString
		}

		client.AppType = AppTypeOwner
		client.Trusted = true
		client.Name = trustedClient.Name
		client.Scopes = trustedClient.Scopes
		scopeJson, _ := json.Marshal(client.Scopes)
		client.ScopesJSON = string(scopeJson)

		if err == gorm.ErrRecordNotFound {
			client.ID = uuid.New()
			store.DB.Create(&client)
		} else if err == nil {
			store.DB.Model(&client).Update(&client)
		}
		trustedClient.ID = client.ID

		fmt.Printf("Trusted client id: %s, name: %s, secret: %s\n", trustedClient.ID, trustedClient.Name, secret)
	}
}

func (store *Store) CreateScopeInfo(config *Config) {
	scopes := make(map[string]bool)
	for _, backend := range config.Frontend {
		for _, frontendConfig := range backend {
			for _, scope := range frontendConfig.Scopes {
				scopes[scope] = true
			}
		}
	}
	scopes["offline"] = true

	for scopeName, _ := range scopes {
		// TODO gorm not yet supports batch insert
		// https://github.com/jinzhu/gorm/issues/255
		scopeInfo := &ScopeInfo{
			Name: scopeName,
			DisplayName: scopeName,
			Description: "",
		}
		store.DB.FirstOrCreate(scopeInfo)
	}
}

func (store *Store) GetConnectionByID(connectionID string) (*Connection, error) {
	connection := &Connection{ID: connectionID}

	err := store.DB.Find(connection).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrRecordNotFound
		}
		return nil, ErrDatabase
	}
	return connection, nil
}

func (store *Store) GetConnection(clientID string, userID string) (*Connection, error) {
	connection := &Connection{
		UserID: userID,
		ClientID: clientID,
	}

	err := store.DB.Where(connection).Find(connection).Error
	if err != nil {
		if err == gorm.ErrRecordNotFound {
			return nil, ErrRecordNotFound
		}
		return connection, ErrDatabase
	}
	return connection, nil
}

func (store *Store) UpdateConnection(clientID string, userID string, scopes []string) (*Connection, error) {
	connection := &Connection{
		UserID: userID,
		ClientID: clientID,
	}

	err := store.DB.Where(connection).Find(&connection).Error
	// connection found
	if err == nil {
		connection.ScopeString = connection.MergeScope(scopes)
		store.DB.Model(connection).Update(connection)
	} else {
		if err == gorm.ErrRecordNotFound {
			connection.ID = uuid.New()
			connection.ScopeString = connection.MergeScope(scopes)
			store.DB.Create(connection)
		} else {
			return nil, ErrDatabase
		}
	}
	return connection, nil
}

func (store *Store) ResetClientPassword(clientID string) (string, error) {
	client, err := store.GetRvpClient(clientID)
	if err != nil {
		return "", err
	}
	password, err := client.ResetPassword()
	if err != nil {
		return "", err
	}
	store.DB.Model(client).Update(client)
	return password, nil
}
