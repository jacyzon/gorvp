---
title: API Reference

language_tabs:
  - http
  - shell

includes:
  - errors

search: true
---

# Introduction

```shell
# ==============================
#  架構圖
# ==============================
#      |
# |-----------------|
# |     Nginx       |
# | SSL Termination |
# |_________________|
#      |
#      |
# |---------|
# |   NOP   |     |----------|
# |         |-----|  MySQL   |
# |_________|     |__________|
#      |
#      ----------------
#      |              |
# |---------|     |---------|
# |  Micro  |     |  Micro  |
# | Service |     | Service |  ...
# |_________|     |_________|
# ==============================
```
```http
```

GoRvp 作為 OAuth2 認證伺服器，以及反向代理伺服器的功能，連線經過 GoRvp，若認證通過才會被導向至後端的 API 伺服器。

# Identity provider

由於 GoRvp 本身不管理帳號資料，在帳號與密碼的驗證需要透過 identity server 提供，
因此在設定檔有 identity_endpoint 的欄位可以設定 identity server 的 URL。

GoRvp 與 identity server 使用 JWT + JWE 交換使用者資訊。


# User Login

### HTTP Request

一般使用者

`POST http://api.example.com/authorize`

管理者

`POST http://api.example.com/admin/authorize`

### Parameters (JSON)

Parameter | Description |
-------------- | -------------- |
username | 帳號 |
password | 密碼 |

### Response Parameters

Parameter | Description |
-------------- | -------------- |
access_token | access token |
expiry | expiry date |
token_type | token type |

> Example request

```shell
http -v --form POST https://api.example.com/auth \
password="foobar" \
username="peter
```

```http
POST /auth HTTP/1.1
Content-Type: application/x-www-form-urlencoded; charset=utf-8
Host: api.example.com

password=foobar&username=peter
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
    "access_token": "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI3ZDZhYTcxMy03ZDc3LTQzN2EtYTA5Ny0zNTUyZDVlZWIwMzEiLCJjbmkiOiJkOTJjNWM1OS02ZjZhLTQyNWQtODY3Ny1mMDUzNjk0YzUwMGIiLCJleHAiOjE0NzY2Mzc3NDksImlhdCI6MTQ3MTQ1Mzc0OSwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiZmZjY2QyNzktYTg4Zi00ODdhLTk4ZjQtZWI1NTg2ZDMxMGQwIiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.YojIVY_P8yijcVQjpw1J50JnujFkupFB1tXx19IUhaUtPt5-yH2idGFfE27RDJMAFRHcvm0ydqfIS1ueLqE9_ieroR8IGpi9SHqxjGPI4Zo0vUx_jFFTPhdYQuCWIfNxNcBrZNqpTmkYWj4SW8EsB1qhiORAryKGKlGvEUsS-aq6VjxSRVFDUhUwNU4ZXi2C",
    "expiry": "2016-10-17T01:09:09.9836053+08:00",
    "token_type": "bearer"
}
```

# Admin API

<aside class="notice">
需要 admin 權限， 透過 admin user login 取得 token
</aside>

App type | OAuth flow |
-------------- | -------------- |
android | Implicit flow |
web_app (frontend) | Implicit flow |
web_baclend (backend) | Explicit flow |

## Create an Android Client

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`POST https://api.example.com/admin/client`

### Parameters (JSON)

Parameter | Description |
-------------- | -------------- |
app_type | 固定為 android |
key_hash | 簽署此 app 的 sha1 hash |
name | 名稱 |
package_name | package name |
scope | 授予的權限 |

### Response Parameters

回傳的 secret 可以忽略，在 Android 目前沒有用到。

Parameter | Description |
-------------- | -------------- |
id | client id |
secret | client secret |

> Example request

```shell
http -v POST https://api.example.com/admin/client \
app_type=android \
key_hash=4b9312cb6558ea60d8d97cdc735746c85172dc3c \
name=example \
package_name=com.example.third_party_app \
scope:='[ { "name": "grade", "required": true }, { "name": "class_schedule", "required": true }, { "name": "event", "required": true }, { "name": "offline", "required": true } ]' \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u"
```

```http
POST /admin/client HTTP/1.1
Content-Type: application/json
Host: api.example.com

{
    "app_type": "android",
    "key_hash": "4b9312cb6558ea60d8d97cdc735746c85172dc3c",
    "name": "third-party",
    "package_name": "com.example.third_party_app",
    "scope": [
        {
            "name": "grade",
            "required": true
        },
        {
            "name": "class_schedule",
            "required": true
        },
        {
            "name": "event",
            "required": true
        },
        {
            "name": "offline",
            "required": true
        }
    ]
}
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
    "id": "067748c1-9cc4-47d5-b337-0f452f3801f3",
    "secret": "0c931a6eecc26f13eba386cd92dae809"
}

```

## Create a non-confidential client

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`POST https://api.example.com/admin/client`

### Parameters (JSON)

Parameter | Description |
-------------- | -------------- |
app_type | 固定為 web_app |
redirect_uri | 重導向的 URI |
name | 名稱 |
scope | 授予的權限 |

### Response Parameters

回傳的 secret 可以忽略，在 Android 目前沒有用到。

Parameter | Description |
-------------- | -------------- |
id | client id |
secret | client secret |

> Example request

```shell
http -v POST https://api.example.com/admin/client \
app_type=web_app \
redirect_uri="http://www.example.com/callback" \
name=example \
scope:='[ { "name": "grade", "required": true }, { "name": "class_schedule", "required": true }, { "name": "event", "required": true }, { "name": "offline", "required": true } ]' \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u"
```

```http

POST /admin/client HTTP/1.1
Content-Type: application/json
Host: api.example.com

{
    "app_type": "web_app",
    "name": "example",
    "redirect_URI": "http://www.example.com/callback",
    "scope": [
        {
            "name": "grade",
            "required": true
        },
        {
            "name": "class_schedule",
            "required": true
        },
        {
            "name": "event",
            "required": true
        },
        {
            "name": "offline",
            "required": true
        }
    ]
}
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
    "id": "ff3c35b8-a207-4a78-8e8e-2162dbadfc47",
    "secret": "db3d216b2a2cb599249f5d3403d4d87c"
}
```

## Create a confidential client

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`POST https://api.example.com/admin/client`

### Parameters

Parameter | Description |
-------------- | -------------- |
app_type | 固定為 web_backend |
redirect_URI | 重導向的 URI |
name | 名稱 |
scope | 授予的權限 |

### Response Parameters

回傳的 secret 可以忽略，在 Android 目前沒有用到。

Parameter | Description |
-------------- | -------------- |
id | client id |
secret | client secret |

> Example request

```shell
http -v POST https://api.example.com/admin/client \
app_type=web_backend \
redirect_URI="http://www.example.com/callback" \
name=example \
scope:='[ { "name": "grade", "required": true }, { "name": "class_schedule", "required": true }, { "name": "event", "required": true }, { "name": "offline", "required": true } ]' \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u"
```

```http

POST /admin/client HTTP/1.1
Content-Type: application/json
Host: api.example.com

{
    "app_type": "web_backend",
    "name": "example",
    "redirect_URI": "http://www.example.com/callback",
    "scope": [
        {
            "name": "grade",
            "required": true
        },
        {
            "name": "class_schedule",
            "required": true
        },
        {
            "name": "event",
            "required": true
        },
        {
            "name": "offline",
            "required": true
        }
    ]
}
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
    "id": "4231b40a-c40e-4e66-8fdf-eb351eeeb081",
    "secret": "2f5b59cba286ddb9abeb439cb59757cd"
}
```

## List clients

列出所有第三方應用程式

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`GET https://api.example.com/clients`

> Example request

```shell
http -v GET https://api.example.com/admin/clients \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u"
```
```http
GET /connections/applications HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u
Host: api.example.com
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "name": "tecccccst",
  "app_type": "web_app",
  "scopes": [
    {
      "name": "grade",
      "required": true
    },
    {
      "name": "class_schedule",
      "required": true
    },
    {
      "name": "event",
      "required": true
    }
  ],
  "trusted": false,
  "public": false,
  "redirect_uri": "http://localhost/callback",
  "start_activity": "",
  "package_name": "",
  "key_hash": ""
}
```

## Update client

修改第三方應用程式，可以部份更改 (partial)，但不允許變更 app type

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`PATCH https://api.example.com/admin/client/:id`

> Example request

```shell
http -v PATCH
redirect_uri="http://www.example.com/callback" \
name=example \
scope:='[ { "name": "grade", "required": true }, { "name": "offline", "required": true } ]' \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u"
```
```http

PATCH /admin/client/fa53c1ae-632f-4631-a2c7-3f37907c0951 HTTP/1.1
Content-Type: application/json
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u
Host: api.example.com

{
    "name": "example",
    "redirect_URI": "http://www.example.com/callback",
    "scope": [
        {
            "name": "grade",
            "required": true
        },
        {
            "name": "offline",
            "required": true
        }
    ]
}
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
  "id": "fa53c1ae-632f-4631-a2c7-3f37907c0951",
  "created_at": "2016-11-21T17:23:15.063200935+08:00",
  "updated_at": "2016-11-23T00:17:48.087843308+08:00",
  "name": "example",
  "app_type": "web_app",
  "scopes": [
    {
      "name": "grade",
      "required": true
    },
    {
      "name": "offline",
      "required": true
    }
  ],
  "trusted": false,
  "public": true,
  "redirect_uri": "http://www.example.com/callback",
  "start_activity": "",
  "package_name": "",
  "key_hash": ""
}
```

## Delete client

刪除第三方應用程式

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`DELETE https://api.example.com/admin/client/:id`

### Query Parameters

Parameter | Description |
-------------- | -------------- |
id | client ID |

> Example request

```shell
http -v DELETE https://api.example.com/admin/client/a3838257-6d8b-400e-beab-45d3420c38ea \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u"
```

```http
DELETE /admin/client/a3838257-6d8b-400e-beab-45d3420c38ea HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI1MzJjNDRjZS1hMDQwLTQ5YmMtYWJmOS02MjcxYzY5YmNkYmMiLCJjbmkiOiI2NDc1MjA1Yy04MTYxLTRmNDItYTIzMC0zMjQxYmFiOTY4OGEiLCJleHAiOjEuNDg1MDcxMDg0ZSswOSwiaWF0IjoxLjQ3OTg4NzA4NGUrMDksImlzcyI6Imh0dHBzOi8vYXBpLmdvcnZwLmRldiIsImp0aSI6ImViYjUyYTUzLTliYzQtNDg5Ni05ZTRmLTU3MTlhNjA5ZjlmZSIsIm5iZiI6LTYuMjEzNTU5NjhlKzEwLCJzY28iOiJhZG1pbiIsInN1YiI6InBldGVyIn0.wNFbF95ruZHKTZIw7RjFgTMyjMtyXTX7oKU_hl2OdrVmvyew5KgIfofzNlxQBKPph0b9i7IEDVtYDkQHBi_Ny9UrodMpL0WQ0Y-Nj9r7TQm_zl8UGwXFeHSubf2dYNthAgLMPnEEoy_byv5DLfw73I-lCf8aVjkkWnYyHGHGUfeFKvSsgEKOJRqHQl67ti5u
Host: api.example.com
````

> Example response

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
```

# Third party client

## Client detail

### HTTP Request

`GET https://api.example.com/client/:id`

### Query Parameters

Parameter | Description |
-------------- | -------------- |
id | client id |

### Response Parameters

回傳的 secret 可以忽略，在 Android 目前沒有用到。

Parameter | Description |
-------------- | -------------- |
id | client id |
logo_url | client 的 LOGO URL |
name | client 名稱 |
scopes | client 允許要求的權限 |

> Example request

```shell
http -v GET http://api.example.com/client/ff3c35b8-a207-4a78-8e8e-2162dbadfc47
```

```http
GET /client/ff3c35b8-a207-4a78-8e8e-2162dbadfc47 HTTP/1.1
Host: api.example.com
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
{
    "id": "ff3c35b8-a207-4a78-8e8e-2162dbadfc47",
    "logo_url": "",
    "name": "example",
    "scopes": [
        {
            "description": "",
            "display_name": "class_schedule",
            "name": "class_schedule",
            "required": true
        },
        {
            "description": "",
            "display_name": "event",
            "name": "event",
            "required": true
        },
        {
            "description": "",
            "display_name": "grade",
            "name": "grade",
            "required": true
        },
        {
            "description": "",
            "display_name": "offline",
            "name": "offline",
            "required": true
        }
    ]
}
```

## Grant

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`POST https://api.example.com/oauth/authorize`


### Parameters (form-urlencoded)

Parameter | Description |
-------------- | -------------- |
client_id | 帳號 |
response_type | 這裡使用 implicit flow， 固定為 token |
scope | 要授予第三方的權限，用空格分開 |
package_name | Android APP 的 package name |
key_hash | 簽署 APP 用的 sha1 hash |
state | 隨機產生的狀態，回傳時要比對一不一樣 |

### Response Parameters

回傳的 secret 可以忽略，在 Android 目前沒有用到。

Parameter | Description |
-------------- | -------------- |
id | client id |
access_token | access token |
refresh_token | 若有 offline 權限會回傳此欄位作為更新 access_token 用 |
scope | 獲得的權限 |
state | 在 query 帶入的 state |
token_type | 固定為 bearer |

> Example request

```shell
http -v --form POST https://api.example.com/oauth \
client_id=="6b1bdd86-563d-450e-b1ca-fdd7f4c29879" \
response_type=="token" \
scope=="gorvp foo offline" \
package_name=="io.github.gorvp.third_party_app" \
key_hash=="4b9312cb6558ea60d8d97cdc735746c85172dc3c" \
state==some-random-state-foobar \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJiNGZlY2YwYS02OGI2LTRlN2ItODQyOC05YTNjOTI3Y2JhZTEiLCJjbmkiOiI0ZGU5OWM2NC03OTM3LTRlN2QtYTMzNC0wZWM4MTdlZDEwOWIiLCJleHAiOjE0NzEyMDMyOTcsImlhdCI6MTQ3MTE5OTY5NywiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiMTY2OWU4YjQtZWJhYi00MmI3LWEyNTctM2NjNTg5NTM4OThkIiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.tDM385RkwYrJNF7D27YbHKufwxYMLC9GjIKMr3JkwBCeuzK_1jIE-Dmex-M3MX9T0lsBHwbWo06BwRa3mT0htJUK-8jO7bGVfzUX1XzVf_Wr7xDrIAaFsZOwaDowoKNUYbES8cB5Dx2yUJ1tajH8RcT-IZUTsmITdFH99rFmLp-4mFwU4qv8h_LJ12MM-E5B"
```

```http
GET /oauth?client_id=93d74867-9e37-47c3-964a-cc23b5497711&response_type=token&scope=grade+class_schedule+event+offline&package_name=com.example.third_party_app&key_hash=4b9312cb6558ea60d8d97cdc735746c85172dc3c&state=some-random-state HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI3ZDZhYTcxMy03ZDc3LTQzN2EtYTA5Ny0zNTUyZDVlZWIwMzEiLCJjbmkiOiJkOTJjNWM1OS02ZjZhLTQyNWQtODY3Ny1mMDUzNjk0YzUwMGIiLCJleHAiOjE0NzY2MzcxMDMsImlhdCI6MTQ3MTQ1MzEwMywiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiNjQwMmNkNDMtMGIyZC00Y2U5LWFkZDEtOGUyZmZlODY4ODY1IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.nkmdqiR4zpyNPZMAlQ6p2ESZVjRbQMZIKeTyIdx_jzDITwhwopjyXgwV72QSuG_UuKTN3mv1MVJFQZ8TJy7KXZgQ0qi_lUmXqoiShTUdz-6dvQyWs_yRddZQ3ZBe7eBD8DtZq0w48SNZJrXLrAtvD-sHA65uDs42C9gyNXKpPkxHAEMrTJBDthE48OzSEbTZ
Host: api.example.com
```

> Example response

```http
HTTP/1.1 302 Found
Location: http://localhost#access_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI5M2Q3NDg2Ny05ZTM3LTQ3YzMtOTY0YS1jYzIzYjU0OTc3MTEiLCJjbmkiOiIxZmYxNGQ5My00OGU3LTQyMGQtOTI1Yy0xMjhmNWE4ODM0MjQiLCJleHAiOjE0NzY2NDA1NDYsImlhdCI6MTQ3MTQ1NjU0NiwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiOTIzNTI0NTItZTcxMy00OWQyLTgzYmMtNzdkYjI4YWJlNTI2IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6ImdyYWRlIGNsYXNzX3NjaGVkdWxlIGV2ZW50IG9mZmxpbmUiLCJzdWIiOiJwZXRlciJ9.YpoWC01cXbZg5jxOS_KIAP8LJoVlLQXb-Op07yrvdfEMxH9XjxhGEL58H4h3a2_1VizpdReogtG1Z9lyIv5QirqtAEKq8qtmQ33xaskKpSXfVNxmudEw_hJkQgeTL0s8vbzP5_W3XlyKS1hzkpGrO87ZkdJjjG1x_Xg7xuNplm6LlEN9uHyzKbUUfaocMW72&expires_in=5184000&refresh_token=eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI5M2Q3NDg2Ny05ZTM3LTQ3YzMtOTY0YS1jYzIzYjU0OTc3MTEiLCJjbmkiOiIxZmYxNGQ5My00OGU3LTQyMGQtOTI1Yy0xMjhmNWE4ODM0MjQiLCJleHAiOjE0ODcwMDg1NDYsImlhdCI6MTQ3MTQ1NjU0NiwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiMmZmNTVjMjctNTRhMC00OWYwLTk3NGQtZTc2ZjE0ZjNjNzc2IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6ImdyYWRlIGNsYXNzX3NjaGVkdWxlIGV2ZW50IG9mZmxpbmUiLCJzdWIiOiJwZXRlciJ9.O3afmEipZA5WZyBb3hn-Osn4h6QJrjZk5njjUjOKXiEdRGtlFwe9QyQrOJNbHC2qkteP9fRN7PaiyZX_j9fSjDphicMO8HaoKwGWplLyi2Eg2SQ_nbStBLYWjOeeMU-GVgAvqXMhh70OcUh63v4NjYk2J3KQbSqJSK_C42_GAYTFDd_jelK9SeDmsBNFYXbR&scope=grade%252Bclass_schedule%252Bevent%252Boffline&start_activity=&state=some-random-state&token_type=bearer
```

# Token Management

## Token Revocation

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`POST https://api.example.com/token/:signature`

### Query Parameters

Parameter | Description |
-------------- | -------------- |
signature | JWT 的 signature |

> Example request

```shell
http -v DELETE https://api.example.com/token/EsDyr7drNnUsaV4TA7I3BvMpuR0WLypOsESCYN1WgfIQQNxq1ij4P1BBYRWgdjJBidY5WPtMmg9FZanmYN66swEkVtl3od-7OXnUtSElyCqDdizm78k_vdraLnlqnd2rEJoZYvWSNLQxHmCkYyS9Ldvy7hAr7LHaJLIomq8Cz1F3nXE7QmFM4aPcEzBZJI7c \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI4YTdhMGQxNS1iZjZiLTRjMWEtODhjYS0yOGUzNGYyZWYyMjQiLCJjbmkiOiJhMzgzODI1Ny02ZDhiLTQwMGUtYmVhYi00NWQzNDIwYzM4ZWEiLCJleHAiOjE0NzY3MDg4MDAsImlhdCI6MTQ3MTUyNDgwMCwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiNDhjMmQxMjAtZTJkZS00MzQ2LWFhMWMtM2VkMzYzMzIyMTM5IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.e7L-rI8b3Zja-eZQdb8IubcHQUKniadloozX-km4bgSm9WrPAyjMkAJ6frQ1JXw1ACmHAEgrCm4zzyN_I3o7mNYE6iUZ8alWOU6Z7a6NUPIyWj6-hCjSgq0axNx-gqmJ-GAxztOEGNLDe1eQNgAwyEDBc2CHL6OJ4oWoi3JYu7B1XiQnRpZ7hXV0d_HkMru7"
```

```http
DELETE /token/EsDyr7drNnUsaV4TA7I3BvMpuR0WLypOsESCYN1WgfIQQNxq1ij4P1BBYRWgdjJBidY5WPtMmg9FZanmYN66swEkVtl3od-7OXnUtSElyCqDdizm78k_vdraLnlqnd2rEJoZYvWSNLQxHmCkYyS9Ldvy7hAr7LHaJLIomq8Cz1F3nXE7QmFM4aPcEzBZJI7c HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI4YTdhMGQxNS1iZjZiLTRjMWEtODhjYS0yOGUzNGYyZWYyMjQiLCJjbmkiOiJhMzgzODI1Ny02ZDhiLTQwMGUtYmVhYi00NWQzNDIwYzM4ZWEiLCJleHAiOjE0NzY3MDg4MDAsImlhdCI6MTQ3MTUyNDgwMCwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiNDhjMmQxMjAtZTJkZS00MzQ2LWFhMWMtM2VkMzYzMzIyMTM5IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.e7L-rI8b3Zja-eZQdb8IubcHQUKniadloozX-km4bgSm9WrPAyjMkAJ6frQ1JXw1ACmHAEgrCm4zzyN_I3o7mNYE6iUZ8alWOU6Z7a6NUPIyWj6-hCjSgq0axNx-gqmJ-GAxztOEGNLDe1eQNgAwyEDBc2CHL6OJ4oWoi3JYu7B1XiQnRpZ7hXV0d_HkMru7
Host: api.example.com
```

> Example response

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
```
## List applications

列出所有授予權限的第三方應用程式

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`GET https://api.example.com/connections/applications`

> Example request

```shell
http -v GET https://api.example.com/connections/applications \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI4YTdhMGQxNS1iZjZiLTRjMWEtODhjYS0yOGUzNGYyZWYyMjQiLCJjbmkiOiJhMzgzODI1Ny02ZDhiLTQwMGUtYmVhYi00NWQzNDIwYzM4ZWEiLCJleHAiOjE0NzY3MDg4MDAsImlhdCI6MTQ3MTUyNDgwMCwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiNDhjMmQxMjAtZTJkZS00MzQ2LWFhMWMtM2VkMzYzMzIyMTM5IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.e7L-rI8b3Zja-eZQdb8IubcHQUKniadloozX-km4bgSm9WrPAyjMkAJ6frQ1JXw1ACmHAEgrCm4zzyN_I3o7mNYE6iUZ8alWOU6Z7a6NUPIyWj6-hCjSgq0axNx-gqmJ-GAxztOEGNLDe1eQNgAwyEDBc2CHL6OJ4oWoi3JYu7B1XiQnRpZ7hXV0d_HkMru7"
```
```http
GET /connections/applications HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI4YTdhMGQxNS1iZjZiLTRjMWEtODhjYS0yOGUzNGYyZWYyMjQiLCJjbmkiOiJhMzgzODI1Ny02ZDhiLTQwMGUtYmVhYi00NWQzNDIwYzM4ZWEiLCJleHAiOjE0NzY3MDg4MDAsImlhdCI6MTQ3MTUyNDgwMCwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiNDhjMmQxMjAtZTJkZS00MzQ2LWFhMWMtM2VkMzYzMzIyMTM5IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.e7L-rI8b3Zja-eZQdb8IubcHQUKniadloozX-km4bgSm9WrPAyjMkAJ6frQ1JXw1ACmHAEgrCm4zzyN_I3o7mNYE6iUZ8alWOU6Z7a6NUPIyWj6-hCjSgq0axNx-gqmJ-GAxztOEGNLDe1eQNgAwyEDBc2CHL6OJ4oWoi3JYu7B1XiQnRpZ7hXV0d_HkMru7
Host: api.example.com
````

> Example response

```http
HTTP/1.1 200 OK
Content-Type: application/json
```
```json
[
    {
        "client": {
            "id": "8a7a0d15-bf6b-4c1a-88ca-28e34f2ef224",
            "logo_url": "",
            "name": "example_api",
            "scopes": []
        },
        "id": "a3838257-6d8b-400e-beab-45d3420c38ea"
    }
]
```

## Revoke application

撤銷應用程式的存取

<aside class="notice">
使用 Bearer Token 驗證
</aside>

### HTTP Request

`DELETE https://api.example.com/connections/:id`

### Query Parameters

Parameter | Description |
-------------- | -------------- |
id | connection ID |

> Example request

```shell
http -v DELETE https://api.example.com/connections/a3838257-6d8b-400e-beab-45d3420c38ea \
Authorization:"Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI4YTdhMGQxNS1iZjZiLTRjMWEtODhjYS0yOGUzNGYyZWYyMjQiLCJjbmkiOiJhMzgzODI1Ny02ZDhiLTQwMGUtYmVhYi00NWQzNDIwYzM4ZWEiLCJleHAiOjE0NzY3MDg4MDAsImlhdCI6MTQ3MTUyNDgwMCwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiNDhjMmQxMjAtZTJkZS00MzQ2LWFhMWMtM2VkMzYzMzIyMTM5IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.e7L-rI8b3Zja-eZQdb8IubcHQUKniadloozX-km4bgSm9WrPAyjMkAJ6frQ1JXw1ACmHAEgrCm4zzyN_I3o7mNYE6iUZ8alWOU6Z7a6NUPIyWj6-hCjSgq0axNx-gqmJ-GAxztOEGNLDe1eQNgAwyEDBc2CHL6OJ4oWoi3JYu7B1XiQnRpZ7hXV0d_HkMru7"
```
```http
DELETE /connections/a3838257-6d8b-400e-beab-45d3420c38ea HTTP/1.1
Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiI4YTdhMGQxNS1iZjZiLTRjMWEtODhjYS0yOGUzNGYyZWYyMjQiLCJjbmkiOiJhMzgzODI1Ny02ZDhiLTQwMGUtYmVhYi00NWQzNDIwYzM4ZWEiLCJleHAiOjE0NzY3MDg4MDAsImlhdCI6MTQ3MTUyNDgwMCwiaXNzIjoiaHR0cHM6Ly9hcGkuZ29ydnAuZGV2IiwianRpIjoiNDhjMmQxMjAtZTJkZS00MzQ2LWFhMWMtM2VkMzYzMzIyMTM5IiwibmJmIjotNjIxMzU1OTY4MDAsInNjbyI6InBhc3N3b3JkIiwic3ViIjoicGV0ZXIifQ.e7L-rI8b3Zja-eZQdb8IubcHQUKniadloozX-km4bgSm9WrPAyjMkAJ6frQ1JXw1ACmHAEgrCm4zzyN_I3o7mNYE6iUZ8alWOU6Z7a6NUPIyWj6-hCjSgq0axNx-gqmJ-GAxztOEGNLDe1eQNgAwyEDBc2CHL6OJ4oWoi3JYu7B1XiQnRpZ7hXV0d_HkMru7
Host: api.example.com
````

> Example response

```http
HTTP/1.1 200 OK
Content-Type: text/plain; charset=utf-8
```
