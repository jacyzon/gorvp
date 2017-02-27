# Errors

## Response Parameters

Parameter | Description |
-------------- | -------------- |
error_description | error description |
error_type | error type |
status_code | http status code |

> Example request

```shell
http -v GET http://api.example.com/client/client-not-exist
```
```http
GET /client/client-not-exist HTTP/1.1
Host: api.example.com
```

> Example response

```http
HTTP/1.1 404 Not Found
Content-Type: application/json
```
```json
{
    "error_description": "Record not found",
    "error_type": "not_found",
    "status_code": 404
}
```
