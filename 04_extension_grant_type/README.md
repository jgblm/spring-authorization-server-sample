### 请求
```shell
curl --location 'http://localhost:8080/oauth2/token' \
--header 'Authorization: Basic amdibG06MTIzNDU2' \
--header 'Cookie: JSESSIONID=20DDCF93C051C32900CE4B482D8D3E91' \
--form 'username="user"' \
--form 'password="password"' \
--form 'grant_type="password"'
```
### 响应
```json
{
    "access_token": "eyJraWQiOiJkODcwYzA0MC1lYWQ2LTQ0YmEtYWJkNy0wNDgzNThjN2ZkZjciLCJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJqZ2JsbSIsImF1ZCI6ImpnYmxtIiwibmJmIjoxNzA5MjgwMDgwLCJpc3MiOiJodHRwOi8vbG9jYWxob3N0OjgwODAiLCJleHAiOjE3MDkyODAzODAsImlhdCI6MTcwOTI4MDA4MH0.jr_GzrmECQ2uo74Kufkn0ScP81GwKUZc2C0ihVld-S8s5Rxk-mxkNYtSPjSKvqjux1byARyxjv7YkUmnN1aQP8LwkMusQSoX_1O9mjet9DQPWsrtZYvSyKTPuF9P8W3Pe6KlEIUxJo_nIPF6FRpxl_u9LmGGNoApOlTkErpY59RBB9E1Yz9u7i5oZdrK5FJlqEGFYz4ddEpR_rUpz2JeBl0BnTJw3-gbuE-wuykdQMRN0avpjZGbGjF8Ua2pasNS1CVDJAqO_tnW1qYp5ubemsz6XlYWaBul-_4OrYVsQ1d0qxjgBzofJXJGbCEXIZKaCGx99SgJ7RjE62opZ4hinQ",
    "token_type": "Bearer",
    "expires_in": 299
}
```
### access_token解析
HEADER:ALGORITHM & TOKEN TYPE
```json
{
  "kid": "d870c040-ead6-44ba-abd7-048358c7fdf7",
  "alg": "RS256"
}
```
PAYLOAD:DATA
```json
{
  "sub": "jgblm",
  "aud": "jgblm",
  "nbf": 1709280080,
  "iss": "http://localhost:8080",
  "exp": 1709280380,
  "iat": 1709280080
}
```