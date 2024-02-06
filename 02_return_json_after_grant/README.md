### 1. 构造请求获取资源服务器的授权
http://localhost:8080/oauth2/authorize?response_type=code&client_id=jgblm&scope=openapi&state=12345&redirect_uri=https://www.baidu.com
### 2. 用户登录
使用用户`user`和密码`password`登录，选中openapi，Submit Consent。
### 3. 查看返回结果
```json
{
    "code": "tOur1RbdBhujO...",
    "uri": "http://www.baidu.com"
}
```