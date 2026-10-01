using HTTP

response = HTTP.get("https://grin.2miners.com/api/accounts/{walletid}")

println(String(response.body))
