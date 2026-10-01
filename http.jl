using HTTP

response = HTTP.get("stratum+tcp://grin.2miners.com:3030/api/accounts/{walletid}")

println(String(response.body))
