local str = require "resty.string"
local http = require "resty.http"
local json = require "cjson.safe"
local json = require("cjson")
local yaml = require("lyaml")
local inspect = require("inspect")
--local jwt = require "resty.jwt"
local openssl = require("resty.openssl")
local openssl_cipher = require "resty.openssl.cipher"
local resty_sha256 = require "resty.sha256"
local openssl_kdf = require "resty.openssl.kdf"

local KongAuthzProxyHandler = {}


local function parse_cookies(header)
  local cookies = {}
  if not header then return cookies end
  for pair in header:gmatch("[^;]+") do
    local k, v = pair:match("%s*([^=]+)%s*=%s*(.*)")
    if k and v then
      cookies[k] = v
    end
  end
  return cookies
end

local function kong_get_current_context()
  local context = {}
  context['request'] = {}
  context['request']['headers'] = kong.request.get_headers()
  context['request']['query'] = {}
  for k, v in pairs(kong.request.get_query()) do
    context['request']['query'][k] = v
  end
  context['request']['cookies'] = parse_cookies(kong.request.get_header("cookie"))
  context['request']['path'] = kong.request.get_path()
  context['request']['method'] = kong.request.get_method()
  context['request']['body'] = kong.request.get_body()
  context['request']['raw_body'] = kong.request.get_raw_body()
  context['request']['time'] = kong.request.get_start_time()
  context['client'] = {}
  context['client']['ip'] = kong.client.get_ip()
  context['client']['consumer'] = kong.client.get_consumer()
  return context
end


local function get_aes_key(user_key, salt)
  local salt = salt or "some-random-salt"
  local kdf_instance = assert(openssl_kdf.new("HKDF"))

  local key = assert(kdf_instance:derive(32, { -- 32 bytes for AES-256
    digest = "sha256",
    key = user_key,
    salt = salt,
    mode = openssl_kdf.HKDEF_MODE_EXPAND_ONLY
   }))

  return key
end


local function generate_token(key, salt, alg, claims)
  claims.exp = os.time() + claims.exp
  -- TODO: for algs that support aads
  --local aad = aad or "some random authenticated data"
  local cipher = assert(openssl_cipher.new(alg))
  local to_be_encrypted = json.encode(claims)

  -- Generate a 12-byte IV:
  local openssl_rand = require("resty.openssl.rand")
  local iv = openssl_rand.bytes(16)

  -- get AES Key
  local aes_key = get_aes_key(key, salt)
  -- Encrypt the data
  local encrypted = assert(cipher:encrypt(aes_key, iv, to_be_encrypted, false, aad))

  -- Return the IV and encrypted data, encoded in Base64
  return ngx.encode_base64(iv) .. "." .. ngx.encode_base64(encrypted)
end

local function decode_token(key, salt, alg, token)
  --local aad = aad or "some random authenticated data"
  -- Split the token into Base64-encoded IV and encrypted data
  local iv_b64, encrypted_b64 = token:match("([^%.]+)%.([^%.]+)")
  local iv = ngx.decode_base64(iv_b64)
  local encrypted = ngx.decode_base64(encrypted_b64)

   -- Derive the AES key from the provided key
  local aes_key = get_aes_key(key, salt)

  -- Decrypt the data
  local cipher = assert(openssl_cipher.new(alg))
  local decrypted, err = cipher:decrypt(aes_key, iv, encrypted, false)

  if not decrypted then
    ngx.log(ngx.ERR, "Decryption error: ", err)
    return nil, "Decryption error: " .. err
   end

  return json.decode(decrypted)
end

-- Helper function to split a string
local function split_string(str, sep)
  local fields = {}
  local pattern = string.format("([^%s]+)", sep)
  str:gsub(pattern, function(c) fields[#fields + 1] = c end)
  return fields
end

local function validate_request(conf, token, context)
  token = ngx.unescape_uri(token)
  local iv_b64, encrypted_b64 = token:match("([^%.]+)%.([^%.]+)")
  if not iv_b64 or not encrypted_b64 then
    return false, "Malformed token"
  end

  local iv = ngx.decode_base64(iv_b64)
  if not iv or #iv ~= 16 then
    return false, "Invalid IV size"
  end

  local decoded_claims, err = decode_token(conf.encryption_key, conf.salt, conf.alg, token)
  if not decoded_claims then
    return false, "Invalid token: " .. (err or "unknown error")
  end

  if decoded_claims.exp and decoded_claims.exp < os.time() then
    return false, "Token expired"
  end

  local scope_value = context
  for _, part in ipairs(split_string(decoded_claims.scope, "%.")) do
    scope_value = scope_value[part]
    if not scope_value then
      return false, "Invalid scope: " .. decoded_claims.scope
    end
  end

  local operator = decoded_claims.operator
  local value = decoded_claims.value
  local is_valid = false

  if operator == "equals" then
    is_valid = (scope_value == value)
  elseif operator == "prefix" then
    is_valid = scope_value:sub(1, #value) == value
  elseif operator == "regex" then
    is_valid = scope_value:match(value) ~= nil
  else
    return false, "Invalid operator: " .. operator
  end

  return is_valid, is_valid and nil or "Authorization failed"
end

function KongAuthzProxyHandler:access(conf)
  local context = kong_get_current_context()
  if kong.request.get_path() == conf.authz_listener_path and kong.request.get_method() == "POST" then
    -- Validate Kong Consumer
    local consumer = kong.client.get_consumer()
    if conf. authz_listener_path_validate_consumer and not consumer then
       return kong.response.exit(401, { message = "Invalid consumer" })
    end

    -- Validate payload claims
    -- TODO: validate the scope vocabulary
    local body = kong.request.get_body() -- Assuming the body is JSON
    if not body or type(body.scope) ~= "string" or type(body.operator) ~= "string" or type(body.value) ~= "string" then
      return kong.response.exit(400, { message = "Invalid claims" })
    end

    -- Validate expiry
    local exp = tonumber(body.exp) or 120 -- Default to 120 seconds if not specified
    if exp < 60 then
      return kong.response.exit(400, { message = "Expiry must be at least 60 seconds" })
    end

    body['exp'] = exp

    -- Generate and return the token
    local token = generate_token(conf.encryption_key, conf.salt, conf.alg, body)
    -- test: decode the token
    --local decoded = decode_token(conf.encryption_key, conf.alg, token)
    return kong.response.exit(200, { token = ngx.escape_uri(token) })
    end
  
  local allowed = false
  request_path = kong.request.get_raw_path()
  kong.log.inspect(request_path)
  for _, pattern in ipairs(conf.whitelist_path_patterns or {}) do
    local match, err = ngx.re.match(request_path, pattern, "jo")
    if match then
      allowed = true
      break
    elseif err then
      kong.log.err("Invalid whitelist regex: ", err)
    end
  end
  
  if not allowed then
    kong.log.debug("Skipping plugin for unmatched path: ", request_path)
    return -- pass through
  end
   
    -- request path. validate
    -- token could come from cookie, query or headers
  -- Retrieve token from context (pre-parsed headers, query, cookies)
  local token_source = conf.authz_token_source or "header"
  local token_key = conf.authz_token_key or "authorization"
  local token

  if token_source == "query" then
    token = context.request.query[token_key]

  elseif token_source == "header" then
    token = context.request.headers[token_key]
    if token and token:match("^Bearer ") then
      token = token:sub(8)
    end

  elseif token_source == "cookie" then
    token = context.request.cookies[token_key]
  end


    if not token then
      return kong.response.exit(400, { message = "No token" })
    end

    local is_valid, err = validate_request(conf, token, context)
    if not is_valid then
      return kong.response.exit(400, { message = err })
    end
end    

KongAuthzProxyHandler.PRIORITY = 1000

KongAuthzProxyHandler.VERSION = "0.1.0"
return KongAuthzProxyHandler
