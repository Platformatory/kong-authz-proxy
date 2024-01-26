local plugin_name = ({ ... })[1]:match("^kong%.plugins%.([^%.]+)")
local typedefs = require "kong.db.schema.typedefs"


return {
  --consumer = typedefs.no_consumer,
  name = "kong-authz-proxy",
  fields = {
    { consumer = typedefs.no_consumer },
    { protocols = typedefs.protocols_http },
    {
      config = {
        type = "record",
        fields = {
          { authz_listener_path = { type = "string", required = true, default = "/authz", }, },
          { authz_listener_path_validate_consumer = { type = "boolean", required = false, default = true, }, }, 
          { encryption_key = { type = "string", required = true, }, }, -- TODO: make this referenceable
          { alg = { type = "string", required = false, default = "aes256", }, },
          { salt = { type = "string", required = false, default = "some-random-salt", }, }, -- TODO: make this referenceable
        }
      } 
    }
  }
}            
