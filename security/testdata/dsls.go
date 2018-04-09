package testdata

import (
	. "goa.design/goa/http/design"
	. "goa.design/plugins/security/dsl"
)

var BasicAuth = BasicAuthSecurity("basic")

var JWTAuth = JWTSecurity("jwt", func() {
	Scope("api:read", "Read-only access")
	Scope("api:write", "Read and write access")
})

var APIKeyAuth = APIKeySecurity("api_key")

var OAuth2AuthorizationCode = OAuth2Security("authCode", func() {
	AuthorizationCodeFlow("/authorization", "/token", "/refresh")
	Scope("api:write", "Write acess")
	Scope("api:read", "Read access")
})

var EndpointWithoutRequirementDSL = func() {
	Service("EndpointWithoutRequirement", func() {
		Method("Unsecure", func() {
			HTTP(func() {
				GET("/")
			})
		})
	})
}

var EndpointNoSecurityDSL = func() {
	Service("EndpointNoSecurity", func() {
		Security(BasicAuth)
		Method("NoSecurity", func() {
			NoSecurity()
			HTTP(func() {
				GET("/")
			})
		})
	})
}

var EndpointsWithServiceRequirementsDSL = func() {
	Service("EndpointsWithServiceRequirements", func() {
		Security(BasicAuth)
		Method("SecureWithRequirements", func() {
			Payload(func() {
				Username("user", String)
				Password("pass", String)
			})
			HTTP(func() {
				GET("/")
			})
		})
		Method("AlsoSecureWithRequirements", func() {
			Payload(func() {
				Username("user", String)
				Password("pass", String)
			})
			HTTP(func() {
				POST("/")
			})
		})
	})
}

var EndpointsWithRequirementsDSL = func() {
	Service("EndpointsWithRequirements", func() {
		Method("SecureWithRequirements", func() {
			Security(BasicAuth)
			Payload(func() {
				Username("user", String)
				Password("pass", String)
			})
			HTTP(func() {
				GET("/")
			})
		})
		Method("DoublySecureWithRequirements", func() {
			Security(BasicAuth, JWTAuth)
			Payload(func() {
				Username("user", String)
				Password("pass", String)
				Token("token", String)
			})
			HTTP(func() {
				POST("/")
			})
		})
	})
}

var EndpointWithRequiredScopesDSL = func() {
	Service("EndpointWithRequiredScopes", func() {
		Method("SecureWithRequiredScopes", func() {
			Security(JWTAuth, func() {
				Scope("api:read")
				Scope("api:write")
			})
			Payload(func() {
				Token("token", String)
			})
			HTTP(func() {
				GET("/")
			})
		})
	})
}

var EndpointWithAPIKeyOverrideDSL = func() {
	Service("EndpointWithAPIKeyOverride", func() {
		Security(BasicAuth)
		Method("SecureWithAPIKeyOverride", func() {
			Security(APIKeyAuth)
			Payload(func() {
				APIKey("api_key", "key", String)
			})
			HTTP(func() {
				GET("/")
			})
		})
	})
}

var EndpointWithOAuth2DSL = func() {
	Service("EndpointWithOAuth2", func() {
		Method("SecureWithOAuth2", func() {
			Security(OAuth2AuthorizationCode)
			Payload(func() {
				AccessToken("token", String)
			})
			HTTP(func() {
				GET("/")
			})
		})
	})
}

var SingleServiceDSL = func() {
	Service("SingleService", func() {
		Method("Method", func() {
			Security(APIKeyAuth)
			Payload(func() {
				APIKey("api_key", "key", String)
			})
			Error("unauthorized")
			Error("forbidden", String)
			HTTP(func() {
				GET("/")
				Response("unauthorized", StatusUnauthorized)
				Response("forbidden", StatusForbidden)
			})
		})
	})
}

var ServiceWithNoAuthErrorResponseDSL = func() {
	Service("ServiceNoAuthError", func() {
		Method("Method", func() {
			Security(APIKeyAuth)
			Payload(func() {
				APIKey("api_key", "key", String)
			})
			Error("bad_request")
			HTTP(func() {
				GET("/")
				Response("bad_request", StatusBadRequest)
			})
		})
	})
}

var ServiceWithUserTypeErrorDSL = func() {
	var CustomError = Type("CustomError", func() {
		Attribute("id", String)
		Attribute("error", String, func() {
			Metadata("struct:error:name")
		})
	})
	Service("ServiceUserTypeError", func() {
		Method("Method", func() {
			Security(APIKeyAuth)
			Payload(func() {
				APIKey("api_key", "key", String)
			})
			Error("unauthorized", CustomError)
			HTTP(func() {
				GET("/")
				Response("unauthorized", StatusUnauthorized)
			})
		})
	})
}

var MultipleServicesDSL = func() {
	Service("ServiceWithAPIKeyAuth", func() {
		Method("Method", func() {
			Security(APIKeyAuth)
			Payload(func() {
				APIKey("api_key", "key", String)
			})
			Error("forbidden")
			HTTP(func() {
				GET("/")
				Response("forbidden", StatusForbidden)
			})
		})
	})
	Service("ServiceWithJWTAndAPIKey", func() {
		Security(APIKeyAuth, JWTAuth)
		Method("Method", func() {
			Payload(func() {
				APIKey("api_key", "key", String)
				Token("token", String)
			})
			Error("unauthorized", String)
			HTTP(func() {
				GET("/")
				Response("unauthorized", StatusUnauthorized)
			})
		})
	})
	Service("ServiceWithNoSecurity", func() {
		Method("Method", func() {
			Payload(func() {
				Attribute("a", String)
			})
			HTTP(func() {
				GET("/{a}")
			})
		})
	})
}