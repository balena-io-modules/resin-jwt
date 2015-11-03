Promise = require 'bluebird'
jsonwebtoken = require 'jsonwebtoken'
passport = require 'passport'
JwtStrategy = require('passport-jwt').Strategy
TypedError = require 'typed-error'

class InvalidJwtSecretError extends TypedError

exports.InvalidJwtSecretError = InvalidJwtSecretError

SECRET = process.env.JSON_WEB_TOKEN_SECRET
EXPIRY_MINUTES = process.env.JSON_WEB_TOKEN_EXPIRY_MINUTES

exports.strategy = (secret = SECRET) ->
	new JwtStrategy
		secretOrKey: secret
		tokenBodyField: '_token'
		authScheme: 'Bearer'
		(jwtData, done) ->
			Promise.try ->
				if !jwtData?
					throw new InvalidJwtSecretError()
				# TODO: user jwt
				if jwtData.service
					if jwtData.apikey and process.env["#{jwtData.service.toUpperCase()}_SERVICE_API_KEY"] == jwtData.apikey
						return true
					else
						throw new InvalidJwtSecretError()
				else
					throw new InvalidJwtSecretError()
			.return(jwtData)
			.nodeify(done)

exports.createJwt = (payload, secret = SECRET, expiry = EXPIRY_MINUTES) ->
	jsonwebtoken.sign(payload, secret, expiresInMinutes: expiry)

exports.createServiceJwt = (payload, service, apikey, secret = SECRET, expiry = EXPIRY_MINUTES) ->
	if not service
		throw new Error('Service name not defined')
	if not apikey
		throw new Error('Api key not defined')
	payload.service = service
	payload.apikey = apikey
	createJwt(payload, secret, expiry)

exports.middleware = (req, res, next) ->
	authenticate = passport.authenticate 'jwt', session: false, (err, auth) ->
		return res.sendStatus(401) if err instanceof InvalidJwtSecretError
		return next(err) if err
		return next() if !auth

		req.auth = auth
		next()
	authenticate(req, res, next)
