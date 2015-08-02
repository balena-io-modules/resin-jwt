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
					return true
				else
					throw new InvalidJwtSecretError()
			.return(jwtData)
			.nodeify(done)

exports.createJwt = (payload, secret = SECRET, expiry = EXPIRY_MINUTES) ->
	jsonwebtoken.sign(payload, secret, expiresInMinutes: expiry)

exports.middleware = (req, res, next) ->
	authenticate = passport.authenticate 'jwt', session: false, (err, auth) ->
		return res.sendStatus(401) if err instanceof InvalidJwtSecretError
		return next(err) if err
		return next() if !auth

		req.auth = auth
		next()
	authenticate(req, res, next)
