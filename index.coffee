Promise = require 'bluebird'
jsonwebtoken = require 'jsonwebtoken'
passport = require 'passport'
JwtStrategy = require('passport-jwt').Strategy
TypedError = require 'typed-error'
request = Promise.promisifyAll(require 'request')

class InvalidJwtSecretError extends TypedError

exports.InvalidJwtSecretError = InvalidJwtSecretError

DEFAULT_EXPIRY_MINUTES = 10080

exports.strategy = (opts = {}) ->
	if not opts.secret
		throw new Exception('Json web token secret not defined in jwt strategy')
	new JwtStrategy
		secretOrKey: opts.secret
		tokenBodyField: '_token'
		authScheme: 'Bearer'
		passReqToCallback: true
		(req, jwtData, done) ->
			Promise.try ->
				if !jwtData?
					return false
				if jwtData.service
					if jwtData.apikey and opts.apiKeys[jwtData.service] == jwtData.apikey
						return jwtData
					else
						return false
				else
					requestOpts =
						url: "https://#{opts.apiHost}:#{opts.apiPort}/whoami"
						headers:
							Authorization: req.headers.authorization
					request.getAsync(requestOpts)
					.spread (response) ->
						if response.statusCode isnt 200
							return false
						else
							return jwtData
			.nodeify(done)

exports.createJwt = createJwt = (payload, secret, expiry = DEFAULT_EXPIRY_MINUTES) ->
	jsonwebtoken.sign(payload, secret, expiresIn: expiry * 60)

exports.createServiceJwt = ({ service, apikey, secret, payload, expiry }) ->
	if not service
		throw new Error('Service name not defined')
	if not apikey
		throw new Error('Api key not defined')
	expiry ?= DEFAULT_EXPIRY_MINUTES
	payload ?= {}
	payload.service = service
	payload.apikey = apikey
	createJwt({ payload, secret, expiry })

exports.requestUserJwt = Promise.method (opts = {}) ->
	if opts.userId?
		qs = userId: opts.userId
	else if opts.username
		qs = username: opts.username
	else
		throw new Error('Neither userId not username specified when requesting authorization')
	requestOpts =
		url: "https://#{opts.apiHost}:#{opts.apiPort}/authorize"
		qs: qs
		json: true
		headers:
			Authorizaton: "Bearer #{opts.token}"
	request.postAsync(requestOpts)
	.get(1)
	.get('token')
	.catch (e) ->
		console.error('authorization request failed', e, e.message, e.stack)
		throw e
