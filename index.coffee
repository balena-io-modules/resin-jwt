###
	Copyright 2015 Resin.io Ltd.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
###

Promise = require 'bluebird'
jsonwebtoken = require 'jsonwebtoken'
{ Strategy: JwtStrategy, ExtractJwt } = require 'passport-jwt'
request = Promise.promisifyAll(require('request'), multiArgs: true)

DEFAULT_EXPIRY_MINUTES = 1440

exports.strategy = (opts = {}) ->
	if not opts.secret
		throw new Error('Json web token secret not defined in jwt strategy')
	new JwtStrategy
		secretOrKey: opts.secret
		passReqToCallback: true
		jwtFromRequest: ExtractJwt.versionOneCompatibility(
			tokenBodyField: '_token'
			authScheme: 'Bearer'
		)
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

exports.createServiceJwt = ({ service, apikey, secret, payload = {}, expiry = DEFAULT_EXPIRY_MINUTES }) ->
	if not service
		throw new Error('Service name not defined')
	if not apikey
		throw new Error('Api key not defined')
	payload.service = service
	payload.apikey = apikey
	createJwt(payload, secret, expiry)

exports.requestUserJwt = Promise.method (opts = {}) ->
	if opts.userId?
		qs = userId: opts.userId
	else if opts.username
		qs = username: opts.username
	else
		throw new Error('Neither userId nor username specified when requesting authorization')
	requestOpts =
		url: "https://#{opts.apiHost}:#{opts.apiPort}/authorize"
		qs: qs
		headers:
			Authorization: "Bearer #{opts.token}"
	request.postAsync(requestOpts)
	.spread (response, body) ->
		if response.statusCode isnt 200 or not body
			throw new Error("Authorization failed. Status code: #{response.statusCode}, body: #{body}")
		return body
	.catch (e) ->
		console.error('authorization request failed', e, e.message, e.stack)
		throw e
