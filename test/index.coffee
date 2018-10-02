chai = require 'chai'
chaiAsPromised = require 'chai-as-promised'
chai.use(chaiAsPromised)
{ expect } = chai
passport = require 'passport'
atob = require 'atob'
express = require 'express'
passport = require 'passport'
supertest = require 'supertest'
mockery = require 'mockery'
requestMock = require 'requestmock'
jsonwebtoken = require 'jsonwebtoken'

mockery.enable(warnOnUnregistered: false)
mockery.registerMock('request', requestMock)

API_KEYS =
	builder: 'builderApiKey'

JSON_WEB_TOKEN_SECRET = 'testsecret'
USER_ID = 1
USER_JWT_SECRET = 's3cr3t'

apiHost = 'api.resindev.io'
apiPort = 80

jwt = require '../index'

describe 'createJwt', ->
	it 'should return a valid jwt', ->
		token = jwt.createJwt({ data: 'test' }, 'secret')
		expect(token).to.be.a('string')
		expect(token.split('.')).to.have.length(3)

		token = jwt.createJwt({}, 'secret')
		expect(token).to.be.a('string')
		expect(token.split('.')).to.have.length(3)

	it 'should return a jwt containing the given payload', ->
		token = jwt.createJwt({ data: 'test' }, 'secret')
		payload = JSON.parse(atob(token.split('.')[1]))
		expect(payload).to.have.property('data').that.eql('test')

describe 'requestUserJwt', ->
	before ->
		@serviceToken = jwt.createJwt({ service: 'builder', 'apikey': API_KEYS.builder }, JSON_WEB_TOKEN_SECRET)
		@userToken = jwt.createJwt({ id: USER_ID, jwt_secret: USER_JWT_SECRET }, JSON_WEB_TOKEN_SECRET)
		requestMock.register 'post', "https://#{apiHost}:#{apiPort}/authorize", (opts, cb) =>
			if opts.qs.userId != USER_ID
				cb(null, statusCode: 404, 'No such user')
			cb(null, statusCode: 200, @userToken)

	it 'should complain if no user identifier is passed', ->
		expect(jwt.requestUserJwt({ apiHost, apiPort, token: @serviceToken })).to.be.rejectedWith(Error)

	it 'should return a promise that resolves to the jwt created by api', ->
		expect(jwt.requestUserJwt({ userId: 1, apiHost, apiPort, token: @token })).to.eventually.equal(@userToken)

describe 'strategy', ->
	before ->
		@app = express()
		passport.use(jwt.strategy({ apiHost, apiPort, secret: JSON_WEB_TOKEN_SECRET, apiKeys: API_KEYS }))
		@app.use(passport.initialize())
		@app.use(passport.authenticate('jwt', { session: false, assignProperty: 'auth' }))
		@app.get('/test', (req, res) ->
			res.json(req.auth)
		)

		requestMock.register 'get', "https://#{apiHost}:#{apiPort}/whoami", (opts, cb) ->
			try
				jwtData = jsonwebtoken.verify(opts.headers.Authorization[7..], JSON_WEB_TOKEN_SECRET)
				if jwtData.id == USER_ID and jwtData.jwt_secret == USER_JWT_SECRET
					cb(null, statusCode: 200, 'OK')
				else
					throw new Error('invalid user')
			catch
				cb(null, statusCode: 401, 'Forbidden')

	it 'should return 401 when jwt is missing', ->
		supertest(@app)
		.get('/test')
		.expect(401)

	it 'should return 401 when jwt is signed with wrong key', ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ service: 'builder' }, 'wrongsecret'))
		.expect(401)

	it 'should return 401 if neither service not user id is defined', ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ data: 'test' }, JSON_WEB_TOKEN_SECRET))
		.expect(401)

	describe 'service token', ->
		it 'should return 401 if no api key is used in a service token', ->
			supertest(@app)
			.get('/test')
			.set('Authorization', 'Bearer ' + jwt.createJwt({ service: 'builder' }, JSON_WEB_TOKEN_SECRET))
			.expect(401)

		it 'should return 401 if wrong api key is used in a service token', ->
			supertest(@app)
			.get('/test')
			.set('Authorization', 'Bearer ' + jwt.createServiceJwt({ service: 'builder', 'apikey': 'notapikey', secret: JSON_WEB_TOKEN_SECRET }))
			.expect(401)

		it 'should return 200 passing correct jwt', ->
			supertest(@app)
			.get('/test')
			.set('Authorization', 'Bearer ' + jwt.createServiceJwt({ service: 'builder', 'apikey': API_KEYS.builder, secret: JSON_WEB_TOKEN_SECRET }))
			.expect(200)
			.expect (res) ->
				expect(res.body).to.have.property('service').that.eql('builder')

	describe 'user token', ->

		it 'should return 200 passing a correct user jwt', ->
			supertest(@app)
			.get('/test')
			.set('Authorization', 'Bearer ' + jwt.createJwt({ id: USER_ID, jwt_secret: USER_JWT_SECRET }, JSON_WEB_TOKEN_SECRET))
			.expect(200)
			.expect (res) ->
				expect(res.body).to.have.property('id').that.eql(USER_ID)
				expect(res.body).to.have.property('jwt_secret').that.eql(USER_JWT_SECRET)

		it 'should return 401 passing an invalid user jwt', ->
			supertest(@app)
			.get('/test')
			.set('Authorization', 'Bearer ' + jwt.createJwt({ id: USER_ID, jwt_secret: "not-#{USER_JWT_SECRET}" }, JSON_WEB_TOKEN_SECRET))
			.expect(401)
