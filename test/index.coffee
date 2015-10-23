{ expect } = require 'chai'
passport = require 'passport'
atob = require 'atob'
express = require 'express'
passport = require 'passport'
supertest = require 'supertest'
mockery = require 'mockery'
requestMock = require 'requestmock'

mockery.enable(warnOnUnregistered: false)
mockery.registerMock('request', requestMock)

apiHost = 'api.resindev.io'
apiPort = 80
requestMock.register 'post', "https://#{apiHost}:#{apiPort}/auth", (opts, cb) ->
	if opts.body.id == 1 and opts.body.jwt_secret == 's3cr3t'
		cb(null, statusCode: 200, 'OK')
	else
		cb(null, statusCode: 401, 'Forbidden')

jwt = require '../index'

describe 'InvalidJwtSecretError', ->
	it 'should be instance of Error', ->
		expect(jwt.InvalidJwtSecretError).to.be.instanceof.Error

describe 'createJwt', ->
	it 'should return a valid jwt', ->
		token = jwt.createJwt({ data: 'test' }, 'secret')
		expect(token).to.be.a.String
		expect(token.split('.')).to.have.length(3)

		token = jwt.createJwt({}, 'secret')
		expect(token).to.be.a.String
		expect(token.split('.')).to.have.length(3)

	it 'should return a jwt containing the given payload', ->
		token = jwt.createJwt({ data: 'test' }, 'secret')
		payload = JSON.parse(atob(token.split('.')[1]))
		expect(payload).to.have.property('data').that.eql('test')

describe 'middleware', ->
	before ->
		@app = express()
		passport.use(jwt.strategy('test-jwt', apiHost, apiPort, 'testsecret'))
		@app.use(passport.initialize())
		@app.use(jwt.middleware)
		@app.get('/test', (req, res) ->
			if not req.auth?
				res.sendStatus(401)
			else
				res.json(req.auth)
		)

	it 'should return 401 when jwt is missing', (done) ->
		supertest(@app)
		.get('/test')
		.expect(401)
		.end(done)

	it 'should return 401 when jwt is signed with wrong key', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ service: 'builder' }, 'wrongsecret'))
		.expect(401)
		.end(done)

	it 'should return 401 if neither service not user id is defined', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ data: 'test' }, 'testsecret'))
		.expect(401)
		.end(done)

	it 'should return 401 if no api key is used in a service token', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ service: 'builder' }, 'testsecret'))
		.expect(401)
		.end(done)

	it 'should return 401 if wrong api key is used in a service token', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ service: 'builder', 'apikey': 'notapikey' }, 'testsecret'))
		.expect(401)
		.end(done)

	it 'should return 200 passing correct jwt', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ service: 'builder', 'apikey': process.env.BUILDER_SERVICE_API_KEY }, 'testsecret'))
		.expect(200)
		.expect (res) ->
			expect(res.body).to.have.property('service').that.eql('builder')
		.end(done)
	it 'should return 200 passing a correct user jwt', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ id: 1, jwt_secret: 's3cr3t' }, 'testsecret'))
		.expect(200)
		.expect (res) ->
			expect(res.body).to.have.property('id').that.eql(1)
			expect(res.body).to.have.property('jwt_secret').that.eql('s3cr3t')
		.end(done)
	it 'should return 401 passing an invalid user jwt', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ id: 1, jwt_secret: 'not-s3cr3t' }, 'testsecret'))
		.expect(401)
		.end(done)
