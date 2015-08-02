{ expect } = require 'chai'
passport = require 'passport'
atob = require 'atob'
express = require 'express'
passport = require 'passport'
supertest = require 'supertest'

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
		passport.use(jwt.strategy('testsecret'))
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

	it 'should return 401 if service is not defined', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ data: 'test' }, 'testsecret'))
		.expect(401)
		.end(done)

	it 'should return 200 passing correct jwt', (done) ->
		supertest(@app)
		.get('/test')
		.set('Authorization', 'Bearer ' + jwt.createJwt({ service: 'builder' }, 'testsecret'))
		.expect(200)
		.expect (res) ->
			expect(res.body).to.have.property('service').that.eql('builder')
		.end(done)
