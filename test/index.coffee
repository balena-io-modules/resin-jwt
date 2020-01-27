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

chai = require 'chai'
chaiAsPromised = require 'chai-as-promised'
chai.use(chaiAsPromised)
{ expect } = chai
atob = require 'atob'
mockery = require 'mockery'
requestMock = require 'requestmock'

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
