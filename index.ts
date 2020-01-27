/*
	Copyright 2020 Balena Ltd.

	Licensed under the Apache License, Version 2.0 (the "License");
	you may not use this file except in compliance with the License.
	You may obtain a copy of the License at

		http://www.apache.org/licenses/LICENSE-2.0

	Unless required by applicable law or agreed to in writing, software
	distributed under the License is distributed on an "AS IS" BASIS,
	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
	See the License for the specific language governing permissions and
	limitations under the License.
*/
import { promisify } from 'util';
import * as jsonwebtoken from 'jsonwebtoken';
import * as request from 'request';
const postAsync = promisify(request.post);

const DEFAULT_EXPIRY_MINUTES = 1440;

export const createJwt = (
	payload: { [key: string]: any },
	secret: string,
	expiry = DEFAULT_EXPIRY_MINUTES,
) => jsonwebtoken.sign(payload, secret, { expiresIn: expiry * 60 });

export interface CreateServiceJwtOptions {
	service: string;
	apikey: string;
	secret: string;
	payload?: { [key: string]: any };
	expiry?: number;
}

export const createServiceJwt = ({
	service,
	apikey,
	secret,
	payload = {},
	expiry = DEFAULT_EXPIRY_MINUTES,
}: CreateServiceJwtOptions) => {
	if (!service) {
		throw new Error('Service name not defined');
	}
	if (!apikey) {
		throw new Error('Api key not defined');
	}
	payload.service = service;
	payload.apikey = apikey;
	return createJwt(payload, secret, expiry);
};

export interface RequestUserJwtOptions {
	apiHost: string;
	apiPort: string;
	token: string;
	userId?: string;
	username?: string;
}

export const requestUserJwt = async (
	opts: RequestUserJwtOptions,
) => {
	let qs;
	if (opts.userId != null) {
		qs = { userId: opts.userId };
	} else if (opts.username) {
		qs = { username: opts.username };
	} else {
		throw new Error(
			'Neither userId nor username specified when requesting authorization',
		);
	}
	const requestOpts = {
		url: `https://${opts.apiHost}:${opts.apiPort}/authorize`,
		qs,
		headers: {
			Authorization: `Bearer ${opts.token}`,
		},
	};
	try {
		const response = await postAsync(requestOpts)
		if (response.statusCode !== 200 || !response.body) {
			throw new Error(
				`Authorization failed. Status code: ${response.statusCode}, body: ${response.body}`,
			);
		}
		return response.body;
	} catch(e) {
		console.error('authorization request failed', e, e.message, e.stack);
		throw e;
	}
};
