declare module 'resin-jwt' {
	import Strategy from 'passport-jwt';

	interface StrategyOpts {
		secret: string;
		apiKeys: {[key: string]: string};
		apiHost: string;
		apiPort: string;
	}

	interface CreateServiceJwtOpts {
		service: string;
		apikey: string;
		secret: string;
		payload?: any;
		expiry?: number;
	}

	interface RequestUserJwtOpts {
		apiHost: string;
		apiPort: string;
		token: string;
		userId?: string;
		username?: string;
	}

	export function strategy(opts: StrategyOpts): Strategy;
	export function createJwt(payload: any, secret: string, expiry?: number): string;
	export function createServiceJwt(opts: CreateServiceJwtOpts): string;
	export function requestUserJwt(opts: RequestUserJwtOpts): Promise<string>;
}
