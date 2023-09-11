import { EncodeResult, TokenPayLoad, User } from "./hackTokens-formats.js";
import { Role } from "../../models";
import ms from "ms";
import Constants from "../../constants.js";
import crypto from "crypto";

export function getTokenPayLoadFromUser(u: User): TokenPayLoad {
	const uUser:string = u.user;
	const uRole:Role = u.data.role;
	const uAccessLevel:number = u.data.access_level;

	const payLoad: TokenPayLoad = {
		user: uUser,
		role: uRole,
		access_level: uAccessLevel,
	};

	return payLoad;
}
export function encodeToken(payload?: TokenPayLoad, expiration?: string): EncodeResult {
	if (!payload) {
		throw new Error("No Payload Passed In!");
	}
	//const secret: string | undefined = process.env.JWT_SECRET;
	const secret: string = "12345678920234059739139467043y9y9384759369832479";
	if (!secret) {
		throw new Error("No secret specified");
	}
	const offset: number = ms(expiration ?? Constants.DEFAULT_JWT_OFFSET);
	payload.exp = Math.floor(Date.now() + offset) / Constants.MILLISECONDS_PER_SECOND;
	const keyLen: number = 24;
	const key: Buffer = crypto.scryptSync(secret, "salt", keyLen);

	const payloadString: string = JSON.stringify(payload);
	const n: number = 16;
	const f: number = 0;
	const iv: Buffer = Buffer.alloc(n, f);
	const cipher:crypto.Cipher = crypto.createCipheriv("aes-192-cbc", key, iv);


	let encryptPayload: string = cipher.update(payloadString, "utf-8", "hex");
	encryptPayload += cipher.final("hex");

	// todo signature stuff

	return {
		token: encryptPayload,
		context: {
			iv: iv.readInt32LE(),
		},
	};
}

export function decodeToken(token?: EncodeResult): TokenPayLoad {
	if (!token) {
		throw new Error("No Token Provided!");
	}
	//const secret: string | undefined = process.env.JWT_SECRET;
	const secret: string = "12345678920234059739139467043y9y9384759369832479";
	if (!secret) {
		throw new Error("No secret Specified!");
	}
	const keyLen: number = 24;
	const key: Buffer = crypto.scryptSync(secret, "salt", keyLen);
	const n: number = 16;
	const f: number = 0;
	const iv: Buffer = Buffer.alloc(n, f);
	// JSON.parse(token.context)
	iv.writeInt32LE(token.context.iv);

	const decipher:crypto.Decipher = crypto.createDecipheriv("aes-192-cbc", key, iv);
	let decryptPayload:string = decipher.update(token.token, "hex", "utf8");
	decryptPayload += decipher.final("utf8");

	const decodedPayload:TokenPayLoad = JSON.parse(decryptPayload) as TokenPayLoad;
	const currTime:number = Math.floor(Date.now()) / Constants.MILLISECONDS_PER_SECOND;

	if (!decodedPayload.exp) {
		throw new Error("Token lacks expiration date!");
	}
	//check if token expired
	if (decodedPayload && decodedPayload.exp < currTime) {
		throw new Error("Token is expired!");
	}
	return decodedPayload;
}

export function getUserFromTokenPayload(payload: TokenPayLoad): User {
	const uUserID: string = payload.user;
	const uUserRole: Role = payload.role;
	const uAccessLevel: number = payload.access_level;

	const u : User = {
		user: uUserID,
		data: {
			role: uUserRole,
			access_level: uAccessLevel,
		},
	};

	return u;
}
