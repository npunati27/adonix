import { EncodeResult, HackTokenPayLoad } from "./hackTokens-formats.js";
import ms from "ms";
import Constants from "../../constants.js";
// import { randomBytes } from "crypto";
import * as crypto from "crypto";

/**
 * encodeToken takes a HackTokenPayload and an optional expiration to return an encoded token.
 * Uses the aes-192-cbc algorithm along with a 16 byte initialization vector.
 * The token it returns is in the format of `{encryptPayload}.${signature}`.
 * For brevity, the Initialization vector is represented as a 32 bit Little endian integer.
 * @param payload
 * @param expiration
 */
export function encodeToken(payload?: HackTokenPayLoad, expiration?: string): EncodeResult {
	if (!payload) {
		throw new Error("No Payload Passed In!");
	}
	const secret: string = process.env.JWT_SECRET ?? Constants.DEFAULT_JWT_SIGNING_SECRET;
	const offset: number = ms(expiration ?? Constants.DEFAULT_JWT_OFFSET);
	payload.exp = Math.floor(Date.now() + offset) / Constants.MILLISECONDS_PER_SECOND;
	const key: Buffer = crypto.scryptSync(secret, "salt", Constants.HACKTOKEN_KEYLEN);

	const payloadString: string = JSON.stringify(payload);
	const iv: Buffer = Buffer.alloc(Constants.HACKTOKEN_IV_SIZE);
	const cipher:crypto.Cipher = crypto.createCipheriv(Constants.HACKTOKEN_ALGORITHM, key, iv);

	let encryptPayload: string = cipher.update(payloadString, "utf-8", "hex");
	encryptPayload += cipher.final("hex");

	const signature:string = crypto.createHmac("sha256", secret).update(encryptPayload).digest("hex");
	const token:string = `${encryptPayload}.${signature}`;

	return {
		token: token,
		context: {
			iv: iv.readInt32LE(),
		},
	};
}

/**
 * decodeToken takes the result from encodeToken() and returns the original user information in the form of a
 * HackTokenPayload.
 * @param encoded
 */
export function decodeToken(encoded?: EncodeResult): HackTokenPayLoad {
	if (!encoded) {
		throw new Error("No Token Provided!");
	}

	const [ receivedPayload , receivedSignature ] = encoded.token.split(".");
	const secret: string = process.env.JWT_SECRET ?? Constants.DEFAULT_JWT_SIGNING_SECRET;

	const expectedSignature: string = crypto.createHmac("sha256", secret).update(receivedPayload as string).digest("hex");
	if (expectedSignature != receivedSignature) {
		throw new Error("Invalid Token: given signature does not match expected signature");
	}

	const key: Buffer = crypto.scryptSync(secret, "salt", Constants.HACKTOKEN_KEYLEN);
	const ivDefaultValue: number = 0;
	const iv: Buffer = Buffer.alloc(Constants.HACKTOKEN_IV_SIZE, ivDefaultValue);
	iv.writeInt32LE(encoded.context.iv);

	const decipher: crypto.Decipher = crypto.createDecipheriv(Constants.HACKTOKEN_ALGORITHM, key, iv);
	let decryptPayload: string = decipher.update(receivedPayload as string, "hex", "utf8");
	decryptPayload += decipher.final("utf8");

	const decodedPayload: HackTokenPayLoad = JSON.parse(decryptPayload) as HackTokenPayLoad;
	const currTime: number = Math.floor(Date.now()) / Constants.MILLISECONDS_PER_SECOND;

	if (!decodedPayload.exp) {
		throw new Error("Token lacks expiration date!");
	}

	if (decodedPayload.exp < currTime) {
		throw new Error("Token is expired!");
	}
	return decodedPayload;
}
