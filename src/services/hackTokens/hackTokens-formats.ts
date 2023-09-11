import { Role } from "../../models";

export interface User {
	user: string,
	data: {
		role: Role,
		access_level: number
	}
}

export interface TokenPayLoad {
	user: string,
	role: Role,
	access_level: number,
	exp?: number
}

export interface EncodeResult {
	token: string,
	context: EncodeContext
}

export interface EncodeContext {
	iv: number
}
