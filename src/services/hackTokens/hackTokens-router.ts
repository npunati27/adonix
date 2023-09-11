import { Request, Router, Response } from "express";
import { EncodeResult, TokenPayLoad, User } from "./hackTokens-formats.js";
import { decodeToken, encodeToken, getTokenPayLoadFromUser, getUserFromTokenPayload } from "./hackTokens-lib.js";
import Constants from "../../constants.js";
import * as console from "console";

const hackTokensRouter: Router = Router();

/**
 * @api {post} /hackTokens/encode/ POST /hackTokens/encode
 * @apiGroup hackTokens
 * @apiDescription encodes user and data into a token string.
 *
 * @apiBody {String} user UserID.
 * @apiBody {Object} data User's Data.
 * @apiBody {Object} role User's role.
 * @apiBody {number} access_level User's access_level.
 * @apiParamExample {json} Example Request:
 *	{
 "user": "john_doe",
 "data": {
        "role": admin,
        "access_level" : 5
        }
 * 	}
 *
 * @apiSuccess (200: Success) {String} token Encoded Token.
 * @apiSuccess (200: Success) {String} context Additional Data.

 * @apiSuccessExample Example Success Response:
 * 	HTTP/1.1 200 OK
 *	{
 "token": "loremipsumdolorsitelet",
 "context": {}
 * 	}
 *
 * @apiUse verifyErrors
 */
hackTokensRouter.post("/encode", (req: Request, res: Response) => {
	try {
		const user: User = req.body as User;

		const payload: TokenPayLoad | undefined = getTokenPayLoadFromUser(user);
		const token: EncodeResult = encodeToken(payload);
		res.status(Constants.SUCCESS).json(token);
	} catch (error: unknown) {
		console.error(error);
		res.status(Constants.BAD_REQUEST).send({ error: "Invalid Data" });
	}
});

/**
 * @api {post} /hackTokens/decode/ POST /hackTokens/decode/
 * @apiGroup hackTokens
 * @apiDescription decode a token to a user and it's data
 *
 * @apiBody {String} token Encoded Token
 * @apiBody {Object} context Additional Information.
 * @apiParamExample {json} Example Request:
 *    {
 *  "token": "loremipsumdolorsitelet",
 *  "context": {}
 *    }
 *
 * @apiSuccess (200: Success) {String} user UserID
 * @apiSuccess (200: Success) {Object} data User's data.
 * @apiSuccess (200: Success) {Object} role User's role.
 * @apiSuccess (200: Success) {number} access_level User's access level.

 * @apiSuccessExample Example Success Response:
 * 	HTTP/1.1 200 OK
 * {
 *  "user": "john_doe",
 *  "data": {
 *         "role": admin
 *         "access_level" : 5
 *         }
 * }
 *
 * @apiUse verifyErrors
 */
hackTokensRouter.post("/decode", (req: Request, res: Response) => {
	const encoded: EncodeResult = req.body as EncodeResult;
	try {
		const payload:TokenPayLoad | undefined = decodeToken(encoded);
		const user: User | undefined = getUserFromTokenPayload(payload);
		res.status(Constants.SUCCESS).json(user);
	} catch (error: unknown) {
		console.error(error);
		res.status(Constants.BAD_REQUEST).send({ error: "Invalid Data" });
	}
});


export default hackTokensRouter;
