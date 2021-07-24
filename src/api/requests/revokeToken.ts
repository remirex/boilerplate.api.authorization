import {Request} from "express";
import {Response} from "express";
import {NextFunction} from "express";
import Joi from "joi";
import middleware from "../middlewares";

export function revokeTokenSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
  });
  middleware.joiValidation(req, res, next, schema);
}
