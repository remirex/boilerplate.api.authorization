import {Request} from "express";
import {Response} from "express";
import {NextFunction} from "express";
import Joi from "joi";
import middleware from "../middlewares";

export function signInSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'io'] } })
      .required(),
    password: Joi.string().required(),
  });
  middleware.joiValidation(req, res, next, schema);
}
