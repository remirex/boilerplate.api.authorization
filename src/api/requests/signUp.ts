import {Request} from "express";
import {Response} from "express";
import {NextFunction} from "express";
import Joi from "joi";
import middleware from "../middlewares";

export function signUpSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    name: Joi.string().required(),
    email: Joi.string()
      .email({ minDomainSegments: 2, tlds: { allow: ['com', 'net', 'io'] } })
      .required(),
    username: Joi.string().alphanum().min(3).max(30).required(),
    password: Joi.string().required().min(8).max(20).pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
    repeatPassword: Joi.ref('password'),
    acceptTerms: Joi.boolean().required().invalid(false),
  }).with('password', 'repeatPassword');
  middleware.joiValidation(req, res, next, schema);
}
