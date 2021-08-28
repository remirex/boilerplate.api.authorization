import {Request} from "express";
import {Response} from "express";
import {NextFunction} from "express";
import Joi from "joi";
import middleware from "../middlewares";

export function resetPasswordSchema(req: Request, res: Response, next: NextFunction) {
  const schema = Joi.object({
    token: Joi.string().required(),
    password: Joi.string().required().min(8).max(20).pattern(new RegExp('^[a-zA-Z0-9]{3,30}$')),
    repeatPassword: Joi.ref('password'),
  });
  middleware.joiValidation(req, res, next, schema);
}
