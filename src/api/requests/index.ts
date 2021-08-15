import {signUpSchema} from './signUp';
import {verifySchema} from "./verifyEmail";
import {signInSchema} from "./signIn";
import {refreshTokenSchema} from "./refreshToken";
import {revokeTokenSchema} from "./revokeToken";
import {forgotPasswordSchema} from './forgotPassword';
import {resetPasswordSchema} from "./resetPassword";

export default {
  signUpSchema,
  verifySchema,
  signInSchema,
  refreshTokenSchema,
  revokeTokenSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
}
