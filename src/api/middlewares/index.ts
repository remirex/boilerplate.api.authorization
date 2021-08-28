import joiValidation from './validation';
import allow from './isAllow';
import {expressAuthentication} from "./isAuth";
import attachCurrentUser from "./attachCurrentUser";

export default {
  joiValidation,
  allow,
  expressAuthentication,
  attachCurrentUser,
}
