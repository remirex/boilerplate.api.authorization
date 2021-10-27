import joiValidation from './validation';
import allowMiddleware from './allow';
import authMiddleware from './auth';
import {uploadFileMiddleware} from "./file/file";

export default {
  joiValidation,
  allowMiddleware,
  authMiddleware,
  uploadFileMiddleware,
}
