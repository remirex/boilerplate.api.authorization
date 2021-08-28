import {Container} from "typedi";
import mongoose from "mongoose";
import {IUser} from "../../interfaces/IUser";
import {Logger} from 'winston';

const attachCurrentUser = async (req, res, next) => {
  const Logger : Logger = Container.get('logger');
  try {
    const UserModel = Container.get('userModel') as mongoose.Model<IUser & mongoose.Document>;
    const userRecord = await UserModel.findById(req.token.id);
    if (!userRecord) {
      return res.sendStatus(401);
    }
    const currentUser = userRecord.toObject();
    Reflect.deleteProperty(currentUser, 'password');
    Reflect.deleteProperty(currentUser, 'verificationToken');
    Reflect.deleteProperty(currentUser, 'resetToken');
    Reflect.deleteProperty(currentUser, 'twoFactorAuthenticationCode');
    Reflect.deleteProperty(currentUser, '__v');
    req.currentUser = currentUser;
    req.currentUser.id = currentUser._id;
    Reflect.deleteProperty(currentUser, '_id');
    return next();
  } catch (error) {
    Logger.error('🔥 Error attaching user to req: %o', error);
    return next(error);
  }
}

export default attachCurrentUser;
