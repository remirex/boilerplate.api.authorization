import { Document, Model } from 'mongoose';

import { IUser, IRefreshToken } from '../../interfaces/IUser';

declare global {
  namespace Models {
    export type UserModel = Model<IUser & Document>;
    export type RefreshTokenModel = Model<IRefreshToken & Document>;
  }

  namespace Express {
    export interface Request {
      currentUser: IUser & Document;
    }
  }
}
