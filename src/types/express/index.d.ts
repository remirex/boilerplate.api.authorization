import { Document, Model } from 'mongoose';

import { IUser } from '../../interfaces/IUser';
import { IRefreshToken } from '../../interfaces/IRefreshToken';

declare global {
  namespace Models {
    export type UserModel = Model<IUser & Document>;
    export type RefreshTokenModel = Model<IRefreshToken & Document>;
  }
}
