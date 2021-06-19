import { Document, Model } from 'mongoose';

import { IUser } from '../../interfaces/IUser';

declare global {
  namespace Model {
    export type UserModel = Model<IUser & Document>;
  }
}
