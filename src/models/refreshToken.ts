import mongoose from 'mongoose';

import { IRefreshToken } from '../interfaces/IUser';

const RefreshToken = new mongoose.Schema({
  account: { type: mongoose.Schema.Types.ObjectId, ref: 'User' },
  token: String,
  expires: Date,
  created: { type: Date, default: Date.now },
  createdByIp: String,
  revoked: Date,
  revokedByIp: String,
  replacedByToken: String,
});

RefreshToken.virtual('isExpired').get(function (this: { expires: any }): boolean {
  return Date.now() >= this.expires;
});

RefreshToken.virtual('isActive').get(function (this: { revoked: any; isExpired: boolean }): boolean {
  return !this.revoked && !this.isExpired;
});

export default mongoose.model<IRefreshToken & mongoose.Document>('RefreshToken', RefreshToken);
