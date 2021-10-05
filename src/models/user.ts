import mongoose from 'mongoose';

import {UserRole, UserStatus} from '../interfaces/types'
import {IUser} from "../interfaces/IUser";
import Password from '../services/password';

const User = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    index: true
  },
  email: {
    type: String,
    unique: true,
    required: true,
    index: true
  },
  username: {
    type: String,
    unique: true,
    required: true,
    index: true
  },
  password: {
    type: String,
    required: true
  },
  acceptTerms: {
    type: Boolean,
    required: true
  },
  role: {
    type: String,
    default: UserRole.GUEST,
    enum: [UserRole.GUEST, UserRole.ADMIN]
  },
  status: {
    type: String,
    default: UserStatus.INACTIVE,
    enum: [UserStatus.INACTIVE, UserStatus.BANNED, UserStatus.ACTIVE]
  },
  twoFactorAuthenticationCode: {
    type: String,
    default: null,
  },
  isTwoFactorAuthenticationEnabled: {
    type: Boolean,
    default: false,
  },
  verificationToken: {
    token: String,
    expires: Date
  },
  verified: Date,
  resetToken: {
    token: String,
    expires: Date
  },
  passwordReset: Date
}, {
  timestamps: true,
  toJSON: {
    virtuals: true,
    transform(doc, ret) {
      // remove these props when object is serialized
      delete ret.__v;
      delete ret.password;
      delete ret.verificationToken;
      delete ret.resetToken;
      delete ret.twoFactorAuthenticationCode;
      // transform
      ret.id = ret._id;
      delete ret._id;
    }
  }
});

User.pre('save', async function (done) {
  if (this.isModified('password')) {
    const hashed = await Password.toHash(this.get('password'));
    this.set('password', hashed);
  }
  done();
});

User.virtual('isVerified').get(function (this: { verified: Date; passwordReset: Date }): boolean {
  return !!(this.verified || this.passwordReset);
});

export default mongoose.model<IUser & mongoose.Document>('User', User);
