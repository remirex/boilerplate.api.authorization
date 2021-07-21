export interface IRefreshToken {
  id: string;
  token: string;
  createdByIp: string;
  revokedByIp: string;
  isActive: boolean;
  revoked: number;
  replacedByToken: string;
}
