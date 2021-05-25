export enum EmailTemplates {
  VERIFY_EMAIL = 'VERIFY_EMAIL',
  ALREADY_REGISTERED = 'ALREADY_REGISTERED',
  RESET_PASSWORD = 'RESET_PASSWORD',
}

export enum UserStatus {
  ACTIVE = 'ACTIVE',
  INACTIVE = 'INACTIVE',
  BANNED = 'BANNED',
}

export enum UserRole {
  ADMIN = 'ADMIN',
  GUEST = 'GUEST',
}
