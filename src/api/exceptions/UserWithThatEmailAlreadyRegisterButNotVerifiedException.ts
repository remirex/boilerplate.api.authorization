import HttpException from "./HttpException";

class UserWithThatEmailAlreadyRegisterButNotVerifiedException extends HttpException {
  constructor() {
    super(400, 'Register but not verified, please check your email for verification instructions');
  }
}

export default UserWithThatEmailAlreadyRegisterButNotVerifiedException;
