import HttpException from "./HttpException";

class NotVerifiedException extends HttpException {
  constructor() {
    super(400, 'Account not verified yet');
  }
}

export default NotVerifiedException;
