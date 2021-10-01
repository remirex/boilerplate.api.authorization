import HttpException from "./HttpException";

class NotAllowedException extends HttpException {
  constructor() {
    super(405, 'Not allowed');
  }
}

export default NotAllowedException;
