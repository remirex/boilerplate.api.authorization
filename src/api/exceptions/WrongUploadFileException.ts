import HttpException from "./HttpException";

class WrongUploadFileException extends HttpException {
  constructor(err) {
    super(400, `File could not be uploaded: ${err}`);
  }
}

export default WrongUploadFileException;
