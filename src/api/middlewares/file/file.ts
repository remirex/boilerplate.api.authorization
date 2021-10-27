import util from 'util';
import multer from 'multer';
import GridFsStorage from 'multer-gridfs-storage';
  import mongooseLoader from '../../../loaders/mongoose';

import config from '../../../config';

const maxSize = 2 * 1024 * 1024; // max 2MB

const fileFilter = (req: any,file: any,cb: any) => {
  if(file.mimetype === "image/jpg"  ||
    file.mimetype ==="image/jpeg"  ||
    file.mimetype ===  "image/png"){

    cb(null, true);
  }else{
    cb(new Error("Image uploaded is not of type jpg/jpeg or png"),false);
  }
}

const mongoConnection = mongooseLoader();

const storage = new GridFsStorage({
  db: mongoConnection,
  file(req: Express.Request, file: Express.Multer.File): any {
    return {
      bucketName: 'photos',
      filename: `${Date.now()}-${config.appName}-${file.originalname}`,
    };
  },
});

const uploadFile = multer(
  {
    storage: storage,
    limits: {
      fileSize: maxSize
    },
    fileFilter: fileFilter,
  }
).single('file');

export const uploadFileMiddleware = util.promisify(uploadFile);
