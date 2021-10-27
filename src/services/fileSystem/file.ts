import {Inject, Service} from 'typedi';
import {Get, Path, Post, Request, Route, Tags, UploadedFile, Delete} from 'tsoa';
import mongoose from "mongoose";

import {uploadFileMiddleware} from "../../api/middlewares/file/file";
import NotFoundException from "../../api/exceptions/NotFoundException";
import NotAllowedException from "../../api/exceptions/NotAllowedException";

const conn = mongoose.connection;
let gfs;
const gridStream = require('gridfs-stream');
conn.once('open', () => {
  // initialize our stream
  gfs = gridStream(conn.db, mongoose.mongo);
  gfs.collection('photos');
});

@Tags("File")
@Route("/images")
@Service()
export default class FileService {
  constructor(
    @Inject('logger') private logger,
  ) {}

  /**
   * Upload image, only jpeg, jpe and png. max file size 2MB
   * @param req
   * @param res
   * @param file
   */
  @Post("/upload")
  public async uploadFile(@Request() req, @Request() res, @UploadedFile() file: Express.Multer.File) {
    await uploadFileMiddleware(req, res);
  }

  /**
   * Return all photos
   */
  @Get("/all")
  public async getAllPhotos() {
    const images = await gfs.files.find().toArray();
    console.log(images);
    if (images.length == 0) throw new NotFoundException();
    return images;
  }

  /**
   * Image details
   * @param filename
   */
  @Get("/single/{filename}")
  public async getSingleFile(@Path() filename: string) {
    const singleFile = await gfs.files.findOne({ filename });
    if (!singleFile || singleFile.length == null) throw new NotFoundException();
    return singleFile;
  }

  /**
   * Get actual image
   * @param filename
   * @param response
   */
  @Get("/image/{filename}")
  public async getActualFile(@Path() filename: string, @Request() response) {
    const singleFile = await gfs.files.findOne({ filename });
    if (!singleFile || singleFile.length == null) throw new NotFoundException();

    const readStream = gfs.createReadStream(singleFile.filename);
    return readStream.pipe(response);
  }

  /**
   * Delete file
   * @param id
   */
  @Delete("/delete/{id}")
  public async deleteFile(@Path() id: string) {
    const validId = FileService.isValid(id);
    if (!validId) throw new NotAllowedException();
    await gfs.remove({ _id: id, root: 'photos'});
    return null;
  }

  // helper
  private static isValid(id: string) {
    return mongoose.Types.ObjectId.isValid(id);
  }
}
