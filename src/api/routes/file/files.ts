import {NextFunction, Request, Response, Router} from 'express';
import {Container} from 'typedi';
import {Logger} from 'winston';
import middleware from "../../middlewares";

import FileService from "../../../services/fileSystem/file";

const route = Router();

export default (app: Router) => {
  app.use('/images', route);

  const logger: Logger = Container.get('logger');
  const fileServiceInstance = Container.get(FileService);

  route.post('/upload', async (req: Request, res: Response, next: NextFunction) => {
    logger.debug('Calling Upload File endpoint');
    try {
      await fileServiceInstance.uploadFile(req, res, req.file!);
      if (req.file === undefined) return res.status(400).json({ message: 'Please upload a file.' });
      return res.status(200).json({message: 'success'});
    } catch (err) {
      logger.error('Error when trying upload file: ', err);
      return next(err);
    }
  });

  route.get('/all', async (req: Request, res: Response, next: NextFunction) => {
    logger.debug('Calling Get the list of image object (in an array) endpoint');
    try {
      const images = await fileServiceInstance.getAllPhotos();
      return res.status(200).json(images);
    } catch (err) {
      logger.error('Error when trying read images from collection: ', err);
      return next(err);
    }
  });

  route.get('/single/:filename?', async (req: Request, res: Response, next: NextFunction) => {
    logger.debug('Calling Get a single image object endpoint');
    try {
      const filename = req.params.filename;
      if (!filename) return res.status(400).json({ message: 'filename is required.' });
      const file = await fileServiceInstance.getSingleFile(filename);
      return res.status(200).json(file);
    } catch (err) {
      logger.error('Error when trying read single image: ', err);
      return next(err);
    }
  });

  route.get('/image/:filename?', async (req: Request, res: Response, next: NextFunction) => {
    logger.debug('Calling Get actual image object endpoint');
    try {
      const filename = req.params.filename;
      if (!filename) return res.status(400).json({ message: 'filename is required.' });
      return await fileServiceInstance.getActualFile(filename,res);
    } catch (err) {
      logger.error('Error when trying read actual image: ', err);
      return next(err);
    }
  });

  route.delete('/delete/:id', async (req: Request, res: Response, next: NextFunction) => {
    logger.debug('Calling Delete File endpoint');
    try {
      const fileId = req.params.id;
      const response = await fileServiceInstance.deleteFile(fileId);
      return res.status(200).json(response);
    } catch (err) {
      logger.error('Error when trying delete file: ', err);
      return next(err);
    }
  });
}
