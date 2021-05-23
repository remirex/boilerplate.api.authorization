mongodb.document.insertMany([
  // MongoDB adds the _id field with an ObjectId if _id is not present
  {
    name: 'Sample Document', tags: ['docker', 'containers', 'javascript', 'typescript']
  },
  {
    name: 'Another sample document', tags: ['development', 'compose']
  },
]);
