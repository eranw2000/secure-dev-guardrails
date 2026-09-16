// Deliberately insecure: each marked line is a SEC-API-02 case the semgrep rules must report.
// One case per pattern and per allowed name, so deleting any of them turns a check red.
async function writes(req, res, ctx) {
  await Account.create(req.body); // EXPECT SEC-API-02
  await Account.create(req.body, { transaction }); // EXPECT SEC-API-02
  await Account.create({ ...req.body, owner: req.user.id }); // EXPECT SEC-API-02
  await Account.insertMany(req.body); // EXPECT SEC-API-02
  await Account.bulkCreate(request.body); // EXPECT SEC-API-02
  const draft = db.Account.build(ctx.request.body); // EXPECT SEC-API-02
  await Account.update(req.body, { where: { id: req.params.id } }); // EXPECT SEC-API-02
  await Account.findByIdAndUpdate(req.params.id, req.body, { new: true }); // EXPECT SEC-API-02
  await Account.findOneAndUpdate({ _id: req.params.id }, req.body); // EXPECT SEC-API-02
  await Account.updateOne({ _id: req.params.id }, req.body); // EXPECT SEC-API-02
  await Account.updateMany({ team: req.params.team }, req.body); // EXPECT SEC-API-02
  const fresh = new Account(req.body); // EXPECT SEC-API-02
  await prisma.account.create({ data: req.body }); // EXPECT SEC-API-02
  await prisma.account.update({ where: { id: req.params.id }, data: req.body }); // EXPECT SEC-API-02
  await prisma.account.createMany({ data: req.body }); // EXPECT SEC-API-02
  await prisma.account.updateMany({ where: { team: req.params.team }, data: req.body }); // EXPECT SEC-API-02
  await prisma.account.upsert({ where: { id: req.params.id }, create: req.body, update: {} }); // EXPECT SEC-API-02
  await prisma.account.upsert({ where: { id: req.params.id }, create: {}, update: req.body }); // EXPECT SEC-API-02
}

function assignThenSave(req, account) {
  Object.assign(account, req.body); // EXPECT SEC-API-02
  account.save();
}

async function assignThenAwaitSave(req, account) {
  Object.assign(account, req.body); // EXPECT SEC-API-02
  await account.save();
}

function setThenSave(req, doc) {
  doc.set(req.body); // EXPECT SEC-API-02
  doc.save();
}

async function setThenAwaitSave(req, doc) {
  doc.set(req.body); // EXPECT SEC-API-02
  await doc.save();
}
