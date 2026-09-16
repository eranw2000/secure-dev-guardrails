// Deliberately insecure: each marked line is a SEC-API-02 case the semgrep rules must report.
app.post("/accounts/:id", async (req, res) => {
  Object.assign(account, req.body); // EXPECT SEC-API-02
  await Account.create(req.body); // EXPECT SEC-API-02
  await Account.create({ ...req.body }); // EXPECT SEC-API-02
  await Account.create({ ...req.body, owner: req.user.id }); // EXPECT SEC-API-02
  await Account.insertMany(req.body); // EXPECT SEC-API-02
  await Account.findByIdAndUpdate(req.params.id, req.body, { new: true }); // EXPECT SEC-API-02
  await Account.findOneAndUpdate({ _id: req.params.id }, req.body); // EXPECT SEC-API-02
  await Account.updateOne({ _id: req.params.id }, req.body); // EXPECT SEC-API-02
  await Account.updateMany({ team: req.params.team }, req.body); // EXPECT SEC-API-02
  await Account.update(req.body, { where: { id: req.params.id } }); // EXPECT SEC-API-02
  await Account.bulkCreate(req.body); // EXPECT SEC-API-02
  await prisma.account.create({ data: req.body }); // EXPECT SEC-API-02
  await prisma.account.update({ where: { id: req.params.id }, data: req.body }); // EXPECT SEC-API-02
  await prisma.account.upsert({ where: { id: req.params.id }, create: req.body, update: {} }); // EXPECT SEC-API-02
  res.sendStatus(204);
});
