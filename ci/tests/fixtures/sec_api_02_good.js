// The safe shapes, and look-alikes that are not model writes. Nothing here is SEC-API-02.
async function safe(req, res, service) {
  const { displayName, timezone } = req.body;
  await Account.create({ displayName, timezone, owner: req.user.id });
  await Account.create(req.body, { fields: ["displayName", "timezone"] });
  await Account.update(req.body, {
    where: { id: req.params.id },
    fields: ["displayName"],
  });
  await prisma.account.update({ where: { id: req.params.id }, data: { displayName } });
  const dto = Object.assign({}, req.body);
  const copy = Object.assign(draft, req.body);
  await service.create(req.body);
  const failure = new Error(req.body);
  res.set(req.body);
  await axios.post(url, { data: req.body });
  res.json({ displayName, timezone });
}

async function builtIns(req, account, otherId) {
  const proto = Object.create(req.body);
  const link = new URL(req.body);
  const pattern = new RegExp(req.body);
  Object.assign(account, req.body);
  account = await Account.findById(otherId);
  await account.save();
}

async function setThenReplaced(req, doc, otherId) {
  doc.set(req.body);
  doc = await Account.findById(otherId);
  await doc.save();
}
