// The safe shapes of the same operations. Nothing here may be reported as SEC-API-02.
app.post("/accounts/:id", async (req, res) => {
  const { displayName, timezone } = req.body;
  await Account.create({ displayName, timezone, owner: req.user.id });
  await Account.create(req.body, { fields: ["displayName", "timezone"] });
  await Account.update(req.body, { where: { id: req.params.id }, fields: ["displayName"] });
  await prisma.account.update({ where: { id: req.params.id }, data: { displayName } });
  logger.info({ body: req.body.displayName });
  res.json({ displayName, timezone });
});
