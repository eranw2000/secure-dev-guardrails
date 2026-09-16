await Account.create(req.body, { fields: ["name"] });
await Account.update(req.body, {
  where: { id },
  fields: ["name"],
});
