// Deliberately insecure: a TypeScript assertion does not make the body an allowlist.
async function typed(req: Request) {
  await Account.create(req.body as AccountInput); // EXPECT SEC-API-02
}
