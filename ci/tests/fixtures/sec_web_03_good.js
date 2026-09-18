// Must stay quiet: fixed URLs, request values in a non-URL position, and a validating helper.
const axios = require("axios");
const { validateOutboundUrl } = require("./net");

app.get("/status", async (req, res) => {
  await fetch("https://api.example.com/status");
  await fetch(validateOutboundUrl(req.query.url));
  await axios.get("https://api.example.com/search", { params: { q: req.query.q } });
  res.send("ok");
});
