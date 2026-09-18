// Insecure on purpose: every marked line sends a request value to an outgoing request.
const axios = require("axios");
const got = require("got");
const https = require("https");

app.get("/preview", async (req, res) => {
  const u = req.query.url;
  const page = await fetch(u); // EXPECT SEC-WEB-03
  await axios.get(req.body.target); // EXPECT SEC-WEB-03
  https.get(req.params.host); // EXPECT SEC-WEB-03
  await got(`https://${req.query.host}/status`); // EXPECT SEC-WEB-03
  res.send(page.status);
});
