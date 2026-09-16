const a = Object.create(req.body);
const b = Object.create(req.body, { x: { value: 1 } });
