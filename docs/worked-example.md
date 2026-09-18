# Worked example: one endpoint, before and after

This file walks one small endpoint from unsafe to safe, so the rules, the tiers and the
self-check in `standards/claude-security-guidance.md` can be seen working on real code. The
code is Python with Flask, but every fix has the same shape in any stack.

## The task

"Add an endpoint that returns one invoice by its id."

## First draft

```python
@app.get("/invoices/<invoice_id>")
def get_invoice(invoice_id):
    user = current_user()
    log.info(f"invoice {invoice_id} requested by {user.email}")
    row = db.execute(
        f"SELECT * FROM invoices WHERE id = {invoice_id}"
    ).fetchone()
    if row is None:
        return {"error": f"no invoice {invoice_id}"}, 404
    return dict(row)
```

It works, and every test that asks for a real invoice passes. It has five problems.

## Step 1: pick the tier

The endpoint takes an id from the URL (outside input) and returns billing data about a
customer (personal data). That is **tier 2**. It does not change how anyone signs in or what
roles exist, so it is not tier 3.

Tier 2 means: name the rules that apply, and write a test that attacks each input path.

## Step 2: find what is wrong

1. **The id goes straight into the SQL text** (SEC-INJ-01). A request for
   `/invoices/0 OR 1=1` returns the first invoice in the table, whoever owns it.
2. **Nothing checks that the invoice belongs to the caller** (SEC-WEB-02). Any signed-in user
   can read any invoice by counting upward from 1.
3. **Nothing checks that there is a caller at all** (SEC-AUTH-01). With no session,
   `current_user()` returns `None` and the log line crashes with a 500 instead of a 401.
4. **The log line holds an email address** (PRIV-LOG-01), and it writes the raw URL value into
   the log text, so a crafted id can forge a fake log line (SEC-LOG-02).
5. **`SELECT *` sends every column back** (SEC-API-03), including any internal column added
   to the table later, with no one deciding it should be public.

## Step 3: the safe version

```python
INVOICE_FIELDS = ("id", "number", "issued_on", "amount", "currency", "status")

@app.get("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id: int):
    user = current_user()
    row = db.execute(
        "SELECT id, number, issued_on, amount, currency, status"
        " FROM invoices WHERE id = %s AND owner_id = %s",
        (invoice_id, user.id),
    ).fetchone()
    log.info("invoice_read", extra={"invoice_id": invoice_id, "user_id": user.id})
    if row is None:
        return {"error": "not found"}, 404
    return {field: row[field] for field in INVOICE_FIELDS}
```

What changed, one line each:

- `<int:invoice_id>` rejects anything that is not a number before the function runs, and
  `%s` with a separate tuple keeps the value out of the SQL text (SEC-INJ-01).
- `AND owner_id = %s` ties the record to the caller inside the same query (SEC-WEB-02).
- `@login_required` answers 401 before any work is done (SEC-AUTH-01).
- The log line is a fixed event name with the values as fields, and it carries the user id,
  not the email (PRIV-LOG-01, SEC-LOG-02).
- The query and the response both name their columns (SEC-API-03).

The 404 is the same whether the invoice does not exist or belongs to someone else. A
different answer for the two cases tells an attacker which ids are real.

## Step 4: the attack tests

Tier 2 asks for a test per input path that tries to break it (SEC-TEST-01). Each test names
the attack, and each one fails if its guard is removed.

```python
def test_invoice_without_login_is_401(client):
    assert client.get("/invoices/1").status_code == 401

def test_invoice_of_another_user_is_404(client, alice, bob_invoice):
    client.login(alice)
    assert client.get(f"/invoices/{bob_invoice.id}").status_code == 404

def test_invoice_id_with_sql_is_rejected(client, alice):
    client.login(alice)
    assert client.get("/invoices/0%20OR%201=1").status_code == 404

def test_invoice_response_has_only_listed_fields(client, alice, alice_invoice):
    client.login(alice)
    body = client.get(f"/invoices/{alice_invoice.id}").get_json()
    assert set(body) == set(INVOICE_FIELDS)
```

To prove a test is real, delete the guard it defends (the `owner_id` clause for the second
one) and watch that test, and only that test, go red.

## Step 5: the self-check, as it should be reported

The check runs once, after the last edit, over the changed lines. For the safe version the
whole report is one line:

> Tier 2, self-check clean.

For the first draft it would have been:

> Tier 2. Failed: 1 (id in SQL text), 2 (no owner check), 3 (email in log), 6 (no attack tests).

The author fixes those four and reports. The check does not run a second time over the fixes.
Problem 5, `SELECT *`, is a review item under SEC-API-03. The six questions are the fast
last look, and the reviewer is the one who reads which fields a response sends.
