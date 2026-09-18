# Worked example: one endpoint, before and after

This file walks one small endpoint from unsafe to safe, so the rules, the tiers and the
self-check in `standards/claude-security-guidance.md` can be seen working on real code. The
code is Python with Flask and Flask-Login, but every fix has the same shape in any stack.

## The task

"Add an endpoint that returns one invoice by its id."

## First draft

```python
from flask_login import current_user

@app.get("/invoices/<invoice_id>")
def get_invoice(invoice_id):
    log.info(f"invoice {invoice_id} requested by {current_user.email}")
    row = db.execute(
        f"SELECT * FROM invoices WHERE id = {invoice_id}"
    ).fetchone()
    if row is None:
        return {"error": f"no invoice {invoice_id}"}, 404
    return dict(row)
```

It works, and every test that asks for a real invoice passes. It has five problems.

## Step 1: pick the tier

The endpoint decides who may read which invoice, so doing it right means a sign-in check and
an owner check. Authentication and authorization are both on the SEC-DES-01 list, so this is
**tier 3**, even though the change is one short function.

Tier 3 means: name the rules that apply, write the tests SEC-TEST-01 asks for, ask whether a
threat model has run, and say the change needs a human security review.

## Step 2: find what is wrong

1. **The id goes straight into the SQL text** (SEC-INJ-01). A request for
   `/invoices/0 OR 1=1` returns the first invoice in the table, whoever owns it.
2. **Nothing checks that the invoice belongs to the caller** (SEC-WEB-02). Any signed-in user
   can read any invoice by counting upward from 1.
3. **Nothing checks that there is a caller at all** (SEC-AUTH-01). With no session,
   `current_user` is Flask-Login's anonymous user, which has no `email`, so the request dies
   with a 500 instead of a 401.
4. **The log line holds an email address** (PRIV-LOG-01), and it writes the raw URL value into
   the log text, so an id carrying an encoded line break can forge a fake log line
   (SEC-LOG-02).
5. **`SELECT *` sends every column back** (SEC-API-03), including `owner_id` and any internal
   column added to the table later, with no one deciding it should be public.

## Step 3: the safe version

```python
from flask_login import LoginManager, current_user, login_required

login_manager = LoginManager(app)

@login_manager.unauthorized_handler
def unauthorized():
    return {"error": "sign in required"}, 401

@app.get("/invoices/<int:invoice_id>")
@login_required
def get_invoice(invoice_id: int):
    row = db.execute(
        "SELECT id, number, issued_on, amount, currency, status"
        " FROM invoices WHERE id = %s AND owner_id = %s",
        (invoice_id, current_user.id),
    ).fetchone()
    log.info("invoice_read", extra={"user_ref": user_ref(current_user.id)})
    if row is None:
        return {"error": "not found"}, 404
    return dict(row)
```

What changed, one line each:

- `<int:invoice_id>` rejects anything that is not a number before the function runs, and
  `%s` with a separate tuple keeps the value out of the SQL text (SEC-INJ-01).
- `AND owner_id = %s` ties the record to the caller inside the same query (SEC-WEB-02).
- `@login_required` runs before the function (SEC-AUTH-01). The handler above it keeps the
  refusal a 401 for this API even once the app sets a `login_view`, which would otherwise turn
  it into a redirect to the login page.
- The log line is a fixed event name with one field, a keyed hash of the user id from the
  team's `user_ref` helper, and no raw id or email (PRIV-LOG-01, SEC-LOG-02).
- The query names its columns, so the response holds exactly those (SEC-API-03).

The 404 is the same whether the invoice does not exist or belongs to someone else. A
different answer for the two cases tells an attacker which ids are real.

## Step 4: the attack tests

SEC-TEST-01 asks for one test per case the change touches, each named for its attack.

```python
INVOICE_FIELDS = {"id", "number", "issued_on", "amount", "currency", "status"}

def test_invoice_without_login_is_401(client):
    assert client.get("/invoices/1").status_code == 401

def test_invoice_of_another_user_is_404(client, alice, bob_invoice):
    client.login(alice)
    assert client.get(f"/invoices/{bob_invoice.id}").status_code == 404

def test_invoice_id_with_sql_is_refused(client, alice):
    client.login(alice)
    assert client.get("/invoices/0%20OR%201=1").status_code == 404

def test_invoice_response_has_only_listed_fields(client, alice, alice_invoice):
    client.login(alice)
    body = client.get(f"/invoices/{alice_invoice.id}").get_json()
    assert set(body) == INVOICE_FIELDS
```

To prove a test is real, remove the guard it defends and watch that test go red:

- remove `@login_required`, and the first test gets a 500, not a 401
- remove the `owner_id` clause, and the second test gets Bob's invoice
- replace the column list with `*`, and the fourth test sees `owner_id`

The third test has two guards behind it, the `int` converter and the `%s` parameter, and it
stays green while either one holds. Remove both to see it go red.

## Step 5: the self-check, as it should be reported

The check runs once, after the last edit, over the changed lines. For the safe version the
whole report is one line:

> Tier 3, self-check clean. Has a threat model run for this? It needs a human security review.

For the first draft it would have been:

> Tier 3. Failed: 1 (id in SQL text), 2 (no sign-in check, no owner check), 3 (email in log,
> raw value in log text), 6 (no attack tests). Has a threat model run for this? It needs a
> human security review.

The author fixes those and reports. The check does not run a second time over the fixes.
Problem 5, `SELECT *`, is a review item under SEC-API-03. The six questions are the fast
last look, and the reviewer is the one who reads which fields a response sends.
