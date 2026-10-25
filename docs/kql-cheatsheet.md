# KQL Cheat Sheet (from the hunts)

| Need | Operator / pattern | Example |
|---|---|---|
| Filter rows | `where` | `where IPAddress == "1.2.3.4"` |
| Case-insensitive match | `=~` | `where UserPrincipalName =~ "user@x.org"` |
| Whole-term search | `has` | `where UserPrincipalName has "mark"` |
| Time window | `between` | `where TimeGenerated between (datetime(...) .. datetime(...))` |
| Pick columns | `project` | `project TimeGenerated, IPAddress` |
| Count / group | `summarize ... by` | `summarize count() by IPAddress` |
| Conditional count | `countif()` | `countif(ResultType == "0")` |
| Sort | `order by` | `order by TimeGenerated asc` |
| Parse JSON | `parse_json()` | `parse_json(RawEventData).Parameters` |
| Array → rows | `mv-expand` | `mv-expand Param = parse_json(RawEventData).Parameters` |
| Previous row | `serialize` + `prev()` | `extend Gap = TimeGenerated - prev(TimeGenerated)` |
| Time difference | `datetime_diff()` | `datetime_diff('second', t2, t1)` |
| Variable | `let` | `let sid = "...";` |
| Single value from a query | `toscalar()` | `let t = toscalar(... | summarize min(TimeGenerated));` |
| Combine tables | `union` | `union (SigninLogs | ...), (CloudAppEvents | ...)` |

## Gotchas

- `summarize` keeps only the `by` columns and the calculated ones; a later `project` of other columns fails.
- Time column names differ: `TimeGenerated` (SigninLogs) vs `Timestamp` (CloudAppEvents, EmailEvents).
- IP column names differ: `IPAddress` vs `SenderIPv4` (EmailEvents).
- The portal may display local time; timestamps in the data are UTC.

## Entra ID sign-in ResultType codes

| Code | Meaning |
|---|---|
| `0` | Success |
| `50074` | Strong authentication (MFA) required, not completed |
| `500121` | Authentication failed during strong authentication |
| `50126` | Invalid username or password |
| `50140` | "Keep me signed in" interrupt (not an MFA push) |
