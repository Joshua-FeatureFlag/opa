# OPA

The permission system for the featureflagging system

You can test policies here: https://play.openpolicyagent.org/

INPUT
```json
{
    "role": "org_reader",
    "action": "read",
    "organization": "org1",
    "environment": "dev",
    "flag": "flag2"
}
```

Copy the `data.json` into the DATA section
Copy the `permission_engine.rego` into the policy section
Change the INPUT as desired for testing.