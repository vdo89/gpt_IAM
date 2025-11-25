package intent.validation

import rego.v1

# METADATA
# schemas:
#   - input: schema["intent.schema.json"]
#   - data.allowed_exports: schema["allowed_exports.schema.json"]

import data.intent.schema
import data.intent.naming
import data.intent.routing
import data.intent.vni
import data.intent.exposure

# Entry point that aggregates all category-specific denies so conftest can
# continue to evaluate a single package.
deny[err] {
  err := schema.deny[_]
}

deny[err] {
  err := naming.deny[_]
}

deny[err] {
  err := routing.deny[_]
}

deny[err] {
  err := vni.deny[_]
}

deny[err] {
  err := exposure.deny[_]
}
