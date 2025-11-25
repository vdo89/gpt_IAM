package intent.schema

import rego.v1
import data.intent.lib

deny[error] {
  some vrf_name
  allowed := data.allowed_exports[vrf_name]
  not lib.vrf_names[vrf_name]
  error := {
    "msg": lib.strict_hint(sprintf("allowed_exports entry references unknown VRF %s", [vrf_name])),
    "path": sprintf("data.allowed_exports.%s", [vrf_name]),
  }
}
