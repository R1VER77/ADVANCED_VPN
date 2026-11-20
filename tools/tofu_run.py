"""Run the pinned OpenTofu on one server's workspace (docs/INSTALL_AND_SETUP_PLAN.md
phase 3, docs/GEMMA_SETUP_FLOW.md step 1). Standard library only.

- One workspace per server, under the user's data directory: a root module naming the
  provider and the repository's module, the variables as JSON, the module's lock file
  copied read-only (`init -lockfile=readonly`: only the pinned provider hashes are accepted).
- State and saved plans are encrypted by OpenTofu itself (AES-GCM, key from PBKDF2 over a
  32-byte secret the caller supplies); nothing is written in the clear. The caller decides
  where that secret lives (the operator's hardware vault in production).
- `plan` saves the exact plan and returns what it would add, change and destroy; `apply`
  applies only that saved plan, after the person approved its summary.
"""

import json
import os
from pathlib import Path
import shutil
import subprocess

import tofu

MODULES = Path(__file__).resolve().parents[1] / "tofu" / "modules"
# Per module: the provider's source (declared in the root too, or OpenTofu would infer a
# default namespace the read-only lock file refuses) and its configuration.
PROVIDERS = {
    "azure-server": (
        'azurerm = { source = "hashicorp/azurerm" }',
        'provider "azurerm" {\n  features {}\n  subscription_id = %(subscription)s\n}\n',
    ),
    "oci-server": (
        'oci = { source = "oracle/oci" }',
        'provider "oci" {\n  config_file_profile = %(profile)s\n  region = %(region)s\n}\n',
    ),
}


class TofuRunError(RuntimeError):
    """A tofu step failed; the message is its last error line."""


def operator_key(vault, controller):
    """The state key from the operator's vault (one PIN + touch), through the controller's
    pipe: `controller` is its argv (cloud.controller()). Held in memory only."""
    r = subprocess.run([*controller, "--json", "state-key", "--vault", str(vault)], capture_output=True, text=True,
                       timeout=300, check=False)  # fmt: skip
    if r.returncode != 0:
        raise TofuRunError("the vault did not release the state key: " + (r.stderr.strip().splitlines() or ["?"])[-1])
    key = bytes.fromhex(json.loads(r.stdout.strip().splitlines()[-1])["key"])
    if len(key) != 32:
        raise TofuRunError("wrong state key length")
    return key


def workspaces():
    """Where each server's workspace lives (user data, private)."""
    return tofu.home().parent / "workspaces"


def _hcl(value):
    return json.dumps(value)  # a JSON string is a valid HCL string literal


def encryption(key):
    """OpenTofu's encryption config for one run: AES-GCM over state and plans, key from
    PBKDF2 over the caller's 32-byte secret. Passed in the environment (TF_ENCRYPTION),
    never written next to the state it protects."""
    if len(key) != 32:
        raise TofuRunError("state key must be 32 bytes")
    return (
        'key_provider "pbkdf2" "k" {\n  passphrase = %s\n}\n'
        'method "aes_gcm" "m" {\n  keys = key_provider.pbkdf2.k\n}\n'
        "state {\n  method = method.aes_gcm.m\n  enforced = true\n}\n"
        "plan {\n  method = method.aes_gcm.m\n  enforced = true\n}\n" % _hcl(key.hex())
    )


def workspace(name, module, variables, provider):
    """Write (or refresh) the workspace for `name`; returns its directory. No secret is written."""
    if module not in PROVIDERS:
        raise TofuRunError("no module %s" % module)
    d = workspaces() / name
    d.mkdir(mode=0o700, parents=True, exist_ok=True)
    source = MODULES / module
    root = "terraform {\n  required_providers {\n    %s\n  }\n}\n\n" % PROVIDERS[module][0]
    root += PROVIDERS[module][1] % {k: _hcl(v) for k, v in provider.items()}
    root += '\nmodule "server" {\n  source = %s\n' % _hcl(str(source))
    root += "".join("  %s = var.%s\n" % (k, k) for k in sorted(variables))
    root += "}\n\n"
    root += "".join('variable "%s" {}\n' % k for k in sorted(variables))
    root += '\noutput "server" {\n  value = module.server\n}\n'
    _write(d / "main.tf", root)
    _write(d / "terraform.tfvars.json", json.dumps(variables, indent=1, sort_keys=True))
    shutil.copyfile(source / ".terraform.lock.hcl", d / ".terraform.lock.hcl")
    return d


def _write(path, text):
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(text)
    tmp.chmod(0o600)
    tmp.replace(path)


def run(d, *args, key=None, run=subprocess.run):
    """`tofu ARGS` in workspace `d` (state and plans encrypted with `key`); returns stdout."""
    env = dict(os.environ, TF_IN_AUTOMATION="1", TF_INPUT="0",
               TF_PLUGIN_CACHE_DIR=str(tofu.home().parent / "plugins"))  # fmt: skip
    if key is not None:
        env["TF_ENCRYPTION"] = encryption(key)
    Path(env["TF_PLUGIN_CACHE_DIR"]).mkdir(mode=0o700, parents=True, exist_ok=True)
    r = run([str(tofu.ensure()), *args, "-no-color"], cwd=d, env=env, capture_output=True, text=True,
            timeout=1800, check=False)  # fmt: skip
    if r.returncode != 0:
        lines = [x for x in (r.stderr or r.stdout).splitlines() if x.strip()]
        raise TofuRunError(next((x for x in lines if "Error" in x), lines[-1] if lines else "tofu failed"))
    return r.stdout


def init(d, key):
    """Install only the pinned provider (the lock file is read-only)."""
    run(d, "init", "-lockfile=readonly", "-input=false", key=key)


def plan(d, key, destroy=False):
    """Save the exact plan; return its summary: {action: [resource addresses]}."""
    run(d, "plan", "-input=false", "-out=plan.bin", *(["-destroy"] if destroy else []), key=key)
    shown = json.loads(run(d, "show", "-json", "plan.bin", key=key))
    summary = {}
    for change in shown.get("resource_changes", []):
        actions = "/".join(change["change"]["actions"])
        if actions != "no-op":
            summary.setdefault(actions, []).append(change["address"])
    return summary


def apply(d, key):
    """Apply only the saved plan; returns the outputs."""
    run(d, "apply", "-input=false", "plan.bin", key=key)
    return json.loads(run(d, "output", "-json", key=key))
