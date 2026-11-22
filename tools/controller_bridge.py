"""Caller-bound controller plans and operation tracking, independent of D-Bus transport.

Transport code supplies authenticated bus identities and performs Polkit checks.
The adapter supplies authoritative checks/actions. Neither GUI strings nor model
output can select a command, pathname, environment, PIN, provider credential or key.
"""

import base64
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
import secrets
import threading
import time

MAX_REQUEST = 1_500_000
MAX_BUNDLE = 1024 * 1024
MAX_KEY = 8192
MAX_PLANS = 32
MAX_PER_CALLER = 4
PLAN_TTL = 90
OP_TTL = 300
ID = re.compile(r"[a-f0-9]{64}\Z")
BUS_NAME = re.compile(r":[A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)+\Z")


class Refused(ValueError):
    """A fixed public refusal. Never embed raw provider, subprocess or secret text."""


@dataclass(frozen=True)
class Caller:
    """All fields come from the system bus driver, never method parameters."""

    bus_id: str
    name: str
    uid: int

    def __post_init__(self):
        if (
            not isinstance(self.bus_id, str)
            or not re.fullmatch(r"[a-fA-F0-9]{32}", self.bus_id)
            or not isinstance(self.name, str)
            or len(self.name) > 255
            or not BUS_NAME.fullmatch(self.name)
            or type(self.uid) is not int
            or not 0 <= self.uid < 2**32
        ):
            raise Refused("invalid_caller")


def canonical(value):
    """Canonical action bytes are the sole input to the action digest."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def no_duplicates(pairs):
    """Duplicate JSON keys must not get different meanings across boundaries."""
    result = {}
    for key, value in pairs:
        if key in result:
            raise Refused("duplicate_action_field")
        result[key] = value
    return result


def blob(value, maximum):
    """Accept bounded canonical base64 bytes, never an arbitrary user file path."""
    if not isinstance(value, str) or not value or len(value) > ((maximum + 2) // 3) * 4:
        raise Refused("invalid_import_bytes")
    try:
        raw = base64.b64decode(value, validate=True)
    except ValueError:
        raise Refused("invalid_import_bytes") from None
    if not raw or len(raw) > maximum or base64.b64encode(raw).decode() != value:
        raise Refused("invalid_import_bytes")
    return raw


def action(raw):
    """Strict allowlist and exact fields before any privileged adapter is invoked."""
    if not isinstance(raw, str) or len(raw.encode()) > MAX_REQUEST:
        raise Refused("invalid_action_size")
    try:
        request = json.loads(raw, object_pairs_hook=no_duplicates)
    except (ValueError, RecursionError):
        raise Refused("invalid_action_json") from None
    if not isinstance(request, dict) or not isinstance(request.get("action"), str):
        raise Refused("invalid_action")
    name = request["action"]
    fields = {"action"}
    if name == "connect":
        fields.add("scope")
        if request.get("scope") not in ("applications", "whole-device"):
            raise Refused("invalid_connection_scope")
    elif name in ("disconnect", "retry", "unlock", "request_device"):
        pass
    elif name == "repair":
        fields.update(("repair", "selector"))
        repair, selector = request.get("repair"), request.get("selector")
        if repair not in ("install_udev_rule", "yubikey_enable_fido2"):
            raise Refused("unknown_repair")
        if selector is not None and (
            not isinstance(selector, str)
            or not re.fullmatch(r"/dev/hidraw[0-9]{1,4}" if repair == "install_udev_rule" else r"[0-9]{1,16}", selector)
        ):
            raise Refused("invalid_device_selector")
    elif name == "key_software":
        fields.add("mode")
        if request.get("mode") not in ("install", "upgrade"):
            raise Refused("invalid_software_mode")
    elif name == "import_bundle":
        fields.update(("bundle_base64", "operator_key_base64", "replace"))
        blob(request.get("bundle_base64"), MAX_BUNDLE)
        blob(request.get("operator_key_base64"), MAX_KEY)
        if type(request.get("replace")) is not bool:
            raise Refused("invalid_replace_flag")
    else:
        raise Refused("unknown_action")
    if set(request) != fields:
        raise Refused("unexpected_action_fields")
    return request


@dataclass
class Plan:
    """Private in-memory inputs bound to the initiating live bus connection."""

    caller: Caller
    request: dict
    digest: str
    generation: str
    checked_inputs: str
    deadline: float
    public: dict


@dataclass
class Operation:
    """Caller-owned progress and an operation-scoped cancellation event."""

    caller: Caller
    deadline: float
    public: dict
    cancel: threading.Event = field(default_factory=threading.Event)


class Broker:
    """Adapter operations serialize; observation can remain available during prompts.

    The adapter must take the controller's cooperating mutation lock in `locked`
    and recheck its live inputs in `prepare`. It must never silently broaden an
    approved action. Hardware/user cancellation remains checked by `execute`.
    """

    def __init__(self, adapter, clock=time.monotonic, wall=time.time):
        self.adapter, self.clock, self.wall = adapter, clock, wall
        self.plans = {}
        self.operations = {}
        self.lock = threading.RLock()

    def expire(self):
        """Bound private in-memory records; active operations cannot be evicted."""
        now = self.clock()
        self.plans = {key: value for key, value in self.plans.items() if value.deadline > now}
        self.operations = {
            key: value
            for key, value in self.operations.items()
            if value.deadline > now or value.public["state"] in ("running", "waiting_for_user", "waiting_for_hardware")
        }

    def preview(self, caller, raw):
        """Bind exact action, caller, live generation and live hardware/profile inputs."""
        request = action(raw)
        with self.lock:
            self.expire()
            if any(
                o.public["state"] in ("running", "waiting_for_user", "waiting_for_hardware")
                for o in self.operations.values()
            ):
                raise Refused("another_operation_is_running")
            if len(self.plans) >= MAX_PLANS or sum(p.caller == caller for p in self.plans.values()) >= MAX_PER_CALLER:
                raise Refused("too_many_pending_plans")
        # Never wait for the adapter while holding the record mutex: a running
        # operation may need that mutex to publish progress/cancellation.
        with self.adapter.locked():
            prepared = self.adapter.prepare(caller, request)
            generation = self.adapter.generation()
        with self.lock:
            self.expire()
            if len(self.plans) >= MAX_PLANS or sum(p.caller == caller for p in self.plans.values()) >= MAX_PER_CALLER:
                raise Refused("too_many_pending_plans")
            digest = hashlib.sha256(b"cypherpunk/gui-action/v1\0" + canonical(request)).hexdigest()
            token = secrets.token_hex(32)
            public = dict(
                schema=1,
                id=token,
                input_digest=digest,
                generation=generation,
                expires_at=self.wall() + PLAN_TTL,
                summary=prepared["summary"],
                effects=prepared["effects"],
            )
            self.plans[token] = Plan(
                caller, request, digest, generation, prepared["checked_inputs"], self.clock() + PLAN_TTL, public
            )
            return dict(public)

    def plan(self, caller, token):
        """Private transport lookup for trusted native review; never consume the plan."""
        with self.lock:
            self.expire()
            plan = self.plans.get(token) if isinstance(token, str) and ID.fullmatch(token) else None
            if plan is None or plan.caller != caller:
                raise Refused("unknown_or_expired_plan")
            return json.loads(canonical(plan.public))

    def apply(self, caller, token):
        """Authorization is required in the transport before calling this method."""
        with self.lock:
            self.expire()
            plan = self.plans.get(token) if isinstance(token, str) and ID.fullmatch(token) else None
            if plan is None or plan.caller != caller:
                raise Refused("unknown_or_expired_plan")
            # Consume before validation/dispatch. A failed action needs a newly
            # reviewed plan, including after a controller or hardware change.
            del self.plans[token]
            if len(self.operations) >= MAX_PLANS:
                raise Refused("too_many_operations")
            if any(
                p.public["state"] in ("running", "waiting_for_user", "waiting_for_hardware")
                for p in self.operations.values()
            ):
                raise Refused("another_operation_is_running")
            identifier = secrets.token_hex(32)
            operation = Operation(
                caller,
                self.clock() + OP_TTL,
                dict(schema=1, id=identifier, state="running", message="Applying the reviewed action."),
            )
            self.operations[identifier] = operation
        try:
            with self.adapter.locked():
                prepared = self.adapter.prepare(caller, plan.request)
                digest = hashlib.sha256(b"cypherpunk/gui-action/v1\0" + canonical(plan.request)).hexdigest()
                if (
                    self.clock() >= plan.deadline
                    or not hmac.compare_digest(plan.digest, digest)
                    or self.adapter.generation() != plan.generation
                    or prepared["checked_inputs"] != plan.checked_inputs
                    or prepared["summary"] != plan.public["summary"]
                    or prepared["effects"] != plan.public["effects"]
                ):
                    raise Refused("plan_inputs_changed")
        except BaseException:
            with self.lock:
                del self.operations[identifier]
            raise
        with self.lock:
            thread = threading.Thread(
                target=self._execute, args=(operation, plan), daemon=True, name="cypherpunk-reviewed-action"
            )
            thread.start()
            return dict(operation.public)

    def _execute(self, operation, plan):
        def progress(state, message):
            if state not in ("running", "waiting_for_user", "waiting_for_hardware"):
                raise Refused("invalid_operation_state")
            with self.lock:
                operation.public.update(state=state, message=message)

        try:
            # Recheck inside the execution transaction, after thread dispatch.
            with self.adapter.locked():
                prepared = self.adapter.prepare(plan.caller, plan.request)
                if (
                    self.clock() >= plan.deadline
                    or self.adapter.generation() != plan.generation
                    or prepared["checked_inputs"] != plan.checked_inputs
                ):
                    raise Refused("plan_inputs_changed")
                if operation.cancel.is_set():
                    raise InterruptedError
                self.adapter.execute(plan.caller, plan.request, operation.cancel, progress)
            with self.lock:
                operation.public.update(
                    state="complete", message="Action finished. Refreshing authoritative checks is required."
                )
        except InterruptedError:
            with self.lock:
                operation.public.update(
                    state="cancelled", message="Action cancelled. Protection must be checked again."
                )
        except Exception:  # noqa: BLE001 (never expose exception arguments)
            with self.lock:
                operation.public.update(
                    state="failed", message="Action could not finish. Review current setup and protection checks."
                )
        finally:
            with self.lock:
                operation.deadline = self.clock() + OP_TTL

    def operation(self, caller, identifier):
        """Only the initiating live bus identity can observe its operation."""
        with self.lock:
            self.expire()
            value = (
                self.operations.get(identifier) if isinstance(identifier, str) and ID.fullmatch(identifier) else None
            )
            if value is None or value.caller != caller:
                raise Refused("unknown_operation")
            return dict(value.public)

    def cancel(self, caller, identifier):
        """Request cancellation of this operation only; never disable the guard."""
        with self.lock:
            current = self.operation(caller, identifier)
            if current["state"] in ("running", "waiting_for_user", "waiting_for_hardware"):
                self.operations[identifier].cancel.set()
            return current
