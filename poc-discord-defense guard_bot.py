```python
# guard_bot.py
#
# Defensive Discord "Guard Bot" PoC:
# - Monitors Audit Log for bursty destructive/admin actions
# - Alerts a security channel
# - Best-effort containment: applies a Quarantine role + removes member roles
# - Optional: strips dangerous permissions from actor's top role (if hierarchy allows)
#
# Requirements:
#   pip install -U discord.py python-dotenv
#
# .env example:
#   DISCORD_TOKEN=xxxxxxxx
#   GUILD_ID=123456789012345678
#   SECURITY_CHANNEL_ID=123456789012345678
#   POLL_SECONDS=5
#   WINDOW_SECONDS=60
#
# Notes:
# - Bot must have: View Audit Log, Manage Roles (for quarantine/role edits), Send Messages
# - Role hierarchy matters: bot's top role must be above roles it edits/removes

import os
import time
import asyncio
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional, Set, Tuple

import discord
from discord.ext import commands
from dotenv import load_dotenv

load_dotenv()

DISCORD_TOKEN = os.getenv("DISCORD_TOKEN", "").strip()
GUILD_ID = int(os.getenv("GUILD_ID", "0"))
SECURITY_CHANNEL_ID = int(os.getenv("SECURITY_CHANNEL_ID", "0"))

POLL_SECONDS = int(os.getenv("POLL_SECONDS", "5"))
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))

# Thresholds are per-action-key within WINDOW_SECONDS
THRESHOLDS = {
    "channel_delete": 3,
    "role_delete": 2,
    "role_update": 6,
    "webhook_create": 4,
    "member_ban": 5,
    "member_kick": 6,
    "channel_create": 12,
}

# Audit actions to watch -> internal key
WATCH_ACTIONS: Dict[discord.AuditLogAction, str] = {
    discord.AuditLogAction.channel_delete: "channel_delete",
    discord.AuditLogAction.channel_create: "channel_create",
    discord.AuditLogAction.role_delete: "role_delete",
    discord.AuditLogAction.role_update: "role_update",
    discord.AuditLogAction.webhook_create: "webhook_create",
    discord.AuditLogAction.ban: "member_ban",
    discord.AuditLogAction.kick: "member_kick",
}

# Dangerous permissions to strip (best-effort). This is containment, not punishment.
DANGEROUS_PERMS = [
    "administrator",
    "manage_guild",
    "manage_roles",
    "manage_channels",
    "manage_webhooks",
    "ban_members",
    "kick_members",
]

# Simple allowlist (comma-separated IDs in env) for actors you NEVER want to quarantine/strip
ALLOWLIST_ACTOR_IDS: Set[int] = set()
_allowlist_raw = os.getenv("ALLOWLIST_ACTOR_IDS", "").strip()
if _allowlist_raw:
    for part in _allowlist_raw.split(","):
        part = part.strip()
        if part.isdigit():
            ALLOWLIST_ACTOR_IDS.add(int(part))

# Cooldown per actor/action to prevent repeated alert spam
ALERT_COOLDOWN_SECONDS = int(os.getenv("ALERT_COOLDOWN_SECONDS", "120"))


@dataclass
class Incident:
    actor_id: int
    key: str
    ts: float


class GuardBot(commands.Bot):
    def __init__(self) -> None:
        intents = discord.Intents.default()
        intents.guilds = True
        intents.members = True  # for role changes / quarantine
        super().__init__(command_prefix="!", intents=intents)

        # actor_id -> key -> timestamps within window
        self.actor_events: Dict[int, Dict[str, Deque[float]]] = defaultdict(lambda: defaultdict(deque))

        # last processed audit log entry id
        self.last_audit_id: Optional[int] = None

        # last incident to avoid repeats
        self.last_incident: Dict[Tuple[int, str], float] = {}

    async def setup_hook(self) -> None:
        self.loop.create_task(self._audit_poll_loop())

    async def on_ready(self) -> None:
        print(f"[+] GuardBot logged in as {self.user} (id={self.user.id})")

    def _now(self) -> float:
        return time.time()

    def _roll_window(self, dq: Deque[float], now: float) -> None:
        while dq and (now - dq[0]) > WINDOW_SECONDS:
            dq.popleft()

    def _incident_on_cooldown(self, actor_id: int, key: str, now: float) -> bool:
        last = self.last_incident.get((actor_id, key))
        return last is not None and (now - last) < ALERT_COOLDOWN_SECONDS

    def _mark_incident(self, actor_id: int, key: str, now: float) -> None:
        self.last_incident[(actor_id, key)] = now

    async def _audit_poll_loop(self) -> None:
        await self.wait_until_ready()

        if not DISCORD_TOKEN or not GUILD_ID or not SECURITY_CHANNEL_ID:
            print("[!] Missing env vars. Require DISCORD_TOKEN, GUILD_ID, SECURITY_CHANNEL_ID")
            return

        guild = self.get_guild(GUILD_ID)
        if guild is None:
            print("[!] Guild not found. Check GUILD_ID and bot membership.")
            return

        print("[+] Audit poll loop started.")
        while not self.is_closed():
            try:
                await self._poll_audit_logs(guild)
            except Exception as e:
                print(f"[!] Poll error: {e}")
            await asyncio.sleep(max(2, POLL_SECONDS))

    async def _poll_audit_logs(self, guild: discord.Guild) -> None:
        # Pull a small batch frequently
        entries = [e async for e in guild.audit_logs(limit=25)]
        if not entries:
            return

        newest_id = entries[0].id

        # First run: set cursor so we don't alert on historical events
        if self.last_audit_id is None:
            self.last_audit_id = newest_id
            return

        # Process entries oldest->newest
        now = self._now()
        new_entries = []
        for e in reversed(entries):
            if e.id > self.last_audit_id and e.action in WATCH_ACTIONS:
                new_entries.append(e)

        if not new_entries:
            # still advance cursor to keep up with log churn
            self.last_audit_id = max(self.last_audit_id, newest_id)
            return

        self.last_audit_id = max(self.last_audit_id, newest_id)

        for e in new_entries:
            key = WATCH_ACTIONS.get(e.action)
            if not key:
                continue

            actor = e.user
            if actor is None:
                continue

            # Skip allowlisted actors
            if actor.id in ALLOWLIST_ACTOR_IDS:
                continue

            dq = self.actor_events[actor.id][key]
            dq.append(now)
            self._roll_window(dq, now)

            threshold = THRESHOLDS.get(key, 999999)
            if len(dq) >= threshold:
                if not self._incident_on_cooldown(actor.id, key, now):
                    await self._handle_incident(guild, actor, key, len(dq), e)
                    self._mark_incident(actor.id, key, now)
                # clear this key to prevent immediate retriggering
                dq.clear()

    async def _handle_incident(
        self,
        guild: discord.Guild,
        actor: discord.abc.User,
        key: str,
        count: int,
        entry: discord.AuditLogEntry,
    ) -> None:
        channel = guild.get_channel(SECURITY_CHANNEL_ID)
        if channel is None:
            print("[!] SECURITY_CHANNEL_ID channel not found.")
            return

        actor_tag = f"{actor} (id={actor.id})"
        msg = (
            "SECURITY ALERT\n"
            "Detected abnormal privileged activity rate in Audit Logs.\n\n"
            f"Actor: {actor_tag}\n"
            f"Signal: {key}\n"
            f"Count in last {WINDOW_SECONDS}s: {count}\n"
            f"Audit action type: {entry.action}\n\n"
            "Containment: attempting best-effort quarantine (role removal + Quarantine role).\n"
            "If containment fails due to role hierarchy or permissions, take manual action:\n"
            "- Remove/disable the bot or user\n"
            "- Revoke elevated roles and permissions\n"
            "- Review Audit Log for additional changes\n"
        )
        await channel.send(msg)

        await self._contain_actor(guild, actor, channel)

    async def _contain_actor(
        self,
        guild: discord.Guild,
        actor: discord.abc.User,
        channel: discord.abc.Messageable,
    ) -> None:
        member = guild.get_member(actor.id)
        if member is None:
            await channel.send(
                "Containment result: actor is not a current guild member (or not cached). Manual review required."
            )
            return

        # Do not attempt to quarantine the server owner
        if member.id == guild.owner_id:
            await channel.send("Containment skipped: actor is server owner. Manual response required.")
            return

        # Create/find quarantine role
        quarantine_role = discord.utils.get(guild.roles, name="Quarantine")
        if quarantine_role is None:
            try:
                quarantine_role = await guild.create_role(
                    name="Quarantine",
                    permissions=discord.Permissions.none(),
                    reason="Security containment role (GuardBot)",
                )
                await channel.send("Containment: created Quarantine role (no permissions).")
            except discord.Forbidden:
                await channel.send("Containment: failed to create Quarantine role (missing permissions).")
                quarantine_role = None

        # Try removing roles (except @everyone) then apply quarantine
        try:
            removable = [r for r in member.roles if r.name != "@everyone"]
            if removable:
                await member.remove_roles(*removable, reason="Security containment: removing roles (GuardBot)")
            if quarantine_role is not None:
                await member.add_roles(quarantine_role, reason="Security containment: quarantine (GuardBot)")
                await channel.send(f"Containment: removed existing roles and applied Quarantine to {member}.")
            else:
                await channel.send("Containment: removed existing roles. Quarantine role unavailable.")
        except discord.Forbidden:
            await channel.send(
                "Containment failed: unable to modify member roles (role hierarchy or missing Manage Roles)."
            )
            return
        except Exception as e:
            await channel.send(f"Containment error while modifying member roles: {e}")
            return

        # Best-effort: strip dangerous perms from actor's top role (if editable)
        try:
            top_role = member.top_role
            if top_role and top_role.name != "@everyone":
                perms = top_role.permissions
                changed = False
                for p in DANGEROUS_PERMS:
                    if getattr(perms, p, False):
                        setattr(perms, p, False)
                        changed = True
                if changed:
                    await top_role.edit(permissions=perms, reason="Security containment: strip dangerous perms (GuardBot)")
                    await channel.send(f"Containment: stripped dangerous permissions from role '{top_role.name}'.")
                else:
                    await channel.send("Containment: actor top role has no listed dangerous permissions.")
        except discord.Forbidden:
            await channel.send(
                "Containment note: could not edit role permissions (missing perms or role hierarchy)."
            )
        except Exception as e:
            await channel.send(f"Containment note: role permission edit failed: {e}")

    @commands.command(name="guard_status")
    @commands.has_permissions(view_audit_log=True)
    async def guard_status(self, ctx: commands.Context) -> None:
        """Quick health check (requires View Audit Log permission)."""
        await ctx.send(
            f"GuardBot active. Poll={POLL_SECONDS}s Window={WINDOW_SECONDS}s "
            f"Cooldown={ALERT_COOLDOWN_SECONDS}s Allowlist={len(ALLOWLIST_ACTOR_IDS)}"
        )

    @commands.command(name="guard_set_threshold")
    @commands.has_permissions(administrator=True)
    async def guard_set_threshold(self, ctx: commands.Context, key: str, value: int) -> None:
        """Admin-only: adjust a threshold at runtime."""
        if key not in THRESHOLDS:
            await ctx.send(f"Unknown key. Known keys: {', '.join(sorted(THRESHOLDS.keys()))}")
            return
        if value < 1 or value > 500:
            await ctx.send("Value out of range (1..500).")
            return
        THRESHOLDS[key] = value
        await ctx.send(f"Threshold updated: {key} = {value} (within {WINDOW_SECONDS}s)")

    @guard_set_threshold.error
    async def guard_set_threshold_error(self, ctx: commands.Context, error: commands.CommandError) -> None:
        await ctx.send("Permission denied or invalid usage.")


def main() -> None:
    if not DISCORD_TOKEN:
        raise SystemExit("DISCORD_TOKEN not set")
    if not GUILD_ID or not SECURITY_CHANNEL_ID:
        raise SystemExit("GUILD_ID and SECURITY_CHANNEL_ID must be set")

    bot = GuardBot()
    bot.run(DISCORD_TOKEN)


if __name__ == "__main__":
    main()
```
