"""SCIM 2.0 conformance for the request shapes Okta and Microsoft Entra send."""
from __future__ import annotations

import pytest
import pytest_asyncio

from app import auth as auth_svc

SCIM = "application/scim+json"
USER = "urn:ietf:params:scim:schemas:core:2.0:User"
GROUP = "urn:ietf:params:scim:schemas:core:2.0:Group"
PATCH = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
ERROR = "urn:ietf:params:scim:api:messages:2.0:Error"


@pytest_asyncio.fixture
async def scim(client):
    r = await client.post("/v1/auth/sso/admin/scim-tokens", json={"name": "okta"})
    assert r.status_code == 201, r.text
    tok = r.json()["token"]
    assert tok.startswith("pscim_")
    return {"Authorization": f"Bearer {tok}", "Content-Type": SCIM}


@pytest_asyncio.fixture
async def mappings(client):
    r = await client.put("/v1/auth/sso/admin/settings", json={
        "scim_role_mappings": [
            {"group": "Paddock Admins", "role": "admin", "clearance": "restricted"},
            {"group": "Paddock Analysts", "role": "analyst", "clearance": "confidential"},
        ],
    })
    assert r.status_code == 200, r.text


def okta_user(user_name="ann@corp.example", active=True):
    return {
        "schemas": [USER],
        "userName": user_name,
        "name": {"givenName": "Ann", "familyName": "Lee"},
        "emails": [{"primary": True, "value": user_name, "type": "work"}],
        "displayName": "Ann Lee",
        "locale": "en-US",
        "externalId": "00u1okta",
        "groups": [],
        "password": "ignored-never-stored",
        "active": active,
    }


def entra_user(user_name="ben@corp.example"):
    return {
        "schemas": [USER, "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
        "externalId": "oid-ben",
        "userName": user_name,
        "active": True,
        "displayName": "Ben Ortiz",
        "emails": [{"primary": True, "type": "work", "value": user_name}],
        "meta": {"resourceType": "User"},
        "name": {"formatted": "Ben Ortiz", "familyName": "Ortiz", "givenName": "Ben"},
        "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User": {"department": "SecOps"},
    }


async def _jwt_for(pool, username):
    async with pool.acquire() as con:
        u = await con.fetchrow("SELECT id, username, role, clearance FROM app_users WHERE username = $1", username)
    tok, _ = auth_svc.issue_jwt(user_id=str(u["id"]), username=u["username"], role=u["role"], clearance=u["clearance"])
    return {"Authorization": f"Bearer {tok}"}


# --------------------------------------------------------------------------- #
# Auth
# --------------------------------------------------------------------------- #

async def test_scim_requires_scim_token(client, db_pool, scim):
    r = await client.get("/scim/v2/Users")
    # dev mode injects an admin -- which still has no `scim` capability
    assert r.status_code == 403 and r.json()["schemas"] == [ERROR]
    r = await client.get("/scim/v2/Users", headers={"Authorization": "Bearer pscim_bad_token"})
    assert r.status_code == 401 and r.json()["status"] == "401"
    assert r.headers["content-type"].startswith(SCIM)
    # a SCIM token is useless outside /scim
    r = await client.get("/v1/assets", headers=scim)
    assert r.status_code == 403
    r = await client.get("/v1/auth/sso/admin/providers", headers=scim)
    assert r.status_code == 403
    # an admin API key can't call SCIM
    from .test_governance import _hdr, _seed_user_with_key

    _, admin_key = await _seed_user_with_key(db_pool, "boss", "admin", "restricted")
    assert (await client.get("/scim/v2/Users", headers=_hdr(admin_key))).status_code == 403


async def test_scim_token_hashed_revocable_and_audited(client, db_pool, scim):
    async with db_pool.acquire() as con:
        row = await con.fetchrow("SELECT token_hash, prefix FROM scim_tokens")
    assert scim["Authorization"].split()[1] not in row["token_hash"]
    lst = (await client.get("/v1/auth/sso/admin/scim-tokens")).json()
    assert "token" not in lst[0] and lst[0]["prefix"] == row["prefix"]
    assert (await client.get("/scim/v2/Users", headers=scim)).status_code == 200
    assert (await client.delete(f"/v1/auth/sso/admin/scim-tokens/{lst[0]['id']}")).status_code == 200
    assert (await client.get("/scim/v2/Users", headers=scim)).status_code == 401
    async with db_pool.acquire() as con:
        acts = await con.fetch("SELECT action FROM audit_log WHERE resource_type = 'scim_token'")
    assert {a["action"] for a in acts} == {"create", "delete"}


async def test_discovery_endpoints(client, scim):
    spc = (await client.get("/scim/v2/ServiceProviderConfig", headers=scim)).json()
    assert spc["patch"]["supported"] is True and spc["bulk"]["supported"] is False
    assert spc["filter"]["supported"] is True
    assert spc["authenticationSchemes"][0]["type"] == "oauthbearertoken"
    rts = (await client.get("/scim/v2/ResourceTypes", headers=scim)).json()
    assert {r["id"] for r in rts["Resources"]} == {"User", "Group"}
    assert (await client.get("/scim/v2/ResourceTypes/User", headers=scim)).json()["endpoint"] == "/Users"
    schemas = (await client.get("/scim/v2/Schemas", headers=scim)).json()
    assert {s["id"] for s in schemas["Resources"]} == {USER, GROUP}
    r = await client.get(f"/scim/v2/Schemas/{USER}", headers=scim)
    assert any(a["name"] == "userName" for a in r.json()["attributes"])


# --------------------------------------------------------------------------- #
# Okta
# --------------------------------------------------------------------------- #

async def test_okta_user_lifecycle(client, db_pool, scim, mappings):
    # 1. Okta checks for an existing user first
    r = await client.get("/scim/v2/Users", params={"filter": 'userName eq "ann@corp.example"',
                                                   "startIndex": 1, "count": 100}, headers=scim)
    assert r.status_code == 200
    assert r.json() == {"schemas": ["urn:ietf:params:scim:api:messages:2.0:ListResponse"],
                        "totalResults": 0, "startIndex": 1, "itemsPerPage": 0, "Resources": []}
    # 2. create
    r = await client.post("/scim/v2/Users", json=okta_user(), headers=scim)
    assert r.status_code == 201, r.text
    u = r.json()
    assert r.headers["location"].endswith(f"/scim/v2/Users/{u['id']}")
    assert u["userName"] == "ann@corp.example" and u["active"] is True and u["externalId"] == "00u1okta"
    assert u["name"]["givenName"] == "Ann" and u["emails"][0]["value"] == "ann@corp.example"
    assert u["roles"] == [{"value": "viewer", "primary": True}]
    async with db_pool.acquire() as con:
        pw = await con.fetchval("SELECT pw_hash FROM app_users WHERE id = $1", u["id"])
    assert pw is None  # SCIM never sets a password
    # filter is case-insensitive on userName (caseExact=false)
    r = await client.get("/scim/v2/Users", params={"filter": 'userName eq "ANN@corp.example"'}, headers=scim)
    assert r.json()["totalResults"] == 1
    # 3. duplicate -> 409 uniqueness
    r = await client.post("/scim/v2/Users", json=okta_user(), headers=scim)
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"
    # 4. Okta profile update = PUT full resource
    body = okta_user()
    body["name"]["familyName"] = "Lee-Smith"
    r = await client.put(f"/scim/v2/Users/{u['id']}", json=body, headers=scim)
    assert r.status_code == 200 and r.json()["name"]["familyName"] == "Lee-Smith"

    # give the user a live session + API key, then deactivate the Okta way
    sess = await _jwt_for(db_pool, "ann@corp.example")
    full, prefix, key_hash = auth_svc.generate_api_key()
    async with db_pool.acquire() as con:
        await con.execute(
            "INSERT INTO api_keys (user_id, name, prefix, key_hash, scopes) VALUES ($1, 'k', $2, $3, '{read}')",
            u["id"], prefix, key_hash,
        )
    assert (await client.get("/v1/auth/me", headers=sess)).status_code == 200
    assert (await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {full}"})).status_code == 200

    r = await client.patch(f"/scim/v2/Users/{u['id']}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "replace", "value": {"active": False}}],
    })
    assert r.status_code == 200 and r.json()["active"] is False
    # 5. deactivation kills sessions and API keys immediately
    assert (await client.get("/v1/auth/me", headers=sess)).status_code == 401
    assert (await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {full}"})).status_code == 401
    # 6. re-activation does NOT revive the old session or key
    r = await client.patch(f"/scim/v2/Users/{u['id']}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "replace", "value": {"active": True}}],
    })
    assert r.json()["active"] is True
    assert (await client.get("/v1/auth/me", headers=sess)).status_code == 401
    assert (await client.get("/v1/auth/me", headers={"Authorization": f"Bearer {full}"})).status_code == 401
    async with db_pool.acquire() as con:
        await con.execute(
            "UPDATE app_users SET sessions_revoked_at = NOW() - INTERVAL '5 seconds' WHERE id = $1", u["id"],
        )
    assert (await client.get("/v1/auth/me", headers=await _jwt_for(db_pool, "ann@corp.example"))).status_code == 200

    async with db_pool.acquire() as con:
        rows = await con.fetch("SELECT action, details FROM audit_log WHERE resource_type = 'scim_user' ORDER BY id")
    assert [r["action"] for r in rows] == ["create", "update", "update", "update"]
    assert '"active": false' in str(rows[2]["details"])
    assert "ignored-never-stored" not in " ".join(str(r["details"]) for r in rows)


async def test_okta_groups_drive_roles(client, db_pool, scim, mappings):
    uid = (await client.post("/scim/v2/Users", json=okta_user(), headers=scim)).json()["id"]
    sess = await _jwt_for(db_pool, "ann@corp.example")
    r = await client.post("/scim/v2/Groups", headers=scim,
                          json={"schemas": [GROUP], "displayName": "Paddock Admins", "members": []})
    assert r.status_code == 201
    gid = r.json()["id"]
    # Okta push-group membership
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={
        "schemas": [PATCH],
        "Operations": [{"op": "add", "path": "members", "value": [{"value": uid, "display": "ann@corp.example"}]}],
    })
    assert r.status_code == 200 and [m["value"] for m in r.json()["members"]] == [uid]
    u = (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).json()
    assert u["roles"][0]["value"] == "admin" and u["groups"][0]["display"] == "Paddock Admins"
    # role is read live per request: the existing session is now admin
    me = (await client.get("/v1/auth/me", headers=sess)).json()
    assert me["role"] == "admin" and me["clearance"] == "restricted"
    # Okta rename: replace without path
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "replace", "value": {"id": gid, "displayName": "Paddock Analysts"}}],
    })
    assert r.json()["displayName"] == "Paddock Analysts"
    assert (await client.get("/v1/auth/me", headers=sess)).json()["role"] == "analyst"
    # Okta removal uses a member filter path
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "remove", "path": f'members[value eq "{uid}"]'}],
    })
    assert r.json()["members"] == []
    assert (await client.get("/v1/auth/me", headers=sess)).json()["role"] == "viewer"
    # delete group
    assert (await client.delete(f"/scim/v2/Groups/{gid}", headers=scim)).status_code == 204
    assert (await client.get(f"/scim/v2/Groups/{gid}", headers=scim)).status_code == 404


# --------------------------------------------------------------------------- #
# Microsoft Entra ID
# --------------------------------------------------------------------------- #

async def test_entra_user_and_group_shapes(client, db_pool, scim, mappings):
    # Entra probes with a random filter first
    r = await client.get("/scim/v2/Users", params={"filter": 'userName eq "non-existent-user-xyz"'}, headers=scim)
    assert r.json()["totalResults"] == 0
    r = await client.post("/scim/v2/Users", json=entra_user(), headers=scim)
    assert r.status_code == 201, r.text
    uid = r.json()["id"]
    r = await client.get("/scim/v2/Users", params={"filter": 'externalId eq "oid-ben"'}, headers=scim)
    assert r.json()["Resources"][0]["id"] == uid

    # Entra PATCH: capitalised ops, explicit paths, string booleans, extension attrs
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim, json={
        "schemas": [PATCH],
        "Operations": [
            {"op": "Replace", "path": "displayName", "value": "Benjamin Ortiz"},
            {"op": "Replace", "path": "name.givenName", "value": "Benjamin"},
            {"op": "Add", "path": 'emails[type eq "work"].value', "value": "benjamin@corp.example"},
            {"op": "Replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department",
             "value": "IR"},
            {"op": "Add", "path": "phoneNumbers[type eq \"work\"].value", "value": "+1 555"},
        ],
    })
    assert r.status_code == 200, r.text
    u = r.json()
    assert u["displayName"] == "Benjamin Ortiz" and u["name"]["givenName"] == "Benjamin"
    assert u["emails"][0]["value"] == "benjamin@corp.example"

    r = await client.post("/scim/v2/Groups", headers=scim, json={
        "schemas": [GROUP], "externalId": "gid-1", "displayName": "Paddock Analysts",
    })
    gid = r.json()["id"]
    r = await client.get("/scim/v2/Groups", headers=scim,
                         params={"filter": 'displayName eq "Paddock Analysts"', "excludedAttributes": "members"})
    assert r.json()["totalResults"] == 1 and "members" not in r.json()["Resources"][0]
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "Add", "path": "members", "value": [{"value": uid}]}],
    })
    assert r.status_code == 200
    assert (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).json()["roles"][0]["value"] == "analyst"
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "Remove", "path": "members", "value": [{"value": uid}]}],
    })
    assert (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).json()["roles"][0]["value"] == "viewer"
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "Replace", "path": "displayName", "value": "Renamed"}],
    })
    assert r.json()["displayName"] == "Renamed"

    # Entra soft-delete: active "False" as a string
    sess = await _jwt_for(db_pool, "ben@corp.example")
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "Replace", "path": "active", "value": "False"}],
    })
    assert r.json()["active"] is False
    assert (await client.get("/v1/auth/me", headers=sess)).status_code == 401

    # hard delete -> 404 afterwards, userName can be provisioned again
    assert (await client.delete(f"/scim/v2/Users/{uid}", headers=scim)).status_code == 204
    assert (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).status_code == 404
    r = await client.post("/scim/v2/Users", json=entra_user(), headers=scim)
    assert r.status_code == 201 and r.json()["id"] == uid and r.json()["active"] is True
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM audit_log WHERE resource_type = 'scim_user' "
                                  "AND action = 'delete'") == 1


# --------------------------------------------------------------------------- #
# Guard rails + errors
# --------------------------------------------------------------------------- #

async def test_local_and_break_glass_users_invisible_to_scim(client, db_pool, scim):
    r = await client.get("/scim/v2/Users", params={"filter": 'userName eq "admin"'}, headers=scim)
    assert r.json()["totalResults"] == 0
    r = await client.post("/scim/v2/Users", json=okta_user("admin"), headers=scim)
    assert r.status_code == 409
    async with db_pool.acquire() as con:
        local_id = await con.fetchval(
            "INSERT INTO app_users (username, role) VALUES ('localops', 'admin') RETURNING id"
        )
        admin_id = await con.fetchval("SELECT id FROM app_users WHERE username = 'admin'")
    for target in (local_id, admin_id):
        assert (await client.delete(f"/scim/v2/Users/{target}", headers=scim)).status_code == 404
        r = await client.patch(f"/scim/v2/Users/{target}", headers=scim, json={
            "schemas": [PATCH], "Operations": [{"op": "replace", "value": {"active": False}}],
        })
        assert r.status_code == 404
    r = await client.post("/scim/v2/Users", json=okta_user("localops"), headers=scim)
    assert r.status_code == 409
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT bool_and(active) FROM app_users WHERE id = ANY($1::uuid[])",
                                  [local_id, admin_id])


async def test_scim_adopts_sso_jit_user(client, db_pool, scim):
    async with db_pool.acquire() as con:
        uid = await con.fetchval(
            "INSERT INTO app_users (username, role, provisioned_by) VALUES ('jit@corp.example', 'viewer', 'sso:okta') "
            "RETURNING id"
        )
    r = await client.get("/scim/v2/Users", params={"filter": 'userName eq "jit@corp.example"'}, headers=scim)
    assert r.json()["totalResults"] == 1
    r = await client.put(f"/scim/v2/Users/{uid}", json=okta_user("jit@corp.example"), headers=scim)
    assert r.status_code == 200
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT provisioned_by FROM app_users WHERE id = $1", uid) == "scim"


@pytest.mark.parametrize("flt", ['password eq "x"', "userName eq", 'userName eq "a" and', '(userName eq "a"',
                                 'userName eq "a")', 'userName xx "a"', 'not userName eq "a"', 'active eq "maybe"',
                                 'active co "t"', 'meta.lastModified gt "yesterday"', 'userName eq a',
                                 'emails[type eq "work"].value eq "x"', 'groups[display eq "x"]',
                                 "(" * 20 + 'userName eq "a"' + ")" * 20,
                                 " and ".join(['userName eq "a"'] * 30), 'userName eq "' + "a" * 2000 + '"'])
async def test_invalid_filters(client, scim, flt):
    r = await client.get("/scim/v2/Users", params={"filter": flt}, headers=scim)
    assert r.status_code == 400 and r.json()["scimType"] == "invalidFilter"


async def test_pagination(client, scim):
    for i in range(5):
        await client.post("/scim/v2/Users", json=okta_user(f"u{i}@corp.example"), headers=scim)
    r = (await client.get("/scim/v2/Users", params={"startIndex": 2, "count": 2}, headers=scim)).json()
    assert r["totalResults"] == 5 and r["startIndex"] == 2 and r["itemsPerPage"] == 2
    assert [x["userName"] for x in r["Resources"]] == ["u1@corp.example", "u2@corp.example"]
    r = (await client.get("/scim/v2/Users", params={"count": 0}, headers=scim)).json()
    assert r["totalResults"] == 5 and r["Resources"] == []


async def test_errors_use_scim_schema(client, scim):
    r = await client.get("/scim/v2/Users/not-a-uuid", headers=scim)
    assert r.status_code == 404 and r.json()["schemas"] == [ERROR]
    r = await client.post("/scim/v2/Users", content=b"{not json", headers=scim)
    assert r.status_code == 400 and r.json()["scimType"] == "invalidSyntax"
    r = await client.post("/scim/v2/Users", json={"schemas": [USER]}, headers=scim)
    assert r.status_code == 400 and r.json()["scimType"] == "invalidValue"
    uid = (await client.post("/scim/v2/Users", json=okta_user(), headers=scim)).json()["id"]
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim,
                           json={"schemas": [PATCH], "Operations": [{"op": "move", "path": "active"}]})
    assert r.status_code == 400
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim,
                           json={"schemas": [PATCH], "Operations": [{"op": "replace", "path": "active",
                                                                     "value": "maybe"}]})
    assert r.status_code == 400 and r.json()["scimType"] == "invalidValue"
    r = await client.post("/scim/v2/Groups", json={"schemas": [GROUP], "displayName": "G"}, headers=scim)
    assert r.status_code == 201
    r = await client.post("/scim/v2/Groups", json={"schemas": [GROUP], "displayName": "g"}, headers=scim)
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"


async def test_mapping_change_recomputes_existing_scim_users(client, db_pool, scim):
    uid = (await client.post("/scim/v2/Users", json=okta_user(), headers=scim)).json()["id"]
    await client.post("/scim/v2/Groups", headers=scim,
                      json={"schemas": [GROUP], "displayName": "SecOps", "members": [{"value": uid}]})
    r = await client.put("/v1/auth/sso/admin/settings", json={
        "scim_role_mappings": [{"group": "secops", "role": "analyst"}],
    })
    assert r.status_code == 200
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT role FROM app_users WHERE id = $1", uid) == "analyst"
        d = await con.fetchval(
            "SELECT details FROM audit_log WHERE resource_type = 'identity_settings' ORDER BY id DESC LIMIT 1"
        )
    assert '"scim_users_recomputed": 1' in str(d)

