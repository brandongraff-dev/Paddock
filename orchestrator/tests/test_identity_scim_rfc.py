"""SCIM RFC 7644 completeness: filter grammar, .search, attribute projection,
pagination edges, ETags / If-Match, and PATCH request shapes as recorded from
Okta and Microsoft Entra ID provisioning."""
from __future__ import annotations

import pytest
import pytest_asyncio

from app.identity import scim_filter

from .test_identity_scim import GROUP, PATCH, SCIM, USER, entra_user, okta_user


@pytest_asyncio.fixture
async def scim(client):
    r = await client.post("/v1/auth/sso/admin/scim-tokens", json={"name": "idp"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}", "Content-Type": SCIM}


@pytest_asyncio.fixture
async def people(client, scim):
    """alice (okta shape, active), bob (entra shape), carol (inactive)."""
    ids = {}
    for key, body in (("alice", okta_user("alice@corp.example")),
                      ("bob", entra_user("bob@corp.example")),
                      ("carol", okta_user("carol@other.example", active=False))):
        body = {**body, "externalId": f"ext-{key}"} if key != "carol" else {**body, "externalId": None}
        r = await client.post("/scim/v2/Users", json=body, headers=scim)
        assert r.status_code == 201, r.text
        ids[key] = r.json()["id"]
    return ids


async def names(client, scim, flt, path="Users", **params):
    r = await client.get(f"/scim/v2/{path}", params={"filter": flt, **params}, headers=scim)
    assert r.status_code == 200, (flt, r.text)
    key = "userName" if path == "Users" else "displayName"
    return sorted(x[key] for x in r.json()["Resources"])


ALICE, BOB, CAROL = "alice@corp.example", "bob@corp.example", "carol@other.example"


# --------------------------------------------------------------------------- #
# filters
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("flt,expected", [
    ('userName eq "alice@corp.example"', [ALICE]),
    ('USERNAME EQ "ALICE@CORP.EXAMPLE"', [ALICE]),                      # attr, op and value are case-insensitive
    ('urn:ietf:params:scim:schemas:core:2.0:User:userName eq "bob@corp.example"', [BOB]),
    ('userName sw "al"', [ALICE]),
    ('userName ew "@corp.example"', [ALICE, BOB]),
    ('userName co "ol@"', [CAROL]),
    ('userName ne "alice@corp.example"', [BOB, CAROL]),
    ('userName gt "bob@corp.example"', [CAROL]),
    ('userName ge "bob@corp.example"', [BOB, CAROL]),
    ('userName lt "bob@corp.example"', [ALICE]),
    ('userName le "bob@corp.example"', [ALICE, BOB]),
    ('active eq true', [ALICE, BOB]),
    ('active eq false', [CAROL]),
    ('active ne true', [CAROL]),
    ('externalId pr', [ALICE, BOB]),
    ('externalId eq "ext-bob"', [BOB]),
    ('externalId eq "EXT-BOB"', []),                                  # externalId is caseExact
    ('externalId eq null', [CAROL]),
    ('name.givenName eq "Ann"', [ALICE, CAROL]),
    ('emails.value co "@other"', [CAROL]),
    ('emails[type eq "work" and value sw "bob"]', [BOB]),
    ('emails[type eq "home"]', []),
    ('userName eq "alice@corp.example" or userName eq "bob@corp.example"', [ALICE, BOB]),
    ('(userName sw "a" or userName sw "b") and active eq true', [ALICE, BOB]),
    ('(userName sw "a" or userName sw "c") and not (active eq true)', [CAROL]),
    ('not (userName co "corp")', [CAROL]),
    ('meta.lastModified gt "2000-01-01T00:00:00Z"', [ALICE, BOB, CAROL]),
    ('meta.lastModified lt "2000-01-01T00:00:00Z"', []),
    ('meta.created ge "2000-01-01"', [ALICE, BOB, CAROL]),
])
async def test_user_filters(client, scim, people, flt, expected):
    assert await names(client, scim, flt) == expected


async def test_filter_by_id_and_group_membership(client, scim, people):
    gid = (await client.post("/scim/v2/Groups", headers=scim, json={
        "schemas": [GROUP], "displayName": "Ops", "members": [{"value": people["alice"]}]})).json()["id"]
    assert await names(client, scim, f'id eq "{people["bob"]}"') == [BOB]
    assert await names(client, scim, f'groups[value eq "{gid}"]') == [ALICE]
    assert await names(client, scim, f'groups.value eq "{gid}"') == [ALICE]
    assert await names(client, scim, f'groups.value eq "{gid.upper()}"') == [ALICE]
    assert await names(client, scim, f'groups.value ne "{gid}"') == [BOB, CAROL]
    assert await names(client, scim, 'groups pr' if False else 'groups.value pr') == [ALICE]
    # Groups
    assert await names(client, scim, f'members[value eq "{people["alice"]}"]', "Groups") == ["Ops"]
    assert await names(client, scim, f'members.value eq "{people["bob"]}"', "Groups") == []
    assert await names(client, scim, 'displayName sw "op"', "Groups") == ["Ops"]
    assert await names(client, scim, 'displayName co "x"', "Groups") == []
    assert await names(client, scim, f'id eq "{gid}" and meta.lastModified gt "2000-01-01T00:00:00Z"', "Groups") == ["Ops"]


@pytest.mark.parametrize("flt", [
    'userName eq "a\\" or 1=1 --"',
    "userName eq \"x' OR '1'='1\"",
    'userName eq "a"; DROP TABLE app_users; --',
    'userName co "%"', 'userName co "_"', 'userName sw "\\\\"',
])
async def test_filters_cannot_inject_sql_and_wildcards_are_literal(client, db_pool, scim, people, flt):
    r = await client.get("/scim/v2/Users", params={"filter": flt}, headers=scim)
    assert r.status_code in (200, 400)
    if r.status_code == 200:
        assert r.json()["totalResults"] == 0
    async with db_pool.acquire() as con:
        assert await con.fetchval("SELECT count(*) FROM app_users WHERE provisioned_by = 'scim'") == 3


def test_filter_parser_is_bounded():
    for bad in ("(" * (scim_filter.MAX_DEPTH + 2) + 'userName eq "a"' + ")" * (scim_filter.MAX_DEPTH + 2),
                " and ".join(['userName eq "a"'] * (scim_filter.MAX_TERMS + 1)),
                'userName eq "' + "a" * scim_filter.MAX_LEN + '"'):
        with pytest.raises(scim_filter.FilterError):
            scim_filter.compile_filter(bad, {"username": scim_filter.Col("u.username")}, [])


# --------------------------------------------------------------------------- #
# .search, attributes, pagination
# --------------------------------------------------------------------------- #

async def test_post_search_users_and_groups(client, scim, people):
    r = await client.post("/scim/v2/Users/.search", headers=scim, json={
        "schemas": ["urn:ietf:params:scim:api:messages:2.0:SearchRequest"],
        "filter": 'userName ew "@corp.example"', "startIndex": 2, "count": 1,
        "attributes": ["userName"]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["totalResults"] == 2 and body["startIndex"] == 2 and body["itemsPerPage"] == 1
    assert body["Resources"][0]["userName"] == BOB and "emails" not in body["Resources"][0]
    await client.post("/scim/v2/Groups", headers=scim, json={"schemas": [GROUP], "displayName": "Ops"})
    r = await client.post("/scim/v2/Groups/.search", headers=scim, json={"filter": 'displayName eq "ops"'})
    assert r.json()["totalResults"] == 1
    bad = await client.post("/scim/v2/Users/.search", headers=scim, json={"filter": "nonsense"})
    assert bad.status_code == 400 and bad.json()["scimType"] == "invalidFilter"
    bad = await client.post("/scim/v2/Users/.search", headers=scim, json={"startIndex": "x"})
    assert bad.status_code == 400


async def test_attributes_and_excluded_attributes(client, scim, people):
    u = (await client.get(f"/scim/v2/Users/{people['alice']}", headers=scim,
                          params={"attributes": "userName,emails"})).json()
    assert set(u) == {"schemas", "id", "userName", "emails"}
    u = (await client.get(f"/scim/v2/Users/{people['alice']}", headers=scim,
                          params={"excludedAttributes": "emails,name,roles,groups"})).json()
    assert "emails" not in u and "name" not in u and u["userName"] == ALICE
    lst = (await client.get("/scim/v2/Users", headers=scim, params={"attributes": "userName"})).json()
    assert all(set(x) == {"schemas", "id", "userName"} for x in lst["Resources"])


async def test_pagination_edges(client, scim, people):
    get = lambda **p: client.get("/scim/v2/Users", params=p, headers=scim)  # noqa: E731
    r = (await get(startIndex=0)).json()                    # < 1 is treated as 1
    assert r["startIndex"] == 1 and r["itemsPerPage"] == 3
    r = (await get(startIndex=99)).json()                   # past the end: empty page, true total
    assert r["totalResults"] == 3 and r["Resources"] == [] and r["itemsPerPage"] == 0
    r = (await get(count=-5)).json()                        # negative count = 0
    assert r["Resources"] == [] and r["totalResults"] == 3
    r = (await get(startIndex=3, count=100)).json()
    assert [x["userName"] for x in r["Resources"]] == [CAROL]
    r = (await get(startIndex=2, count=1000000)).json()     # count is capped, never unbounded
    assert r["itemsPerPage"] == 2
    assert (await get(startIndex="abc")).status_code == 400


# --------------------------------------------------------------------------- #
# ETags
# --------------------------------------------------------------------------- #

async def test_etag_and_if_match_on_users(client, scim, people):
    uid = people["alice"]
    g = await client.get(f"/scim/v2/Users/{uid}", headers=scim)
    etag = g.headers["etag"]
    assert etag.startswith('W/"') and g.json()["meta"]["version"] == etag
    assert (await client.get(f"/scim/v2/Users/{uid}", headers={**scim, "If-None-Match": etag})).status_code == 304
    assert (await client.get(f"/scim/v2/Users/{uid}", headers={**scim, "If-None-Match": 'W/"other"'})).status_code == 200

    op = {"schemas": [PATCH], "Operations": [{"op": "replace", "path": "displayName", "value": "A. Lee"}]}
    ok = await client.patch(f"/scim/v2/Users/{uid}", json=op, headers={**scim, "If-Match": etag})
    assert ok.status_code == 200 and ok.headers["etag"] != etag
    stale = await client.patch(f"/scim/v2/Users/{uid}", json=op, headers={**scim, "If-Match": etag})
    assert stale.status_code == 412 and stale.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert (await client.put(f"/scim/v2/Users/{uid}", json=okta_user(ALICE), headers={**scim, "If-Match": etag})
            ).status_code == 412
    assert (await client.delete(f"/scim/v2/Users/{uid}", headers={**scim, "If-Match": etag})).status_code == 412
    assert (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).status_code == 200      # still there
    # no If-Match (Okta, Entra) and "*" always work
    assert (await client.patch(f"/scim/v2/Users/{uid}", json=op, headers=scim)).status_code == 200
    assert (await client.patch(f"/scim/v2/Users/{uid}", json=op, headers={**scim, "If-Match": "*"})).status_code == 200
    cfg = (await client.get("/scim/v2/ServiceProviderConfig", headers=scim)).json()
    assert cfg["etag"]["supported"] is True


async def test_group_membership_changes_the_version_of_group_and_user(client, scim, people):
    uid = people["alice"]
    gid = (await client.post("/scim/v2/Groups", headers=scim,
                             json={"schemas": [GROUP], "displayName": "Ops"})).json()["id"]
    g1 = (await client.get(f"/scim/v2/Groups/{gid}", headers=scim)).headers["etag"]
    u1 = (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).headers["etag"]
    await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "add", "path": "members", "value": [{"value": uid}]}]})
    assert (await client.get(f"/scim/v2/Groups/{gid}", headers=scim)).headers["etag"] != g1
    assert (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).headers["etag"] != u1
    stale = await client.patch(f"/scim/v2/Groups/{gid}", headers={**scim, "If-Match": g1}, json={
        "schemas": [PATCH], "Operations": [{"op": "replace", "path": "displayName", "value": "X"}]})
    assert stale.status_code == 412
    assert (await client.delete(f"/scim/v2/Groups/{gid}", headers={**scim, "If-Match": g1})).status_code == 412
    assert (await client.get(f"/scim/v2/Groups/{gid}", headers=scim)).status_code == 200


# --------------------------------------------------------------------------- #
# Recorded PATCH shapes
# --------------------------------------------------------------------------- #

async def test_okta_patch_shapes(client, db_pool, scim, people):
    uid = people["alice"]
    # Okta deactivation / reactivation: no path, object value
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "replace", "value": {"active": False}}]})
    assert r.status_code == 200 and r.json()["active"] is False
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim, json={
        "schemas": [PATCH], "Operations": [{"op": "replace", "value": {"active": True}}]})
    assert r.json()["active"] is True
    # profile push: several attributes at once
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "replace", "value": {"displayName": "Ann L.", "name": {"givenName": "Anna", "familyName": "Lee"},
                                    "emails": [{"primary": True, "value": "ann.lee@corp.example", "type": "work"}]}}]})
    u = r.json()
    assert u["displayName"] == "Ann L." and u["name"]["givenName"] == "Anna"
    assert u["emails"][0]["value"] == "ann.lee@corp.example"
    # Okta group push removing one member with a filter path, then adding two
    gid = (await client.post("/scim/v2/Groups", headers=scim, json={
        "schemas": [GROUP], "displayName": "Okta Push",
        "members": [{"value": uid, "display": ALICE}]})).json()["id"]
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "remove", "path": f'members[value eq "{uid}"]'}]})
    assert r.json()["members"] == []
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "add", "path": "members", "value": [{"value": people["alice"], "display": ALICE},
                                                   {"value": people["bob"], "display": BOB}]}]})
    assert len(r.json()["members"]) == 2
    # Okta: members.value filter with a trailing .value, and an upper-cased GUID
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "remove", "path": f'members[value eq "{people["bob"].upper()}"].value'}]})
    assert [m["value"] for m in r.json()["members"]] == [people["alice"]]


async def test_entra_patch_shapes(client, db_pool, scim, people):
    uid = people["bob"]
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "Add", "path": "name.familyName", "value": "Ortiz-Ruiz"},
        {"op": "Remove", "path": "name.givenName"},
        {"op": "Replace", "path": "userName", "value": "bob.ortiz@corp.example"},
        {"op": "Replace", "path": 'emails[type eq "work"].value', "value": "bob.ortiz@corp.example"},
        {"op": "Remove", "path": 'phoneNumbers[type eq "mobile"]'},            # unsupported attribute: ignored
        {"op": "Add", "value": {"urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department": "IR",
                                "displayName": "Bob O."}},
        {"op": "Replace", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:manager",
         "value": "someone"},
    ]})
    assert r.status_code == 200, r.text
    u = r.json()
    assert u["userName"] == "bob.ortiz@corp.example" and u["displayName"] == "Bob O."
    assert u["name"]["familyName"] == "Ortiz-Ruiz" and "givenName" not in u["name"]
    assert u["emails"][0]["value"] == "bob.ortiz@corp.example"

    # Entra Groups: add two members, replace all, remove with a value array, upper-cased ids, unknown id
    gid = (await client.post("/scim/v2/Groups", headers=scim, json={
        "schemas": [GROUP], "externalId": "ent-1", "displayName": "Entra Group"})).json()["id"]
    ids = [people["alice"], people["bob"]]
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "Add", "path": "members", "value": [{"value": i} for i in ids]}]})
    assert sorted(m["value"] for m in r.json()["members"]) == sorted(ids)
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "Remove", "path": "members", "value": [{"value": ids[0].upper()}]}]})
    assert [m["value"] for m in r.json()["members"]] == [ids[1]]
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "Add", "path": "members", "value": [{"value": "00000000-0000-4000-8000-000000000000"}]}]})
    assert r.status_code == 200 and [m["value"] for m in r.json()["members"]] == [ids[1]]  # unknown id: ignored
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "Replace", "path": "members", "value": [{"value": ids[0]}]},
        {"op": "Replace", "path": "externalId", "value": "ent-2"}]})
    assert [m["value"] for m in r.json()["members"]] == [ids[0]] and r.json()["externalId"] == "ent-2"
    r = await client.patch(f"/scim/v2/Groups/{gid}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "Remove", "path": "members"}]})
    assert r.json()["members"] == []


@pytest.mark.parametrize("ops", [
    [],
    "not-a-list",
    [{"op": "add"}],                                          # add without path or value
    [{"op": "remove"}],                                       # remove without path
    [{"op": "replace", "path": "active", "value": {"a": 1}}],
    [{"op": "replace", "path": "userName", "value": ""}],
    [{"op": "remove", "path": "userName"}],
    ["x"],
])
async def test_bad_user_patches_are_400_and_change_nothing(client, scim, people, ops):
    uid = people["alice"]
    before = (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).json()
    r = await client.patch(f"/scim/v2/Users/{uid}", headers=scim, json={"schemas": [PATCH], "Operations": ops})
    assert r.status_code == 400 and r.json()["schemas"] == ["urn:ietf:params:scim:api:messages:2.0:Error"]
    assert (await client.get(f"/scim/v2/Users/{uid}", headers=scim)).json() == before


async def test_patch_username_collision_is_409(client, scim, people):
    r = await client.patch(f"/scim/v2/Users/{people['alice']}", headers=scim, json={"schemas": [PATCH], "Operations": [
        {"op": "replace", "path": "userName", "value": BOB.upper()}]})
    assert r.status_code == 409 and r.json()["scimType"] == "uniqueness"
