import pytest

from sshleash.policy import STARTER, Context, PolicyError, parse


def test_starter_policy_parses_and_behaves():
    p = parse(STARTER)
    assert p.default == "allow" and p.confirm == "auto"
    assert p.decide(Context(forwarded=True, via=["devbox"]))[0] == "confirm"
    assert p.decide(Context(processes=["git", "codex"]))[0] == "confirm"
    assert p.decide(Context(processes=["ssh", "bash"]))[0] == "allow"
    assert p.decide(Context(processes=["ssh", "com.docker.backend"]))[0] == "confirm"


POL = '''
[[rule]]
name = "bot key: github only"
key = "bot"
host = ["github.com"]
action = "allow"
[[rule]]
name = "bot key: nothing else"
key = "bot"
action = "deny"
[[rule]]
name = "no prod via forwarding"
forwarded = true
host = ["*.prod.example"]
action = "deny"
[[rule]]
name = "unknown destinations from forwarded agents"
forwarded = true
host = ["unknown"]
action = "confirm"
[[rule]]
name = "work never on the ci box"
key = ["work", "SHA256:abc"]
via = ["ci-*"]
action = "deny"
[default]
action = "allow"
'''


def test_first_match_wins_and_host_globs():
    p = parse(POL)
    assert p.decide(Context(key_comment="bot", hosts=["github.com"])) == ("allow", "bot key: github only")
    assert p.decide(Context(key_comment="bot", hosts=["gitlab.com"]))[0] == "deny"
    assert p.decide(Context(key_comment="work", hosts=["db1.prod.example"], forwarded=True))[0] == "deny"
    assert p.decide(Context(key_comment="work", hosts=["db1.prod.example"]))[0] == "allow"
    assert p.decide(Context(key_comment="work", forwarded=True))[0] == "confirm"
    assert p.decide(Context(key_fp="SHA256:abc", hosts=["x"], forwarded=True, via=["ci-7"]))[0] == "deny"


def test_visibility_only_uses_connection_level_rules():
    p = parse(POL)
    # "bot key: github only" could still allow a request, so bot stays listed
    assert p.visible(Context(key_comment="bot")) == (True, "bot key: github only")
    # an earlier forwarded rule could still "confirm" a request, so work stays listed on ci-1 ...
    assert p.visible(Context(key_comment="work", forwarded=True, via=["ci-1"]))[0] is True
    # ... but a request through ci-1 to a known host is denied by the via rule
    assert p.decide(Context(key_comment="work", forwarded=True, via=["ci-1"], hosts=["x"]))[0] == "deny"
    assert p.visible(Context(key_comment="work", forwarded=True, via=["devbox"]))[0] is True


def test_kind_and_namespace():
    p = parse('''
[[rule]]
name = "no file signatures"
kind = ["sshsig"]
namespace = ["file"]
action = "deny"
[[rule]]
name = "work: no git signing"
kind = "sshsig"
key = "work"
action = "deny"
''')
    assert p.decide(Context(key_comment="bot", kind="sshsig", namespace="file")) == ("deny", "no file signatures")
    assert p.decide(Context(key_comment="bot", kind="sshsig", namespace="git"))[0] == "allow"
    assert p.decide(Context(key_comment="work", kind="sshsig", namespace="git")) == ("deny", "work: no git signing")
    assert p.decide(Context(key_comment="work", kind="ssh-auth"))[0] == "allow"


@pytest.mark.parametrize("text,msg", [
    ('[[rule]]\naction = "maybe"', "action"),
    ('[[rule]]\naction = "deny"\nhots = "x"', "unknown field"),
    ('[[rule]]\naction = "deny"\nkind = "login"', "unknown kind"),
    ('[[rule]]\naction = "deny"\nforwarded = "yes"', "forwarded"),
    ('[default]\naction = "nope"', "default"),
    ('[bogus]\n', "unknown section"),
    ('[[rule]\n', "policy"),
    ('[[rule]]\naction = "deny"\nkey = 5', "key"),
])
def test_policy_errors(text, msg):
    with pytest.raises(PolicyError, match=msg):
        parse(text)


def test_connection_deny_after_request_rule_keeps_key_visible():
    p = parse('''
[[rule]]
name = "forwarded: github asks"
forwarded = true
host = "github.com"
action = "confirm"
[[rule]]
name = "forwarded: nothing else"
forwarded = true
action = "deny"
''')
    # the key must stay listed, or the remote ssh would never try it for github.com
    assert p.visible(Context(key_comment="work", forwarded=True))[0] is True
    assert p.decide(Context(key_comment="work", forwarded=True, hosts=["github.com"]))[0] == "confirm"
    assert p.decide(Context(key_comment="work", forwarded=True, hosts=["gitlab.com"]))[0] == "deny"
    p2 = parse('[[rule]]\nname = "x"\nforwarded = true\naction = "deny"\n[[rule]]\nname = "y"\nhost = "a"\naction = "allow"\n')
    assert p2.visible(Context(forwarded=True))[0] is False
