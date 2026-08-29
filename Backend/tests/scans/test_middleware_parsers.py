"""
tests/scans/test_middleware_parsers.py
─────────────────────────────────────────────────────────────────────────────
The structured configuration parsers. Phase 8 (GAP-09).

Nothing here touches a transport. The parsers are pure text-in, structure-out,
and the fixtures below are trimmed from configuration captured off live
nginx 1.27, httpd 2.4 and Tomcat 10.1 containers — not invented, because a
parser tested only against input its author imagined is a parser tested against
its author's assumptions.

Four of these tests exist because the parser got it wrong against a real file
first: nginx block scoping, Apache's ServerRoot-relative includes, quoted
values containing braces, and the XML default namespace that made every Tomcat
selection silently return nothing.
"""

import pytest

from core.config_audit.structured import (
    Directive,
    ParseError,
    apache_includes,
    apache_server_root,
    json_pointer,
    nginx_includes,
    parse_apache,
    parse_nginx,
    render_value,
    rescope,
    select_directives,
    xml_select,
)

# ── Fixtures, trimmed from the real files ────────────────────────────────────

NGINX = """
user  nginx;
worker_processes  auto;
error_log  /var/log/nginx/error.log notice;

events {
    worker_connections  1024;
}

http {
    include       /etc/nginx/mime.types;
    default_type  application/octet-stream;

    log_format  main  '$remote_addr - $remote_user [$time_local] "$request" '
                      '$status $body_bytes_sent "$http_referer"';

    access_log  /var/log/nginx/access.log  main;
    #gzip  on;
    keepalive_timeout  65;

    server {
        listen 80;
        location / {
            autoindex on;
        }
    }

    include /etc/nginx/conf.d/*.conf;
}
"""

APACHE = """
ServerRoot "/usr/local/apache2"
Listen 80

LoadModule unixd_module modules/mod_unixd.so

<IfModule unixd_module>
User www-data
Group www-data
</IfModule>

<Directory />
    AllowOverride none
    Require all denied
</Directory>

<Directory "/usr/local/apache2/htdocs">
    Options Indexes FollowSymLinks
    AllowOverride None
</Directory>

ErrorLog /proc/self/fd/2
LogLevel warn

<IfModule log_config_module>
    <IfModule logio_module>
      LogFormat "%h %l" combinedio
    </IfModule>
    CustomLog /proc/self/fd/1 common
</IfModule>

Include conf/extra/proxy-html.conf
"""

TOMCAT_USERS_NS = """<?xml version="1.0" encoding="UTF-8"?>
<tomcat-users xmlns="http://tomcat.apache.org/xml"
              xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
              version="1.0">
  <role rolename="manager-gui"/>
  <user username="tomcat" password="s3cret" roles="manager-gui"/>
</tomcat-users>
"""

SERVER_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Server port="8005" shutdown="SHUTDOWN">
  <Service name="Catalina">
    <Connector port="8080" protocol="HTTP/1.1" connectionTimeout="20000"/>
    <Connector port="8443" protocol="org.apache.coyote.http11.Http11NioProtocol"/>
    <Engine name="Catalina" defaultHost="localhost">
      <Host name="localhost" appBase="webapps">
        <Valve className="org.apache.catalina.valves.AccessLogValve"
               directory="logs" prefix="localhost_access_log"/>
      </Host>
    </Engine>
  </Service>
</Server>
"""


# ── nginx ────────────────────────────────────────────────────────────────────


def test_nginx_directives_carry_their_block_path():
    parsed = parse_nginx(NGINX)
    assert [d.value for d in select_directives(parsed, "user", scope=[])] == ["nginx"]
    assert [
        d.value
        for d in select_directives(parsed, "worker_connections", scope=["events"])
    ] == ["1024"]
    assert [
        d.value for d in select_directives(parsed, "listen", scope=["http", "server"])
    ] == ["80"]


def test_nginx_scope_is_matched_exactly_not_by_suffix():
    """
    ``autoindex`` sits in ``http > server > location``. A rule about
    ``http > server`` must not match it — the whole reason to parse structure
    is that a directive in a nested location is a different statement.
    """
    parsed = parse_nginx(NGINX)
    assert select_directives(parsed, "autoindex", scope=["http", "server"]) == []
    assert (
        len(
            select_directives(parsed, "autoindex", scope=["http", "server", "location"])
        )
        == 1
    )
    # scope=None still finds it at any depth.
    assert len(select_directives(parsed, "autoindex")) == 1


def test_nginx_top_level_scope_excludes_nested():
    parsed = parse_nginx(NGINX)
    assert select_directives(parsed, "keepalive_timeout", scope=[]) == []
    assert len(select_directives(parsed, "keepalive_timeout", scope=["http"])) == 1


def test_nginx_quoted_values_survive_braces_and_semicolons():
    """
    ``log_format`` spans lines and its quoted parts contain ``;`` and ``$``. A
    naive split turns one directive into several malformed ones and then
    reports the settings around it as absent — a parser bug that presents as a
    fleet-wide configuration gap.
    """
    parsed = parse_nginx(NGINX)
    fmt = select_directives(parsed, "log_format", scope=["http"])
    assert len(fmt) == 1
    assert "$remote_addr" in fmt[0].value
    # The directives after it are still found, which is the real assertion.
    assert select_directives(parsed, "access_log", scope=["http"])


def test_nginx_comments_are_not_directives():
    parsed = parse_nginx(NGINX)
    assert select_directives(parsed, "gzip") == []


def test_nginx_includes_are_returned_with_their_scope():
    parsed = parse_nginx(NGINX)
    includes = nginx_includes(parsed)
    assert [i.value for i in includes] == [
        "/etc/nginx/mime.types",
        "/etc/nginx/conf.d/*.conf",
    ]
    # Both sit inside `http`, which is what lets the collector graft the
    # included file's `server` blocks onto `http > server`.
    assert all(i.scope == ("http",) for i in includes)


def test_nginx_unclosed_block_is_a_parse_error():
    with pytest.raises(ParseError):
        parse_nginx("http { server { listen 80;")


def test_nginx_stray_closing_brace_is_a_parse_error():
    with pytest.raises(ParseError):
        parse_nginx("listen 80; }")


# ── Rescoping ────────────────────────────────────────────────────────────────


def test_rescope_grafts_an_included_file_onto_its_parent_block():
    """
    An included file parses with scopes starting at nothing. nginx ships its
    ``server`` blocks in ``conf.d/*.conf``, included from inside ``http``, so
    without this they read as ``server`` and every rule about ``http > server``
    finds nothing and reports it as not configured.
    """
    child = parse_nginx("server { listen 8080; }")
    grafted = rescope(child.directives, ("http",))
    assert grafted[0].scope == ("http", "server")
    assert select_directives(
        type(child)(directives=grafted), "listen", scope=["http", "server"]
    )


def test_rescope_with_no_prefix_is_a_no_op():
    child = parse_nginx("server { listen 8080; }")
    assert rescope(child.directives, ()) == child.directives


# ── Apache ───────────────────────────────────────────────────────────────────


def test_apache_sections_nest():
    parsed = parse_apache(APACHE)
    overrides = select_directives(parsed, "AllowOverride", scope=["Directory"])
    assert [d.value for d in overrides] == ["none", "None"]
    nested = select_directives(parsed, "LogFormat", scope=["IfModule", "IfModule"])
    assert len(nested) == 1


def test_apache_user_is_inside_ifmodule_on_a_stock_install():
    """
    The stock layout puts ``User`` inside ``<IfModule unixd_module>``. A rule
    asserting it at the top level reports ABSENT on an entirely normal server,
    which is a false "not configured" — so the shipped rule uses scope=None.
    """
    parsed = parse_apache(APACHE)
    assert select_directives(parsed, "User", scope=[]) == []
    assert [d.value for d in select_directives(parsed, "User")] == ["www-data"]


def test_apache_server_root_is_read_for_include_resolution():
    """
    Apache resolves a relative Include against ServerRoot, not against the
    directory holding the file. Getting that wrong left the include unexpanded
    and downgraded every absent directive from a verdict to "could not assess".
    """
    parsed = parse_apache(APACHE)
    assert apache_server_root(parsed) == "/usr/local/apache2"
    assert [i.value for i in apache_includes(parsed)] == ["conf/extra/proxy-html.conf"]


def test_apache_line_continuations_are_joined():
    parsed = parse_apache('Header set X-Test \\\n    "value here"\n')
    hits = select_directives(parsed, "Header")
    assert len(hits) == 1
    assert "value here" in hits[0].value


def test_apache_mismatched_close_is_a_parse_error():
    """
    A parser that silently recovers produces a directive tree whose scopes are
    wrong from that point on, and every verdict after it is about the wrong
    part of the filesystem.
    """
    with pytest.raises(ParseError):
        parse_apache("<Directory />\n  AllowOverride None\n</Location>\n")


def test_apache_unclosed_section_is_a_parse_error():
    with pytest.raises(ParseError):
        parse_apache("<Directory />\n  AllowOverride None\n")


def test_apache_comments_are_not_directives():
    parsed = parse_apache("# ServerTokens Full\nServerTokens Prod\n")
    assert [d.value for d in select_directives(parsed, "ServerTokens")] == ["Prod"]


# ── XML ──────────────────────────────────────────────────────────────────────


def test_xml_default_namespace_does_not_hide_elements():
    """
    The bug that mattered most in this phase. Tomcat 10 declares
    xmlns="http://tomcat.apache.org/xml" on tomcat-users.xml, and ElementTree
    then needs the URI in the path — a plain ``.//user`` matches nothing.

    Nothing about that looks like a failure: the parse succeeds, the selection
    is empty, the collector reports ABSENT, and a rule whose absence policy is
    PASS declares the server clean. A namespace declaration silently produced a
    false negative on a real container.
    """
    assert xml_select(TOMCAT_USERS_NS, ".//user", attribute="username") == ["tomcat"]
    assert xml_select(TOMCAT_USERS_NS, ".//role", attribute="rolename") == [
        "manager-gui"
    ]


def test_xml_root_attributes_are_reachable():
    assert xml_select(SERVER_XML, ".", attribute="shutdown") == ["SHUTDOWN"]
    assert xml_select(SERVER_XML, ".", attribute="port") == ["8005"]


def test_xml_selects_every_match_in_order():
    assert xml_select(SERVER_XML, ".//Connector", attribute="port") == ["8080", "8443"]


def test_xml_predicate_selection_works():
    valves = xml_select(
        SERVER_XML,
        ".//Valve[@className='org.apache.catalina.valves.AccessLogValve']",
        attribute="directory",
    )
    assert valves == ["logs"]


def test_xml_missing_attribute_yields_nothing_not_an_empty_string():
    """
    "The Connector has no ``server`` attribute" and "it has ``server=''``" are
    different facts, and only the parser can still tell them apart. Collapsing
    them would let an unset attribute satisfy a rule about its value.
    """
    assert xml_select(SERVER_XML, ".//Connector", attribute="server") == []


def test_xml_malformed_document_raises_rather_than_returning_nothing():
    with pytest.raises(ParseError):
        xml_select("<Server><unclosed>", ".//Server")


# ── JSON ─────────────────────────────────────────────────────────────────────

DAEMON = (
    '{"hosts": ["unix:///var/run/docker.sock", "tcp://0.0.0.0:2375"], '
    '"icc": false, "log-driver": "json-file", '
    '"default-ulimits": {"nofile": {"Hard": 4096}}}'
)


def test_json_pointer_reads_scalars_lists_and_nested_paths():
    assert json_pointer(DAEMON, "log-driver") == "json-file"
    assert json_pointer(DAEMON, "icc") is False
    assert json_pointer(DAEMON, "hosts.1") == "tcp://0.0.0.0:2375"
    assert json_pointer(DAEMON, "default-ulimits.nofile.Hard") == 4096


def test_json_pointer_returns_none_for_an_absent_path():
    """
    None becomes ABSENT, which for the Docker daemon is the common and correct
    case: a host with no daemon.json is running every setting at its default
    rather than having no settings.
    """
    assert json_pointer(DAEMON, "userns-remap") is None
    assert json_pointer(DAEMON, "hosts.99") is None
    assert json_pointer(DAEMON, "log-driver.nope") is None


def test_json_malformed_document_raises():
    with pytest.raises(ParseError):
        json_pointer("{not json", "x")


def test_render_value_keeps_booleans_readable_by_the_operators():
    assert render_value(True) == "true"
    assert render_value(False) == "false"
    assert render_value(["a", 1]) == ["a", "1"]
    assert render_value(None) is None


# ── Evidence ─────────────────────────────────────────────────────────────────


def test_directive_evidence_names_the_scope_and_the_file():
    d = Directive(
        name="ssl_protocols",
        value="TLSv1.2",
        scope=("http", "server"),
        source="/etc/nginx/conf.d/tls.conf",
    )
    rendered = d.as_evidence()
    assert "http > server" in rendered
    assert "ssl_protocols TLSv1.2" in rendered
    assert "tls.conf" in rendered


# ── XML entity-expansion refusal ─────────────────────────────────────────────


def test_a_doctype_is_refused_before_the_parser_sees_it():
    """
    ElementTree *does* expand internal entities — measured, not assumed: the
    ten-line document below expands in a plain interpreter. The XML parsed here
    comes off a target being audited, so an entity bomb in a server.xml is a
    denial-of-service route into the scanner.

    Refusing any DOCTYPE closes it without a new dependency, and costs nothing
    real: no configuration file this phase reads carries a DTD.
    """
    bomb = (
        '<?xml version="1.0"?>'
        '<!DOCTYPE lolz [<!ENTITY lol "lol">'
        '<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>'
        "<x>&lol2;</x>"
    )
    with pytest.raises(ParseError) as exc:
        xml_select(bomb, ".//x")
    assert "DOCTYPE" in str(exc.value)


def test_ordinary_xml_declarations_are_not_mistaken_for_a_doctype():
    """The guard must not refuse every well-formed document that declares its
    version and encoding, which is all of them."""
    assert xml_select(SERVER_XML, ".", attribute="port") == ["8005"]
    assert xml_select(TOMCAT_USERS_NS, ".//user", attribute="username") == ["tomcat"]
