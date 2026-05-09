--
-- PostgreSQL database dump
--

\restrict 2EF0Nu2dntvBUOJytXvKkXSH2RmtL88RynU4Ie6D1WBwH7hHh5487c23FKDPicb

-- Dumped from database version 18.3
-- Dumped by pg_dump version 18.3

SET statement_timeout = 0;
SET lock_timeout = 0;
SET idle_in_transaction_session_timeout = 0;
SET transaction_timeout = 0;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = on;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET xmloption = content;
SET client_min_messages = warning;
SET row_security = off;

--
-- Name: pg_trgm; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pg_trgm WITH SCHEMA public;


--
-- Name: EXTENSION pg_trgm; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pg_trgm IS 'text similarity measurement and index searching based on trigrams';


--
-- Name: pgcrypto; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public;


--
-- Name: EXTENSION pgcrypto; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION pgcrypto IS 'cryptographic functions';


--
-- Name: uuid-ossp; Type: EXTENSION; Schema: -; Owner: -
--

CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;


--
-- Name: EXTENSION "uuid-ossp"; Type: COMMENT; Schema: -; Owner: 
--

COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';


SET default_tablespace = '';

SET default_table_access_method = heap;

--
-- Name: asset_change_log; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.asset_change_log (
    id bigint NOT NULL,
    asset_id text NOT NULL,
    scan_id text,
    change_type character varying(50) NOT NULL,
    field_name character varying(100),
    old_value jsonb,
    new_value jsonb,
    detected_at timestamp with time zone NOT NULL
);


ALTER TABLE public.asset_change_log OWNER TO ccure_user;

--
-- Name: asset_change_log_id_seq; Type: SEQUENCE; Schema: public; Owner: ccure_user
--

CREATE SEQUENCE public.asset_change_log_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_change_log_id_seq OWNER TO ccure_user;

--
-- Name: asset_change_log_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: ccure_user
--

ALTER SEQUENCE public.asset_change_log_id_seq OWNED BY public.asset_change_log.id;


--
-- Name: asset_notes; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.asset_notes (
    id bigint NOT NULL,
    asset_id text NOT NULL,
    user_id text,
    content text NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.asset_notes OWNER TO ccure_user;

--
-- Name: asset_notes_id_seq; Type: SEQUENCE; Schema: public; Owner: ccure_user
--

CREATE SEQUENCE public.asset_notes_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_notes_id_seq OWNER TO ccure_user;

--
-- Name: asset_notes_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: ccure_user
--

ALTER SEQUENCE public.asset_notes_id_seq OWNED BY public.asset_notes.id;


--
-- Name: asset_tags; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.asset_tags (
    id bigint NOT NULL,
    asset_id text NOT NULL,
    tag character varying(100) NOT NULL,
    created_by_id text,
    created_at timestamp with time zone NOT NULL
);


ALTER TABLE public.asset_tags OWNER TO ccure_user;

--
-- Name: asset_tags_id_seq; Type: SEQUENCE; Schema: public; Owner: ccure_user
--

CREATE SEQUENCE public.asset_tags_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.asset_tags_id_seq OWNER TO ccure_user;

--
-- Name: asset_tags_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: ccure_user
--

ALTER SEQUENCE public.asset_tags_id_seq OWNED BY public.asset_tags.id;


--
-- Name: asset_vulnerabilities; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.asset_vulnerabilities (
    id text NOT NULL,
    scan_id text NOT NULL,
    asset_id text NOT NULL,
    vuln_id character varying(30) NOT NULL,
    service_id text,
    severity character varying(20),
    cvss_score numeric(3,1),
    status character varying(50) NOT NULL,
    proof text,
    plugin_output text,
    remediation_notes text,
    fixed_at timestamp with time zone,
    accepted_risk_reason text,
    accepted_by text,
    first_found_at timestamp with time zone NOT NULL,
    last_found_at timestamp with time zone NOT NULL,
    created_at timestamp with time zone NOT NULL,
    org_id text
);


ALTER TABLE public.asset_vulnerabilities OWNER TO ccure_user;

--
-- Name: assets; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.assets (
    id text NOT NULL,
    org_id text NOT NULL,
    ip_address inet NOT NULL,
    mac_address macaddr,
    hostname character varying(255),
    dns_name character varying(512),
    fqdn character varying(512),
    netbios_name character varying(255),
    device_category character varying(100),
    os_family character varying(100),
    os_name character varying(255),
    os_version character varying(100),
    os_confidence smallint,
    vendor character varying(255),
    manufacturer character varying(255),
    subnet character varying(50),
    vlan_id integer,
    first_seen_at timestamp with time zone NOT NULL,
    last_seen_at timestamp with time zone NOT NULL,
    last_scan_id text,
    risk_score smallint NOT NULL,
    risk_level character varying(20) NOT NULL,
    vuln_counts jsonb NOT NULL,
    is_active boolean NOT NULL,
    is_managed boolean NOT NULL,
    owner character varying(255),
    notes_summary text,
    custom_attributes jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    discovery_method character varying(50),
    response_time_ms integer
);


ALTER TABLE public.assets OWNER TO ccure_user;

--
-- Name: audit_logs; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.audit_logs (
    id text NOT NULL,
    org_id text,
    user_id text,
    action character varying(100) NOT NULL,
    resource_type character varying(100),
    resource_id character varying(255),
    changes jsonb,
    ip_address inet,
    user_agent text,
    status character varying(20) NOT NULL,
    created_at timestamp with time zone NOT NULL
);


ALTER TABLE public.audit_logs OWNER TO ccure_user;

--
-- Name: audit_logs_id_seq; Type: SEQUENCE; Schema: public; Owner: ccure_user
--

CREATE SEQUENCE public.audit_logs_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.audit_logs_id_seq OWNER TO ccure_user;

--
-- Name: audit_logs_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: ccure_user
--

ALTER SEQUENCE public.audit_logs_id_seq OWNED BY public.audit_logs.id;


--
-- Name: http_security_details; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.http_security_details (
    id text NOT NULL,
    service_id text NOT NULL,
    status_code integer,
    server_header character varying(255),
    content_type character varying(255),
    has_hsts boolean NOT NULL,
    hsts_max_age integer,
    has_csp boolean NOT NULL,
    csp_value text,
    x_frame_options character varying(100),
    x_content_type boolean NOT NULL,
    x_xss_protection character varying(100),
    referrer_policy character varying(100),
    permissions_policy text,
    redirects_to_https boolean NOT NULL,
    missing_headers jsonb NOT NULL,
    security_score smallint,
    created_at timestamp with time zone NOT NULL
);


ALTER TABLE public.http_security_details OWNER TO ccure_user;

--
-- Name: notifications; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.notifications (
    id text NOT NULL,
    user_id text NOT NULL,
    type character varying(50) NOT NULL,
    category character varying(50) NOT NULL,
    title character varying(255) NOT NULL,
    message text NOT NULL,
    is_read boolean NOT NULL,
    related_scan_id character varying(100),
    related_data jsonb,
    action_url character varying(512),
    created_at timestamp with time zone NOT NULL,
    read_at timestamp with time zone
);


ALTER TABLE public.notifications OWNER TO ccure_user;

--
-- Name: organizations; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.organizations (
    id text NOT NULL,
    name character varying(255) NOT NULL,
    slug character varying(100) NOT NULL,
    plan character varying(50) NOT NULL,
    max_assets integer NOT NULL,
    max_users integer NOT NULL,
    is_active boolean NOT NULL,
    settings jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.organizations OWNER TO ccure_user;

--
-- Name: permissions; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.permissions (
    id smallint NOT NULL,
    resource character varying(100) NOT NULL,
    action character varying(50) NOT NULL,
    description text
);


ALTER TABLE public.permissions OWNER TO ccure_user;

--
-- Name: permissions_id_seq; Type: SEQUENCE; Schema: public; Owner: ccure_user
--

CREATE SEQUENCE public.permissions_id_seq
    AS smallint
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.permissions_id_seq OWNER TO ccure_user;

--
-- Name: permissions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: ccure_user
--

ALTER SEQUENCE public.permissions_id_seq OWNED BY public.permissions.id;


--
-- Name: refresh_token_sessions; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.refresh_token_sessions (
    id bigint NOT NULL,
    user_id text NOT NULL,
    org_id text NOT NULL,
    token_jti character varying(128) NOT NULL,
    token_hash character varying(255) NOT NULL,
    issued_at timestamp with time zone NOT NULL,
    expires_at timestamp with time zone NOT NULL,
    revoked_at timestamp with time zone,
    replaced_by character varying(128),
    ip_address inet,
    device_info jsonb
);


ALTER TABLE public.refresh_token_sessions OWNER TO ccure_user;

--
-- Name: refresh_token_sessions_id_seq; Type: SEQUENCE; Schema: public; Owner: ccure_user
--

CREATE SEQUENCE public.refresh_token_sessions_id_seq
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.refresh_token_sessions_id_seq OWNER TO ccure_user;

--
-- Name: refresh_token_sessions_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: ccure_user
--

ALTER SEQUENCE public.refresh_token_sessions_id_seq OWNED BY public.refresh_token_sessions.id;


--
-- Name: role_permissions; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.role_permissions (
    role_id smallint NOT NULL,
    permission_id smallint NOT NULL
);


ALTER TABLE public.role_permissions OWNER TO ccure_user;

--
-- Name: roles; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.roles (
    id smallint NOT NULL,
    name character varying(50) NOT NULL,
    description text,
    is_system_role boolean NOT NULL,
    created_at timestamp with time zone NOT NULL
);


ALTER TABLE public.roles OWNER TO ccure_user;

--
-- Name: roles_id_seq; Type: SEQUENCE; Schema: public; Owner: ccure_user
--

CREATE SEQUENCE public.roles_id_seq
    AS smallint
    START WITH 1
    INCREMENT BY 1
    NO MINVALUE
    NO MAXVALUE
    CACHE 1;


ALTER SEQUENCE public.roles_id_seq OWNER TO ccure_user;

--
-- Name: roles_id_seq; Type: SEQUENCE OWNED BY; Schema: public; Owner: ccure_user
--

ALTER SEQUENCE public.roles_id_seq OWNED BY public.roles.id;


--
-- Name: scan_phases; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.scan_phases (
    id text NOT NULL,
    scan_id text NOT NULL,
    phase_key character varying(50) NOT NULL,
    phase_order smallint NOT NULL,
    status character varying(50) NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_seconds double precision,
    hosts_processed integer NOT NULL,
    summary jsonb NOT NULL,
    error_message text,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.scan_phases OWNER TO ccure_user;

--
-- Name: scans; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.scans (
    id text NOT NULL,
    org_id text NOT NULL,
    created_by text,
    scan_name character varying(255),
    target_network cidr,
    target_hosts jsonb NOT NULL,
    target_str character varying(512) NOT NULL,
    scan_type character varying(50) NOT NULL,
    pipeline_mode character varying(50) NOT NULL,
    intensity character varying(50),
    options jsonb NOT NULL,
    status character varying(50) NOT NULL,
    failure_reason text,
    queued_at timestamp with time zone NOT NULL,
    started_at timestamp with time zone,
    completed_at timestamp with time zone,
    duration_seconds double precision,
    total_hosts integer NOT NULL,
    active_hosts integer NOT NULL,
    total_vulns integer NOT NULL,
    critical_count integer NOT NULL,
    high_count integer NOT NULL,
    medium_count integer NOT NULL,
    low_count integer NOT NULL,
    info_count integer NOT NULL,
    report_pdf_path character varying(512),
    report_xml_path character varying(512),
    report_json_path character varying(512),
    is_archived boolean NOT NULL,
    archived_at timestamp with time zone,
    is_deleted boolean NOT NULL,
    deleted_at timestamp with time zone,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    scan_no bigint
);


ALTER TABLE public.scans OWNER TO ccure_user;

--
-- Name: services; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.services (
    id text NOT NULL,
    scan_id text NOT NULL,
    asset_id text NOT NULL,
    port integer NOT NULL,
    protocol character varying(10) NOT NULL,
    state character varying(20) NOT NULL,
    service_name character varying(100),
    service_product character varying(255),
    service_version character varying(255),
    service_extra character varying(512),
    banner text,
    created_at timestamp with time zone NOT NULL
);


ALTER TABLE public.services OWNER TO ccure_user;

--
-- Name: tls_details; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.tls_details (
    id text NOT NULL,
    service_id text NOT NULL,
    is_enabled boolean NOT NULL,
    protocol_version character varying(20),
    cipher_suite character varying(255),
    key_bits integer,
    cert_subject jsonb,
    cert_issuer jsonb,
    cert_serial character varying(128),
    cert_not_before timestamp with time zone,
    cert_not_after timestamp with time zone,
    cert_is_expired boolean,
    cert_is_self_signed boolean,
    cert_san_domains jsonb NOT NULL,
    cert_fingerprint_sha256 character varying(95),
    grade character varying(5),
    is_weak_cipher boolean NOT NULL,
    issues jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL
);


ALTER TABLE public.tls_details OWNER TO ccure_user;

--
-- Name: users; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.users (
    id text NOT NULL,
    org_id text NOT NULL,
    role_id smallint NOT NULL,
    username character varying(100) NOT NULL,
    email character varying(320) NOT NULL,
    full_name character varying(255),
    password_hash character varying(255) NOT NULL,
    is_active boolean NOT NULL,
    is_verified boolean NOT NULL,
    last_login_at timestamp with time zone,
    failed_login_count integer NOT NULL,
    locked_until timestamp with time zone,
    avatar_url character varying(512),
    preferences jsonb NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL,
    is_deleted boolean DEFAULT false NOT NULL,
    deleted_at timestamp with time zone
);


ALTER TABLE public.users OWNER TO ccure_user;

--
-- Name: vulnerability_definitions; Type: TABLE; Schema: public; Owner: ccure_user
--

CREATE TABLE public.vulnerability_definitions (
    id character varying(30) NOT NULL,
    cve_id character varying(30),
    cwe_ids jsonb NOT NULL,
    title character varying(512) NOT NULL,
    description text,
    cvss_v2_score numeric(3,1),
    cvss_v3_score numeric(3,1),
    cvss_v4_score numeric(3,1),
    cvss_vector character varying(255),
    severity character varying(20) NOT NULL,
    published_at date,
    last_modified_at date,
    "references" jsonb NOT NULL,
    affected_software jsonb NOT NULL,
    source character varying(50) NOT NULL,
    is_custom boolean NOT NULL,
    created_at timestamp with time zone NOT NULL,
    updated_at timestamp with time zone NOT NULL
);


ALTER TABLE public.vulnerability_definitions OWNER TO ccure_user;

--
-- Name: asset_change_log id; Type: DEFAULT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_change_log ALTER COLUMN id SET DEFAULT nextval('public.asset_change_log_id_seq'::regclass);


--
-- Name: asset_notes id; Type: DEFAULT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_notes ALTER COLUMN id SET DEFAULT nextval('public.asset_notes_id_seq'::regclass);


--
-- Name: asset_tags id; Type: DEFAULT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_tags ALTER COLUMN id SET DEFAULT nextval('public.asset_tags_id_seq'::regclass);


--
-- Name: audit_logs id; Type: DEFAULT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.audit_logs ALTER COLUMN id SET DEFAULT nextval('public.audit_logs_id_seq'::regclass);


--
-- Name: permissions id; Type: DEFAULT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.permissions ALTER COLUMN id SET DEFAULT nextval('public.permissions_id_seq'::regclass);


--
-- Name: refresh_token_sessions id; Type: DEFAULT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.refresh_token_sessions ALTER COLUMN id SET DEFAULT nextval('public.refresh_token_sessions_id_seq'::regclass);


--
-- Name: roles id; Type: DEFAULT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.roles ALTER COLUMN id SET DEFAULT nextval('public.roles_id_seq'::regclass);


--
-- Name: asset_change_log asset_change_log_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_change_log
    ADD CONSTRAINT asset_change_log_pkey PRIMARY KEY (id);


--
-- Name: asset_notes asset_notes_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_notes
    ADD CONSTRAINT asset_notes_pkey PRIMARY KEY (id);


--
-- Name: asset_tags asset_tags_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_tags
    ADD CONSTRAINT asset_tags_pkey PRIMARY KEY (id);


--
-- Name: asset_vulnerabilities asset_vulnerabilities_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_pkey PRIMARY KEY (id);


--
-- Name: assets assets_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_pkey PRIMARY KEY (id);


--
-- Name: audit_logs audit_logs_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_pkey PRIMARY KEY (id);


--
-- Name: http_security_details http_security_details_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.http_security_details
    ADD CONSTRAINT http_security_details_pkey PRIMARY KEY (id);


--
-- Name: http_security_details http_security_details_service_id_key; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.http_security_details
    ADD CONSTRAINT http_security_details_service_id_key UNIQUE (service_id);


--
-- Name: notifications notifications_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_name_key; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_name_key UNIQUE (name);


--
-- Name: organizations organizations_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_pkey PRIMARY KEY (id);


--
-- Name: organizations organizations_slug_key; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.organizations
    ADD CONSTRAINT organizations_slug_key UNIQUE (slug);


--
-- Name: permissions permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT permissions_pkey PRIMARY KEY (id);


--
-- Name: refresh_token_sessions refresh_token_sessions_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.refresh_token_sessions
    ADD CONSTRAINT refresh_token_sessions_pkey PRIMARY KEY (id);


--
-- Name: refresh_token_sessions refresh_token_sessions_token_hash_key; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.refresh_token_sessions
    ADD CONSTRAINT refresh_token_sessions_token_hash_key UNIQUE (token_hash);


--
-- Name: role_permissions role_permissions_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_pkey PRIMARY KEY (role_id, permission_id);


--
-- Name: roles roles_name_key; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_name_key UNIQUE (name);


--
-- Name: roles roles_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.roles
    ADD CONSTRAINT roles_pkey PRIMARY KEY (id);


--
-- Name: scan_phases scan_phases_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.scan_phases
    ADD CONSTRAINT scan_phases_pkey PRIMARY KEY (id);


--
-- Name: scans scans_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_pkey PRIMARY KEY (id);


--
-- Name: services services_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_pkey PRIMARY KEY (id);


--
-- Name: tls_details tls_details_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.tls_details
    ADD CONSTRAINT tls_details_pkey PRIMARY KEY (id);


--
-- Name: tls_details tls_details_service_id_key; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.tls_details
    ADD CONSTRAINT tls_details_service_id_key UNIQUE (service_id);


--
-- Name: asset_tags uq_asset_tags_asset_tag; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_tags
    ADD CONSTRAINT uq_asset_tags_asset_tag UNIQUE (asset_id, tag);


--
-- Name: asset_vulnerabilities uq_asset_vuln_scan_asset_cve; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT uq_asset_vuln_scan_asset_cve UNIQUE (scan_id, asset_id, vuln_id);


--
-- Name: permissions uq_permissions_resource_action; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.permissions
    ADD CONSTRAINT uq_permissions_resource_action UNIQUE (resource, action);


--
-- Name: scan_phases uq_scan_phases_scan_phase; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.scan_phases
    ADD CONSTRAINT uq_scan_phases_scan_phase UNIQUE (scan_id, phase_key);


--
-- Name: services uq_services_scan_asset_port_proto; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT uq_services_scan_asset_port_proto UNIQUE (scan_id, asset_id, port, protocol);


--
-- Name: users users_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_pkey PRIMARY KEY (id);


--
-- Name: vulnerability_definitions vulnerability_definitions_pkey; Type: CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.vulnerability_definitions
    ADD CONSTRAINT vulnerability_definitions_pkey PRIMARY KEY (id);


--
-- Name: idx_user_category; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX idx_user_category ON public.notifications USING btree (user_id, category);


--
-- Name: idx_user_read_created; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX idx_user_read_created ON public.notifications USING btree (user_id, is_read, created_at);


--
-- Name: ix_asset_change_log_asset_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_change_log_asset_id ON public.asset_change_log USING btree (asset_id);


--
-- Name: ix_asset_change_log_change_type; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_change_log_change_type ON public.asset_change_log USING btree (change_type);


--
-- Name: ix_asset_change_log_detected_at; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_change_log_detected_at ON public.asset_change_log USING btree (detected_at);


--
-- Name: ix_asset_change_log_scan_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_change_log_scan_id ON public.asset_change_log USING btree (scan_id);


--
-- Name: ix_asset_notes_asset_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_notes_asset_id ON public.asset_notes USING btree (asset_id);


--
-- Name: ix_asset_tags_asset_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_tags_asset_id ON public.asset_tags USING btree (asset_id);


--
-- Name: ix_asset_tags_tag; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_tags_tag ON public.asset_tags USING btree (tag);


--
-- Name: ix_asset_vuln_asset_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vuln_asset_id ON public.asset_vulnerabilities USING btree (asset_id);


--
-- Name: ix_asset_vuln_first_found; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vuln_first_found ON public.asset_vulnerabilities USING btree (first_found_at);


--
-- Name: ix_asset_vuln_severity; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vuln_severity ON public.asset_vulnerabilities USING btree (severity);


--
-- Name: ix_asset_vuln_status; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vuln_status ON public.asset_vulnerabilities USING btree (status);


--
-- Name: ix_asset_vuln_vuln_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vuln_vuln_id ON public.asset_vulnerabilities USING btree (vuln_id);


--
-- Name: ix_asset_vulnerabilities_asset_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vulnerabilities_asset_id ON public.asset_vulnerabilities USING btree (asset_id);


--
-- Name: ix_asset_vulnerabilities_scan_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vulnerabilities_scan_id ON public.asset_vulnerabilities USING btree (scan_id);


--
-- Name: ix_asset_vulnerabilities_status; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vulnerabilities_status ON public.asset_vulnerabilities USING btree (status);


--
-- Name: ix_asset_vulnerabilities_vuln_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_asset_vulnerabilities_vuln_id ON public.asset_vulnerabilities USING btree (vuln_id);


--
-- Name: ix_assets_category; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_assets_category ON public.assets USING btree (device_category);


--
-- Name: ix_assets_device_category; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_assets_device_category ON public.assets USING btree (device_category);


--
-- Name: ix_assets_last_seen; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_assets_last_seen ON public.assets USING btree (last_seen_at);


--
-- Name: ix_assets_last_seen_at; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_assets_last_seen_at ON public.assets USING btree (last_seen_at);


--
-- Name: ix_assets_org_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_assets_org_id ON public.assets USING btree (org_id);


--
-- Name: ix_assets_org_ip; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_assets_org_ip ON public.assets USING btree (org_id, ip_address);


--
-- Name: ix_assets_org_risk; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_assets_org_risk ON public.assets USING btree (org_id, risk_score);


--
-- Name: ix_audit_logs_action; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_audit_logs_action ON public.audit_logs USING btree (action);


--
-- Name: ix_audit_logs_created_at; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_audit_logs_created_at ON public.audit_logs USING btree (created_at);


--
-- Name: ix_audit_logs_org_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_audit_logs_org_id ON public.audit_logs USING btree (org_id);


--
-- Name: ix_audit_logs_user_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_audit_logs_user_id ON public.audit_logs USING btree (user_id);


--
-- Name: ix_notifications_created_at; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_notifications_created_at ON public.notifications USING btree (created_at);


--
-- Name: ix_notifications_is_read; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_notifications_is_read ON public.notifications USING btree (is_read);


--
-- Name: ix_notifications_user_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_notifications_user_id ON public.notifications USING btree (user_id);


--
-- Name: ix_refresh_token_sessions_org_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_refresh_token_sessions_org_id ON public.refresh_token_sessions USING btree (org_id);


--
-- Name: ix_refresh_token_sessions_token_jti; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE UNIQUE INDEX ix_refresh_token_sessions_token_jti ON public.refresh_token_sessions USING btree (token_jti);


--
-- Name: ix_refresh_token_sessions_user_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_refresh_token_sessions_user_id ON public.refresh_token_sessions USING btree (user_id);


--
-- Name: ix_scan_phases_scan_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scan_phases_scan_id ON public.scan_phases USING btree (scan_id);


--
-- Name: ix_scans_created_by; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_created_by ON public.scans USING btree (created_by);


--
-- Name: ix_scans_is_deleted; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_is_deleted ON public.scans USING btree (is_deleted);


--
-- Name: ix_scans_org_created; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_org_created ON public.scans USING btree (org_id, created_at);


--
-- Name: ix_scans_org_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_org_id ON public.scans USING btree (org_id);


--
-- Name: ix_scans_org_pipeline; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_org_pipeline ON public.scans USING btree (org_id, pipeline_mode);


--
-- Name: ix_scans_org_scan_no_idx; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_org_scan_no_idx ON public.scans USING btree (org_id, scan_no);


--
-- Name: ix_scans_org_status; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_org_status ON public.scans USING btree (org_id, status);


--
-- Name: ix_scans_status; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_scans_status ON public.scans USING btree (status);


--
-- Name: ix_services_asset_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_services_asset_id ON public.services USING btree (asset_id);


--
-- Name: ix_services_asset_port; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_services_asset_port ON public.services USING btree (asset_id, port);


--
-- Name: ix_services_scan_asset; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_services_scan_asset ON public.services USING btree (scan_id, asset_id);


--
-- Name: ix_services_scan_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_services_scan_id ON public.services USING btree (scan_id);


--
-- Name: ix_services_service_name; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_services_service_name ON public.services USING btree (service_name);


--
-- Name: ix_users_deleted_at; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_users_deleted_at ON public.users USING btree (deleted_at);


--
-- Name: ix_users_email; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE UNIQUE INDEX ix_users_email ON public.users USING btree (email);


--
-- Name: ix_users_is_deleted; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_users_is_deleted ON public.users USING btree (is_deleted);


--
-- Name: ix_users_org_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_users_org_id ON public.users USING btree (org_id);


--
-- Name: ix_users_role_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_users_role_id ON public.users USING btree (role_id);


--
-- Name: ix_users_username; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE UNIQUE INDEX ix_users_username ON public.users USING btree (username);


--
-- Name: ix_vuln_def_cvss_v3; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_vuln_def_cvss_v3 ON public.vulnerability_definitions USING btree (cvss_v3_score);


--
-- Name: ix_vuln_def_published; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_vuln_def_published ON public.vulnerability_definitions USING btree (published_at);


--
-- Name: ix_vuln_def_severity; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_vuln_def_severity ON public.vulnerability_definitions USING btree (severity);


--
-- Name: ix_vuln_def_source; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_vuln_def_source ON public.vulnerability_definitions USING btree (source);


--
-- Name: ix_vulnerability_definitions_cve_id; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE UNIQUE INDEX ix_vulnerability_definitions_cve_id ON public.vulnerability_definitions USING btree (cve_id);


--
-- Name: ix_vulnerability_definitions_severity; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE INDEX ix_vulnerability_definitions_severity ON public.vulnerability_definitions USING btree (severity);


--
-- Name: uq_assets_org_mac; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE UNIQUE INDEX uq_assets_org_mac ON public.assets USING btree (org_id, mac_address) WHERE (mac_address IS NOT NULL);


--
-- Name: uq_scans_org_user_scan_no_idx; Type: INDEX; Schema: public; Owner: ccure_user
--

CREATE UNIQUE INDEX uq_scans_org_user_scan_no_idx ON public.scans USING btree (org_id, created_by, scan_no) WHERE (scan_no IS NOT NULL);


--
-- Name: asset_change_log asset_change_log_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_change_log
    ADD CONSTRAINT asset_change_log_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: asset_change_log asset_change_log_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_change_log
    ADD CONSTRAINT asset_change_log_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: asset_notes asset_notes_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_notes
    ADD CONSTRAINT asset_notes_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: asset_notes asset_notes_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_notes
    ADD CONSTRAINT asset_notes_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: asset_tags asset_tags_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_tags
    ADD CONSTRAINT asset_tags_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: asset_tags asset_tags_created_by_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_tags
    ADD CONSTRAINT asset_tags_created_by_id_fkey FOREIGN KEY (created_by_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_accepted_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_accepted_by_fkey FOREIGN KEY (accepted_by) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.services(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: asset_vulnerabilities asset_vulnerabilities_vuln_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.asset_vulnerabilities
    ADD CONSTRAINT asset_vulnerabilities_vuln_id_fkey FOREIGN KEY (vuln_id) REFERENCES public.vulnerability_definitions(id) ON DELETE RESTRICT;


--
-- Name: assets assets_last_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_last_scan_id_fkey FOREIGN KEY (last_scan_id) REFERENCES public.scans(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: assets assets_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.assets
    ADD CONSTRAINT assets_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: audit_logs audit_logs_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: audit_logs audit_logs_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.audit_logs
    ADD CONSTRAINT audit_logs_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: http_security_details http_security_details_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.http_security_details
    ADD CONSTRAINT http_security_details_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.services(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: notifications notifications_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.notifications
    ADD CONSTRAINT notifications_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: refresh_token_sessions refresh_token_sessions_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.refresh_token_sessions
    ADD CONSTRAINT refresh_token_sessions_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: refresh_token_sessions refresh_token_sessions_user_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.refresh_token_sessions
    ADD CONSTRAINT refresh_token_sessions_user_id_fkey FOREIGN KEY (user_id) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_permission_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_permission_id_fkey FOREIGN KEY (permission_id) REFERENCES public.permissions(id) ON DELETE CASCADE;


--
-- Name: role_permissions role_permissions_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.role_permissions
    ADD CONSTRAINT role_permissions_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE CASCADE;


--
-- Name: scan_phases scan_phases_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.scan_phases
    ADD CONSTRAINT scan_phases_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: scans scans_created_by_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_created_by_fkey FOREIGN KEY (created_by) REFERENCES public.users(id) ON UPDATE CASCADE ON DELETE SET NULL;


--
-- Name: scans scans_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.scans
    ADD CONSTRAINT scans_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: services services_asset_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_asset_id_fkey FOREIGN KEY (asset_id) REFERENCES public.assets(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: services services_scan_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.services
    ADD CONSTRAINT services_scan_id_fkey FOREIGN KEY (scan_id) REFERENCES public.scans(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: tls_details tls_details_service_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.tls_details
    ADD CONSTRAINT tls_details_service_id_fkey FOREIGN KEY (service_id) REFERENCES public.services(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: users users_org_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_org_id_fkey FOREIGN KEY (org_id) REFERENCES public.organizations(id) ON UPDATE CASCADE ON DELETE CASCADE;


--
-- Name: users users_role_id_fkey; Type: FK CONSTRAINT; Schema: public; Owner: ccure_user
--

ALTER TABLE ONLY public.users
    ADD CONSTRAINT users_role_id_fkey FOREIGN KEY (role_id) REFERENCES public.roles(id) ON DELETE RESTRICT;


--
-- Name: SCHEMA public; Type: ACL; Schema: -; Owner: pg_database_owner
--

GRANT ALL ON SCHEMA public TO ccure_user;


--
-- PostgreSQL database dump complete
--

\unrestrict 2EF0Nu2dntvBUOJytXvKkXSH2RmtL88RynU4Ie6D1WBwH7hHh5487c23FKDPicb

