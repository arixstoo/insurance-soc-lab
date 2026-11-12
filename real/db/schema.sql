-- real-db-01: schema of the fictional InsurCo customer database (table names match the
-- simulated audit trail, so rule 100131's sensitive-table list applies unchanged).
CREATE TABLE clients (
    id          integer PRIMARY KEY,
    full_name   text NOT NULL,
    birth_date  date NOT NULL,
    email       text NOT NULL,
    city        text NOT NULL,
    created_on  date NOT NULL
);
CREATE TABLE policies (
    id          integer PRIMARY KEY,
    client_id   integer NOT NULL REFERENCES clients(id),
    product     text NOT NULL,
    premium_dzd numeric(12, 2) NOT NULL,
    start_date  date NOT NULL,
    status      text NOT NULL
);
CREATE TABLE claims (
    id          integer PRIMARY KEY,
    policy_id   integer NOT NULL REFERENCES policies(id),
    claim_date  date NOT NULL,
    kind        text NOT NULL,
    amount_dzd  numeric(12, 2) NOT NULL,
    status      text NOT NULL
);
CREATE TABLE payments (
    id          integer PRIMARY KEY,
    claim_id    integer NOT NULL REFERENCES claims(id),
    paid_on     date NOT NULL,
    amount_dzd  numeric(12, 2) NOT NULL,
    method      text NOT NULL
);
CREATE TABLE beneficiaries (
    id           integer PRIMARY KEY,
    policy_id    integer NOT NULL REFERENCES policies(id),
    full_name    text NOT NULL,
    relationship text NOT NULL
);

-- Lab roles (passwords set at start from the real-secrets volume):
--   portal_app     the claims portal: one record at a time
--   svc_reporting  scheduled BI extracts (allow-listed in detection/lists/db-service-accounts)
--   lab_analyst    a person; its bulk export is what rules 100131 / 100132 must catch
CREATE ROLE portal_app LOGIN;
CREATE ROLE svc_reporting LOGIN;
CREATE ROLE lab_analyst LOGIN;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO portal_app, svc_reporting, lab_analyst;
-- The portal updates the status of a claim (a WRITE line in the audit trail)
GRANT UPDATE (status) ON claims TO portal_app;
