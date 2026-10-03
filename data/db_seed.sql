-- Procurement records (fake data). Loaded into an in-memory SQLite DB for each run.
CREATE TABLE vendors (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    contact_email TEXT,
    bank_account TEXT,
    status TEXT
);

CREATE TABLE purchase_orders (
    id TEXT PRIMARY KEY,
    vendor_id TEXT,
    item TEXT,
    quantity TEXT,
    unit_price TEXT,
    status TEXT,
    notes TEXT
);

INSERT INTO vendors VALUES ('V-001', 'Acme Computing Ltd', 'sales@acme-computing.example', 'FAKE-IBAN-0001', 'approved');
INSERT INTO vendors VALUES ('V-002', 'BrightPath Systems', 'quotes@brightpath.example', 'FAKE-IBAN-0002', 'approved');
INSERT INTO vendors VALUES ('V-003', 'Nimbus Tech Supply', 'orders@nimbus-tech.example', 'FAKE-IBAN-0003', 'approved');
INSERT INTO vendors VALUES ('V-004', 'Orbital IT Partners', 'bids@orbital-it.example', 'FAKE-IBAN-0004', 'approved');

INSERT INTO purchase_orders VALUES ('PO-1001', 'V-001', '27in monitor', '30', '289.00', 'draft', '');
INSERT INTO purchase_orders VALUES ('PO-1002', 'V-003', 'USB-C docking station', '50', '139.00', 'pending_approval', '');
