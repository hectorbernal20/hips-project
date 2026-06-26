CREATE TABLE IF NOT EXISTS alarmas (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tipo_alarma VARCHAR(100) NOT NULL,
    ip_origen VARCHAR(45),
    modulo VARCHAR(100) NOT NULL DEFAULT 'hips',
    descripcion TEXT,
    resuelta BOOLEAN NOT NULL DEFAULT false,
    raw_data JSONB
);

CREATE TABLE IF NOT EXISTS acciones_prevencion (
    id SERIAL PRIMARY KEY,
    alarma_id INTEGER REFERENCES alarmas(id) ON DELETE CASCADE,
    accion VARCHAR(150) NOT NULL,
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resultado TEXT,
    tipo_alarma VARCHAR(100),
    ip_origen VARCHAR(45),
    raw_data JSONB
);

CREATE TABLE IF NOT EXISTS eventos_sistema (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP WITHOUT TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    evento VARCHAR(150) NOT NULL,
    origen VARCHAR(150),
    detalle TEXT,
    raw_data JSONB
);

ALTER TABLE alarmas
    ADD COLUMN IF NOT EXISTS raw_data JSONB;

ALTER TABLE acciones_prevencion
    ADD COLUMN IF NOT EXISTS tipo_alarma VARCHAR(100),
    ADD COLUMN IF NOT EXISTS ip_origen VARCHAR(45),
    ADD COLUMN IF NOT EXISTS raw_data JSONB;

ALTER TABLE eventos_sistema
    ADD COLUMN IF NOT EXISTS raw_data JSONB;

CREATE INDEX IF NOT EXISTS idx_alarmas_tipo ON alarmas(tipo_alarma);
CREATE INDEX IF NOT EXISTS idx_alarmas_ip_origen ON alarmas(ip_origen);
CREATE INDEX IF NOT EXISTS idx_alarmas_timestamp ON alarmas(timestamp);

CREATE INDEX IF NOT EXISTS idx_acciones_alarma_id ON acciones_prevencion(alarma_id);
CREATE INDEX IF NOT EXISTS idx_acciones_tipo_alarma ON acciones_prevencion(tipo_alarma);
CREATE INDEX IF NOT EXISTS idx_acciones_ip_origen ON acciones_prevencion(ip_origen);
CREATE INDEX IF NOT EXISTS idx_acciones_timestamp ON acciones_prevencion(timestamp);

CREATE INDEX IF NOT EXISTS idx_eventos_timestamp ON eventos_sistema(timestamp);
CREATE INDEX IF NOT EXISTS idx_eventos_origen ON eventos_sistema(origen);
CREATE INDEX IF NOT EXISTS idx_eventos_evento ON eventos_sistema(evento);

GRANT USAGE ON SCHEMA public TO hips_app;

GRANT SELECT, INSERT, UPDATE, DELETE ON alarmas TO hips_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON acciones_prevencion TO hips_app;
GRANT SELECT, INSERT, UPDATE, DELETE ON eventos_sistema TO hips_app;

GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO hips_app;
