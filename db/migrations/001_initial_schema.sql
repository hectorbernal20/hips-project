CREATE TABLE IF NOT EXISTS alarmas (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tipo_alarma VARCHAR(100) NOT NULL,
    ip_origen VARCHAR(45),
    modulo VARCHAR(100) NOT NULL,
    descripcion TEXT,
    resuelta BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS acciones_prevencion (
    id SERIAL PRIMARY KEY,
    alarma_id INTEGER REFERENCES alarmas(id) ON DELETE CASCADE,
    accion VARCHAR(150) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resultado TEXT
);

CREATE TABLE IF NOT EXISTS usuarios_web (
    id SERIAL PRIMARY KEY,
    username VARCHAR(80) UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    rol VARCHAR(30) NOT NULL DEFAULT 'operador',
    ultimo_login TIMESTAMP
);

CREATE TABLE IF NOT EXISTS configuracion_modulos (
    id SERIAL PRIMARY KEY,
    modulo VARCHAR(100) NOT NULL,
    parametro VARCHAR(100) NOT NULL,
    valor TEXT NOT NULL,
    activo BOOLEAN NOT NULL DEFAULT TRUE,
    UNIQUE (modulo, parametro)
);

CREATE TABLE IF NOT EXISTS eventos_sistema (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    evento VARCHAR(150) NOT NULL,
    origen VARCHAR(150),
    detalle TEXT
);

CREATE TABLE IF NOT EXISTS baseline_archivos (
    id SERIAL PRIMARY KEY,
    ruta_archivo TEXT UNIQUE NOT NULL,
    hash VARCHAR(128) NOT NULL,
    ultima_revision TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_alarmas_timestamp ON alarmas(timestamp);
CREATE INDEX IF NOT EXISTS idx_alarmas_tipo ON alarmas(tipo_alarma);
CREATE INDEX IF NOT EXISTS idx_alarmas_ip_origen ON alarmas(ip_origen);
CREATE INDEX IF NOT EXISTS idx_acciones_alarma_id ON acciones_prevencion(alarma_id);
