-- Migración inicial del esquema HIPS
-- Base de datos: hips_db
-- Sistema: Rocky Linux 9.8 + PostgreSQL

CREATE TABLE IF NOT EXISTS alarmas (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    tipo_alarma VARCHAR(80) NOT NULL,
    ip_origen VARCHAR(45),
    modulo VARCHAR(80) NOT NULL,
    descripcion TEXT,
    severidad VARCHAR(20) NOT NULL DEFAULT 'MEDIA',
    resuelta BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE IF NOT EXISTS acciones_prevencion (
    id SERIAL PRIMARY KEY,
    alarma_id INTEGER NOT NULL,
    accion VARCHAR(100) NOT NULL,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    resultado VARCHAR(50) NOT NULL,
    detalle TEXT,
    CONSTRAINT fk_acciones_alarma
        FOREIGN KEY (alarma_id)
        REFERENCES alarmas(id)
        ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS usuarios_web (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    rol VARCHAR(30) NOT NULL DEFAULT 'admin',
    ultimo_login TIMESTAMP,
    activo BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS configuracion_modulos (
    id SERIAL PRIMARY KEY,
    modulo VARCHAR(80) NOT NULL,
    parametro VARCHAR(100) NOT NULL,
    valor TEXT NOT NULL,
    activo BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE TABLE IF NOT EXISTS eventos_sistema (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    modulo VARCHAR(80) NOT NULL,
    evento VARCHAR(100) NOT NULL,
    detalle TEXT
);

CREATE TABLE IF NOT EXISTS baseline_archivos (
    id SERIAL PRIMARY KEY,
    ruta_archivo TEXT NOT NULL UNIQUE,
    hash_original TEXT NOT NULL,
    fecha_registro TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    activo BOOLEAN NOT NULL DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_alarmas_timestamp
    ON alarmas(timestamp);

CREATE INDEX IF NOT EXISTS idx_alarmas_tipo_alarma
    ON alarmas(tipo_alarma);

CREATE INDEX IF NOT EXISTS idx_alarmas_ip_origen
    ON alarmas(ip_origen);

CREATE INDEX IF NOT EXISTS idx_acciones_prevencion_alarma_id
    ON acciones_prevencion(alarma_id);

CREATE INDEX IF NOT EXISTS idx_configuracion_modulos_modulo
    ON configuracion_modulos(modulo);
