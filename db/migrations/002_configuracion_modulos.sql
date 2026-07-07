DROP TABLE IF EXISTS configuracion_modulos CASCADE;

CREATE TABLE configuracion_modulos (
    id SERIAL PRIMARY KEY,
    modulo VARCHAR(80) NOT NULL UNIQUE,
    habilitado BOOLEAN NOT NULL DEFAULT true,
    intervalo_segundos INTEGER NOT NULL DEFAULT 60,
    umbral INTEGER,
    configuracion JSONB NOT NULL DEFAULT '{}'::jsonb,
    timestamp TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT chk_intervalo_positivo CHECK (intervalo_segundos > 0)
);

CREATE INDEX IF NOT EXISTS idx_configuracion_modulos_modulo
ON configuracion_modulos(modulo);

INSERT INTO configuracion_modulos (modulo, habilitado, intervalo_segundos, umbral, configuracion)
VALUES
('integridad_archivos', true, 60, null, '{}'),
('auth_failures', true, 60, 5, '{}'),
('sniffers', true, 60, null, '{}'),
('process_monitor', true, 60, null, '{}'),
('user_monitor', true, 60, null, '{}'),
('system_logs', true, 60, null, '{}'),
('tmp_monitor', true, 60, null, '{}'),
('cron_monitor', true, 60, null, '{}'),
('mail_queue', true, 60, 20, '{}'),
('ddos_monitor', true, 30, 50, '{}');
