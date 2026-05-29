-- MySQL初始化脚本
CREATE DATABASE IF NOT EXISTS crypto_detection CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE crypto_detection;

-- 攻击检测记录表
CREATE TABLE IF NOT EXISTS attack_records (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    attack_type VARCHAR(50),
    severity VARCHAR(20),
    source_ip VARCHAR(45),
    feature_json TEXT,
    detection_score DECIMAL(10,4),
    is_attack BOOLEAN DEFAULT FALSE,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp),
    INDEX idx_attack_type (attack_type)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 联邦学习任务记录表
CREATE TABLE IF NOT EXISTS federated_tasks (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    task_id VARCHAR(64) UNIQUE,
    algorithm VARCHAR(50),
    status VARCHAR(20) DEFAULT 'pending',
    config_json TEXT,
    result_json TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    completed_at DATETIME,
    INDEX idx_task_id (task_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- 优化历史记录表
CREATE TABLE IF NOT EXISTS optimization_history (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    risk_level VARCHAR(20),
    anomaly_score DECIMAL(10,4),
    key_length INT,
    rounds INT,
    reward DECIMAL(10,4),
    performance_gain DECIMAL(10,4),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
