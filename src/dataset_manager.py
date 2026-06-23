"""数据集导入与管理模块

支持上传、管理、预览数据集，并用数据集继续训练检测模型。
数据集存储在 data/datasets/ 目录下，索引文件 data/datasets/index.json。
"""

import os
import json
import csv
import time
import uuid
import shutil
import threading
from datetime import datetime

import numpy as np
from loguru import logger

try:
    import pandas as pd
except ImportError:
    pd = None

DATASETS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "datasets")
INDEX_FILE = os.path.join(DATASETS_DIR, "index.json")
TRAINING_RECORDS_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), "data", "training_records.json"
)

os.makedirs(DATASETS_DIR, exist_ok=True)


class DatasetManager:
    """数据集管理器"""

    def __init__(self):
        self._lock = threading.Lock()
        self._ensure_index()

    def _ensure_index(self):
        if not os.path.exists(INDEX_FILE):
            with open(INDEX_FILE, "w", encoding="utf-8") as f:
                json.dump({"datasets": []}, f)

    def _read_index(self):
        with self._lock:
            with open(INDEX_FILE, "r", encoding="utf-8") as f:
                return json.load(f)

    def _write_index(self, data):
        with self._lock:
            with open(INDEX_FILE, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=2)

    def upload_dataset(self, file_path, filename):
        """上传数据集文件

        Args:
            file_path: 临时文件路径
            filename: 原始文件名

        Returns:
            数据集信息字典
        """
        dataset_id = "ds_%s_%s" % (datetime.now().strftime("%Y%m%d"), uuid.uuid4().hex[:8])
        dest_dir = os.path.join(DATASETS_DIR, dataset_id)
        os.makedirs(dest_dir, exist_ok=True)

        dest_file = os.path.join(dest_dir, filename)
        shutil.copy2(file_path, dest_file)

        # 解析文件获取信息
        info = self._parse_file(dest_file, filename)
        info["id"] = dataset_id
        info["filename"] = filename
        info["file_path"] = dest_file
        info["upload_time"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        info["status"] = "ready"

        # 写入索引
        index = self._read_index()
        index["datasets"].append(info)
        self._write_index(index)

        logger.info("数据集已导入: %s (%d行, %d列)" % (filename, info["row_count"], info["column_count"]))
        return info

    def _parse_file(self, file_path, filename):
        """解析数据集文件，返回统计信息"""
        result = {
            "row_count": 0,
            "column_count": 0,
            "columns": [],
            "dtypes": {},
            "sample_rows": [],
            "has_label": False,
            "label_column": None,
            "file_size": os.path.getsize(file_path),
            "file_type": "csv" if filename.endswith(".csv") else "json",
        }

        try:
            if filename.endswith(".csv"):
                if pd is not None:
                    df = pd.read_csv(file_path)
                    result["row_count"] = len(df)
                    result["column_count"] = len(df.columns)
                    result["columns"] = list(df.columns)
                    result["dtypes"] = {c: str(dt) for c, dt in df.dtypes.items()}
                    result["sample_rows"] = json.loads(df.head(20).to_json(orient="records", force_ascii=False))
                else:
                    with open(file_path, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        rows = list(reader)
                        result["row_count"] = len(rows)
                        if rows:
                            result["columns"] = list(rows[0].keys())
                            result["column_count"] = len(result["columns"])
                            result["sample_rows"] = rows[:20]

            elif filename.endswith(".json"):
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    result["row_count"] = len(data)
                    if data:
                        result["columns"] = list(data[0].keys())
                        result["column_count"] = len(result["columns"])
                        result["sample_rows"] = data[:20]
                elif isinstance(data, dict):
                    result["row_count"] = 1
                    result["columns"] = list(data.keys())
                    result["column_count"] = len(result["columns"])
                    result["sample_rows"] = [data]

            # 检查是否有标签列
            for col in result["columns"]:
                col_lower = col.lower()
                if col_lower in ("label", "is_attack", "is_fraud", "attack", "class", "y"):
                    result["has_label"] = True
                    result["label_column"] = col
                    break

        except Exception as e:
            logger.error("解析文件失败: %s" % e)
            result["status"] = "error"
            result["error"] = str(e)

        return result

    def list_datasets(self):
        """列出所有已导入数据集"""
        index = self._read_index()
        # 按上传时间倒序
        datasets = sorted(index["datasets"], key=lambda x: x.get("upload_time", ""), reverse=True)
        # 返回精简信息
        result = []
        for ds in datasets:
            result.append({
                "id": ds["id"],
                "filename": ds["filename"],
                "row_count": ds["row_count"],
                "column_count": ds["column_count"],
                "columns": ds.get("columns", []),
                "has_label": ds.get("has_label", False),
                "label_column": ds.get("label_column"),
                "file_size": ds.get("file_size", 0),
                "file_type": ds.get("file_type", "csv"),
                "upload_time": ds["upload_time"],
                "status": ds.get("status", "ready"),
            })
        return result

    def get_dataset(self, dataset_id):
        """获取数据集详情（含预览数据）"""
        index = self._read_index()
        for ds in index["datasets"]:
            if ds["id"] == dataset_id:
                return ds
        return None

    def delete_dataset(self, dataset_id):
        """删除数据集"""
        index = self._read_index()
        new_datasets = []
        deleted = False
        for ds in index["datasets"]:
            if ds["id"] == dataset_id:
                # 删除文件目录
                dest_dir = os.path.join(DATASETS_DIR, dataset_id)
                if os.path.exists(dest_dir):
                    shutil.rmtree(dest_dir)
                deleted = True
                logger.info("数据集已删除: %s (%s)" % (ds["filename"], dataset_id))
            else:
                new_datasets.append(ds)

        if deleted:
            index["datasets"] = new_datasets
            self._write_index(index)
        return deleted

    def load_dataset_data(self, dataset_id):
        """加载数据集的实际数据（用于训练）"""
        ds = self.get_dataset(dataset_id)
        if ds is None:
            return None, None, None

        file_path = ds.get("file_path")
        if not file_path or not os.path.exists(file_path):
            return None, None, None

        try:
            if file_path.endswith(".csv"):
                if pd is not None:
                    df = pd.read_csv(file_path)
                    data = df.to_dict(orient="records")
                else:
                    with open(file_path, "r", encoding="utf-8") as f:
                        reader = csv.DictReader(f)
                        data = list(reader)
            else:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, dict):
                    data = [data]

            return data, ds.get("columns", []), ds.get("label_column")
        except Exception as e:
            logger.error("加载数据集数据失败: %s" % e)
            return None, None, None


# 训练记录管理

def save_training_record(record):
    """保存训练记录"""
    os.makedirs(os.path.dirname(TRAINING_RECORDS_FILE), exist_ok=True)
    records = []
    if os.path.exists(TRAINING_RECORDS_FILE):
        try:
            with open(TRAINING_RECORDS_FILE, "r", encoding="utf-8-sig") as f:
                records = json.load(f)
        except Exception:
            records = []
    records.append(record)
    with open(TRAINING_RECORDS_FILE, "w", encoding="utf-8") as f:
        json.dump(records[-100:], f, ensure_ascii=False, indent=2)


def get_training_records(limit=20):
    """获取历史训练记录"""
    if not os.path.exists(TRAINING_RECORDS_FILE):
        return []
    try:
        with open(TRAINING_RECORDS_FILE, "r", encoding="utf-8-sig") as f:
            records = json.load(f)
        return records[-limit:][::-1]  # 最新的在前
    except Exception:
        return []


# 全局单例
dataset_manager = DatasetManager()
